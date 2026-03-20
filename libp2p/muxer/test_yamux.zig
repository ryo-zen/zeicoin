const std = @import("std");
const yamux = @import("yamux.zig");
const noise = @import("../security/noise.zig");
const inproc = @import("../transport/inproc.zig");
const ms = @import("../protocol/multistream.zig");

const Session = yamux.Session;
const Stream = yamux.Stream;
const SessionOptions = yamux.SessionOptions;
const YamuxError = yamux.YamuxError;

const FLAG_SYN: u16 = 0x1;
const FLAG_ACK: u16 = 0x2;
const INITIAL_STREAM_WINDOW: usize = 8 * 1024 * 1024;
const MAX_PENDING_ACCEPT: usize = 64;

fn readAllFromStream(allocator: std.mem.Allocator, stream: *Stream) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try stream.readSome(&buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
    }
    return out.toOwnedSlice();
}

const TestReader = struct {
    stream: *Stream,

    pub fn readByte(self: *TestReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.stream.readSome(&one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *TestReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.stream.readSome(dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const TestWriter = struct {
    stream: *Stream,

    pub fn writeAll(self: *TestWriter, data: []const u8) !void {
        try self.stream.writeAll(data);
    }

    pub fn writeByte(self: *TestWriter, b: u8) !void {
        try self.stream.writeByte(b);
    }
};

fn readLineFromTestStream(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();

    while (true) {
        const b = try reader.readByte();
        if (b == '\n') break;
        try buf.append(b);
    }

    return buf.toOwnedSlice();
}

fn readExpectedReply(stream: *Stream, expected: []const u8) !void {
    var out: [32]u8 = undefined;
    std.debug.assert(expected.len <= out.len);
    var out_len: usize = 0;

    while (out_len < expected.len) {
        const n = stream.readSome(out[out_len..]) catch |err| switch (err) {
            YamuxError.SessionClosed => break,
            else => return err,
        };
        if (n == 0) break;
        out_len += n;
    }

    if (out_len < expected.len) return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(expected, out[0..expected.len]);
}

fn readExact(stream: *Stream, dest: []u8) !void {
    var off: usize = 0;
    while (off < dest.len) {
        const n = try stream.readSome(dest[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

test "yamux header parse primitives" {
    var header: [12]u8 = undefined;
    header[0] = 0;
    header[1] = 0; // FrameType.data
    std.mem.writeInt(u16, header[2..4], FLAG_SYN | FLAG_ACK, .big);
    std.mem.writeInt(u32, header[4..8], 5, .big);
    std.mem.writeInt(u32, header[8..12], 123, .big);

    try std.testing.expectEqual(@as(u8, 0), header[0]);
    try std.testing.expectEqual(@as(u8, 0), header[1]);
    try std.testing.expectEqual(@as(u16, FLAG_SYN | FLAG_ACK), std.mem.readInt(u16, header[2..4], .big));
    try std.testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, header[4..8], .big));
    try std.testing.expectEqual(@as(u32, 123), std.mem.readInt(u32, header[8..12], .big));
}

test "yamux supports two concurrent streams" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const Sync = struct {
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    };
    var sync = Sync{};

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,
        sync: *Sync,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x11} ** 32;
            const rx_key = [_]u8{0x22} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var first_accept = try session.acceptStreamConcurrent();
            var second_accept = try session.acceptStreamConcurrent();
            var first = try first_accept.await(ctx.io);
            defer first.deinit();
            var second = try second_accept.await(ctx.io);
            defer second.deinit();

            const first_msg = try readAllFromStream(ctx.allocator, &first);
            defer ctx.allocator.free(first_msg);
            const second_msg = try readAllFromStream(ctx.allocator, &second);
            defer ctx.allocator.free(second_msg);

            if (std.mem.eql(u8, first_msg, "one")) {
                try first.writeAll("uno");
            } else if (std.mem.eql(u8, first_msg, "two")) {
                try first.writeAll("dos");
            } else {
                return error.TestExpectedEqual;
            }
            if (std.mem.eql(u8, second_msg, "one")) {
                try second.writeAll("uno");
            } else if (std.mem.eql(u8, second_msg, "two")) {
                try second.writeAll("dos");
            } else {
                return error.TestExpectedEqual;
            }

            // Keep the responder session alive until the initiator confirms replies were drained.
            var spins: usize = 0;
            while (!ctx.sync.done.load(.seq_cst) and spins < 200) : (spins += 1) {
                try ctx.io.sleep(std.Io.Duration.fromMilliseconds(5), .awake);
            }
        }
    };

    var responder_ctx = ResponderCtx{
        .conn = &responder_conn,
        .allocator = allocator,
        .io = io,
        .sync = &sync,
    };

    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x11} ** 32, [_]u8{0x22} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var first_open = try session.openStreamConcurrent();
    var second_open = try session.openStreamConcurrent();
    var first = try first_open.await(io);
    defer first.deinit();
    var second = try second_open.await(io);
    defer second.deinit();

    try first.writeAll("one");
    try first.close();
    try second.writeAll("two");
    try second.close();

    var first_reply: [3]u8 = undefined;
    var second_reply: [3]u8 = undefined;
    try readExact(&first, &first_reply);
    try readExact(&second, &second_reply);
    try std.testing.expectEqualStrings("uno", &first_reply);
    try std.testing.expectEqualStrings("dos", &second_reply);
    sync.done.store(true, .seq_cst);
    try responder_future.await(io);
}

test "yamux supports three simultaneous streams from both sides" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x13} ** 32;
            const rx_key = [_]u8{0x24} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_1_future = try session.acceptStreamConcurrent();
            var accept_2_future = try session.acceptStreamConcurrent();
            var accept_3_future = try session.acceptStreamConcurrent();
            var open_1_future = try session.openStreamConcurrent();
            var open_2_future = try session.openStreamConcurrent();
            var open_3_future = try session.openStreamConcurrent();

            var out_1 = try open_1_future.await(ctx.io);
            defer out_1.deinit();
            var out_2 = try open_2_future.await(ctx.io);
            defer out_2.deinit();
            var out_3 = try open_3_future.await(ctx.io);
            defer out_3.deinit();

            try out_1.writeAll("resp-1");
            try out_1.close();
            try out_2.writeAll("resp-2");
            try out_2.close();
            try out_3.writeAll("resp-3");
            try out_3.close();

            var in_1 = try accept_1_future.await(ctx.io);
            defer in_1.deinit();
            var in_2 = try accept_2_future.await(ctx.io);
            defer in_2.deinit();
            var in_3 = try accept_3_future.await(ctx.io);
            defer in_3.deinit();

            const msg_1 = try readAllFromStream(ctx.allocator, &in_1);
            defer ctx.allocator.free(msg_1);
            const msg_2 = try readAllFromStream(ctx.allocator, &in_2);
            defer ctx.allocator.free(msg_2);
            const msg_3 = try readAllFromStream(ctx.allocator, &in_3);
            defer ctx.allocator.free(msg_3);

            var saw_1 = false;
            var saw_2 = false;
            var saw_3 = false;
            for ([_][]const u8{ msg_1, msg_2, msg_3 }) |msg| {
                if (std.mem.eql(u8, msg, "init-1")) {
                    saw_1 = true;
                } else if (std.mem.eql(u8, msg, "init-2")) {
                    saw_2 = true;
                } else if (std.mem.eql(u8, msg, "init-3")) {
                    saw_3 = true;
                } else {
                    return error.TestExpectedEqual;
                }
            }
            if (!saw_1 or !saw_2 or !saw_3) return error.TestExpectedEqual;
        }
    };

    var responder_ctx = ResponderCtx{ .conn = &responder_conn, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x13} ** 32, [_]u8{0x24} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var accept_1_future = try session.acceptStreamConcurrent();
    var accept_2_future = try session.acceptStreamConcurrent();
    var accept_3_future = try session.acceptStreamConcurrent();
    var open_1_future = try session.openStreamConcurrent();
    var open_2_future = try session.openStreamConcurrent();
    var open_3_future = try session.openStreamConcurrent();

    var out_1 = try open_1_future.await(io);
    defer out_1.deinit();
    var out_2 = try open_2_future.await(io);
    defer out_2.deinit();
    var out_3 = try open_3_future.await(io);
    defer out_3.deinit();

    try out_1.writeAll("init-1");
    try out_1.close();
    try out_2.writeAll("init-2");
    try out_2.close();
    try out_3.writeAll("init-3");
    try out_3.close();

    var in_1 = try accept_1_future.await(io);
    defer in_1.deinit();
    var in_2 = try accept_2_future.await(io);
    defer in_2.deinit();
    var in_3 = try accept_3_future.await(io);
    defer in_3.deinit();

    const msg_1 = try readAllFromStream(allocator, &in_1);
    defer allocator.free(msg_1);
    const msg_2 = try readAllFromStream(allocator, &in_2);
    defer allocator.free(msg_2);
    const msg_3 = try readAllFromStream(allocator, &in_3);
    defer allocator.free(msg_3);

    var saw_1 = false;
    var saw_2 = false;
    var saw_3 = false;
    for ([_][]const u8{ msg_1, msg_2, msg_3 }) |msg| {
        if (std.mem.eql(u8, msg, "resp-1")) {
            saw_1 = true;
        } else if (std.mem.eql(u8, msg, "resp-2")) {
            saw_2 = true;
        } else if (std.mem.eql(u8, msg, "resp-3")) {
            saw_3 = true;
        } else {
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expect(saw_1 and saw_2 and saw_3);
    try responder_future.await(io);
}

test "yamux blocks on exhausted window then resumes after window update" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const payload = try allocator.alloc(u8, INITIAL_STREAM_WINDOW + 64 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0x5A);

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x31} ** 32;
            const rx_key = [_]u8{0x42} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_future = try session.acceptStreamConcurrent();
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            // Delay reads so the remote writer exhausts send_window and blocks.
            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(180), .awake);

            const received = try readAllFromStream(ctx.allocator, &stream);
            defer ctx.allocator.free(received);

            if (received.len != INITIAL_STREAM_WINDOW + 64 * 1024) return error.TestExpectedEqual;
            for (received) |byte| {
                if (byte != 0x5A) return error.TestExpectedEqual;
            }
        }
    };

    var responder_ctx = ResponderCtx{ .conn = &responder_conn, .allocator = allocator, .io = io };

    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x31} ** 32, [_]u8{0x42} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    const WriterCtx = struct {
        stream: *Stream,
        payload: []const u8,
        elapsed_ns: u64 = 0,

        fn run(ctx: *@This()) anyerror!void {
            var timer = try std.time.Timer.start();
            try ctx.stream.writeAll(ctx.payload);
            try ctx.stream.close();
            ctx.elapsed_ns = timer.read();
        }
    };

    var open_future = try session.openStreamConcurrent();
    var stream = try open_future.await(io);
    defer stream.deinit();

    var writer_ctx = WriterCtx{
        .stream = &stream,
        .payload = payload,
    };
    var writer_future = try io.concurrent(WriterCtx.run, .{&writer_ctx});
    defer _ = writer_future.cancel(io) catch {};

    try writer_future.await(io);
    try std.testing.expect(writer_ctx.elapsed_ns >= 120 * std.time.ns_per_ms);
    try responder_future.await(io);
}

test "yamux rst closes only target stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x51} ** 32;
            const rx_key = [_]u8{0x62} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_1 = try session.acceptStreamConcurrent();
            var accept_2 = try session.acceptStreamConcurrent();
            var stream_1 = try accept_1.await(ctx.io);
            defer stream_1.deinit();
            var stream_2 = try accept_2.await(ctx.io);
            defer stream_2.deinit();

            var one: [32]u8 = undefined;
            var two: [32]u8 = undefined;
            const n1 = try stream_1.readSome(&one);
            const n2 = try stream_2.readSome(&two);
            if (n1 == 0 or n2 == 0) return error.TestExpectedEqual;

            const msg_1 = one[0..n1];
            const msg_2 = two[0..n2];

            var survivor: *Stream = undefined;
            if (std.mem.eql(u8, msg_1, "victim") and std.mem.eql(u8, msg_2, "hello2")) {
                try session.testSendRst(stream_1.testStreamId());
                survivor = &stream_2;
            } else if (std.mem.eql(u8, msg_2, "victim") and std.mem.eql(u8, msg_1, "hello2")) {
                try session.testSendRst(stream_2.testStreamId());
                survivor = &stream_1;
            } else {
                return error.TestExpectedEqual;
            }

            var survivor_followup: [7]u8 = undefined;
            try readExact(survivor, &survivor_followup);
            if (!std.mem.eql(u8, &survivor_followup, "stillok")) return error.TestExpectedEqual;
        }
    };

    var responder_ctx = ResponderCtx{
        .conn = &responder_conn,
        .allocator = allocator,
        .io = io,
    };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x51} ** 32, [_]u8{0x62} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var open_1 = try session.openStreamConcurrent();
    var open_2 = try session.openStreamConcurrent();
    var stream_1 = try open_1.await(io);
    defer stream_1.deinit();
    var stream_2 = try open_2.await(io);
    defer stream_2.deinit();

    try stream_1.writeAll("victim");
    try stream_2.writeAll("hello2");

    var one: [1]u8 = undefined;
    _ = stream_1.readSome(&one) catch |err| switch (err) {
        YamuxError.StreamClosed, YamuxError.SessionClosed => 0,
        else => return err,
    };

    // Assert RST on stream_1 did not break unrelated stream_2 writes.
    try stream_2.writeAll("stillok");
    try stream_2.close();
    try responder_future.await(io);
}

test "yamux inbound accept backlog limit is enforced at 64 streams" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x71} ** 32;
            const rx_key = [_]u8{0x82} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            // Let inbound SYNs accumulate in pending_accept before consuming.
            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(250), .awake);

            var accepted_count: usize = 0;
            while (accepted_count < MAX_PENDING_ACCEPT) : (accepted_count += 1) {
                var accepted = try session.acceptStream();
                defer accepted.deinit();
                try accepted.close();
            }
        }
    };

    var responder_ctx = ResponderCtx{
        .conn = &responder_conn,
        .allocator = allocator,
        .io = io,
    };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x71} ** 32, [_]u8{0x82} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var futures: [MAX_PENDING_ACCEPT + 1]std.Io.Future(anyerror!Stream) = undefined;
    for (&futures) |*future| {
        future.* = try session.openStreamConcurrent();
    }

    var opened = std.array_list.Managed(Stream).init(allocator);
    defer opened.deinit();

    var stream_closed_count: usize = 0;
    for (&futures) |*future| {
        const maybe_stream = future.await(io) catch |err| switch (err) {
            YamuxError.StreamClosed => {
                stream_closed_count += 1;
                continue;
            },
            else => return err,
        };
        try opened.append(maybe_stream);
    }

    try std.testing.expectEqual(@as(usize, MAX_PENDING_ACCEPT), opened.items.len);
    try std.testing.expectEqual(@as(usize, 1), stream_closed_count);

    for (opened.items) |*stream| {
        stream.close() catch {};
        stream.deinit();
    }
    try responder_future.await(io);
}

test "yamux handles identify then peer exchange across sequential streams" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x61} ** 32;
            const rx_key = [_]u8{0x72} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var identify_accept = try session.acceptStreamConcurrent();
            var identify_stream = try identify_accept.await(ctx.io);
            defer identify_stream.deinit();

            var identify_reader = TestReader{ .stream = &identify_stream };
            var identify_writer = TestWriter{ .stream = &identify_stream };

            const identify_proto = try ms.readMessage(ctx.io, &identify_reader, ctx.allocator);
            defer ctx.allocator.free(identify_proto);
            if (!std.mem.eql(u8, identify_proto, "/ipfs/id/1.0.0")) return error.TestExpectedEqual;

            try ms.writeMessage(ctx.io, &identify_writer, "/ipfs/id/1.0.0");
            try identify_writer.writeAll("identify-payload");
            try identify_stream.close();

            var peer_accept = try session.acceptStreamConcurrent();
            var peer_stream = try peer_accept.await(ctx.io);
            defer peer_stream.deinit();

            var peer_reader = TestReader{ .stream = &peer_stream };
            var peer_writer = TestWriter{ .stream = &peer_stream };

            const proto = try ms.readMessage(ctx.io, &peer_reader, ctx.allocator);
            defer ctx.allocator.free(proto);
            if (!std.mem.eql(u8, proto, "/zeicoin/peers/1.0.0")) return error.TestExpectedEqual;

            try ms.writeMessage(ctx.io, &peer_writer, "/zeicoin/peers/1.0.0");

            const req_line = try readLineFromTestStream(ctx.allocator, &peer_reader);
            defer ctx.allocator.free(req_line);
            if (!std.mem.eql(u8, req_line, "GET_PEERS 12011")) return error.TestExpectedEqual;

            try peer_writer.writeAll("PEERS 1\n");
            try peer_stream.close();
        }
    };

    var responder_ctx = ResponderCtx{ .conn = &responder_conn, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x61} ** 32, [_]u8{0x72} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var identify_open = try session.openStreamConcurrent();
    var identify_stream = try identify_open.await(io);
    defer identify_stream.deinit();

    var identify_reader = TestReader{ .stream = &identify_stream };
    var identify_writer = TestWriter{ .stream = &identify_stream };

    try ms.writeMessage(io, &identify_writer, "/ipfs/id/1.0.0");
    const identify_ack = try ms.readMessage(io, &identify_reader, allocator);
    defer allocator.free(identify_ack);
    try std.testing.expectEqualStrings("/ipfs/id/1.0.0", identify_ack);

    const identify_payload = try readAllFromStream(allocator, &identify_stream);
    defer allocator.free(identify_payload);
    try std.testing.expectEqualStrings("identify-payload", identify_payload);

    var peer_open = try session.openStreamConcurrent();
    var peer_stream = try peer_open.await(io);
    defer peer_stream.deinit();

    var peer_reader = TestReader{ .stream = &peer_stream };
    var peer_writer = TestWriter{ .stream = &peer_stream };

    try ms.writeMessage(io, &peer_writer, "/zeicoin/peers/1.0.0");
    const peer_ack = try ms.readMessage(io, &peer_reader, allocator);
    defer allocator.free(peer_ack);
    try std.testing.expectEqualStrings("/zeicoin/peers/1.0.0", peer_ack);

    try peer_writer.writeAll("GET_PEERS 12011\n");
    const peer_header = try readLineFromTestStream(allocator, &peer_reader);
    defer allocator.free(peer_header);
    try std.testing.expectEqualStrings("PEERS 1", peer_header);
    try responder_future.await(io);
}

test "yamux normal go away drains existing streams and rejects new ones" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x81} ** 32;
            const rx_key = [_]u8{0x92} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_future = try session.acceptStreamConcurrent();
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            try session.testSendGoAway(0);

            const req = try readAllFromStream(ctx.allocator, &stream);
            defer ctx.allocator.free(req);
            if (!std.mem.eql(u8, req, "still-open")) return error.TestExpectedEqual;

            try stream.writeAll("reply");
            try stream.close();

            _ = session.acceptStream() catch |err| {
                if (err != YamuxError.GoAway) return err;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };

    var responder_ctx = ResponderCtx{ .conn = &responder_conn, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x81} ** 32, [_]u8{0x92} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var open_future = try session.openStreamConcurrent();
    var stream = try open_future.await(io);
    defer stream.deinit();
    try stream.writeAll("still-open");
    try stream.close();

    try readExpectedReply(&stream, "reply");

    try std.testing.expectError(YamuxError.GoAway, session.openStream());
    try responder_future.await(io);
}

test "yamux keepalive ping pong keeps session alive" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    // sleep(400ms) > first_ping(30ms) + timeout(300ms) = 330ms: session would die
    // without keepalive.  300ms gives enough margin over scheduling jitter.
    const opts = SessionOptions{
        .keepalive_interval_ms = 30,
        .keepalive_timeout_ms = 300,
    };

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: SessionOptions,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0xA1} ** 32;
            const rx_key = [_]u8{0xB2} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.initWithOptions(ctx.allocator, &secure, false, ctx.options);
            defer session.deinit();
            try session.start();

            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(400), .awake);

            var accept_future = try session.acceptStreamConcurrent();
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            const req = try readAllFromStream(ctx.allocator, &stream);
            defer ctx.allocator.free(req);
            if (!std.mem.eql(u8, req, "alive")) return error.TestExpectedEqual;

            try stream.writeAll("ok");
            try stream.close();
        }
    };

    var responder_ctx = ResponderCtx{
        .conn = &responder_conn,
        .allocator = allocator,
        .io = io,
        .options = opts,
    };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0xA1} ** 32, [_]u8{0xB2} ** 32);
    defer secure.deinit();

    var session = Session.initWithOptions(allocator, &secure, true, opts);
    defer session.deinit();
    try session.start();

    try io.sleep(std.Io.Duration.fromMilliseconds(400), .awake);

    var open_future = try session.openStreamConcurrent();
    var stream = try open_future.await(io);
    defer stream.deinit();
    try stream.writeAll("alive");
    try stream.close();

    try readExpectedReply(&stream, "ok");
    try responder_future.await(io);
}

test "yamux keepalive timeout closes unresponsive session" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            _ = ctx.conn;
            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(300), .awake);
        }
    };

    var responder_ctx = ResponderCtx{ .conn = &responder_conn, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0xC1} ** 32, [_]u8{0xD2} ** 32);
    defer secure.deinit();

    var session = Session.initWithOptions(allocator, &secure, true, .{
        .keepalive_interval_ms = 20,
        .keepalive_timeout_ms = 60,
    });
    defer session.deinit();
    try session.start();

    try io.sleep(std.Io.Duration.fromMilliseconds(220), .awake);

    _ = session.openStream() catch |err| switch (err) {
        YamuxError.GoAway, YamuxError.SessionClosed => {},
        else => return err,
    };
    if (!session.testSessionIsClosed()) return error.TestUnexpectedResult;
    try responder_future.await(io);
}

test "yamux error go away closes streams and rejects new ones" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();

    const ResponderCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0xE1} ** 32;
            const rx_key = [_]u8{0xF2} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_future = try session.acceptStreamConcurrent();
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            const req = try readAllFromStream(ctx.allocator, &stream);
            defer ctx.allocator.free(req);
            if (!std.mem.eql(u8, req, "boom")) return error.TestExpectedEqual;

            try session.testSendGoAway(2);
        }
    };

    var responder_ctx = ResponderCtx{ .conn = &responder_conn, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};
    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0xE1} ** 32, [_]u8{0xF2} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var open_future = try session.openStreamConcurrent();
    var stream = try open_future.await(io);
    defer stream.deinit();
    try stream.writeAll("boom");
    try stream.close();

    var one: [1]u8 = undefined;
    _ = stream.readSome(&one) catch |err| switch (err) {
        YamuxError.StreamClosed, YamuxError.SessionClosed => 0,
        else => return err,
    };
    _ = session.openStream() catch |err| switch (err) {
        YamuxError.GoAway, YamuxError.SessionClosed => {},
        else => return err,
    };
    if (!session.testSessionIsClosed()) return error.TestUnexpectedResult;
    try responder_future.await(io);
}
