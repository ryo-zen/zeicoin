// handler_registry.zig - Stream handler registry for libp2p protocol dispatch
//
// Stores a map of protocol_id -> Handler and drives Multistream-select
// negotiation on inbound Yamux streams, dispatching to the matched handler.
//
// Usage:
//   var registry = HandlerRegistry.init(allocator);
//   defer registry.deinit();
//
//   try registry.register("/zeicoin/1.0.0", .{ .func = handleZeicoin, .userdata = ctx });
//
//   // In the session accept loop:
//   var stream = try session.acceptStream();
//   try registry.dispatch(&stream);  // negotiates + calls handler

const std = @import("std");
const yamux = @import("../muxer/yamux.zig");
const ms = @import("../protocol/multistream.zig");

// Handler function type. The registry calls func(stream, userdata) after
// Multistream negotiation selects this handler's protocol.
pub const Handler = struct {
    func: *const fn (stream: *yamux.Stream, userdata: ?*anyopaque) anyerror!void,
    userdata: ?*anyopaque = null,
};

pub const DispatchError = error{
    NoHandlersRegistered,
    ProtocolNegotiationFailed,
};

pub const HandlerRegistry = struct {
    allocator: std.mem.Allocator,
    // Keys are owned by the registry (duped on register, freed on deinit).
    handlers: std.StringHashMap(Handler),
    // Cached slice of registered protocol IDs — slices point into handlers keys.
    // Rebuilt only on register(); reused on every dispatch().
    protocol_ids: std.array_list.Managed([]const u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .handlers = std.StringHashMap(Handler).init(allocator),
            .protocol_ids = std.array_list.Managed([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.handlers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.handlers.deinit();
        self.protocol_ids.deinit();
    }

    // Register a handler for a protocol. protocol_id must start with '/'.
    // The registry dupes protocol_id so the caller does not need to keep it alive.
    pub fn register(self: *Self, protocol_id: []const u8, handler: Handler) !void {
        const owned_key = try self.allocator.dupe(u8, protocol_id);
        errdefer self.allocator.free(owned_key);
        try self.handlers.put(owned_key, handler);
        try self.protocol_ids.append(owned_key);
    }

    // Dispatch an inbound stream: run Multistream responder negotiation then
    // call the matched handler. Sends NA for unrecognised protocols (handled
    // internally by the Multistream Negotiator responder).
    //
    // Returns DispatchError.NoHandlersRegistered if the registry is empty.
    // Returns DispatchError.ProtocolNegotiationFailed if negotiation ends
    // without selecting a protocol (e.g. peer closed before agreeing).
    pub fn dispatch(self: *Self, stream: *yamux.Stream) !void {
        if (self.protocol_ids.items.len == 0) return DispatchError.NoHandlersRegistered;

        const io = stream.session.session_io;

        var reader = StreamReader{ .stream = stream };
        var writer = StreamWriter{ .stream = stream };

        var negotiator = ms.Negotiator.init(self.allocator, self.protocol_ids.items, false);
        const selected = negotiator.negotiate(io, &reader, &writer) catch {
            return DispatchError.ProtocolNegotiationFailed;
        };

        const handler = self.handlers.get(selected) orelse {
            // Should not happen — negotiate only returns protocols from our list.
            return DispatchError.ProtocolNegotiationFailed;
        };

        try handler.func(stream, handler.userdata);
    }

    // Returns true if the registry has a handler for the given protocol.
    pub fn has(self: *const Self, protocol_id: []const u8) bool {
        return self.handlers.contains(protocol_id);
    }

    // Returns the number of registered protocols.
    pub fn count(self: *const Self) usize {
        return self.protocol_ids.items.len;
    }
};

// ── stream adapters ────────────────────────────────────────────────────────────
// Multistream's callRead*/callWrite* helpers dispatch to readByte/readNoEof/
// writeAll/writeByte without an io param (hasMethodWithIo returns false for
// these). The yamux.Stream API has no io param either, so these adapters are
// a thin passthrough.

const StreamReader = struct {
    stream: *yamux.Stream,

    pub fn readByte(self: *StreamReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.stream.readSome(&one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *StreamReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.stream.readSome(dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const StreamWriter = struct {
    stream: *yamux.Stream,

    pub fn writeAll(self: *StreamWriter, data: []const u8) !void {
        try self.stream.writeAll(data);
    }

    pub fn writeByte(self: *StreamWriter, b: u8) !void {
        try self.stream.writeByte(b);
    }
};

// ── tests ──────────────────────────────────────────────────────────────────────

const noise = @import("../security/noise.zig");
const inproc = @import("../transport/inproc.zig");
const Session = yamux.Session;
const Stream = yamux.Stream;

// Shared keepalive options for tests — short interval so teardown is fast.
const test_opts = yamux.SessionOptions{
    .keepalive_interval_ms = 100,
    .keepalive_timeout_ms = 500,
};

const KEY_A = [_]u8{0xAA} ** 32;
const KEY_B = [_]u8{0xBB} ** 32;

// Heap-allocated test context. noise.SecureTransport stores a pointer to the
// InProcConnection and Session stores a pointer to SecureTransport, so these
// objects must not move after init. Heap allocation prevents copies on return.
const TestCtx = struct {
    init_conn: inproc.InProcConnection,
    resp_conn: inproc.InProcConnection,
    init_secure: noise.SecureTransport,
    resp_secure: noise.SecureTransport,
    init_session: Session,
    resp_session: Session,

    fn deinit(self: *TestCtx) void {
        self.init_session.deinit();
        self.resp_session.deinit();
        self.init_secure.deinit();
        self.resp_secure.deinit();
        self.init_conn.deinit();
        self.resp_conn.deinit();
    }
};

fn makeTestCtx(allocator: std.mem.Allocator, io: std.Io) !*TestCtx {
    const ctx = try allocator.create(TestCtx);
    errdefer allocator.destroy(ctx);

    var pair = try inproc.InProcConnection.initPair(allocator, io);
    ctx.init_conn = pair.initiator;
    ctx.resp_conn = pair.responder;

    // SecureTransport must be initialised after the connections are in their
    // final heap location so the stored ctx pointer stays valid.
    ctx.init_secure = noise.SecureTransport.init(allocator, ctx.init_conn.connection(), KEY_A, KEY_B);
    ctx.resp_secure = noise.SecureTransport.init(allocator, ctx.resp_conn.connection(), KEY_B, KEY_A);

    ctx.init_session = Session.initWithOptions(allocator, &ctx.init_secure, true, test_opts);
    ctx.resp_session = Session.initWithOptions(allocator, &ctx.resp_secure, false, test_opts);

    try ctx.init_session.start();
    try ctx.resp_session.start();

    return ctx;
}

test "handler registry: register and count" {
    const allocator = std.testing.allocator;

    var registry = HandlerRegistry.init(allocator);
    defer registry.deinit();

    try std.testing.expectEqual(@as(usize, 0), registry.count());
    try std.testing.expect(!registry.has("/test/1.0.0"));

    const noop = struct {
        fn handle(_: *Stream, _: ?*anyopaque) anyerror!void {}
    };

    try registry.register("/test/1.0.0", .{ .func = noop.handle });
    try std.testing.expectEqual(@as(usize, 1), registry.count());
    try std.testing.expect(registry.has("/test/1.0.0"));
    try std.testing.expect(!registry.has("/other/1.0.0"));
}

test "handler registry: dispatch to matched handler" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const ctx = try makeTestCtx(allocator, io);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    // Responder side: registry dispatch on the accepted stream.
    const RegistryCtx = struct {
        session: *Session,
        allocator: std.mem.Allocator,
        received: []u8 = &[_]u8{},

        // Handler called after negotiation.
        fn handlePing(stream: *Stream, userdata: ?*anyopaque) anyerror!void {
            const rctx: *@This() = @ptrCast(@alignCast(userdata.?));
            var buf: [32]u8 = undefined;
            var n: usize = 0;
            while (n < buf.len) {
                const got = try stream.readSome(buf[n..]);
                if (got == 0) break;
                n += got;
            }
            rctx.received = try rctx.allocator.dupe(u8, buf[0..n]);
        }

        fn run(rctx: *@This()) anyerror!void {
            var registry = HandlerRegistry.init(rctx.allocator);
            defer registry.deinit();

            try registry.register("/ping/1.0.0", .{ .func = handlePing, .userdata = rctx });

            var stream = try rctx.session.acceptStream();
            defer stream.deinit();
            try registry.dispatch(&stream);
        }
    };

    var resp_ctx = RegistryCtx{
        .session = &ctx.resp_session,
        .allocator = allocator,
    };
    defer if (resp_ctx.received.len > 0) allocator.free(resp_ctx.received);

    var resp_future = try io.concurrent(RegistryCtx.run, .{&resp_ctx});

    // Initiator side: open stream, run multistream initiator, send payload.
    var stream = try ctx.init_session.openStream();
    defer stream.deinit();

    var reader = StreamReader{ .stream = &stream };
    var writer = StreamWriter{ .stream = &stream };

    // Multistream initiator negotiation.
    const protocols = [_][]const u8{"/ping/1.0.0"};
    var negotiator = ms.Negotiator.init(allocator, &protocols, true);
    const selected = try negotiator.negotiate(io, &reader, &writer);
    try std.testing.expectEqualStrings("/ping/1.0.0", selected);

    try stream.writeAll("hello");
    try stream.close();

    resp_future.await(io) catch {};

    try std.testing.expectEqualStrings("hello", resp_ctx.received);
}

test "handler registry: unregistered protocol sends NA and dispatch fails" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const ctx = try makeTestCtx(allocator, io);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const RegistryCtx = struct {
        session: *Session,
        allocator: std.mem.Allocator,
        dispatch_err: ?anyerror = null,

        fn handleDummy(_: *Stream, _: ?*anyopaque) anyerror!void {}

        fn run(rctx: *@This()) anyerror!void {
            var registry = HandlerRegistry.init(rctx.allocator);
            defer registry.deinit();

            try registry.register("/known/1.0.0", .{ .func = handleDummy });

            var stream = try rctx.session.acceptStream();
            defer stream.deinit();

            registry.dispatch(&stream) catch |err| {
                rctx.dispatch_err = err;
            };
        }
    };

    var resp_ctx = RegistryCtx{
        .session = &ctx.resp_session,
        .allocator = allocator,
    };

    var resp_future = try io.concurrent(RegistryCtx.run, .{&resp_ctx});

    // Initiator proposes an unknown protocol then closes — responder sends NA
    // and eventually gets EOF causing dispatch to fail.
    var stream = try ctx.init_session.openStream();
    defer stream.deinit();

    var reader = StreamReader{ .stream = &stream };
    var writer = StreamWriter{ .stream = &stream };

    const protocols = [_][]const u8{"/unknown/1.0.0"};
    var negotiator = ms.Negotiator.init(allocator, &protocols, true);
    const result = negotiator.negotiate(io, &reader, &writer);
    try std.testing.expectError(error.NoProtocolMatch, result);

    // Close the stream so the responder's negotiateResponder gets EOF and exits
    // its while(true) loop — without this the responder blocks forever.
    try stream.close();

    resp_future.await(io) catch {};

    // Dispatch should have failed since negotiation never completed.
    try std.testing.expect(resp_ctx.dispatch_err != null);
}

test "handler registry: dispatch fails with no handlers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const ctx = try makeTestCtx(allocator, io);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    var registry = HandlerRegistry.init(allocator);
    defer registry.deinit();

    const DispatchCtx = struct {
        session: *Session,
        fn run(dctx: *@This()) anyerror!void {
            var stream = try dctx.session.acceptStream();
            defer stream.deinit();
        }
    };
    var disp_ctx = DispatchCtx{ .session = &ctx.resp_session };
    var resp_future = try io.concurrent(DispatchCtx.run, .{&disp_ctx});

    var stream = try ctx.init_session.openStream();
    defer stream.deinit();

    try std.testing.expectError(
        DispatchError.NoHandlersRegistered,
        registry.dispatch(&stream),
    );

    resp_future.await(io) catch {};
}
