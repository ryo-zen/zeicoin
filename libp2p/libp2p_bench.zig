const std = @import("std");
const libp2p = @import("api.zig");

const Multiaddr = libp2p.Multiaddr;
const TcpTransport = libp2p.TcpTransport;
const TcpConnection = libp2p.TcpConnection;
const IdentityKey = libp2p.IdentityKey;
const noise = libp2p.noise;
const yamux = libp2p.yamux;
const YamuxError = yamux.YamuxError;
const inproc = @import("transport/inproc.zig");
const print = std.debug.print;

const default_duration_secs: u64 = 5;
const default_payload_bytes: usize = 256 * 1024;
const default_iterations: usize = 3;
const default_yamux_streams: usize = 4;

const rust_tcp_noise_yamux_median_gbps = 5.28;
const rust_tcp_noise_yamux_max_gbps = 5.99;

const BenchCase = enum {
    tcp,
    tcp_noise,
    tcp_noise_yamux,
    tcp_noise_yamux_multi,

    fn label(self: BenchCase) []const u8 {
        return switch (self) {
            .tcp => "tcp",
            .tcp_noise => "tcp-noise",
            .tcp_noise_yamux => "tcp-noise-yamux",
            .tcp_noise_yamux_multi => "tcp-noise-yamux-multi",
        };
    }
};

const Direction = enum {
    upload,
    download,
    bidirectional,

    fn label(self: Direction) []const u8 {
        return switch (self) {
            .upload => "upload",
            .download => "download",
            .bidirectional => "bidirectional",
        };
    }
};

const Config = struct {
    duration_secs: u64 = default_duration_secs,
    payload_bytes: usize = default_payload_bytes,
    iterations: usize = default_iterations,
    yamux_streams: usize = default_yamux_streams,
    stack_filter: ?BenchCase = null,
    direction: Direction = .upload,
};

const IterationResult = struct {
    c2s_bytes: u64,
    s2c_bytes: u64,
    elapsed_ns: u64,

    fn uploadGbps(self: IterationResult) f64 {
        const seconds = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        return (@as(f64, @floatFromInt(self.c2s_bytes)) * 8.0) / seconds / 1_000_000_000.0;
    }

    fn downloadGbps(self: IterationResult) f64 {
        const seconds = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        return (@as(f64, @floatFromInt(self.s2c_bytes)) * 8.0) / seconds / 1_000_000_000.0;
    }

    fn combinedGbps(self: IterationResult) f64 {
        const seconds = @as(f64, @floatFromInt(self.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        return (@as(f64, @floatFromInt(self.c2s_bytes + self.s2c_bytes)) * 8.0) / seconds / 1_000_000_000.0;
    }

    fn primaryGbps(self: IterationResult, direction: Direction) f64 {
        return switch (direction) {
            .upload => self.uploadGbps(),
            .download => self.downloadGbps(),
            .bidirectional => self.combinedGbps(),
        };
    }

    fn uploadGiB(self: IterationResult) f64 {
        return @as(f64, @floatFromInt(self.c2s_bytes)) / 1024.0 / 1024.0 / 1024.0;
    }

    fn downloadGiB(self: IterationResult) f64 {
        return @as(f64, @floatFromInt(self.s2c_bytes)) / 1024.0 / 1024.0 / 1024.0;
    }
};

const ServerResult = struct {
    c2s_bytes: u64 = 0,
    s2c_bytes: u64 = 0,
};

const ConnReader = struct {
    conn: *TcpConnection,
    io: std.Io,

    pub fn readByte(self: *ConnReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.conn.readSome(self.io, &one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *ConnReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.conn.readSome(self.io, dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const ConnWriter = struct {
    conn: *TcpConnection,
    io: std.Io,

    pub fn writeAll(self: *ConnWriter, data: []const u8) !void {
        try self.conn.writeAll(self.io, data);
    }

    pub fn writeByte(self: *ConnWriter, b: u8) !void {
        const one = [_]u8{b};
        try self.conn.writeAll(self.io, &one);
    }
};

const SecureReader = struct {
    conn: *noise.SecureTransport,
    io: std.Io,

    pub fn readByte(self: *SecureReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.conn.readSome(self.io, &one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *SecureReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.conn.readSome(self.io, dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const SecureWriter = struct {
    conn: *noise.SecureTransport,
    io: std.Io,

    pub fn writeAll(self: *SecureWriter, data: []const u8) !void {
        try self.conn.writeAll(self.io, data);
    }

    pub fn writeByte(self: *SecureWriter, b: u8) !void {
        try self.conn.writeByte(self.io, b);
    }
};

const TcpServerCtx = struct {
    listener: *TcpTransport.Listener,
    io: std.Io,
    direction: Direction,
    payload: []const u8,
    duration_secs: u64,

    fn run(ctx: *TcpServerCtx) !ServerResult {
        var conn = try ctx.listener.accept(ctx.io);
        defer conn.deinit();
        return switch (ctx.direction) {
            .upload => .{ .c2s_bytes = try readAllFromTcpConn(&conn, ctx.io) },
            .download => .{ .s2c_bytes = try writeAllToTcpConn(&conn, ctx.io, ctx.payload, ctx.duration_secs) },
            .bidirectional => blk: {
                var read_future = try ctx.io.concurrent(readAllFromTcpConnTask, .{ &conn, ctx.io });
                const s2c_bytes = try writeAllToTcpConn(&conn, ctx.io, ctx.payload, ctx.duration_secs);
                try conn.close(ctx.io);
                break :blk .{
                    .c2s_bytes = try read_future.await(ctx.io),
                    .s2c_bytes = s2c_bytes,
                };
            },
        };
    }
};

const TcpNoiseServerCtx = struct {
    listener: *TcpTransport.Listener,
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: *const IdentityKey,
    direction: Direction,
    payload: []const u8,
    duration_secs: u64,

    fn run(ctx: *TcpNoiseServerCtx) !ServerResult {
        var conn = try ctx.listener.accept(ctx.io);
        defer conn.deinit();

        var handshake = try noise.performResponder(ctx.allocator, ctx.io, conn.connection(), ctx.identity, null);
        defer handshake.deinit();

        var secure = noise.SecureTransport.init(ctx.allocator, conn.connection(), handshake.tx_key, handshake.rx_key);
        defer secure.deinit();
        return switch (ctx.direction) {
            .upload => .{ .c2s_bytes = try readAllFromSecureConn(&secure, ctx.io) },
            .download => blk: {
                const s2c_bytes = try writeAllToSecureConn(&secure, ctx.io, ctx.payload, ctx.duration_secs);
                try conn.close(ctx.io);
                break :blk .{ .s2c_bytes = s2c_bytes };
            },
            .bidirectional => blk: {
                var read_future = try ctx.io.concurrent(readAllFromSecureConnTask, .{ &secure, ctx.io });
                const s2c_bytes = try writeAllToSecureConn(&secure, ctx.io, ctx.payload, ctx.duration_secs);
                try conn.close(ctx.io);
                break :blk .{
                    .c2s_bytes = try read_future.await(ctx.io),
                    .s2c_bytes = s2c_bytes,
                };
            },
        };
    }
};

const TcpNoiseYamuxServerCtx = struct {
    listener: *TcpTransport.Listener,
    allocator: std.mem.Allocator,
    io: std.Io,
    identity: *const IdentityKey,
    streams: usize,
    direction: Direction,
    payload: []const u8,
    duration_secs: u64,

    fn run(ctx: *TcpNoiseYamuxServerCtx) !ServerResult {
        var conn = try ctx.listener.accept(ctx.io);
        defer conn.deinit();

        var handshake = try noise.performResponder(ctx.allocator, ctx.io, conn.connection(), ctx.identity, null);
        defer handshake.deinit();

        var secure = noise.SecureTransport.init(ctx.allocator, conn.connection(), handshake.tx_key, handshake.rx_key);
        defer secure.deinit();

        var session = yamux.Session.init(ctx.allocator, &secure, false);
        defer session.deinit();
        try session.start();

        var accepted_streams = try ctx.allocator.alloc(yamux.Stream, ctx.streams);
        defer ctx.allocator.free(accepted_streams);

        var accepted: usize = 0;
        while (accepted < ctx.streams) : (accepted += 1) {
            accepted_streams[accepted] = try session.acceptStream();
        }

        const result: ServerResult = switch (ctx.direction) {
            .upload => .{ .c2s_bytes = try readAllFromYamuxStreams(ctx.io, accepted_streams) },
            .download => .{ .s2c_bytes = try writeAllToYamuxStreams(ctx.io, accepted_streams, ctx.payload, ctx.duration_secs) },
            .bidirectional => blk: {
                const counts = try runBidirectionalYamuxStreams(ctx.io, accepted_streams, ctx.payload, ctx.duration_secs);
                break :blk .{
                    .c2s_bytes = counts.read_bytes,
                    .s2c_bytes = counts.write_bytes,
                };
            },
        };
        if (ctx.direction != .upload) {
            secure.conn.close() catch {};
        }
        return result;
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_it.deinit();
    _ = args_it.next();

    var config = Config{};
    while (args_it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "--duration-secs")) {
            config.duration_secs = try parseNextU64(&args_it, "--duration-secs");
        } else if (std.mem.eql(u8, arg, "--payload-bytes")) {
            config.payload_bytes = try parseNextUsize(&args_it, "--payload-bytes");
        } else if (std.mem.eql(u8, arg, "--iterations")) {
            config.iterations = try parseNextUsize(&args_it, "--iterations");
        } else if (std.mem.eql(u8, arg, "--yamux-streams")) {
            config.yamux_streams = try parseNextUsize(&args_it, "--yamux-streams");
        } else if (std.mem.eql(u8, arg, "--stack")) {
            config.stack_filter = try parseStack(&args_it);
        } else if (std.mem.eql(u8, arg, "--direction")) {
            config.direction = try parseDirection(&args_it);
        } else {
            print("unknown argument: {s}\n", .{arg});
            printUsage();
            return error.InvalidArgument;
        }
    }

    if (config.duration_secs == 0) return error.InvalidDuration;
    if (config.payload_bytes == 0) return error.InvalidPayloadSize;
    if (config.iterations == 0) return error.InvalidIterations;
    if (config.yamux_streams == 0) return error.InvalidStreams;

    print("libp2p benchmark matrix: local loopback {s} throughput\n", .{config.direction.label()});
    print(
        "config: duration={}s payload={} bytes iterations={} yamux_streams={} direction={s}\n",
        .{ config.duration_secs, config.payload_bytes, config.iterations, config.yamux_streams, config.direction.label() },
    );
    print(
        "rust reference (tcp-noise-yamux): median={d:.2} Gbps max={d:.2} Gbps\n",
        .{ rust_tcp_noise_yamux_median_gbps, rust_tcp_noise_yamux_max_gbps },
    );

    const payload = try allocator.alloc(u8, config.payload_bytes);
    defer allocator.free(payload);
    @memset(payload, 0xA5);

    const cases = [_]BenchCase{
        .tcp,
        .tcp_noise,
        .tcp_noise_yamux,
        .tcp_noise_yamux_multi,
    };

    for (cases) |bench_case| {
        if (config.stack_filter) |filter| {
            if (bench_case != filter) continue;
        }
        try runCase(allocator, io, payload, config, bench_case);
    }
}

fn runCase(
    allocator: std.mem.Allocator,
    io: std.Io,
    payload: []const u8,
    config: Config,
    bench_case: BenchCase,
) !void {
    const streams = switch (bench_case) {
        .tcp_noise_yamux_multi => config.yamux_streams,
        else => 1,
    };

    print("\ncase: {s}", .{bench_case.label()});
    if (streams > 1) print(" ({})", .{streams});
    print("\n", .{});

    const results = try allocator.alloc(IterationResult, config.iterations);
    defer allocator.free(results);

    var best_primary_gbps: f64 = 0.0;
    var total_primary_gbps: f64 = 0.0;

    var i: usize = 0;
    while (i < config.iterations) : (i += 1) {
        const result = switch (bench_case) {
            .tcp => try runTcpIteration(allocator, io, payload, config.duration_secs, config.direction),
            .tcp_noise => try runTcpNoiseIteration(allocator, io, payload, config.duration_secs, config.direction),
            .tcp_noise_yamux => try runTcpNoiseYamuxIteration(allocator, io, payload, config.duration_secs, 1, config.direction),
            .tcp_noise_yamux_multi => try runTcpNoiseYamuxIteration(allocator, io, payload, config.duration_secs, streams, config.direction),
        };
        results[i] = result;
        const primary_gbps = result.primaryGbps(config.direction);
        if (primary_gbps > best_primary_gbps) best_primary_gbps = primary_gbps;
        total_primary_gbps += primary_gbps;

        switch (config.direction) {
            .upload => print(
                "run {}: {d:.2} Gbps upload, {d:.2} GiB sent in {d:.3}s\n",
                .{
                    i + 1,
                    result.uploadGbps(),
                    result.uploadGiB(),
                    @as(f64, @floatFromInt(result.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)),
                },
            ),
            .download => print(
                "run {}: {d:.2} Gbps download, {d:.2} GiB received in {d:.3}s\n",
                .{
                    i + 1,
                    result.downloadGbps(),
                    result.downloadGiB(),
                    @as(f64, @floatFromInt(result.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)),
                },
            ),
            .bidirectional => print(
                "run {}: upload {d:.2} Gbps, download {d:.2} Gbps, combined {d:.2} Gbps in {d:.3}s\n",
                .{
                    i + 1,
                    result.uploadGbps(),
                    result.downloadGbps(),
                    result.combinedGbps(),
                    @as(f64, @floatFromInt(result.elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s)),
                },
            ),
        }
    }

    std.mem.sort(IterationResult, results, config.direction, struct {
        fn lessThan(direction: Direction, a: IterationResult, b: IterationResult) bool {
            return a.primaryGbps(direction) < b.primaryGbps(direction);
        }
    }.lessThan);

    const median_primary = results[results.len / 2].primaryGbps(config.direction);
    const average_primary = total_primary_gbps / @as(f64, @floatFromInt(config.iterations));
    switch (config.direction) {
        .upload => print(
            "summary: best={d:.2} Gbps median={d:.2} Gbps avg={d:.2} Gbps\n",
            .{ best_primary_gbps, median_primary, average_primary },
        ),
        .download => print(
            "summary: best={d:.2} Gbps median={d:.2} Gbps avg={d:.2} Gbps\n",
            .{ best_primary_gbps, median_primary, average_primary },
        ),
        .bidirectional => print(
            "summary: best_combined={d:.2} Gbps median_combined={d:.2} Gbps avg_combined={d:.2} Gbps\n",
            .{ best_primary_gbps, median_primary, average_primary },
        ),
    }

    if (bench_case == .tcp_noise_yamux and config.direction == .upload) {
        print(
            "reference compare: zig_median_vs_rust_median={d:.2}x zig_best_vs_rust_max={d:.2}x\n",
            .{
                median_primary / rust_tcp_noise_yamux_median_gbps,
                best_primary_gbps / rust_tcp_noise_yamux_max_gbps,
            },
        );
    }
}

fn runTcpIteration(
    allocator: std.mem.Allocator,
    io: std.Io,
    payload: []const u8,
    duration_secs: u64,
    direction: Direction,
) !IterationResult {
    var transport = TcpTransport.init(allocator);
    defer transport.deinit();

    const listener = try makeLoopbackListener(allocator, io, &transport);

    var server_ctx = TcpServerCtx{
        .listener = listener,
        .io = io,
        .direction = direction,
        .payload = payload,
        .duration_secs = duration_secs,
    };
    var server_future = try io.concurrent(TcpServerCtx.run, .{&server_ctx});
    defer _ = server_future.cancel(io) catch {};

    var conn = try dialLoopback(allocator, io, &transport, listener);
    defer conn.deinit();

    var client_c2s: u64 = 0;
    var client_s2c: u64 = 0;
    var timer = try std.time.Timer.start();
    switch (direction) {
        .upload => {
            client_c2s = try writeAllToTcpConn(&conn, io, payload, duration_secs);
            try conn.close(io);
        },
        .download => {
            client_s2c = try readAllFromTcpConn(&conn, io);
        },
        .bidirectional => {
            var read_future = try io.concurrent(readAllFromTcpConnTask, .{ &conn, io });
            client_c2s = try writeAllToTcpConn(&conn, io, payload, duration_secs);
            try conn.close(io);
            client_s2c = try read_future.await(io);
        },
    }
    const elapsed_ns: u64 = timer.read();

    const server_result = try server_future.await(io);
    return .{
        .c2s_bytes = if (direction == .download) server_result.c2s_bytes else client_c2s,
        .s2c_bytes = if (direction == .upload) server_result.s2c_bytes else client_s2c,
        .elapsed_ns = elapsed_ns,
    };
}

fn runTcpNoiseIteration(
    allocator: std.mem.Allocator,
    io: std.Io,
    payload: []const u8,
    duration_secs: u64,
    direction: Direction,
) !IterationResult {
    var transport = TcpTransport.init(allocator);
    defer transport.deinit();

    const listener = try makeLoopbackListener(allocator, io, &transport);

    var server_identity = try IdentityKey.generate(allocator, io);
    defer server_identity.deinit();
    var client_identity = try IdentityKey.generate(allocator, io);
    defer client_identity.deinit();

    var server_ctx = TcpNoiseServerCtx{
        .listener = listener,
        .allocator = allocator,
        .io = io,
        .identity = &server_identity,
        .direction = direction,
        .payload = payload,
        .duration_secs = duration_secs,
    };
    var server_future = try io.concurrent(TcpNoiseServerCtx.run, .{&server_ctx});
    defer _ = server_future.cancel(io) catch {};

    var conn = try dialLoopback(allocator, io, &transport, listener);
    defer conn.deinit();

    var handshake = try noise.performInitiator(allocator, io, conn.connection(), &client_identity, null);
    defer handshake.deinit();

    var secure = noise.SecureTransport.init(allocator, conn.connection(), handshake.tx_key, handshake.rx_key);
    defer secure.deinit();

    var client_c2s: u64 = 0;
    var client_s2c: u64 = 0;
    var timer = try std.time.Timer.start();
    switch (direction) {
        .upload => {
            client_c2s = try writeAllToSecureConn(&secure, io, payload, duration_secs);
            try conn.close(io);
        },
        .download => {
            client_s2c = try readAllFromSecureConn(&secure, io);
        },
        .bidirectional => {
            var read_future = try io.concurrent(readAllFromSecureConnTask, .{ &secure, io });
            client_c2s = try writeAllToSecureConn(&secure, io, payload, duration_secs);
            try conn.close(io);
            client_s2c = try read_future.await(io);
        },
    }
    const elapsed_ns: u64 = timer.read();

    const server_result = try server_future.await(io);
    return .{
        .c2s_bytes = if (direction == .download) server_result.c2s_bytes else client_c2s,
        .s2c_bytes = if (direction == .upload) server_result.s2c_bytes else client_s2c,
        .elapsed_ns = elapsed_ns,
    };
}

fn runTcpNoiseYamuxIteration(
    allocator: std.mem.Allocator,
    io: std.Io,
    payload: []const u8,
    duration_secs: u64,
    streams: usize,
    direction: Direction,
) !IterationResult {
    var transport = TcpTransport.init(allocator);
    defer transport.deinit();

    const listener = try makeLoopbackListener(allocator, io, &transport);

    var server_identity = try IdentityKey.generate(allocator, io);
    defer server_identity.deinit();
    var client_identity = try IdentityKey.generate(allocator, io);
    defer client_identity.deinit();

    var server_ctx = TcpNoiseYamuxServerCtx{
        .listener = listener,
        .allocator = allocator,
        .io = io,
        .identity = &server_identity,
        .streams = streams,
        .direction = direction,
        .payload = payload,
        .duration_secs = duration_secs,
    };
    var server_future = try io.concurrent(TcpNoiseYamuxServerCtx.run, .{&server_ctx});
    defer _ = server_future.cancel(io) catch {};

    var conn = try dialLoopback(allocator, io, &transport, listener);
    defer conn.deinit();

    var handshake = try noise.performInitiator(allocator, io, conn.connection(), &client_identity, null);
    defer handshake.deinit();

    var secure = noise.SecureTransport.init(allocator, conn.connection(), handshake.tx_key, handshake.rx_key);
    defer secure.deinit();

    var session = yamux.Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    if (streams == 1) {
        var stream = try session.openStream();
        defer stream.deinit();

        var client_c2s: u64 = 0;
        var client_s2c: u64 = 0;
        var timer = try std.time.Timer.start();
        switch (direction) {
            .upload => client_c2s = try writeAllToYamuxStream(&stream, payload, duration_secs),
            .download => client_s2c = try readAllFromYamuxStream(&stream),
            .bidirectional => {
                var read_future = try io.concurrent(readAllFromYamuxStreamTask, .{&stream});
                client_c2s = try writeAllToYamuxStream(&stream, payload, duration_secs);
                client_s2c = try read_future.await(io);
            },
        }
        const elapsed_ns: u64 = timer.read();

        if (direction != .download) {
            stream.close() catch {};
        }
        const server_result = try server_future.await(io);
        return .{
            .c2s_bytes = if (direction == .download) server_result.c2s_bytes else client_c2s,
            .s2c_bytes = if (direction == .upload) server_result.s2c_bytes else client_s2c,
            .elapsed_ns = elapsed_ns,
        };
    }

    const opened_streams = try allocator.alloc(yamux.Stream, streams);
    defer allocator.free(opened_streams);
    for (opened_streams) |*stream| {
        stream.* = try session.openStream();
    }

    var timer = try std.time.Timer.start();
    const counts = switch (direction) {
        .upload => TransferCounts{ .write_bytes = try writeAllToYamuxStreams(io, opened_streams, payload, duration_secs) },
        .download => TransferCounts{ .read_bytes = try readAllFromYamuxStreams(io, opened_streams) },
        .bidirectional => try runBidirectionalYamuxStreams(io, opened_streams, payload, duration_secs),
    };
    const elapsed_ns: u64 = timer.read();
    const server_result = try server_future.await(io);
    return .{
        .c2s_bytes = if (direction == .download) server_result.c2s_bytes else counts.write_bytes,
        .s2c_bytes = if (direction == .upload) server_result.s2c_bytes else counts.read_bytes,
        .elapsed_ns = elapsed_ns,
    };
}

fn makeLoopbackListener(
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: *TcpTransport,
) !*TcpTransport.Listener {
    var listen_ma = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    return transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };
}

fn dialLoopback(
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: *TcpTransport,
    listener: *TcpTransport.Listener,
) !TcpConnection {
    var dial_ma = try Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    return transport.dial(io, &dial_ma);
}

fn readAllFromTcpConn(conn: *TcpConnection, io: std.Io) !u64 {
    var total: u64 = 0;
    var buf: [256 * 1024]u8 = undefined;
    while (true) {
        const n = try conn.readSome(io, &buf);
        if (n == 0) return total;
        total += n;
    }
}

fn readAllFromTcpConnTask(conn: *TcpConnection, io: std.Io) anyerror!u64 {
    return readAllFromTcpConn(conn, io);
}

fn writeAllToTcpConn(conn: *TcpConnection, io: std.Io, payload: []const u8, duration_secs: u64) !u64 {
    var timer = try std.time.Timer.start();
    const target_ns = duration_secs * std.time.ns_per_s;
    var total: u64 = 0;
    while (timer.read() < target_ns) {
        try conn.writeAll(io, payload);
        total += payload.len;
    }
    return total;
}

fn readAllFromSecureConn(conn: *noise.SecureTransport, io: std.Io) !u64 {
    var total: u64 = 0;
    var buf: [256 * 1024]u8 = undefined;
    while (true) {
        const n = conn.readSome(io, &buf) catch |err| switch (err) {
            error.EndOfStream => return total,
            else => return err,
        };
        if (n == 0) return total;
        total += n;
    }
}

fn readAllFromSecureConnTask(conn: *noise.SecureTransport, io: std.Io) anyerror!u64 {
    return readAllFromSecureConn(conn, io);
}

fn writeAllToSecureConn(conn: *noise.SecureTransport, io: std.Io, payload: []const u8, duration_secs: u64) !u64 {
    var timer = try std.time.Timer.start();
    const target_ns = duration_secs * std.time.ns_per_s;
    var total: u64 = 0;
    while (timer.read() < target_ns) {
        try conn.writeAll(io, payload);
        total += payload.len;
    }
    return total;
}

const TransferCounts = struct {
    read_bytes: u64 = 0,
    write_bytes: u64 = 0,
};

fn readAllFromYamuxStream(stream: *yamux.Stream) !u64 {
    var total: u64 = 0;
    var buf: [256 * 1024]u8 = undefined;
    while (true) {
        const n = stream.readSome(&buf) catch |err| switch (err) {
            YamuxError.StreamClosed, YamuxError.SessionClosed => return total,
            else => return err,
        };
        if (n == 0) return total;
        total += n;
    }
}

fn readAllFromYamuxStreamTask(stream: *yamux.Stream) anyerror!u64 {
    return readAllFromYamuxStream(stream);
}

fn writeAllToYamuxStream(stream: *yamux.Stream, payload: []const u8, duration_secs: u64) !u64 {
    var timer = try std.time.Timer.start();
    const target_ns = duration_secs * std.time.ns_per_s;
    var total: u64 = 0;
    while (timer.read() < target_ns) {
        stream.writeAll(payload) catch |err| switch (err) {
            YamuxError.StreamClosed, YamuxError.SessionClosed => break,
            else => return err,
        };
        total += payload.len;
    }
    return total;
}

fn readAllFromYamuxStreams(io: std.Io, streams: []yamux.Stream) !u64 {
    var total = std.atomic.Value(u64).init(0);
    var group: std.Io.Group = .init;
    defer group.cancel(io);

    for (streams) |stream| {
        try group.concurrent(io, readYamuxStreamTask, .{ stream, &total });
    }
    try group.await(io);
    return total.load(.acquire);
}

fn writeAllToYamuxStreams(io: std.Io, streams: []yamux.Stream, payload: []const u8, duration_secs: u64) !u64 {
    var stop = std.atomic.Value(bool).init(false);
    var total = std.atomic.Value(u64).init(0);
    var group: std.Io.Group = .init;
    defer group.cancel(io);

    for (streams) |stream| {
        try group.concurrent(io, writeYamuxStreamTask, .{ stream, payload, &stop, &total });
    }
    try io.sleep(std.Io.Duration.fromSeconds(@as(i64, @intCast(duration_secs))), .awake);
    stop.store(true, .release);
    try group.await(io);
    return total.load(.acquire);
}

fn runBidirectionalYamuxStreams(io: std.Io, streams: []yamux.Stream, payload: []const u8, duration_secs: u64) !TransferCounts {
    var stop = std.atomic.Value(bool).init(false);
    var read_total = std.atomic.Value(u64).init(0);
    var write_total = std.atomic.Value(u64).init(0);
    var group: std.Io.Group = .init;
    defer group.cancel(io);

    for (streams) |stream| {
        try group.concurrent(io, readYamuxStreamTask, .{ stream, &read_total });
        try group.concurrent(io, writeYamuxStreamTask, .{ stream, payload, &stop, &write_total });
    }
    try io.sleep(std.Io.Duration.fromSeconds(@as(i64, @intCast(duration_secs))), .awake);
    stop.store(true, .release);
    try group.await(io);
    return .{
        .read_bytes = read_total.load(.acquire),
        .write_bytes = write_total.load(.acquire),
    };
}

fn readYamuxStreamTask(
    stream: yamux.Stream,
    total: *std.atomic.Value(u64),
) error{Canceled}!void {
    var owned_stream = stream;
    defer owned_stream.deinit();

    var buf: [256 * 1024]u8 = undefined;
    while (true) {
        const n = owned_stream.readSome(&buf) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            YamuxError.StreamClosed, YamuxError.SessionClosed => return,
            else => std.debug.panic("readYamuxStreamTask failed: {s}", .{@errorName(err)}),
        };
        if (n == 0) return;
        _ = total.fetchAdd(n, .acq_rel);
    }
}

fn writeYamuxStreamTask(
    stream: yamux.Stream,
    payload: []const u8,
    stop: *std.atomic.Value(bool),
    total: *std.atomic.Value(u64),
) error{Canceled}!void {
    var owned_stream = stream;
    defer owned_stream.deinit();

    while (!stop.load(.acquire)) {
        owned_stream.writeAll(payload) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            YamuxError.StreamClosed, YamuxError.SessionClosed => return,
            else => std.debug.panic("writeYamuxStreamTask failed: {s}", .{@errorName(err)}),
        };
        _ = total.fetchAdd(payload.len, .acq_rel);
    }
    owned_stream.close() catch {};
}

fn parseNextU64(args_it: *std.process.Args.Iterator, flag: []const u8) !u64 {
    const value = args_it.next() orelse {
        print("missing value for {s}\n", .{flag});
        return error.InvalidArgument;
    };
    return std.fmt.parseInt(u64, value, 10);
}

fn parseNextUsize(args_it: *std.process.Args.Iterator, flag: []const u8) !usize {
    const value = args_it.next() orelse {
        print("missing value for {s}\n", .{flag});
        return error.InvalidArgument;
    };
    return std.fmt.parseInt(usize, value, 10);
}

fn parseStack(args_it: *std.process.Args.Iterator) !BenchCase {
    const value = args_it.next() orelse {
        print("missing value for --stack\n", .{});
        return error.InvalidArgument;
    };

    if (std.mem.eql(u8, value, "tcp")) return .tcp;
    if (std.mem.eql(u8, value, "tcp-noise")) return .tcp_noise;
    if (std.mem.eql(u8, value, "tcp-noise-yamux")) return .tcp_noise_yamux;
    if (std.mem.eql(u8, value, "tcp-noise-yamux-multi")) return .tcp_noise_yamux_multi;

    print("invalid stack: {s}\n", .{value});
    return error.InvalidArgument;
}

fn parseDirection(args_it: *std.process.Args.Iterator) !Direction {
    const value = args_it.next() orelse {
        print("missing value for --direction\n", .{});
        return error.InvalidArgument;
    };

    if (std.mem.eql(u8, value, "upload")) return .upload;
    if (std.mem.eql(u8, value, "download")) return .download;
    if (std.mem.eql(u8, value, "bidirectional")) return .bidirectional;

    print("invalid direction: {s}\n", .{value});
    return error.InvalidArgument;
}

fn printUsage() void {
    print(
        \\usage: libp2p_bench [--duration-secs N] [--payload-bytes N] [--iterations N]
        \\                   [--yamux-streams N]
        \\                   [--direction upload|download|bidirectional]
        \\                   [--stack tcp|tcp-noise|tcp-noise-yamux|tcp-noise-yamux-multi]
        \\benchmarks local loopback throughput for a small stack matrix
        \\defaults: --duration-secs 5 --payload-bytes 262144 --iterations 3 --yamux-streams 4
        \\
    , .{});
}

test "readYamuxStreamTask treats session close as eof" {
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
            const tx_key = [_]u8{0x41} ** 32;
            const rx_key = [_]u8{0x52} ** 32;

            var secure = noise.SecureTransport.init(ctx.allocator, ctx.conn.connection(), rx_key, tx_key);
            defer secure.deinit();

            var session = yamux.Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accepted = try session.acceptStream();
            defer accepted.deinit();

            // Give the initiator reader task time to block in readSome before the
            // responder session shuts down and surfaces SessionClosed.
            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(10), .awake);
        }
    };

    var responder_ctx = ResponderCtx{
        .conn = &responder_conn,
        .allocator = allocator,
        .io = io,
    };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var secure = noise.SecureTransport.init(allocator, initiator_conn.connection(), [_]u8{0x41} ** 32, [_]u8{0x52} ** 32);
    defer secure.deinit();

    var session = yamux.Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    const stream = try session.openStream();
    var total = std.atomic.Value(u64).init(0);
    var read_future = try io.concurrent(readYamuxStreamTask, .{ stream, &total });

    try responder_future.await(io);
    try read_future.await(io);
    try std.testing.expectEqual(@as(u64, 0), total.load(.acquire));
}
