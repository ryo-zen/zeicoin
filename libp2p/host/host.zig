// host.zig — libp2p Host: orchestration layer for dial/listen/stream lifecycle.
//
// Wraps the five-step upgrade stack (TCP → Noise → Yamux → per-stream Multistream)
// behind three operations:
//   session = host.dial(io, addr)       — full outbound upgrade
//   stream  = host.newStream(io, s, p)  — open + negotiate one protocol stream
//   host.serve(io)                      — accept-loop (run concurrently)
//
// See docs/LIBP2P_HOST_ABSTRACTION.md for design rationale.

const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const noise = @import("../security/noise.zig");
const yamux = @import("../muxer/yamux.zig");
const ms = @import("../protocol/multistream.zig");
const peer_id_mod = @import("../peer/peer_id.zig");
const handler_registry_mod = @import("handler_registry.zig");

const Multiaddr = @import("../multiaddr/multiaddr.zig").Multiaddr;
const IdentityKey = peer_id_mod.IdentityKey;
const PeerId = peer_id_mod.PeerId;
const ConnInfo = handler_registry_mod.ConnInfo;

pub const HandlerRegistry = handler_registry_mod.HandlerRegistry;
pub const Handler = handler_registry_mod.Handler;

// ── TCP adapters ──────────────────────────────────────────────────────────────
// Store io internally so methods have no io param — Multistream's
// hasMethodWithIo() returns false and calls them without io.

const ConnReader = struct {
    conn: *tcp.TcpConnection,
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
    conn: *tcp.TcpConnection,
    io: std.Io,

    pub fn writeAll(self: *ConnWriter, data: []const u8) !void {
        try self.conn.writeAll(self.io, data);
    }

    pub fn writeByte(self: *ConnWriter, b: u8) !void {
        const one = [_]u8{b};
        try self.conn.writeAll(self.io, &one);
    }
};

// ── Noise adapters ────────────────────────────────────────────────────────────

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

// ── Yamux stream adapters ─────────────────────────────────────────────────────
// Yamux streams have no io param — matches handler_registry.zig pattern.

const YamuxReader = struct {
    stream: *yamux.Stream,

    pub fn readByte(self: *YamuxReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.stream.readSome(&one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *YamuxReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.stream.readSome(dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const YamuxWriter = struct {
    stream: *yamux.Stream,

    pub fn writeAll(self: *YamuxWriter, data: []const u8) !void {
        try self.stream.writeAll(data);
    }

    pub fn writeByte(self: *YamuxWriter, b: u8) !void {
        try self.stream.writeByte(b);
    }
};

// ── UpgradedConn ──────────────────────────────────────────────────────────────
// Heap-allocated struct that owns the full upgrade chain for one connection.
//
// SecureTransport stores a pointer into tcp_conn (via Connection vtable).
// Session stores *SecureTransport. All three must not move after init.
// A single heap allocation satisfies this — pointers into the struct are stable.

const UpgradedConn = struct {
    allocator: std.mem.Allocator,
    tcp_conn: tcp.TcpConnection,
    secure: noise.SecureTransport,
    session: yamux.Session,
    remote_peer_id: PeerId,

    const Self = @This();

    fn deinit(self: *Self) void {
        self.session.deinit();
        self.secure.deinit();
        self.tcp_conn.deinit();
        self.remote_peer_id.deinit();
    }
};

// ── Multistream helpers ───────────────────────────────────────────────────────

// proposeProtocol: send header + protocol proposal, verify acks (initiator).
fn proposeProtocol(
    alloc: std.mem.Allocator,
    io: std.Io,
    reader: anytype,
    writer: anytype,
    protocol: []const u8,
) !void {
    try ms.writeMessage(io, writer, ms.PROTOCOL_ID);
    const header_ack = try ms.readMessage(io, reader, alloc);
    defer alloc.free(header_ack);
    if (!std.mem.eql(u8, header_ack, ms.PROTOCOL_ID)) return error.ProtocolMismatch;
    try ms.writeMessage(io, writer, protocol);
    const proto_ack = try ms.readMessage(io, reader, alloc);
    defer alloc.free(proto_ack);
    if (!std.mem.eql(u8, proto_ack, protocol)) return error.ProtocolNegotiationFailed;
}

// acceptProtocol: read header + proposal, echo acks (responder).
fn acceptProtocol(
    alloc: std.mem.Allocator,
    io: std.Io,
    reader: anytype,
    writer: anytype,
    expected: []const u8,
) !void {
    const header = try ms.readMessage(io, reader, alloc);
    defer alloc.free(header);
    if (!std.mem.eql(u8, header, ms.PROTOCOL_ID)) return error.ProtocolMismatch;
    try ms.writeMessage(io, writer, ms.PROTOCOL_ID);
    const proposal = try ms.readMessage(io, reader, alloc);
    defer alloc.free(proposal);
    if (!std.mem.eql(u8, proposal, expected)) {
        try ms.writeMessage(io, writer, ms.NA);
        return error.ProtocolNegotiationFailed;
    }
    try ms.writeMessage(io, writer, expected);
}

// ── upgradeOutbound ───────────────────────────────────────────────────────────
// Takes ownership of conn. On error, conn is cleaned up before returning.

fn upgradeOutbound(
    alloc: std.mem.Allocator,
    io: std.Io,
    conn: tcp.TcpConnection,
    identity: *const IdentityKey,
    expected_peer_id: ?[]const u8,
) !*UpgradedConn {
    var local_conn = conn;
    const uc = alloc.create(UpgradedConn) catch |err| {
        local_conn.deinit();
        return err;
    };
    errdefer alloc.destroy(uc);

    uc.allocator = alloc;
    uc.tcp_conn = local_conn;
    errdefer uc.tcp_conn.deinit();

    var cr: ConnReader = .{ .conn = &uc.tcp_conn, .io = io };
    var cw: ConnWriter = .{ .conn = &uc.tcp_conn, .io = io };
    try proposeProtocol(alloc, io, &cr, &cw, noise.PROTOCOL_ID);

    var noise_result = try noise.performInitiator(alloc, io, uc.tcp_conn.connection(), identity, expected_peer_id);
    uc.secure = noise.SecureTransport.init(alloc, uc.tcp_conn.connection(), noise_result.tx_key, noise_result.rx_key);
    uc.remote_peer_id = noise_result.remote_peer_id; // move ownership out of noise_result
    std.crypto.secureZero(u8, &noise_result.tx_key);
    std.crypto.secureZero(u8, &noise_result.rx_key);
    std.crypto.secureZero(u8, &noise_result.session_key_material);
    errdefer uc.secure.deinit();
    errdefer uc.remote_peer_id.deinit();

    var sr: SecureReader = .{ .conn = &uc.secure, .io = io };
    var sw: SecureWriter = .{ .conn = &uc.secure, .io = io };
    try proposeProtocol(alloc, io, &sr, &sw, yamux.PROTOCOL_ID);

    uc.session = yamux.Session.init(alloc, &uc.secure, true);
    errdefer uc.session.deinit();
    try uc.session.start();

    return uc;
}

// ── upgradeInbound ────────────────────────────────────────────────────────────
// Takes ownership of conn. On error, conn is cleaned up before returning.

fn upgradeInbound(
    alloc: std.mem.Allocator,
    io: std.Io,
    conn: tcp.TcpConnection,
    identity: *const IdentityKey,
) !*UpgradedConn {
    var local_conn = conn;
    const uc = alloc.create(UpgradedConn) catch |err| {
        local_conn.deinit();
        return err;
    };
    errdefer alloc.destroy(uc);

    uc.allocator = alloc;
    uc.tcp_conn = local_conn;
    errdefer uc.tcp_conn.deinit();

    var cr: ConnReader = .{ .conn = &uc.tcp_conn, .io = io };
    var cw: ConnWriter = .{ .conn = &uc.tcp_conn, .io = io };
    try acceptProtocol(alloc, io, &cr, &cw, noise.PROTOCOL_ID);

    var noise_result = try noise.performResponder(alloc, io, uc.tcp_conn.connection(), identity, null);
    uc.secure = noise.SecureTransport.init(alloc, uc.tcp_conn.connection(), noise_result.tx_key, noise_result.rx_key);
    uc.remote_peer_id = noise_result.remote_peer_id; // move ownership out of noise_result
    std.crypto.secureZero(u8, &noise_result.tx_key);
    std.crypto.secureZero(u8, &noise_result.rx_key);
    std.crypto.secureZero(u8, &noise_result.session_key_material);
    errdefer uc.secure.deinit();
    errdefer uc.remote_peer_id.deinit();

    var sr: SecureReader = .{ .conn = &uc.secure, .io = io };
    var sw: SecureWriter = .{ .conn = &uc.secure, .io = io };
    try acceptProtocol(alloc, io, &sr, &sw, yamux.PROTOCOL_ID);

    uc.session = yamux.Session.init(alloc, &uc.secure, false);
    errdefer uc.session.deinit();
    try uc.session.start();

    return uc;
}

// ── dispatchStream ────────────────────────────────────────────────────────────
// Concurrent target: Multistream responder negotiation + handler call for one stream.

fn dispatchStream(stream: yamux.Stream, registry: *HandlerRegistry, conn_info: ConnInfo) void {
    const log = std.log.scoped(.host);
    var s = stream;
    defer s.deinit();
    registry.dispatch(&s, conn_info) catch |err| {
        log.warn("stream dispatch failed: {s}", .{@errorName(err)});
    };
}

// ── handleInbound ─────────────────────────────────────────────────────────────
// Concurrent target: upgrades one inbound TCP connection and drives the Yamux
// accept loop, dispatching each stream to the handler registry.

fn handleInbound(
    conn: tcp.TcpConnection,
    registry: *HandlerRegistry,
    io: std.Io,
    alloc: std.mem.Allocator,
    identity: *const IdentityKey,
) void {
    const log = std.log.scoped(.host);
    const uc = upgradeInbound(alloc, io, conn, identity) catch |err| {
        log.warn("inbound upgrade failed: {s}", .{@errorName(err)});
        return;
    };
    defer {
        uc.deinit();
        alloc.destroy(uc);
    }

    // Build per-connection info from the upgrade result.
    const remote_addr: ?std.Io.net.IpAddress = if (uc.tcp_conn.remote_multiaddr) |*ma|
        ma.getTcpAddress()
    else
        null;
    const conn_info = ConnInfo{
        .remote_peer_id = &uc.remote_peer_id,
        .remote_addr = remote_addr,
    };

    var stream_group: std.Io.Group = .init;
    defer {
        stream_group.cancel(io);
        stream_group.await(io) catch {};
    }

    while (true) {
        var stream = uc.session.acceptStream() catch break;
        stream_group.concurrent(io, dispatchStream, .{ stream, registry, conn_info }) catch {
            stream.deinit();
        };
    }
}

// ── Host ──────────────────────────────────────────────────────────────────────

pub const Host = struct {
    allocator: std.mem.Allocator,
    identity: IdentityKey,
    registry: HandlerRegistry,
    transport: tcp.TcpTransport,
    listener: ?*tcp.TcpTransport.Listener,
    // Outbound sessions created via dial(). Inbound sessions are owned by
    // their handleInbound concurrent task and not tracked here.
    sessions: std.array_list.Managed(*UpgradedConn),
    // Protects sessions list for concurrent dial() calls.
    sessions_mutex: std.Thread.Mutex,

    const Self = @This();

    // init takes ownership of identity.
    pub fn init(allocator: std.mem.Allocator, identity: IdentityKey) Self {
        return .{
            .allocator = allocator,
            .identity = identity,
            .registry = HandlerRegistry.init(allocator),
            .transport = tcp.TcpTransport.init(allocator),
            .listener = null,
            .sessions = std.array_list.Managed(*UpgradedConn).init(allocator),
            .sessions_mutex = .{},
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.sessions.items) |uc| {
            uc.deinit();
            self.allocator.destroy(uc);
        }
        self.sessions.deinit();
        self.registry.deinit();
        self.transport.deinit(); // closes listener
        self.identity.deinit();
    }

    // Register a handler for an application protocol (e.g. "/zeicoin/sync/1.0.0").
    pub fn setStreamHandler(self: *Self, protocol_id: []const u8, h: Handler) !void {
        try self.registry.register(protocol_id, h);
    }

    // Bind to addr. Must be called before serve().
    pub fn listen(self: *Self, io: std.Io, addr: *const Multiaddr) !void {
        self.listener = try self.transport.listen(io, addr);
    }

    // Dial addr, run the full upgrade stack, and return the Yamux session.
    // If a live session to the same remote PeerId already exists, the new
    // connection is closed and the existing session is returned (dedup).
    // The returned *Session is stable for the lifetime of this Host.
    pub fn dial(self: *Self, io: std.Io, addr: *const Multiaddr) !*yamux.Session {
        const conn = try self.transport.dial(io, addr);
        const uc = try upgradeOutbound(self.allocator, io, conn, &self.identity, null);
        errdefer {
            uc.deinit();
            self.allocator.destroy(uc);
        }

        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();

        // Evict stale (closed) sessions.
        var i: usize = 0;
        while (i < self.sessions.items.len) {
            if (self.sessions.items[i].session.isClosed()) {
                const dead = self.sessions.swapRemove(i);
                dead.deinit();
                self.allocator.destroy(dead);
            } else {
                i += 1;
            }
        }

        // Return the existing session if we already have one for this PeerId.
        for (self.sessions.items) |existing| {
            if (existing.remote_peer_id.equals(&uc.remote_peer_id)) {
                uc.deinit();
                self.allocator.destroy(uc);
                return &existing.session;
            }
        }

        try self.sessions.append(uc);
        return &uc.session;
    }

    // Return the remote PeerId for an outbound session created by dial().
    // The returned pointer is valid while the session is alive (i.e. while this Host is alive).
    // Returns null if the session is not found in the outbound session list.
    pub fn peerIdForSession(self: *Self, session: *const yamux.Session) ?*const PeerId {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();
        for (self.sessions.items) |uc| {
            if (&uc.session == session) return &uc.remote_peer_id;
        }
        return null;
    }

    // Open a Yamux stream on session and negotiate protocol via Multistream.
    // Returns a ready-to-use stream. Caller owns it and must call stream.deinit().
    pub fn newStream(self: *Self, io: std.Io, session: *yamux.Session, protocol: []const u8) !yamux.Stream {
        var stream = try session.openStream();
        errdefer stream.deinit();
        var yr: YamuxReader = .{ .stream = &stream };
        var yw: YamuxWriter = .{ .stream = &stream };
        const protos = [_][]const u8{protocol};
        var negotiator = ms.Negotiator.init(self.allocator, &protos, true);
        _ = try negotiator.negotiate(io, &yr, &yw);
        return stream;
    }

    // Accept and upgrade inbound connections, dispatching streams to registered
    // handlers. Runs until cancelled (io cancellation) or the listener closes.
    // Intended to run as a concurrent task via io.concurrent().
    pub fn serve(self: *Self, io: std.Io) !void {
        const listener = self.listener orelse return error.NotListening;
        var group: std.Io.Group = .init;
        defer {
            group.cancel(io);
            group.await(io) catch {};
        }
        while (true) {
            try std.Io.checkCancel(io);
            var conn = listener.accept(io) catch |err| switch (err) {
                error.Canceled, error.SocketNotListening => break,
                else => {
                    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
                    continue;
                },
            };
            group.concurrent(io, handleInbound, .{
                conn,
                &self.registry,
                io,
                self.allocator,
                &self.identity,
            }) catch {
                conn.deinit();
            };
        }
    }
};

// ── tests ──────────────────────────────────────────────────────────────────────

test "host: dial and newStream echo" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    // Server — Host.init takes ownership of identity; do not call identity.deinit() separately.
    var server = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer server.deinit();

    var listen_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19800");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    const EchoHandler = struct {
        fn handle(stream: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {
            var buf: [4]u8 = undefined;
            var n: usize = 0;
            while (n < buf.len) {
                const got = stream.readSome(buf[n..]) catch break;
                if (got == 0) break;
                n += got;
            }
            if (n > 0) try stream.writeAll(buf[0..n]);
        }
    };
    try server.setStreamHandler("/echo/1.0.0", .{ .func = EchoHandler.handle });

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    // Client — same ownership pattern.
    var client = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer client.deinit();

    var dial_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19800");
    defer dial_addr.deinit();
    const session = try client.dial(io, &dial_addr);

    var stream = try client.newStream(io, session, "/echo/1.0.0");
    defer stream.deinit();

    try stream.writeAll("ping");

    var buf: [4]u8 = undefined;
    var received: usize = 0;
    while (received < 4) {
        const n = try stream.readSome(buf[received..]);
        if (n == 0) break;
        received += n;
    }
    try std.testing.expectEqualStrings("ping", buf[0..received]);
}

test "host: unregistered protocol returns error" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    // Server — Host.init takes ownership of identity.
    var server = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer server.deinit();

    var listen_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19801");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    const DummyHandler = struct {
        fn handle(_: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {}
    };
    try server.setStreamHandler("/known/1.0.0", .{ .func = DummyHandler.handle });

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    // Client — same ownership pattern.
    var client = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer client.deinit();

    var dial_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19801");
    defer dial_addr.deinit();
    const session = try client.dial(io, &dial_addr);

    const result = client.newStream(io, session, "/unknown/1.0.0");
    try std.testing.expectError(error.NoProtocolMatch, result);
}

test "host: multiple concurrent streams on one session" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer server.deinit();

    var listen_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19802");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    const EchoHandler = struct {
        fn handle(stream: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {
            var buf: [4]u8 = undefined;
            var n: usize = 0;
            while (n < buf.len) {
                const got = stream.readSome(buf[n..]) catch break;
                if (got == 0) break;
                n += got;
            }
            if (n > 0) try stream.writeAll(buf[0..n]);
        }
    };
    try server.setStreamHandler("/echo/1.0.0", .{ .func = EchoHandler.handle });

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer client.deinit();

    var dial_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19802");
    defer dial_addr.deinit();
    const session = try client.dial(io, &dial_addr);

    // Each task opens its own stream, writes a unique payload, reads it back.
    const StreamTask = struct {
        client: *Host,
        session: *yamux.Session,
        io: std.Io,
        payload: [4]u8,
        received: [4]u8 = undefined,
        received_len: usize = 0,

        fn run(self: *@This()) anyerror!void {
            var stream = try self.client.newStream(self.io, self.session, "/echo/1.0.0");
            defer stream.deinit();
            try stream.writeAll(&self.payload);
            var n: usize = 0;
            while (n < self.payload.len) {
                const got = try stream.readSome(self.received[n..]);
                if (got == 0) break;
                n += got;
            }
            self.received_len = n;
        }
    };

    var task_a = StreamTask{ .client = &client, .session = session, .io = io, .payload = "aaaa".* };
    var task_b = StreamTask{ .client = &client, .session = session, .io = io, .payload = "bbbb".* };
    var task_c = StreamTask{ .client = &client, .session = session, .io = io, .payload = "cccc".* };

    var fut_a = try io.concurrent(StreamTask.run, .{&task_a});
    var fut_b = try io.concurrent(StreamTask.run, .{&task_b});
    var fut_c = try io.concurrent(StreamTask.run, .{&task_c});

    fut_a.await(io) catch {};
    fut_b.await(io) catch {};
    fut_c.await(io) catch {};

    try std.testing.expectEqualStrings("aaaa", task_a.received[0..task_a.received_len]);
    try std.testing.expectEqualStrings("bbbb", task_b.received[0..task_b.received_len]);
    try std.testing.expectEqualStrings("cccc", task_c.received[0..task_c.received_len]);
}

test "host: multiple protocols dispatch to correct handler" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer server.deinit();

    var listen_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19803");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    // Each handler writes a distinct marker byte so the client can tell them apart.
    const HandlerA = struct {
        fn handle(stream: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {
            try stream.writeAll("A");
        }
    };
    const HandlerB = struct {
        fn handle(stream: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {
            try stream.writeAll("B");
        }
    };
    try server.setStreamHandler("/proto-a/1.0.0", .{ .func = HandlerA.handle });
    try server.setStreamHandler("/proto-b/1.0.0", .{ .func = HandlerB.handle });

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer client.deinit();

    var dial_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19803");
    defer dial_addr.deinit();
    const session = try client.dial(io, &dial_addr);

    const readOne = struct {
        fn call(stream: *yamux.Stream) !u8 {
            var buf: [1]u8 = undefined;
            var n: usize = 0;
            while (n == 0) n = try stream.readSome(&buf);
            return buf[0];
        }
    }.call;

    var stream_a = try client.newStream(io, session, "/proto-a/1.0.0");
    defer stream_a.deinit();
    try std.testing.expectEqual(@as(u8, 'A'), try readOne(&stream_a));

    var stream_b = try client.newStream(io, session, "/proto-b/1.0.0");
    defer stream_b.deinit();
    try std.testing.expectEqual(@as(u8, 'B'), try readOne(&stream_b));
}

test "host: handler error does not kill the session" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer server.deinit();

    var listen_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19804");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    const FailHandler = struct {
        fn handle(_: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {
            return error.IntentionalFailure;
        }
    };
    const EchoHandler = struct {
        fn handle(stream: *yamux.Stream, _: ConnInfo, _: ?*anyopaque) anyerror!void {
            var buf: [2]u8 = undefined;
            var n: usize = 0;
            while (n < buf.len) {
                const got = stream.readSome(buf[n..]) catch break;
                if (got == 0) break;
                n += got;
            }
            if (n > 0) try stream.writeAll(buf[0..n]);
        }
    };
    try server.setStreamHandler("/fail/1.0.0", .{ .func = FailHandler.handle });
    try server.setStreamHandler("/echo/1.0.0", .{ .func = EchoHandler.handle });

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer client.deinit();

    var dial_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19804");
    defer dial_addr.deinit();
    const session = try client.dial(io, &dial_addr);

    // Open a stream to the failing handler — negotiation succeeds, handler errors,
    // server closes its end. Client just discards the stream.
    var fail_stream = try client.newStream(io, session, "/fail/1.0.0");
    fail_stream.deinit();

    // The session must still be alive for a second stream to succeed.
    var ok_stream = try client.newStream(io, session, "/echo/1.0.0");
    defer ok_stream.deinit();

    try ok_stream.writeAll("ok");
    var buf: [2]u8 = undefined;
    var n: usize = 0;
    while (n < 2) {
        const got = try ok_stream.readSome(buf[n..]);
        if (got == 0) break;
        n += got;
    }
    try std.testing.expectEqualStrings("ok", buf[0..n]);
}

test "host: large payload integrity" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer server.deinit();

    var listen_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19805");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    const payload_size: usize = 1024 * 1024; // 1 MiB

    // Handler reads exactly payload_size bytes and echoes them back in 64 KiB chunks.
    const LargeEchoHandler = struct {
        fn handle(stream: *yamux.Stream, _: ConnInfo, userdata: ?*anyopaque) anyerror!void {
            const size: usize = @as(*const usize, @ptrCast(@alignCast(userdata.?))).*;
            var buf: [65536]u8 = undefined;
            var done: usize = 0;
            while (done < size) {
                const want = @min(buf.len, size - done);
                const n = try stream.readSome(buf[0..want]);
                if (n == 0) return error.UnexpectedEof;
                try stream.writeAll(buf[0..n]);
                done += n;
            }
        }
    };
    var size_hint: usize = payload_size;
    try server.setStreamHandler("/large-echo/1.0.0", .{
        .func = LargeEchoHandler.handle,
        .userdata = &size_hint,
    });

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(alloc, try IdentityKey.generate(alloc, io));
    defer client.deinit();

    var dial_addr = try Multiaddr.create(alloc, "/ip4/127.0.0.1/tcp/19805");
    defer dial_addr.deinit();
    const session = try client.dial(io, &dial_addr);

    var stream = try client.newStream(io, session, "/large-echo/1.0.0");
    defer stream.deinit();

    // Build a payload with a known pattern for byte-level verification.
    const payload = try alloc.alloc(u8, payload_size);
    defer alloc.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i);

    try stream.writeAll(payload);

    const received = try alloc.alloc(u8, payload_size);
    defer alloc.free(received);
    var total: usize = 0;
    while (total < payload_size) {
        const n = try stream.readSome(received[total..]);
        if (n == 0) break;
        total += n;
    }

    try std.testing.expectEqual(payload_size, total);
    try std.testing.expectEqualSlices(u8, payload, received[0..total]);
}
