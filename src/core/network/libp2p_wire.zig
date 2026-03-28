// libp2p_wire.zig — ZeiCoin wire protocol adapter over libp2p yamux streams.
//
// Maps the existing ZeiCoin binary framing (WireConnection) onto a negotiated
// yamux stream. The transport changes; the framing does not.
//
// Two touch points replace net.Stream:
//   READ:  stream.readSome → peer.receiveData (same as PeerConnection.run)
//   WRITE: peer.sendMessage → sendCallback → stream.writeAll (replaces tcpSendCallback)
//
// Outbound usage:
//   var stream = try host.newStream(io, session, PROTOCOL_ID);
//   var runner = StreamRunner.init(&stream, peer);
//   try runner.run();
//
// Inbound usage: see NetworkManager.zeicoinInboundHandler() in peer.zig.

const std = @import("std");
const libp2p = @import("libp2p");
const yamux = libp2p.yamux;
const ConnInfo = libp2p.ConnInfo;
const peer_manager = @import("peer_manager.zig");

const Peer = peer_manager.Peer;

pub const PROTOCOL_ID: []const u8 = "/zeicoin/1.0.0";

// Send callback registered on Peer via setTcpSendCallback.
// Writes framed bytes directly to the yamux stream.
pub fn sendCallback(ctx: ?*anyopaque, data: []const u8) anyerror!void {
    const stream: *yamux.Stream = @ptrCast(@alignCast(ctx.?));
    try stream.writeAll(data);
}

// Runs the ZeiCoin wire protocol on a negotiated yamux stream.
//
// Mirrors the transport I/O in PeerConnection.run() but uses a yamux
// Stream instead of net.Stream. WireConnection framing is untouched —
// bytes flow through the same WireReader/WireWriter path.
//
// Phase 3 (peer_manager migration) will call peer.readMessage() and
// dispatch to the MessageHandler from the connection thread. This runner
// only owns the transport layer: receive bytes, feed to peer, flush sends.
pub const StreamRunner = struct {
    stream: *yamux.Stream,
    peer: *Peer,

    const Self = @This();

    pub fn init(stream: *yamux.Stream, peer: *Peer) Self {
        return .{ .stream = stream, .peer = peer };
    }

    // Run the read loop until the stream closes or the peer shuts down.
    // Registers sendCallback for the duration so Peer.sendMessage() writes
    // to this stream.
    pub fn run(self: *Self) !void {
        self.peer.setTcpSendCallback(sendCallback, self.stream);
        defer self.peer.setTcpSendCallback(null, null);

        var buf: [4096]u8 = undefined;

        while (true) {
            if (self.peer.is_shutting_down.load(.acquire)) break;

            const n = self.stream.readSome(&buf) catch break;
            if (n == 0) break; // stream closed by remote

            self.peer.receiveData(buf[0..n]) catch |err| {
                if (err == error.PeerShuttingDown) break;
                return err;
            };

            // Drain the WireReader buffer so it doesn't grow unboundedly.
            // Phase 3 will dispatch these envelopes to MessageHandler.
            while (try self.peer.readMessage()) |envelope| {
                envelope.deinit();
            }
        }

        self.peer.state = .disconnected;
    }
};

// ── tests ─────────────────────────────────────────────────────────────────────

const wire = @import("wire/wire.zig");
const InProcConnection = libp2p.InProcConnection;
const noise = libp2p.noise;
const protocol = @import("protocol/protocol.zig");
const message_types = @import("protocol/messages/message_types.zig");
const util = @import("../util/util.zig");
const net = std.Io.net;

const KEY_A = [_]u8{0xAA} ** 32;
const KEY_B = [_]u8{0xBB} ** 32;

// Heap-allocated test context — Session stores *SecureTransport which stores
// a pointer into InProcConnection, so all three must not move after init.
const TestCtx = struct {
    init_conn: InProcConnection,
    resp_conn: InProcConnection,
    init_secure: noise.SecureTransport,
    resp_secure: noise.SecureTransport,
    init_session: yamux.Session,
    resp_session: yamux.Session,

    const opts = yamux.SessionOptions{
        .keepalive_interval_ms = 100,
        .keepalive_timeout_ms = 500,
    };

    fn init(allocator: std.mem.Allocator, io: std.Io) !*TestCtx {
        const ctx = try allocator.create(TestCtx);
        errdefer allocator.destroy(ctx);

        var pair = try InProcConnection.initPair(allocator, io);
        ctx.init_conn = pair.initiator;
        ctx.resp_conn = pair.responder;

        ctx.init_secure = noise.SecureTransport.init(allocator, ctx.init_conn.connection(), KEY_A, KEY_B);
        ctx.resp_secure = noise.SecureTransport.init(allocator, ctx.resp_conn.connection(), KEY_B, KEY_A);

        ctx.init_session = yamux.Session.initWithOptions(allocator, &ctx.init_secure, true, opts);
        ctx.resp_session = yamux.Session.initWithOptions(allocator, &ctx.resp_secure, false, opts);

        try ctx.init_session.start();
        try ctx.resp_session.start();

        return ctx;
    }

    fn deinit(self: *TestCtx) void {
        self.init_session.deinit();
        self.resp_session.deinit();
        self.init_secure.deinit();
        self.resp_secure.deinit();
        self.init_conn.deinit();
        self.resp_conn.deinit();
    }
};

// Minimal Peer init for tests — no real address needed.
fn makeTestPeer(allocator: std.mem.Allocator, io: std.Io) Peer {
    const addr = net.IpAddress.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    return Peer.init(allocator, io, 1, addr);
}

test "libp2p_wire: framed ping round-trip over yamux stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const ctx = try TestCtx.init(allocator, io);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    // Responder: accept a stream, run StreamRunner, then verify one message arrived.
    const RespCtx = struct {
        session: *yamux.Session,
        allocator: std.mem.Allocator,
        io: std.Io,
        received_type: ?protocol.MessageType = null,

        fn run(self: *@This()) anyerror!void {
            var peer = makeTestPeer(self.allocator, self.io);
            defer peer.deinit();

            var stream = try self.session.acceptStream();
            defer stream.deinit();

            // Wire up send callback and read one chunk of bytes.
            peer.setTcpSendCallback(sendCallback, &stream);
            defer peer.setTcpSendCallback(null, null);

            var buf: [256]u8 = undefined;
            const n = try stream.readSome(&buf);
            try peer.receiveData(buf[0..n]);

            if (try peer.readMessage()) |envelope| {
                self.received_type = envelope.header.message_type;
                envelope.deinit();
            }
        }
    };

    var resp = RespCtx{
        .session = &ctx.resp_session,
        .allocator = allocator,
        .io = io,
    };
    var resp_future = try io.concurrent(RespCtx.run, .{&resp});

    // Initiator: open stream and send a framed ping via WireWriter + sendCallback.
    var init_stream = try ctx.init_session.openStream();
    defer init_stream.deinit();

    var sender_peer = makeTestPeer(allocator, io);
    defer sender_peer.deinit();

    sender_peer.setTcpSendCallback(sendCallback, &init_stream);
    defer sender_peer.setTcpSendCallback(null, null);

    const ping_msg = message_types.PingMessage.init();
    _ = try sender_peer.sendMessage(.ping, ping_msg);

    try init_stream.close();
    resp_future.await(io) catch {};

    try std.testing.expectEqual(protocol.MessageType.ping, resp.received_type.?);
}

test "libp2p_wire: StreamRunner drains wire buffer without dispatch" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const ctx = try TestCtx.init(allocator, io);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    // Responder: run StreamRunner (drains messages without dispatch).
    const RespCtx = struct {
        session: *yamux.Session,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(self: *@This()) anyerror!void {
            var peer = makeTestPeer(self.allocator, self.io);
            defer peer.deinit();

            var stream = try self.session.acceptStream();
            defer stream.deinit();

            var runner = StreamRunner.init(&stream, &peer);
            try runner.run();
        }
    };

    var resp = RespCtx{ .session = &ctx.resp_session, .allocator = allocator, .io = io };
    var resp_future = try io.concurrent(RespCtx.run, .{&resp});

    // Initiator: send two framed messages then close the stream.
    var init_stream = try ctx.init_session.openStream();
    defer init_stream.deinit();

    var sender_peer = makeTestPeer(allocator, io);
    defer sender_peer.deinit();

    sender_peer.setTcpSendCallback(sendCallback, &init_stream);
    defer sender_peer.setTcpSendCallback(null, null);

    _ = try sender_peer.sendMessage(.ping, message_types.PingMessage.init());
    _ = try sender_peer.sendMessage(.ping, message_types.PingMessage.init());

    try init_stream.close();
    resp_future.await(io) catch {};
    // StreamRunner exited cleanly — no deadlock, no leak.
}
