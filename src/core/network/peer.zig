// peer.zig - Network peer management
// Clean modular implementation using libp2p Host for all connections.

const std = @import("std");
const net = std.Io.net;
const libp2p = @import("libp2p");
const yamux = libp2p.yamux;
const Multiaddr = libp2p.Multiaddr;
const types = @import("../types/types.zig");
const bootstrap = @import("bootstrap.zig");
const ip_detection = @import("ip_detection.zig");
const util = @import("../util/util.zig");
const libp2p_wire = @import("libp2p_wire.zig");

const log = std.log.scoped(.network);

// Re-export the modular components
pub const protocol = @import("protocol/protocol.zig");
pub const message_types = @import("protocol/messages/message_types.zig");
pub const wire = @import("wire/wire.zig");
pub const PeerManager = @import("peer_manager.zig").PeerManager;
pub const Peer = @import("peer_manager.zig").Peer;
pub const PeerConnection = @import("peer_connection.zig").PeerConnection;
pub const MessageHandler = @import("peer_connection.zig").MessageHandler;

// Re-export commonly used types
pub const MessageType = protocol.MessageType;
pub const DEFAULT_PORT = protocol.DEFAULT_PORT;
pub const MAX_PEERS = protocol.MAX_PEERS;

// ── Inbound handler context ───────────────────────────────────────────────────
// Stored on NetworkManager and passed as userdata to the HandlerRegistry.
// Lives for the lifetime of the NetworkManager.

const InboundCtx = struct {
    network_manager: *NetworkManager,
    message_handler: MessageHandler,
    allocator: std.mem.Allocator,
    io: std.Io,
};

// HandlerRegistry-compatible inbound handler for /zeicoin/1.0.0 streams.
// Called by the libp2p Host after Multistream negotiation on each inbound stream.
fn zeicoinInboundHandler(
    stream: *yamux.Stream,
    conn_info: libp2p.ConnInfo,
    userdata: ?*anyopaque,
) anyerror!void {
    const ctx = @as(*InboundCtx, @ptrCast(@alignCast(userdata.?)));
    const nm = ctx.network_manager;

    // Clone PeerId for ownership transfer to Peer.
    var owned_pid: ?libp2p.PeerId = if (conn_info.remote_peer_id) |pid|
        try libp2p.PeerId.fromBytes(ctx.allocator, pid.getBytes())
    else
        null;
    errdefer if (owned_pid) |*pid| pid.deinit();

    // Use remote TCP address if available, else 0.0.0.0:0 (still works for dedup by PeerId).
    const remote_addr = conn_info.remote_addr orelse
        net.IpAddress{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };

    const peer = nm.peer_manager.addPeer(remote_addr, owned_pid) catch |err| {
        if (err == error.AlreadyConnected) return;
        return err;
    };
    if (conn_info.remote_peer_id) |remote_peer_id| {
        const observed_ma = try formatIpAsMultiaddr(ctx.allocator, remote_addr);
        defer ctx.allocator.free(observed_ma);
        nm.learnKnownSessionPeer(remote_peer_id.toString(), stream.session, observed_ma, remote_addr) catch |err| {
            std.log.debug("Inbound identify/session learning failed: {}", .{err});
        };
    }
    peer.addRef();
    _ = nm.active_connections.fetchAdd(1, .acq_rel);
    defer {
        _ = nm.active_connections.fetchSub(1, .acq_rel);
        if (nm.isRunning()) nm.peer_manager.removePeer(peer.id);
        peer.release();
    }

    var conn = PeerConnection.init(ctx.allocator, peer, stream.*, ctx.message_handler);
    defer conn.deinit(ctx.io);

    conn.run(ctx.io) catch |err| {
        if (nm.isRunning()) {
            if (ctx.message_handler.onPeerDisconnected) |f| {
                f(peer, err) catch |handler_err| {
                    std.log.debug("Disconnect handler error: {}", .{handler_err});
                };
            }
            std.log.err("🔌 [NETWORK] Inbound peer {} disconnected: {s}", .{
                peer.id, @errorName(err),
            });
        }
    };
}

// ── NetworkManager ────────────────────────────────────────────────────────────

pub const NetworkManager = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    host: libp2p.Host,
    peer_manager: PeerManager,
    address_book: libp2p.AddressBook,
    routing_table: libp2p.kad_routing.RoutingTable,
    kad_service: ?libp2p.kad_query.QueryService,
    message_handler: MessageHandler,
    running: bool,
    stopped: bool,
    bootstrap_nodes: []bootstrap.BootstrapAddr,
    owns_bootstrap_nodes: bool,
    last_reconnect_attempt: i64,
    active_connections: std.atomic.Value(u32),
    last_kad_refresh_ms: u64,
    kad_refresh_interval_ms: u64,
    kad_query_timeout_ms: u64,

    // Inbound handler context — lives for the lifetime of NetworkManager.
    inbound_ctx: InboundCtx,

    // Exponential backoff for reconnections
    reconnect_backoff_seconds: u32,
    reconnect_consecutive_failures: u32,
    last_successful_connection: i64,

    const Self = @This();
    const MAX_ACTIVE_CONNECTIONS = 100;

    inline fn isRunning(self: *const Self) bool {
        return @atomicLoad(bool, &self.running, .acquire);
    }

    inline fn setRunning(self: *Self, value: bool) void {
        @atomicStore(bool, &self.running, value, .release);
    }

    // init takes ownership of identity (moved into host).
    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        handler: MessageHandler,
        identity: libp2p.IdentityKey,
    ) !Self {
        var host = libp2p.Host.init(allocator, identity);
        errdefer host.deinit();

        return .{
            .allocator = allocator,
            .io = io,
            .host = host,
            .peer_manager = PeerManager.init(allocator, io, MAX_PEERS),
            .address_book = try libp2p.AddressBook.init(allocator, host.identity.peer_id.toString()),
            .routing_table = try libp2p.kad_routing.RoutingTable.init(allocator, host.identity.peer_id.toString()),
            .kad_service = null,
            .message_handler = handler,
            .running = false,
            .stopped = false,
            .bootstrap_nodes = &[_]bootstrap.BootstrapAddr{},
            .owns_bootstrap_nodes = false,
            .last_reconnect_attempt = 0,
            .active_connections = std.atomic.Value(u32).init(0),
            .last_kad_refresh_ms = 0,
            .kad_refresh_interval_ms = kad_refresh_interval_default_ms,
            .kad_query_timeout_ms = libp2p.kad_query.query_timeout_default_ms,
            .reconnect_backoff_seconds = 5,
            .reconnect_consecutive_failures = 0,
            .last_successful_connection = 0,
            // inbound_ctx.network_manager is set in listen() once self is at its final
            // heap address. The other fields are stable from init.
            .inbound_ctx = .{
                .network_manager = undefined,
                .message_handler = handler,
                .allocator = allocator,
                .io = io,
            },
        };
    }

    pub fn deinit(self: *Self) void {
        // stop() is idempotent - closes connections and waits for all threads to finish
        self.stop();

        // Only clean up peers if all threads exited cleanly.
        if (self.active_connections.load(.acquire) == 0) {
            self.peer_manager.deinit();
        }

        // Clean up bootstrap nodes if we own them
        if (self.owns_bootstrap_nodes and self.bootstrap_nodes.len > 0) {
            bootstrap.freeList(self.allocator, self.bootstrap_nodes);
        }
        if (self.kad_service) |*kad_service| kad_service.deinit();
        self.routing_table.deinit();
        self.address_book.deinit();
    }

    /// Start listening for connections
    pub fn listen(self: *Self, address_str: []const u8, port: u16) !void {
        // Self is at its final heap address now — safe to take a pointer.
        self.inbound_ctx.network_manager = self;

        const parsed = net.IpAddress.resolve(self.io, address_str, port) catch |err| return err;
        const ma_str = try formatIpAsMultiaddr(self.allocator, parsed);
        defer self.allocator.free(ma_str);

        var ma = try Multiaddr.create(self.allocator, ma_str);
        defer ma.deinit();

        // Register /zeicoin/1.0.0 handler before listening.
        try self.host.setStreamHandler(libp2p_wire.PROTOCOL_ID, .{
            .func = zeicoinInboundHandler,
            .userdata = &self.inbound_ctx,
        });

        try self.host.listen(self.io, &ma);

        const kad_settings = loadKadRuntimeSettings(self.allocator);
        self.kad_refresh_interval_ms = kad_settings.refresh_interval_ms;
        self.kad_query_timeout_ms = kad_settings.query_timeout_ms;

        self.kad_service = libp2p.kad_query.QueryService.init(
            self.allocator,
            &self.host,
            &self.routing_table,
            &self.address_book,
            .server,
        );
        if (self.kad_service) |*kad_service| {
            kad_service.refresh_interval_ms = self.kad_refresh_interval_ms;
            kad_service.query_timeout_ms = self.kad_query_timeout_ms;
            try kad_service.register();
            log.info(
                "Kad runtime enabled: refresh_interval_ms={} query_timeout_ms={}",
                .{ self.kad_refresh_interval_ms, self.kad_query_timeout_ms },
            );
        }

        self.setRunning(true);
        log.info("Listening on {s}:{}", .{ address_str, port });
    }

    /// Connect to a peer by IpAddress (constructs a multiaddr internally).
    /// Used by maintenance() reconnect and peer exchange.
    pub fn connectToPeer(self: *Self, address: net.IpAddress) !void {
        try self.addKnownAddress(address);
        const ma_str = try formatIpAsMultiaddr(self.allocator, address);
        defer self.allocator.free(ma_str);
        var ma = try Multiaddr.create(self.allocator, ma_str);
        defer ma.deinit();
        try self.connectToMultiaddr(&ma);
    }

    /// Dial a peer by Multiaddr. Used for bootstrap connections.
    fn connectToMultiaddr(self: *Self, ma: *const Multiaddr) !void {
        // Check connection limit
        const current_connections = self.active_connections.load(.acquire);
        if (current_connections >= MAX_ACTIVE_CONNECTIONS) {
            return error.TooManyConnections;
        }

        // Prevent self-connections when the target already resolves to a concrete IP.
        // DNS multiaddrs are still allowed through to the transport's resolver path.
        if (ma.getTcpAddress()) |tcp_addr| {
            if (ip_detection.isSelfConnection(self.allocator, self.io, tcp_addr)) {
                log.warn("🚫 Self-connection prevented: skipping connection to own public IP {}", .{tcp_addr});
                return;
            }
        }

        const peer_addr = if (ma.getTcpAddress()) |tcp_addr|
            tcp_addr
        else
            try resolveMultiaddrIpAddress(self.io, ma);

        // Dial — runs Noise + Yamux upgrade
        const session = try self.host.dial(self.io, ma);

        // Get remote PeerId and clone it for ownership transfer to Peer
        var owned_pid: ?libp2p.PeerId = blk: {
            const pid = self.host.peerIdForSession(session) orelse break :blk null;
            break :blk try libp2p.PeerId.fromBytes(self.allocator, pid.getBytes());
        };
        errdefer if (owned_pid) |*pid| pid.deinit();

        // Deduplicate and register peer
        const peer = try self.peer_manager.addPeer(peer_addr, owned_pid);
        const remote_peer_id = self.host.peerIdForSession(session) orelse return error.MissingRemotePeerId;
        try self.learnKnownSessionPeer(remote_peer_id.toString(), session, ma.getStringAddress(), peer_addr);
        log.info("Dialed peer {}", .{peer.id});

        // Add ref for the connection thread
        peer.addRef();
        _ = self.active_connections.fetchAdd(1, .acq_rel);
        errdefer _ = self.active_connections.fetchSub(1, .acq_rel);

        // Spawn connection thread
        const thread = std.Thread.spawn(.{}, runOutboundConnection, .{
            self, peer, session,
        }) catch |err| {
            peer.release();
            self.peer_manager.removePeer(peer.id);
            return err;
        };
        thread.detach();
        log.info("Spawned outbound connection thread for peer {}", .{peer.id});
    }

    /// Outbound connection thread: open /zeicoin/1.0.0 stream and run protocol.
    fn runOutboundConnection(self: *Self, peer: *Peer, session: *yamux.Session) void {
        defer _ = self.active_connections.fetchSub(1, .acq_rel);

        if (!self.isRunning()) {
            self.peer_manager.removePeer(peer.id);
            peer.release();
            return;
        }

        // Open a /zeicoin/1.0.0 stream on the already-upgraded session
        const stream = self.host.newStream(self.io, session, libp2p_wire.PROTOCOL_ID) catch |err| {
            log.warn("Failed to open /zeicoin/1.0.0 stream for peer {}: {}", .{ peer.id, err });
            self.peer_manager.removePeer(peer.id);
            peer.release();
            return;
        };

        var conn = PeerConnection.init(self.allocator, peer, stream, self.message_handler);
        defer conn.deinit(self.io);

        conn.run(self.io) catch |err| {
            if (self.isRunning()) {
                if (self.message_handler.onPeerDisconnected) |onDisconnect| {
                    onDisconnect(peer, err) catch |handler_err| {
                        std.log.debug("Disconnect handler error: {}", .{handler_err});
                    };
                }
                const error_msg = switch (err) {
                    error.ConnectionResetByPeer => "connection reset by peer",
                    error.ConnectionRefused => "connection refused",
                    error.ConnectionTimedOut => "connection timed out",
                    error.NetworkUnreachable => "network unreachable",
                    error.HostUnreachable => "host unreachable",
                    error.BrokenPipe => "connection broken",
                    error.EndOfStream => "connection closed",
                    else => @errorName(err),
                };
                log.err("🔌 [NETWORK] Peer {} disconnected ({s})", .{ peer.id, error_msg });
            }
        };

        if (self.isRunning()) self.peer_manager.removePeer(peer.id);
        peer.release();
    }

    /// Accept incoming connections — delegates to host.serve().
    /// Runs in a dedicated thread (spawned by initialization.zig).
    pub fn acceptConnections(self: *Self) !void {
        _ = self.active_connections.fetchAdd(1, .acq_rel);
        defer _ = self.active_connections.fetchSub(1, .acq_rel);

        self.setRunning(true);
        // host.serve() blocks until shutdown requests a listener wake-up.
        try self.host.serve(self.io);
    }

    /// Start network (convenience method that calls listen)
    pub fn start(self: *Self, address_str: []const u8, port: u16) !void {
        try self.listen(address_str, port);
    }

    /// Add a peer by string address (parses and delegates to connectToPeer)
    pub fn addPeer(self: *Self, address_str: []const u8) !void {
        const address = try net.IpAddress.parse(address_str, 10801);
        try self.connectToPeer(address);
    }

    pub fn addKnownAddress(self: *Self, address: net.IpAddress) !void {
        try self.peer_manager.addKnownAddress(address);
        const ma_str = try formatIpAsMultiaddr(self.allocator, address);
        defer self.allocator.free(ma_str);
        try self.address_book.learn(ma_str, nowMs());
    }

    /// Stop network manager
    pub fn stop(self: *Self) void {
        // Prevent multiple stop calls - use atomic operation for thread safety
        if (@atomicLoad(bool, &self.stopped, .acquire)) return;
        @atomicStore(bool, &self.stopped, true, .release);

        // Signal shutdown first
        @atomicStore(bool, &self.running, false, .release);

        // Give threads a moment to see the running flag change
        const io = self.io;
        io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};

        // Wake the blocking accept() loop before any resources are deinitialized.
        self.host.requestStop(self.io) catch |err| {
            log.warn("Failed to wake listener during shutdown: {}", .{err});
        };

        // Stop peer manager (closes yamux streams to wake blocked readers)
        self.peer_manager.stop();

        // Wait for all detached threads to finish
        log.info("Waiting for network threads to finish...", .{});

        const max_wait_ms: u32 = 5000;
        const poll_interval_ms: u32 = 100;
        var waited_ms: u32 = 0;

        while (waited_ms < max_wait_ms) {
            const active = self.active_connections.load(.acquire);
            if (active == 0) {
                log.info("All network threads finished cleanly after {}ms", .{waited_ms});
                break;
            }
            const io_wait = self.io;
            io_wait.sleep(std.Io.Duration.fromMilliseconds(poll_interval_ms), std.Io.Clock.awake) catch {};
            waited_ms += poll_interval_ms;
        }

        const remaining = self.active_connections.load(.acquire);
        if (remaining > 0) {
            log.warn("Shutdown timeout: {} threads still active after {}ms", .{ remaining, max_wait_ms });
        } else {
            log.info("Network shutdown complete", .{});
        }

        // After the accept loop and peer threads have drained, it is safe to
        // release listener/session resources owned by Host.
        self.host.deinit();
    }

    /// Broadcast to all peers
    pub fn broadcast(self: *Self, msg_type: MessageType, msg: anytype) !void {
        try self.peer_manager.broadcast(msg_type, msg);
    }

    /// Broadcast a new block to all connected peers
    pub fn broadcastBlock(self: *Self, block: types.Block) !void {
        const block_msg = message_types.BlockMessage{ .block = block };
        self.broadcast(.block, block_msg) catch |err| {
            log.warn("Failed to broadcast block: {}", .{err});
        };
        const block_hash = block.hash();
        std.log.debug("Broadcasted block {x} directly to peers (ZSP-001)", .{block_hash});
    }

    /// Broadcast a new transaction to all connected peers
    pub fn broadcastTransaction(self: *Self, tx: types.Transaction) void {
        const tx_msg = message_types.TransactionMessage{ .transaction = tx };
        self.broadcast(.transaction, tx_msg) catch |err| {
            log.warn("Failed to broadcast transaction: {}", .{err});
        };
        const tx_hash = tx.hash();
        std.log.debug("Broadcasted transaction {x} directly to peers (ZSP-001)", .{tx_hash});
    }

    /// Get connected peer count
    pub fn getConnectedPeerCount(self: *Self) usize {
        return self.peer_manager.getConnectedCount();
    }

    /// Get highest peer height
    pub fn getHighestPeerHeight(self: *Self) u32 {
        return self.peer_manager.getHighestPeerHeight();
    }

    /// Get peer statistics
    pub fn getPeerStats(self: *Self) struct { total: usize, connected: usize, syncing: usize } {
        const stats = self.peer_manager.getPeerCount();
        return .{ .total = stats.total, .connected = stats.connected, .syncing = stats.syncing };
    }

    /// Set bootstrap nodes for auto-reconnect (creates a deep copy)
    pub fn setBootstrapNodes(self: *Self, nodes: []const bootstrap.BootstrapAddr) !void {
        if (self.owns_bootstrap_nodes and self.bootstrap_nodes.len > 0) {
            bootstrap.freeList(self.allocator, self.bootstrap_nodes);
        }
        self.bootstrap_nodes = try bootstrap.cloneList(self.allocator, nodes);
        self.owns_bootstrap_nodes = true;
        for (self.bootstrap_nodes) |*node| {
            try self.address_book.learnBootstrap(node.multiaddr.getStringAddress(), nowMs());
        }
    }

    fn logKadStatus(self: *Self, reason: []const u8, lookups_started: usize, timed_out: bool) !void {
        const metrics = try self.collectKadMetrics();
        log.info(
            "kad_status: reason={s} peer_id={s} lookups_started={} timed_out={} routing_peers={} non_empty_buckets={} book_entries={} kad_addrs={} live_sessions={} connected_peers={}",
            .{
                reason,
                self.host.identity.peer_id.toString(),
                lookups_started,
                timed_out,
                metrics.routing_peers,
                metrics.non_empty_buckets,
                metrics.book_entries,
                metrics.kad_addrs,
                metrics.live_sessions,
                self.getConnectedPeerCount(),
            },
        );
    }

    fn collectKadMetrics(self: *Self) !KadMetrics {
        var snapshot = try self.address_book.snapshot(self.allocator);
        defer {
            for (snapshot.items) |entry| {
                self.allocator.free(entry.addr);
                if (entry.peer_id) |peer_id| self.allocator.free(peer_id);
            }
            snapshot.deinit();
        }

        var kad_addrs: usize = 0;
        for (snapshot.items) |entry| {
            if (entry.source.kad) kad_addrs += 1;
        }

        var non_empty = try self.routing_table.nonEmptyBucketIndices(self.allocator);
        defer non_empty.deinit();

        return .{
            .routing_peers = self.routing_table.peerCount(),
            .non_empty_buckets = non_empty.items.len,
            .book_entries = snapshot.items.len,
            .kad_addrs = kad_addrs,
            .live_sessions = self.host.liveSessionCount(),
        };
    }

    /// Calculate exponential backoff delay
    fn calculateBackoff(consecutive_failures: u32) u32 {
        const base: u32 = 5;
        const max_backoff: u32 = 60;
        const capped = @min(consecutive_failures, 6);
        const backoff = base * std.math.pow(u32, 2, capped);
        return @min(backoff, max_backoff);
    }

    fn countMissingBootstrapNodes(self: *Self) usize {
        var missing: usize = 0;

        for (self.bootstrap_nodes) |*node| {
            const address = node.tcpAddress() orelse continue;
            if (!self.peer_manager.hasActivePeerAtAddress(address)) {
                missing += 1;
            }
        }

        return missing;
    }

    /// Clean up timed out connections and handle auto-reconnect
    pub fn maintenance(self: *Self) void {
        if (@atomicLoad(bool, &self.stopped, .acquire)) return;

        self.peer_manager.cleanupTimedOut();
        self.address_book.pruneStale(nowMs());

        const now = util.getTime();
        const connected_peers = self.getConnectedPeerCount();
        const missing_bootstrap_nodes = self.countMissingBootstrapNodes();

        if (missing_bootstrap_nodes > 0 and self.bootstrap_nodes.len > 0) {
            const backoff = calculateBackoff(self.reconnect_consecutive_failures);

            if (now - self.last_reconnect_attempt >= backoff) {
                self.last_reconnect_attempt = now;
                log.info("🔄 [RECONNECT] Attempting reconnection (backoff: {}s, failures: {}, connected: {}, missing_bootstrap: {})", .{
                    backoff,
                    self.reconnect_consecutive_failures,
                    connected_peers,
                    missing_bootstrap_nodes,
                });

                var connection_succeeded = false;
                for (self.bootstrap_nodes) |*node| {
                    const address = node.tcpAddress() orelse continue;
                    if (self.peer_manager.hasActivePeerAtAddress(address)) continue;

                    self.connectToMultiaddr(&node.multiaddr) catch |err| {
                        if (err == error.AlreadyConnected) {
                            log.debug("Already connected to bootstrap node", .{});
                            connection_succeeded = true;
                            continue;
                        } else {
                            log.debug("Failed to connect to bootstrap: {}", .{err});
                        }
                        continue;
                    };
                    connection_succeeded = true;
                }

                if (connection_succeeded) {
                    self.reconnect_consecutive_failures = 0;
                    self.reconnect_backoff_seconds = 5;
                    self.last_successful_connection = now;
                    log.info("✅ [RECONNECT] Connection successful, backoff reset", .{});
                } else {
                    self.reconnect_consecutive_failures += 1;
                    self.reconnect_backoff_seconds = calculateBackoff(self.reconnect_consecutive_failures);
                    log.warn("❌ [RECONNECT] All connections failed, backoff increased to {}s", .{
                        self.reconnect_backoff_seconds,
                    });
                }
            }
        }

        if (self.host.listen_addr) |listen_addr| {
            const local_ma = listen_addr.getStringAddress();
            var attempts: usize = 0;
            while (attempts < 8) : (attempts += 1) {
                const maybe_candidate = self.address_book.chooseDialCandidate(self.allocator, nowMs(), local_ma) catch null;
                const candidate = maybe_candidate orelse break;
                defer self.allocator.free(candidate);

                var ma = Multiaddr.create(self.allocator, candidate) catch continue;
                defer ma.deinit();

                if (ma.getTcpAddress()) |candidate_addr| {
                    if (self.peer_manager.hasActivePeerForCandidate(ma.getPeerId(), candidate_addr)) {
                        continue;
                    }
                }

                self.connectToMultiaddr(&ma) catch |err| {
                    self.address_book.markDialFailure(candidate, nowMs());
                    log.debug("Address-book dial failed for {s}: {}", .{ candidate, err });
                    continue;
                };
                self.address_book.markDialSuccess(candidate, nowMs());
                break;
            }
        }

        if (self.kad_service) |*kad_service| {
            const now_ms = nowMs();
            if (connected_peers > 0 and (self.last_kad_refresh_ms == 0 or now_ms - self.last_kad_refresh_ms >= self.kad_refresh_interval_ms)) {
                const result = kad_service.bootstrapOnce(self.io) catch |err| {
                    log.debug("Kad bootstrap/refresh failed: {}", .{err});
                    return;
                };
                self.last_kad_refresh_ms = now_ms;
                self.logKadStatus("refresh", result.lookups_started, result.timed_out) catch |err| {
                    log.debug("Kad status logging failed: {}", .{err});
                };
            }
        }
    }

    fn learnKnownSessionPeer(
        self: *Self,
        remote_peer_id_text: []const u8,
        session: *yamux.Session,
        dialed_addr: []const u8,
        peer_addr: net.IpAddress,
    ) !void {
        const observed_ma = try formatIpAsMultiaddr(self.allocator, peer_addr);
        defer self.allocator.free(observed_ma);

        var identify_info = self.host.identifyPeer(self.io, session) catch return;
        defer identify_info.deinit(self.allocator);

        if (identify_info.observed_addr.len > 0) {
            if (self.host.listen_addr) |listen_addr| {
                if (libp2p.address_book.extractListenPort(listen_addr.getStringAddress())) |listen_port| {
                    try self.address_book.observeSelfFromIdentify(
                        identify_info.observed_addr,
                        remote_peer_id_text,
                        listen_port,
                        nowMs(),
                    );
                }
            }
        }

        if (identify_info.listen_addrs.items.len > 0) {
            for (identify_info.listen_addrs.items) |addr| {
                try self.address_book.learnIdentifyAddr(addr, remote_peer_id_text, nowMs());
            }
            try self.upsertRoutingPeer(remote_peer_id_text, identify_info.listen_addrs.items, .connected);
        } else {
            try self.address_book.learnIdentifyAddr(dialed_addr, remote_peer_id_text, nowMs());
            try self.upsertRoutingPeer(remote_peer_id_text, &[_][]const u8{dialed_addr}, .connected);
        }
    }

    fn upsertRoutingPeer(
        self: *Self,
        peer_id_text: []const u8,
        addrs: []const []const u8,
        connection: libp2p.kad_routing.ConnectionType,
    ) !void {
        const result = try self.routing_table.insertOrUpdate(
            peer_id_text,
            addrs,
            .server,
            connection,
            nowMs(),
        );
        switch (result) {
            .pending_eviction => |pending| try self.routing_table.keepIncumbent(pending.bucket_index, pending.incumbent_peer_id),
            else => {},
        }
    }
};

const KadMetrics = struct {
    routing_peers: usize,
    non_empty_buckets: usize,
    book_entries: usize,
    kad_addrs: usize,
    live_sessions: usize,
};

const KadRuntimeSettings = struct {
    refresh_interval_ms: u64 = kad_refresh_interval_default_ms,
    query_timeout_ms: u64 = libp2p.kad_query.query_timeout_default_ms,
};

const kad_refresh_interval_default_ms: u64 = 10 * 60 * 1000;

fn loadKadRuntimeSettings(allocator: std.mem.Allocator) KadRuntimeSettings {
    var settings = KadRuntimeSettings{};
    settings.refresh_interval_ms = loadKadDurationMs(
        allocator,
        "ZEICOIN_KAD_REFRESH_INTERVAL_MS",
        settings.refresh_interval_ms,
    );
    settings.query_timeout_ms = loadKadDurationMs(
        allocator,
        "ZEICOIN_KAD_QUERY_TIMEOUT_MS",
        settings.query_timeout_ms,
    );
    return settings;
}

fn loadKadDurationMs(
    allocator: std.mem.Allocator,
    env_key: []const u8,
    default_value: u64,
) u64 {
    const raw = util.getEnvVarOwned(allocator, env_key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;

    const parsed = std.fmt.parseInt(u64, trimmed, 10) catch {
        log.warn("Ignoring {s}={s}: expected a positive millisecond integer", .{ env_key, trimmed });
        return default_value;
    };
    if (parsed == 0) {
        log.warn("Ignoring {s}=0: refresh and timeout settings must be positive", .{env_key});
        return default_value;
    }
    return parsed;
}

fn nowMs() u64 {
    const seconds = util.getTime();
    if (seconds <= 0) return 0;
    return @as(u64, @intCast(seconds)) * 1000;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format a net.IpAddress as a /ip4/.../tcp/port or /ip6/.../tcp/port multiaddr string.
/// Caller owns the returned slice.
fn formatIpAsMultiaddr(allocator: std.mem.Allocator, addr: net.IpAddress) ![]u8 {
    return switch (addr) {
        .ip4 => |a| std.fmt.allocPrint(allocator, "/ip4/{}.{}.{}.{}/tcp/{}", .{
            a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.port,
        }),
        .ip6 => |a| blk: {
            const unresolved: net.Ip6Address.Unresolved = .{
                .bytes = a.bytes,
                .interface_name = null,
            };
            break :blk try std.fmt.allocPrint(allocator, "/ip6/{f}/tcp/{}", .{ unresolved, a.port });
        },
    };
}

const DnsResolveInfo = struct {
    host: []const u8,
    family: ?net.IpAddress.Family,
};

fn resolveMultiaddrIpAddress(io: std.Io, ma: *const Multiaddr) !net.IpAddress {
    const port_text = try ma.getFirstValueForProtocol(.tcp);
    const port = try std.fmt.parseInt(u16, port_text, 10);
    const dns_info = try getDnsResolveInfo(ma);

    const host_name = try net.HostName.init(dns_info.host);
    var canonical_name_buffer: [net.HostName.max_len]u8 = undefined;
    var lookup_buffer: [16]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) = .init(&lookup_buffer);
    var lookup_future = io.async(net.HostName.lookup, .{ host_name, io, &lookup_queue, .{
        .port = port,
        .canonical_name_buffer = &canonical_name_buffer,
        .family = dns_info.family,
    } });
    defer lookup_future.cancel(io) catch {};

    while (lookup_queue.getOne(io)) |result| switch (result) {
        .canonical_name => continue,
        .address => |ip| return ip,
    } else |err| switch (err) {
        error.Canceled => |e| return e,
        error.Closed => {
            lookup_future.await(io) catch |lookup_err| return lookup_err;
            return error.NoTcpAddress;
        },
    }

    return error.NoTcpAddress;
}

fn getDnsResolveInfo(ma: *const Multiaddr) !DnsResolveInfo {
    if (ma.getFirstValueForProtocol(.dns4)) |value| {
        return .{ .host = value, .family = .ip4 };
    } else |err| switch (err) {
        error.ProtocolNotFound => {},
        else => return err,
    }
    if (ma.getFirstValueForProtocol(.dns6)) |value| {
        return .{ .host = value, .family = .ip6 };
    } else |err| switch (err) {
        error.ProtocolNotFound => {},
        else => return err,
    }
    if (ma.getFirstValueForProtocol(.dns)) |value| {
        return .{ .host = value, .family = null };
    } else |err| switch (err) {
        error.ProtocolNotFound => {},
        else => return err,
    }
    if (ma.getFirstValueForProtocol(.dns_addr)) |value| {
        return .{ .host = value, .family = null };
    } else |err| switch (err) {
        error.ProtocolNotFound => return error.NoTcpAddress,
        else => return err,
    }
}
