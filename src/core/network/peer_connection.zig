// peer_connection.zig - Individual peer connection handling
// Manages the lifecycle of a single peer connection

const std = @import("std");
const net = std.Io.net;
const protocol = @import("protocol/protocol.zig");
const message_types = @import("protocol/messages/message_types.zig");
const message_envelope = @import("protocol/message_envelope.zig");
const peer_manager = @import("peer_manager.zig");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");

const Peer = peer_manager.Peer;

/// Peer connection handler
pub const PeerConnection = struct {
    allocator: std.mem.Allocator,
    peer: *Peer,
    stream: net.Stream,
    message_handler: MessageHandler,
    running: bool,
    current_io: ?std.Io,

    const Self = @This();

    /// Initialize a new peer connection
    pub fn init(
        allocator: std.mem.Allocator,
        peer: *Peer,
        stream: net.Stream,
        handler: MessageHandler,
    ) Self {
        // Increment peer reference count to ensure it stays alive during connection lifetime
        peer.addRef();
        
        return .{
            .allocator = allocator,
            .peer = peer,
            .stream = stream,
            .message_handler = handler,
            .running = false,
            .current_io = null,
        };
    }

    /// Clean up peer connection resources
    pub fn deinit(self: *Self, io: std.Io) void {
        self.running = false;
        self.current_io = null;
        // Clear the callback BEFORE closing the stream
        self.peer.setTcpSendCallback(null, null);
        // Only close if PeerManager hasn't already closed it (timeout wakeup)
        if (self.peer.stream != null) {
            self.stream.close(io);
        }

        // Release peer reference
        self.peer.release();
    }

    /// Compare two block hashes lexicographically
    /// Returns: -1 if hash_a < hash_b, 0 if equal, 1 if hash_a > hash_b
    fn compareHashesLexicographic(hash_a: []const u8, hash_b: []const u8) i8 {
        for (hash_a, hash_b) |byte_a, byte_b| {
            if (byte_a < byte_b) return -1;
            if (byte_a > byte_b) return 1;
        }
        return 0;
    }

    /// Run the peer connection (blocking)
    /// Handles the full connection lifecycle including handshake, message processing, and cleanup
    pub fn run(self: *Self, io: std.Io) !void {
        self.running = true;
        self.current_io = io;
        defer {
            self.running = false;
            self.current_io = null;
        }

        std.log.info("Peer {} connected ({})", .{ self.peer.id, self.peer.address });

        // Set up TCP send callback for this peer
        self.peer.setTcpSendCallback(tcpSendCallback, self);

        // Send handshake
        try self.sendHandshake(io);
        self.peer.state = .handshaking;

        // Blocking read loop — zero CPU while idle.
        // PeerManager.cleanupTimedOut() closes the stream to wake a blocked reader on timeout.
        var buffer: [4096]u8 = undefined;

        while (self.running) {
            if (self.peer.is_shutting_down.load(.acquire)) {
                break;
            }

            // Blocking read — suspends thread until data arrives or stream is closed
            var dest = [1][]u8{&buffer};
            const bytes_read = io.vtable.netRead(io.userdata, self.stream.socket.handle, &dest) catch |err| {
                if (self.running and !self.peer.is_shutting_down.load(.acquire)) {
                    std.log.err("Read error from peer {}: {}", .{ self.peer.id, err });
                }
                break;
            };

            if (bytes_read == 0) {
                // Peer closed connection gracefully
                const peer_id = self.peer.id;
                const is_localhost = switch (self.peer.address) {
                    .ip4 => |ip4| ip4.bytes[0] == 127 and ip4.bytes[1] == 0 and ip4.bytes[2] == 0 and ip4.bytes[3] == 1,
                    .ip6 => |ip6| std.mem.eql(u8, &ip6.bytes, &[_]u8{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}),
                };
                if (!is_localhost) {
                    std.log.info("Peer {} disconnected (connection closed)", .{peer_id});
                } else {
                    std.log.debug("Healthcheck probe disconnected (peer {})", .{peer_id});
                }
                break;
            }

            // Safe shutdown check - avoid accessing peer memory if connection is closing
            if (!self.running) {
                break;
            }

            // Process received data
            const peer_id = self.peer.id; // Cache the ID in case peer becomes invalid
            std.log.debug("Peer {} received {} bytes from network", .{ peer_id, bytes_read });
            self.peer.receiveData(buffer[0..bytes_read]) catch |err| {
                if (err == error.PeerShuttingDown) {
                    std.log.info("Peer {} is shutting down, stopping connection", .{peer_id});
                    break;
                }
                return err;
            };

            // Process messages
            while (try self.peer.readMessage()) |envelope| {
                // Check if connection is still running (safer than accessing peer memory)
                if (!self.running) {
                    std.log.debug("Connection shutting down, stopping message processing", .{});
                    break;
                }

                var env = envelope;
                defer env.deinit();
                const msg_peer_id = self.peer.id; // Cache the ID

                // Log message type with extra detail for get_blocks
                if (env.header.message_type == .get_blocks) {
                    std.log.info("📥 [RECEIVE] Peer {d} received GET_BLOCKS message!", .{msg_peer_id});
                    std.log.info("📥 [RECEIVE] Payload size: {d} bytes", .{env.payload.len});
                } else {
                    std.log.debug("Peer {d} processing message type: {}", .{ msg_peer_id, env.header.message_type });
                }

                try self.handleMessage(io, env);

                if (env.header.message_type == .get_blocks) {
                    std.log.info("📥 [RECEIVE] ✅ GET_BLOCKS message processing completed", .{});
                } else {
                    std.log.debug("Peer {d} completed processing message", .{msg_peer_id});
                }
            }

            // Opportunistic ping after processing — keeps ping logic in the same
            // thread as pong handling to avoid races on ping_nonce / last_ping.
            if (self.peer.needsPing()) {
                self.sendPing() catch {};
            }
        }

        self.peer.state = .disconnected;
    }

    /// Send handshake message
    fn sendHandshake(self: *Self, io: std.Io) !void {
        const user_agent = "ZeiCoin/1.0.0";
        var handshake = try message_types.HandshakeMessage.init(self.allocator, user_agent);
        defer handshake.deinit(self.allocator);

        handshake.listen_port = protocol.DEFAULT_PORT;
        handshake.start_height = try self.message_handler.getHeight(io);
        handshake.best_block_hash = try self.message_handler.getBestBlockHash(io);
        handshake.genesis_hash = try self.message_handler.getGenesisHash(io);
        handshake.current_difficulty = try self.message_handler.getCurrentDifficulty(io);

        const peer_id = self.peer.id; // Cache the ID
        std.log.info("Sending handshake to peer {} with height {} and best block hash {x}", .{ peer_id, handshake.start_height, handshake.best_block_hash });
        std.log.info("   ⛓️  Genesis hash: {x}", .{&handshake.genesis_hash});
        std.log.info("   📊 Current difficulty: {} (0x{X})", .{ handshake.current_difficulty, @as(u32, @intCast(handshake.current_difficulty & 0xFFFFFFFF)) });
        _ = try self.peer.sendMessage(.handshake, handshake);
        std.log.info("Handshake sent to peer {}", .{peer_id});
    }

    /// Send ping message
    fn sendPing(self: *Self) !void {
        const ping = message_types.PingMessage.init();
        self.peer.ping_nonce = ping.nonce;
        self.peer.last_ping = util.getTime();

        _ = try self.peer.sendMessage(.ping, ping);
    }

    /// Handle incoming message
    /// Decodes and dispatches messages to appropriate handlers
    fn handleMessage(self: *Self, io: std.Io, envelope: message_envelope.MessageEnvelope) !void {
        const msg_type = envelope.header.message_type;

        std.log.debug("Received {} from peer {}", .{ msg_type, self.peer.id });

        // Decode message
        var reader = std.Io.Reader.fixed(envelope.payload);
        var msg = try message_types.Message.decode(msg_type, self.allocator, &reader);
        defer msg.deinit(self.allocator);

        switch (msg) {
            .handshake => |handshake| try self.handleHandshake(io, handshake),
            .handshake_ack => |ack_msg| try self.handleHandshakeAck(io, ack_msg),
            .ping => |ping| try self.handlePing(ping),
            .pong => |pong| try self.handlePong(pong),
            .block => |block| try self.handleBlock(io, block),
            .transaction => |transaction| try self.handleTransaction(io, transaction),
            .get_blocks => |get_blocks| try self.handleGetBlocks(io, get_blocks),
            .blocks => |blocks| try self.handleBlocks(blocks),
            .get_peers => |get_peers| try self.handleGetPeers(io, get_peers),
            .peers => |peers| try self.handlePeers(io, peers),
            .get_block_hash => |get_block_hash| try self.handleGetBlockHash(io, get_block_hash),
            .block_hash => |block_hash| try self.handleBlockHash(io, block_hash),
            .get_mempool => |get_mempool| try self.handleGetMempool(io, get_mempool),
            .mempool_inv => |mempool_inv| try self.handleMempoolInv(io, mempool_inv),
            .get_missing_blocks => |get_missing_blocks| try self.handleGetMissingBlocks(io, get_missing_blocks),
            .missing_blocks_response => |missing_blocks_response| try self.handleMissingBlocksResponse(io, missing_blocks_response),
            .get_chain_work => |get_chain_work| try self.handleGetChainWork(io, get_chain_work),
            .chain_work_response => |chain_work_response| try self.handleChainWorkResponse(io, chain_work_response),
        }
    }

    fn handleHandshake(self: *Self, io: std.Io, handshake: message_types.HandshakeMessage) !void {
        const our_height = try self.message_handler.getHeight(io);
        const our_best_hash = try self.message_handler.getBestBlockHash(io);
        const our_genesis_hash = try self.message_handler.getGenesisHash(io);
        const peer_id = self.peer.id; // Cache the ID
        std.log.info("🤝 [HANDSHAKE] Received from peer {} - their height: {}, our height: {}", .{ peer_id, handshake.start_height, our_height });
        std.log.info("📊 [HANDSHAKE] Block hashes - theirs: {x}, ours: {x}", .{
            handshake.best_block_hash,
            our_best_hash,
        });

        // Check genesis compatibility first - reject incompatible chains immediately
        handshake.checkGenesisCompatibility(our_genesis_hash) catch |err| {
            std.log.err("🚫 [CHAIN INCOMPATIBLE] Disconnecting peer {} - different genesis block", .{peer_id});
            std.log.err("   💡 This peer is on a completely different blockchain", .{});
            std.log.err("   💡 Check you're connecting to the right network", .{});
            return err;
        };

        // ENHANCED: Comprehensive compatibility checking including difficulty consensus
        const our_difficulty = try self.message_handler.getCurrentDifficulty(io);
        handshake.checkPeerCompatibility(our_height, our_difficulty) catch |err| {
            switch (err) {
                error.IncompatibleProtocolVersion => {
                    std.log.warn("❌ [PROTOCOL ERROR] Peer {} has incompatible protocol version {}", .{ peer_id, handshake.version });
                    std.log.warn("   💡 Peer needs to upgrade to protocol version {}", .{@import("protocol/protocol.zig").PROTOCOL_VERSION});
                    return err;
                },
                error.WrongNetwork => {
                    std.log.warn("❌ [NETWORK ERROR] Peer {} is on wrong network (ID: {})", .{ peer_id, handshake.network_id });
                    std.log.warn("   💡 This peer is on a different network (TestNet vs MainNet)", .{});
                    return err;
                },
                else => {
                    std.log.warn("❌ [HANDSHAKE ERROR] Peer {} failed compatibility check: {}", .{ peer_id, err });
                    return err;
                },
            }
        };

        // Update peer info
        std.log.info("🔧 [HANDSHAKE] Updating peer {d} info:", .{peer_id});
        std.log.info("   📊 Setting height: {d} -> {d}", .{self.peer.height, handshake.start_height});
        std.log.info("   🔧 Setting version: {d}", .{handshake.version});
        std.log.info("   🔧 Setting services: 0x{x}", .{handshake.services});
        self.peer.version = handshake.version;
        self.peer.services = handshake.services;
        self.peer.height = handshake.start_height;
        self.peer.best_block_hash = handshake.best_block_hash;
        std.log.info("   ✅ Peer {d} height now set to: {d}", .{peer_id, self.peer.height});

        // Free old user_agent if exists
        if (self.peer.user_agent.len > 0) {
            self.allocator.free(self.peer.user_agent);
            self.peer.user_agent = &[_]u8{}; // Reset to prevent double-free
        }

        // Allocate new user_agent with proper cleanup on error
        self.peer.user_agent = try self.allocator.dupe(u8, handshake.user_agent);
        errdefer {
            self.allocator.free(self.peer.user_agent);
            self.peer.user_agent = &[_]u8{};
        }

        // Send handshake ack with our current height
        const cached_peer_id = self.peer.id; // Cache the ID
        std.log.info("📤 [HANDSHAKE] Sending ack to peer {} (we are at height {})", .{ cached_peer_id, our_height });
        const ack_msg = message_types.HandshakeAckMessage.init(our_height);
        _ = try self.peer.sendMessage(.handshake_ack, ack_msg);

        self.peer.state = .connected;
        std.log.info("✅ [HANDSHAKE] Complete with Peer {}: peer_height={}, our_height={}, agent={s}", .{ self.peer.id, handshake.start_height, our_height, handshake.user_agent });

        // Check for chain divergence
        if (handshake.start_height == our_height and !std.mem.eql(u8, &handshake.best_block_hash, &our_best_hash)) {
            std.log.warn("⚠️ [CHAIN DIVERGENCE] Detected at height {} - peer hash: {x}, our hash: {x}", .{
                our_height,
                handshake.best_block_hash,
                our_best_hash,
            });
        }

        // Call handler - THIS is where sync should be triggered
        std.log.info("🔄 [HANDSHAKE] Calling onPeerConnected to check sync requirements", .{});
        std.log.info("🔄 [HANDSHAKE] Peer height before onPeerConnected: {d}", .{self.peer.height});
        std.log.info("🔄 [HANDSHAKE] Peer hash before onPeerConnected: {x}", .{&self.peer.best_block_hash});
        try self.message_handler.onPeerConnected(io, self.peer);
        std.log.info("🔄 [HANDSHAKE] onPeerConnected completed", .{});
    }

    fn handleHandshakeAck(self: *Self, io: std.Io, ack_msg: message_types.HandshakeAckMessage) !void {
        if (self.peer.state == .handshaking) {
            const our_height = try self.message_handler.getHeight(io);

            // CRITICAL FIX: Update peer height with the height from handshake_ack
            const peer_id = self.peer.id; // Cache the ID
            std.log.info("🔧 [HANDSHAKE ACK] Updating peer {} height from {} to {}", .{ peer_id, self.peer.height, ack_msg.current_height });
            self.peer.height = ack_msg.current_height;

            std.log.info("✅ [HANDSHAKE ACK] Received - peer height: {}, our height: {}", .{ self.peer.height, our_height });

            self.peer.state = .connected;

            // CRITICAL: The initiating side (sync node) needs to check sync here too!
            std.log.info("🔄 [HANDSHAKE ACK] Connection established, checking if we need to sync", .{});
            try self.message_handler.onPeerConnected(io, self.peer);
        }
    }

    fn handlePing(self: *Self, ping: message_types.PingMessage) !void {
        const pong = message_types.PongMessage.init(ping.nonce);
        _ = try self.peer.sendMessage(.pong, pong);
    }

    fn handlePong(self: *Self, pong: message_types.PongMessage) !void {
        if (self.peer.ping_nonce) |nonce| {
            if (pong.nonce == nonce) {
                const latency = util.getTime() - self.peer.last_ping;
                std.log.debug("Peer {} latency: {}ms", .{ self.peer.id, latency * 1000 });
                self.peer.ping_nonce = null;
            }
        }
    }

    fn handleBlock(self: *Self, io: std.Io, block: message_types.BlockMessage) !void {
        try self.message_handler.onBlock(io, self.peer, block);
    }

    fn handleTransaction(self: *Self, io: std.Io, transaction: message_types.TransactionMessage) !void {
        try self.message_handler.onTransaction(io, self.peer, transaction);
    }

    fn handleGetBlocks(self: *Self, io: std.Io, get_blocks: message_types.GetBlocksMessage) !void {
        std.log.info("🔀 [DISPATCH GET_BLOCKS] Peer {d} dispatching to onGetBlocks handler", .{self.peer.id});
        std.log.info("🔀 [DISPATCH GET_BLOCKS] Message has {d} hashes", .{get_blocks.hashes.len});
        try self.message_handler.onGetBlocks(io, self.peer, get_blocks);
        std.log.info("🔀 [DISPATCH GET_BLOCKS] ✅ Handler completed successfully", .{});
    }

    fn handleBlocks(self: *Self, blocks: void) !void {
        _ = blocks; // blocks message type has no payload (void)
                        std.log.debug("Received blocks message from peer {}", .{self.peer.id});    }

    fn handleGetPeers(self: *Self, io: std.Io, get_peers: message_types.GetPeersMessage) !void {
        try self.message_handler.onGetPeers(io, self.peer, get_peers);
    }

    fn handlePeers(self: *Self, io: std.Io, peers: message_types.PeersMessage) !void {
        try self.message_handler.onPeers(io, self.peer, peers);
    }

    fn handleGetBlockHash(self: *Self, io: std.Io, msg: message_types.GetBlockHashMessage) !void {
        try self.message_handler.onGetBlockHash(io, self.peer, msg);
    }

    fn handleBlockHash(self: *Self, io: std.Io, msg: message_types.BlockHashMessage) !void {
        try self.message_handler.onBlockHash(io, self.peer, msg);
    }

    fn handleGetMempool(self: *Self, io: std.Io, msg: message_types.GetMempoolMessage) !void {
        _ = msg; // No payload to use
        try self.message_handler.onGetMempool(io, self.peer);
    }

    fn handleMempoolInv(self: *Self, io: std.Io, msg: message_types.MempoolInvMessage) !void {
        try self.message_handler.onMempoolInv(io, self.peer, msg);
    }

    fn handleGetMissingBlocks(self: *Self, io: std.Io, msg: message_types.GetMissingBlocksMessage) !void {
        try self.message_handler.onGetMissingBlocks(io, self.peer, msg);
    }

    fn handleMissingBlocksResponse(self: *Self, io: std.Io, msg: message_types.MissingBlocksResponseMessage) !void {
        try self.message_handler.onMissingBlocksResponse(io, self.peer, msg);
    }

    fn handleGetChainWork(self: *Self, io: std.Io, msg: message_types.GetChainWorkMessage) !void {
        try self.message_handler.onGetChainWork(io, self.peer, msg);
    }

    fn handleChainWorkResponse(self: *Self, io: std.Io, msg: message_types.ChainWorkResponseMessage) !void {
        try self.message_handler.onChainWorkResponse(io, self.peer, msg);
    }
};

/// Message handler interface
/// Defines callbacks for handling various network messages
pub const MessageHandler = struct {
    /// Get current blockchain height
    getHeight: *const fn (io: std.Io) anyerror!u32,

    /// Get best block hash
    getBestBlockHash: *const fn (io: std.Io) anyerror![32]u8,

    /// Get genesis block hash
    getGenesisHash: *const fn (io: std.Io) anyerror![32]u8,

    /// Get current difficulty target
    getCurrentDifficulty: *const fn (io: std.Io) anyerror!u64,

    /// Called when peer connects
    onPeerConnected: *const fn (io: std.Io, peer: *Peer) anyerror!void,

    /// Handle block data
    onBlock: *const fn (io: std.Io, peer: *Peer, msg: message_types.BlockMessage) anyerror!void,

    /// Handle transaction data
    onTransaction: *const fn (io: std.Io, peer: *Peer, msg: message_types.TransactionMessage) anyerror!void,

    /// Handle get blocks request
    onGetBlocks: *const fn (io: std.Io, peer: *Peer, msg: message_types.GetBlocksMessage) anyerror!void,

    /// Handle get peers request
    onGetPeers: *const fn (io: std.Io, peer: *Peer, msg: message_types.GetPeersMessage) anyerror!void,

    /// Handle peers message
    onPeers: *const fn (io: std.Io, peer: *Peer, msg: message_types.PeersMessage) anyerror!void,

    /// Handle get block hash request (consensus verification)
    onGetBlockHash: *const fn (io: std.Io, peer: *Peer, msg: message_types.GetBlockHashMessage) anyerror!void,

    /// Handle block hash response (consensus verification)
    onBlockHash: *const fn (io: std.Io, peer: *Peer, msg: message_types.BlockHashMessage) anyerror!void,

    /// Handle get mempool request
    onGetMempool: *const fn (io: std.Io, peer: *Peer) anyerror!void,

    /// Handle mempool inventory message
    onMempoolInv: *const fn (io: std.Io, peer: *Peer, msg: message_types.MempoolInvMessage) anyerror!void,

    /// Handle get missing blocks request (Fix 3: Orphan block resolution)
    onGetMissingBlocks: *const fn (io: std.Io, peer: *Peer, msg: message_types.GetMissingBlocksMessage) anyerror!void,

    /// Handle missing blocks response (Fix 3: Orphan block resolution)
    onMissingBlocksResponse: *const fn (io: std.Io, peer: *Peer, msg: message_types.MissingBlocksResponseMessage) anyerror!void,

    /// Handle get chain work request (for reorganization decisions)
    onGetChainWork: *const fn (io: std.Io, peer: *Peer, msg: message_types.GetChainWorkMessage) anyerror!void,

    /// Handle chain work response (for reorganization decisions)
    onChainWorkResponse: *const fn (io: std.Io, peer: *Peer, msg: message_types.ChainWorkResponseMessage) anyerror!void,

    /// Handle peer disconnect (optional)
    onPeerDisconnected: ?*const fn (peer: *Peer, err: anyerror) anyerror!void = null,
};

/// TCP send callback function
/// Handles actual TCP data transmission for peer connections
fn tcpSendCallback(ctx: ?*anyopaque, data: []const u8) anyerror!void {
    const self = @as(*PeerConnection, @ptrCast(@alignCast(ctx.?)));
    // Check if connection is still running (safer than accessing peer memory)
    if (!self.running or self.current_io == null) {
        return error.PeerShuttingDown;
    }
    const peer_id = self.peer.id; // Cache the ID
    std.log.debug("Peer {} writing {} bytes to TCP stream", .{ peer_id, data.len });
    const io = self.current_io.?;
    var writer = self.stream.writer(io, &[_]u8{});
    try writer.interface.writeAll(data);
}
