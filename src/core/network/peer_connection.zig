// peer_connection.zig - Individual peer connection handling
// Manages the lifecycle of a single peer connection

const std = @import("std");
const net = std.net;
const protocol = @import("protocol/protocol.zig");
const message_types = @import("protocol/messages/message_types.zig");
const message_envelope = @import("protocol/message_envelope.zig");
const peer_manager = @import("peer_manager.zig");
const types = @import("../types/types.zig");

const Peer = peer_manager.Peer;

/// Peer connection handler
pub const PeerConnection = struct {
    allocator: std.mem.Allocator,
    peer: *Peer,
    stream: net.Stream,
    message_handler: MessageHandler,
    running: bool,

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
        };
    }

    /// Clean up peer connection resources
    pub fn deinit(self: *Self) void {
        self.running = false;
        // Clear the callback BEFORE closing the stream
        self.peer.setTcpSendCallback(null, null);
        self.stream.close();
        
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
    pub fn run(self: *Self) !void {
        self.running = true;
        defer self.running = false;

        std.log.info("Peer {} connected", .{self.peer});

        // Set up TCP send callback for this peer
        self.peer.setTcpSendCallback(tcpSendCallback, self);

        // Send handshake
        try self.sendHandshake();
        self.peer.state = .handshaking;

        // Connection loop
        var buffer = try self.allocator.alloc(u8, 4096);
        defer self.allocator.free(buffer);

        while (self.running) {
            // Main connection loop - running flag provides safer shutdown signaling

            // Read data with timeout
            const bytes_read = self.stream.read(buffer) catch |err| switch (err) {
                error.WouldBlock => {
                    // Check for timeout
                    if (self.peer.isTimedOut()) {
                        std.log.warn("Peer {} timed out", .{self.peer});
                        break;
                    }

                    // Check if ping needed
                    if (self.peer.needsPing()) {
                        try self.sendPing();
                    }

                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                else => return err,
            };

            if (bytes_read == 0) {
                // Safe peer disconnection logging - cache ID first to avoid use-after-free
                const peer_id = self.peer.id;
                std.log.info("Peer {} disconnected (connection closed)", .{peer_id});
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

                try self.handleMessage(env);

                if (env.header.message_type == .get_blocks) {
                    std.log.info("📥 [RECEIVE] ✅ GET_BLOCKS message processing completed", .{});
                } else {
                    std.log.debug("Peer {d} completed processing message", .{msg_peer_id});
                }
            }
        }

        self.peer.state = .disconnected;
    }

    /// Send handshake message
    fn sendHandshake(self: *Self) !void {
        const user_agent = "ZeiCoin/1.0.0";
        var handshake = try message_types.HandshakeMessage.init(self.allocator, user_agent);
        defer handshake.deinit(self.allocator);

        handshake.listen_port = protocol.DEFAULT_PORT;
        handshake.start_height = try self.message_handler.getHeight();
        handshake.best_block_hash = try self.message_handler.getBestBlockHash();
        handshake.genesis_hash = try self.message_handler.getGenesisHash();
        handshake.current_difficulty = try self.message_handler.getCurrentDifficulty();

        const peer_id = self.peer.id; // Cache the ID
        std.log.info("Sending handshake to peer {} with height {} and best block hash {s}", .{ peer_id, handshake.start_height, std.fmt.fmtSliceHexLower(&handshake.best_block_hash) });
        std.log.info("   ⛓️  Genesis hash: {s}", .{std.fmt.fmtSliceHexLower(&handshake.genesis_hash)});
        std.log.info("   📊 Current difficulty: {} (0x{X})", .{ handshake.current_difficulty, @as(u32, @intCast(handshake.current_difficulty & 0xFFFFFFFF)) });
        _ = try self.peer.sendMessage(.handshake, handshake);
        std.log.info("Handshake sent to peer {}", .{peer_id});
    }

    /// Send ping message
    fn sendPing(self: *Self) !void {
        const ping = message_types.PingMessage.init();
        self.peer.ping_nonce = ping.nonce;
        self.peer.last_ping = std.time.timestamp();

        _ = try self.peer.sendMessage(.ping, ping);
    }

    /// Handle incoming message
    /// Decodes and dispatches messages to appropriate handlers
    fn handleMessage(self: *Self, envelope: message_envelope.MessageEnvelope) !void {
        const msg_type = envelope.header.message_type;

        std.log.debug("Received {} from {}", .{ msg_type, self.peer });

        // Decode message
        var stream = std.io.fixedBufferStream(envelope.payload);
        var msg = try message_types.Message.decode(msg_type, self.allocator, stream.reader());
        defer msg.deinit(self.allocator);

        switch (msg) {
            .handshake => |handshake| try self.handleHandshake(handshake),
            .handshake_ack => |ack_msg| try self.handleHandshakeAck(ack_msg),
            .ping => |ping| try self.handlePing(ping),
            .pong => |pong| try self.handlePong(pong),
            .block => |block| try self.handleBlock(block),
            .transaction => |transaction| try self.handleTransaction(transaction),
            .get_blocks => |get_blocks| try self.handleGetBlocks(get_blocks),
            .blocks => |blocks| try self.handleBlocks(blocks),
            .get_peers => |get_peers| try self.handleGetPeers(get_peers),
            .peers => |peers| try self.handlePeers(peers),
            .get_block_hash => |get_block_hash| try self.handleGetBlockHash(get_block_hash),
            .block_hash => |block_hash| try self.handleBlockHash(block_hash),
            .get_mempool => |get_mempool| try self.handleGetMempool(get_mempool),
            .mempool_inv => |mempool_inv| try self.handleMempoolInv(mempool_inv),
            .get_missing_blocks => |get_missing_blocks| try self.handleGetMissingBlocks(get_missing_blocks),
            .missing_blocks_response => |missing_blocks_response| try self.handleMissingBlocksResponse(missing_blocks_response),
            .get_chain_work => |get_chain_work| try self.handleGetChainWork(get_chain_work),
            .chain_work_response => |chain_work_response| try self.handleChainWorkResponse(chain_work_response),
        }
    }

    fn handleHandshake(self: *Self, handshake: message_types.HandshakeMessage) !void {
        const our_height = try self.message_handler.getHeight();
        const our_best_hash = try self.message_handler.getBestBlockHash();
        const our_genesis_hash = try self.message_handler.getGenesisHash();
        const peer_id = self.peer.id; // Cache the ID
        std.log.info("🤝 [HANDSHAKE] Received from peer {} - their height: {}, our height: {}", .{ peer_id, handshake.start_height, our_height });
        std.log.info("📊 [HANDSHAKE] Block hashes - theirs: {s}, ours: {s}", .{
            std.fmt.fmtSliceHexLower(&handshake.best_block_hash),
            std.fmt.fmtSliceHexLower(&our_best_hash),
        });

        // Check genesis compatibility first - reject incompatible chains immediately
        handshake.checkGenesisCompatibility(our_genesis_hash) catch |err| {
            std.log.err("🚫 [CHAIN INCOMPATIBLE] Disconnecting peer {} - different genesis block", .{peer_id});
            std.log.err("   💡 This peer is on a completely different blockchain", .{});
            std.log.err("   💡 Check you're connecting to the right network", .{});
            return err;
        };

        // ENHANCED: Comprehensive compatibility checking including difficulty consensus
        const our_difficulty = try self.message_handler.getCurrentDifficulty();
        handshake.checkPeerCompatibility(our_height, our_difficulty) catch |err| {
            switch (err) {
                error.DifficultyConsensusMismatch => {
                    // FORK RESOLUTION: Check if this is an equal-height fork scenario
                    if (handshake.start_height == our_height and
                        !std.mem.eql(u8, &handshake.best_block_hash, &our_best_hash))
                    {
                        std.log.warn("⚠️ [FORK DETECTED] Equal-height fork with peer {} at height {}", .{ peer_id, our_height });
                        std.log.warn("   🔀 Our block hash: {s}", .{std.fmt.fmtSliceHexLower(&our_best_hash)});
                        std.log.warn("   🔀 Peer block hash: {s}", .{std.fmt.fmtSliceHexLower(&handshake.best_block_hash)});

                        // ETHEREUM-STYLE TIE-BREAKER: Compare hashes lexicographically
                        const hash_comparison = compareHashesLexicographic(&handshake.best_block_hash, &our_best_hash);
                        if (hash_comparison > 0) {
                            std.log.warn("   🏆 [TIE-BREAKER] Peer's chain wins (higher hash)", .{});
                            std.log.warn("   🔄 [TIE-BREAKER] We should reorganize to peer's chain", .{});
                        } else if (hash_comparison < 0) {
                            std.log.warn("   🏆 [TIE-BREAKER] Our chain wins (higher hash)", .{});
                            std.log.warn("   💡 [TIE-BREAKER] Peer should reorganize to our chain", .{});
                        } else {
                            std.log.warn("   ⚠️ [TIE-BREAKER] Identical hashes (should never happen!)", .{});
                        }

                        std.log.info("   💡 FORK RESOLUTION: Allowing connection - tie-breaker determined winner", .{});

                        // Allow connection - fork will be resolved via tie-breaker
                        // Don't disconnect! Connection needed for reorganization
                    } else {
                        std.log.warn("❌ [CONSENSUS ERROR] Disconnecting peer {} due to difficulty mismatch", .{peer_id});
                        std.log.warn("   💡 This indicates the peer is using different consensus rules", .{});
                        std.log.warn("   💡 Both nodes may need to reset to a common genesis state", .{});
                        return err;
                    }
                },
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
        if (self.peer.user_agent.len > 0) {
            self.allocator.free(self.peer.user_agent);
        }
        self.peer.user_agent = try self.allocator.dupe(u8, handshake.user_agent);

        // Send handshake ack with our current height
        const cached_peer_id = self.peer.id; // Cache the ID
        std.log.info("📤 [HANDSHAKE] Sending ack to peer {} (we are at height {})", .{ cached_peer_id, our_height });
        const ack_msg = message_types.HandshakeAckMessage.init(our_height);
        _ = try self.peer.sendMessage(.handshake_ack, ack_msg);

        self.peer.state = .connected;
        std.log.info("✅ [HANDSHAKE] Complete with {}: peer_height={}, our_height={}, agent={s}", .{ self.peer, handshake.start_height, our_height, handshake.user_agent });

        // Check for chain divergence
        if (handshake.start_height == our_height and !std.mem.eql(u8, &handshake.best_block_hash, &our_best_hash)) {
            std.log.warn("⚠️ [CHAIN DIVERGENCE] Detected at height {} - peer hash: {s}, our hash: {s}", .{
                our_height,
                std.fmt.fmtSliceHexLower(&handshake.best_block_hash),
                std.fmt.fmtSliceHexLower(&our_best_hash),
            });
        }

        // Call handler - THIS is where sync should be triggered
        std.log.info("🔄 [HANDSHAKE] Calling onPeerConnected to check sync requirements", .{});
        std.log.info("🔄 [HANDSHAKE] Peer height before onPeerConnected: {d}", .{self.peer.height});
        std.log.info("🔄 [HANDSHAKE] Peer hash before onPeerConnected: {s}", .{std.fmt.fmtSliceHexLower(&self.peer.best_block_hash)});
        try self.message_handler.onPeerConnected(self.peer);
        std.log.info("🔄 [HANDSHAKE] onPeerConnected completed", .{});
    }

    fn handleHandshakeAck(self: *Self, ack_msg: message_types.HandshakeAckMessage) !void {
        if (self.peer.state == .handshaking) {
            const our_height = try self.message_handler.getHeight();

            // CRITICAL FIX: Update peer height with the height from handshake_ack
            const peer_id = self.peer.id; // Cache the ID
            std.log.info("🔧 [HANDSHAKE ACK] Updating peer {} height from {} to {}", .{ peer_id, self.peer.height, ack_msg.current_height });
            self.peer.height = ack_msg.current_height;

            std.log.info("✅ [HANDSHAKE ACK] Received - peer height: {}, our height: {}", .{ self.peer.height, our_height });

            self.peer.state = .connected;

            // CRITICAL: The initiating side (sync node) needs to check sync here too!
            std.log.info("🔄 [HANDSHAKE ACK] Connection established, checking if we need to sync", .{});
            try self.message_handler.onPeerConnected(self.peer);
        }
    }

    fn handlePing(self: *Self, ping: message_types.PingMessage) !void {
        const pong = message_types.PongMessage.init(ping.nonce);
        _ = try self.peer.sendMessage(.pong, pong);
    }

    fn handlePong(self: *Self, pong: message_types.PongMessage) !void {
        if (self.peer.ping_nonce) |nonce| {
            if (pong.nonce == nonce) {
                const latency = std.time.timestamp() - self.peer.last_ping;
                std.log.debug("Peer {} latency: {}ms", .{ self.peer, latency * 1000 });
                self.peer.ping_nonce = null;
            }
        }
    }

    fn handleBlock(self: *Self, block: message_types.BlockMessage) !void {
        try self.message_handler.onBlock(self.peer, block);
    }

    fn handleTransaction(self: *Self, transaction: message_types.TransactionMessage) !void {
        try self.message_handler.onTransaction(self.peer, transaction);
    }

    fn handleGetBlocks(self: *Self, get_blocks: message_types.GetBlocksMessage) !void {
        std.log.info("🔀 [DISPATCH GET_BLOCKS] Peer {d} dispatching to onGetBlocks handler", .{self.peer.id});
        std.log.info("🔀 [DISPATCH GET_BLOCKS] Message has {d} hashes", .{get_blocks.hashes.len});
        try self.message_handler.onGetBlocks(self.peer, get_blocks);
        std.log.info("🔀 [DISPATCH GET_BLOCKS] ✅ Handler completed successfully", .{});
    }

    fn handleBlocks(self: *Self, blocks: void) !void {
        _ = blocks; // blocks message type has no payload (void)
        std.log.debug("Received blocks message from {}", .{self.peer});
    }

    fn handleGetPeers(self: *Self, get_peers: message_types.GetPeersMessage) !void {
        try self.message_handler.onGetPeers(self.peer, get_peers);
    }

    fn handlePeers(self: *Self, peers: message_types.PeersMessage) !void {
        try self.message_handler.onPeers(self.peer, peers);
    }

    fn handleGetBlockHash(self: *Self, msg: message_types.GetBlockHashMessage) !void {
        try self.message_handler.onGetBlockHash(self.peer, msg);
    }

    fn handleBlockHash(self: *Self, msg: message_types.BlockHashMessage) !void {
        try self.message_handler.onBlockHash(self.peer, msg);
    }

    fn handleGetMempool(self: *Self, msg: message_types.GetMempoolMessage) !void {
        _ = msg; // No payload to use
        try self.message_handler.onGetMempool(self.peer);
    }

    fn handleMempoolInv(self: *Self, msg: message_types.MempoolInvMessage) !void {
        try self.message_handler.onMempoolInv(self.peer, msg);
    }

    fn handleGetMissingBlocks(self: *Self, msg: message_types.GetMissingBlocksMessage) !void {
        try self.message_handler.onGetMissingBlocks(self.peer, msg);
    }

    fn handleMissingBlocksResponse(self: *Self, msg: message_types.MissingBlocksResponseMessage) !void {
        try self.message_handler.onMissingBlocksResponse(self.peer, msg);
    }

    fn handleGetChainWork(self: *Self, msg: message_types.GetChainWorkMessage) !void {
        try self.message_handler.onGetChainWork(self.peer, msg);
    }

    fn handleChainWorkResponse(self: *Self, msg: message_types.ChainWorkResponseMessage) !void {
        try self.message_handler.onChainWorkResponse(self.peer, msg);
    }
};

/// Message handler interface
/// Defines callbacks for handling various network messages
pub const MessageHandler = struct {
    /// Get current blockchain height
    getHeight: *const fn () anyerror!u32,

    /// Get best block hash
    getBestBlockHash: *const fn () anyerror![32]u8,

    /// Get genesis block hash
    getGenesisHash: *const fn () anyerror![32]u8,

    /// Get current difficulty target
    getCurrentDifficulty: *const fn () anyerror!u64,

    /// Called when peer connects
    onPeerConnected: *const fn (peer: *Peer) anyerror!void,

    /// Handle block data
    onBlock: *const fn (peer: *Peer, msg: message_types.BlockMessage) anyerror!void,

    /// Handle transaction data
    onTransaction: *const fn (peer: *Peer, msg: message_types.TransactionMessage) anyerror!void,

    /// Handle get blocks request
    onGetBlocks: *const fn (peer: *Peer, msg: message_types.GetBlocksMessage) anyerror!void,

    /// Handle get peers request
    onGetPeers: *const fn (peer: *Peer, msg: message_types.GetPeersMessage) anyerror!void,

    /// Handle peers message
    onPeers: *const fn (peer: *Peer, msg: message_types.PeersMessage) anyerror!void,

    /// Handle get block hash request (consensus verification)
    onGetBlockHash: *const fn (peer: *Peer, msg: message_types.GetBlockHashMessage) anyerror!void,

    /// Handle block hash response (consensus verification)
    onBlockHash: *const fn (peer: *Peer, msg: message_types.BlockHashMessage) anyerror!void,

    /// Handle get mempool request
    onGetMempool: *const fn (peer: *Peer) anyerror!void,

    /// Handle mempool inventory message
    onMempoolInv: *const fn (peer: *Peer, msg: message_types.MempoolInvMessage) anyerror!void,

    /// Handle get missing blocks request (Fix 3: Orphan block resolution)
    onGetMissingBlocks: *const fn (peer: *Peer, msg: message_types.GetMissingBlocksMessage) anyerror!void,

    /// Handle missing blocks response (Fix 3: Orphan block resolution)
    onMissingBlocksResponse: *const fn (peer: *Peer, msg: message_types.MissingBlocksResponseMessage) anyerror!void,

    /// Handle get chain work request (for reorganization decisions)
    onGetChainWork: *const fn (peer: *Peer, msg: message_types.GetChainWorkMessage) anyerror!void,

    /// Handle chain work response (for reorganization decisions)
    onChainWorkResponse: *const fn (peer: *Peer, msg: message_types.ChainWorkResponseMessage) anyerror!void,

    /// Handle peer disconnect (optional)
    onPeerDisconnected: ?*const fn (peer: *Peer, err: anyerror) anyerror!void = null,
};

/// TCP send callback function
/// Handles actual TCP data transmission for peer connections
fn tcpSendCallback(ctx: ?*anyopaque, data: []const u8) anyerror!void {
    const self = @as(*PeerConnection, @ptrCast(@alignCast(ctx.?)));
    // Check if connection is still running (safer than accessing peer memory)
    if (!self.running) {
        return error.PeerShuttingDown;
    }
    const peer_id = self.peer.id; // Cache the ID
    std.log.debug("Peer {} writing {} bytes to TCP stream", .{ peer_id, data.len });
    try self.stream.writeAll(data);
    std.log.debug("Peer {} TCP write completed", .{peer_id});
}
