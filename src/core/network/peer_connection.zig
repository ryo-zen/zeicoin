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
    
    pub fn init(
        allocator: std.mem.Allocator,
        peer: *Peer,
        stream: net.Stream,
        handler: MessageHandler,
    ) Self {
        return .{
            .allocator = allocator,
            .peer = peer,
            .stream = stream,
            .message_handler = handler,
            .running = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.running = false;
        self.stream.close();
    }
    
    /// Run the peer connection (blocking)
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
                std.log.info("Peer {} disconnected", .{self.peer});
                break;
            }
            
            // Process received data
            std.debug.print("🌐 [TCP RECV] Peer {} received {} bytes from network\n", .{self.peer.id, bytes_read});
            try self.peer.receiveData(buffer[0..bytes_read]);
            
            // Process messages
            while (try self.peer.readMessage()) |envelope| {
                var env = envelope;
                defer env.deinit();
                std.debug.print("🎯 [MESSAGE HANDLE] Peer {} processing message type: {}\n", .{self.peer.id, env.header.message_type});
                try self.handleMessage(env);
                std.debug.print("✅ [MESSAGE HANDLE] Peer {} completed processing message\n", .{self.peer.id});
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
        
        std.log.info("Sending handshake to peer {} with height {}", .{ self.peer.id, handshake.start_height });
        _ = try self.peer.sendMessage(.handshake, handshake);
        std.log.info("Handshake sent to peer {}", .{self.peer.id});
    }
    
    /// Send ping message
    fn sendPing(self: *Self) !void {
        const ping = message_types.PingMessage.init();
        self.peer.ping_nonce = ping.nonce;
        self.peer.last_ping = std.time.timestamp();
        
        _ = try self.peer.sendMessage(.ping, ping);
    }
    
    /// Handle incoming message
    fn handleMessage(self: *Self, envelope: message_envelope.MessageEnvelope) !void {
        const msg_type = envelope.header.message_type;
        
        std.log.debug("Received {} from {}", .{ msg_type, self.peer });
        
        // Decode message
        var stream = std.io.fixedBufferStream(envelope.payload);
        var msg = try message_types.Message.decode(msg_type, self.allocator, stream.reader());
        defer msg.deinit(self.allocator);
        
        switch (msg) {
            .handshake => |handshake| try self.handleHandshake(handshake),
            .handshake_ack => try self.handleHandshakeAck(),
            .ping => |ping| try self.handlePing(ping),
            .pong => |pong| try self.handlePong(pong),
            // .get_headers => |get_headers| try self.handleGetHeaders(get_headers), // ZSP-001: Disabled
            // .headers => |headers| try self.handleHeaders(headers), // ZSP-001: Disabled
            .block => |block| try self.handleBlock(block),
            .transaction => |transaction| try self.handleTransaction(transaction),
            .get_blocks => |get_blocks| try self.handleGetBlocks(get_blocks),
            .blocks => |blocks| try self.handleBlocks(blocks),
            .get_peers => |get_peers| try self.handleGetPeers(get_peers),
            .peers => |peers| try self.handlePeers(peers),
            .get_block_hash => |get_block_hash| try self.handleGetBlockHash(get_block_hash),
            .block_hash => |block_hash| try self.handleBlockHash(block_hash),
        }
    }
    
    fn handleHandshake(self: *Self, handshake: message_types.HandshakeMessage) !void {
        const our_height = try self.message_handler.getHeight();
        std.log.info("🤝 [HANDSHAKE] Received from peer {} - their height: {}, our height: {}", .{ 
            self.peer.id, handshake.start_height, our_height 
        });
        
        // Validate handshake
        try handshake.validate();
        
        // Update peer info
        self.peer.version = handshake.version;
        self.peer.services = handshake.services;
        self.peer.height = handshake.start_height;
        if (self.peer.user_agent.len > 0) {
            self.allocator.free(self.peer.user_agent);
        }
        self.peer.user_agent = try self.allocator.dupe(u8, handshake.user_agent);
        
        // Send handshake ack
        std.log.info("📤 [HANDSHAKE] Sending ack to peer {} (we are at height {})", .{self.peer.id, our_height});
        _ = try self.peer.sendMessage(.handshake_ack, {});
        
        self.peer.state = .connected;
        std.log.info("✅ [HANDSHAKE] Complete with {}: peer_height={}, our_height={}, agent={s}", .{
            self.peer, handshake.start_height, our_height, handshake.user_agent
        });
        
        // Call handler - THIS is where sync should be triggered
        std.log.info("🔄 [HANDSHAKE] Calling onPeerConnected to check sync requirements", .{});
        try self.message_handler.onPeerConnected(self.peer);
    }
    
    fn handleHandshakeAck(self: *Self) !void {
        if (self.peer.state == .handshaking) {
            const our_height = try self.message_handler.getHeight();
            std.log.info("✅ [HANDSHAKE ACK] Received - peer height: {}, our height: {}", .{
                self.peer.height, our_height
            });
            
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
    
    // ZSP-001: Headers-first disabled - functions commented out
    // fn handleGetHeaders(self: *Self, get_headers: messages.GetHeadersMessage) !void {
    //     try self.message_handler.onGetHeaders(self.peer, get_headers);
    // }
    // 
    // fn handleHeaders(self: *Self, headers: messages.HeadersMessage) !void {
    //     try self.message_handler.onHeaders(self.peer, headers);
    // }
    
    // ZSP-001: Inventory messages disabled - functions commented out
    // fn handleAnnounce(self: *Self, announce: messages.AnnounceMessage) !void {
    //     try self.message_handler.onAnnounce(self.peer, announce);
    // }
    // 
    // fn handleRequest(self: *Self, request: messages.RequestMessage) !void {
    //     try self.message_handler.onRequest(self.peer, request);
    // }
    
    fn handleBlock(self: *Self, block: message_types.BlockMessage) !void {
        try self.message_handler.onBlock(self.peer, block);
    }
    
    fn handleTransaction(self: *Self, transaction: message_types.TransactionMessage) !void {
        try self.message_handler.onTransaction(self.peer, transaction);
    }
    
    fn handleGetBlocks(self: *Self, get_blocks: message_types.GetBlocksMessage) !void {
        try self.message_handler.onGetBlocks(self.peer, get_blocks);
    }
    
    fn handleBlocks(self: *Self, blocks: void) !void {
        _ = blocks; // blocks is void type - handled separately 
        // This might be for streaming large block payloads
        std.log.debug("Received blocks message from {}", .{self.peer});
    }
    
    fn handleGetPeers(self: *Self, get_peers: message_types.GetPeersMessage) !void {
        try self.message_handler.onGetPeers(self.peer, get_peers);
    }
    
    fn handlePeers(self: *Self, peers: message_types.PeersMessage) !void {
        try self.message_handler.onPeers(self.peer, peers);
    }
    
    fn handleGetBlockHash(self: *Self, msg: message_types.GetBlockHashMessage) !void {
        _ = self;
        std.debug.print("🔍 Received get_block_hash request for height {}\n", .{msg.height});
        // TODO: Implement handler callback
    }
    
    fn handleBlockHash(self: *Self, msg: message_types.BlockHashMessage) !void {
        _ = self;
        std.debug.print("📊 Received block_hash response for height {}: exists={}\n", .{ msg.height, msg.exists });
        // TODO: Implement handler callback
    }
    
    // ZSP-001: Inventory disabled - function commented out
    // fn handleNotFound(self: *Self, not_found: messages.NotFoundMessage) !void {
    //     try self.message_handler.onNotFound(self.peer, not_found);
    // }
    
    // ZSP-001: Error handling disabled - function commented out
    // fn handleReject(self: *Self, reject: messages.RejectMessage) !void {
    //     try self.message_handler.onReject(self.peer, reject);
    // }
};

/// Message handler interface
pub const MessageHandler = struct {
    /// Get current blockchain height
    getHeight: *const fn () anyerror!u32,
    
    /// Called when peer connects
    onPeerConnected: *const fn (peer: *Peer) anyerror!void,
    
    // ZSP-001: Headers-first disabled - callbacks commented out
    // /// Handle get headers request
    // onGetHeaders: *const fn (peer: *Peer, msg: messages.GetHeadersMessage) anyerror!void,
    // 
    // /// Handle headers message
    // onHeaders: *const fn (peer: *Peer, msg: messages.HeadersMessage) anyerror!void,
    
    // ZSP-001: Inventory messages disabled - callbacks commented out
    // /// Handle inventory announcement
    // onAnnounce: *const fn (peer: *Peer, msg: messages.AnnounceMessage) anyerror!void,
    // 
    // /// Handle data request
    // onRequest: *const fn (peer: *Peer, msg: messages.RequestMessage) anyerror!void,
    
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
    
    // ZSP-001: Inventory disabled - callback commented out
    // /// Handle not found message
    // onNotFound: *const fn (peer: *Peer, msg: messages.NotFoundMessage) anyerror!void,
    
    // ZSP-001: Error handling disabled - callback commented out
    // /// Handle reject message
    // onReject: *const fn (peer: *Peer, msg: messages.RejectMessage) anyerror!void,
};

/// TCP send callback function
fn tcpSendCallback(ctx: ?*anyopaque, data: []const u8) anyerror!void {
    const self = @as(*PeerConnection, @ptrCast(@alignCast(ctx.?)));
    std.debug.print("🌐 [TCP CALLBACK] Peer {} writing {} bytes to TCP stream\n", .{self.peer.id, data.len});
    try self.stream.writeAll(data);
    std.debug.print("✅ [TCP CALLBACK] Peer {} TCP write completed\n", .{self.peer.id});
}