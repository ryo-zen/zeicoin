// peer_connection.zig - Individual peer connection handling
// Manages the lifecycle of a single peer connection

const std = @import("std");
const net = std.net;
const protocol = @import("protocol/protocol.zig");
const messages = @import("protocol/messages/messages.zig");
const message_mod = @import("protocol/message.zig");
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
            try self.peer.receiveData(buffer[0..bytes_read]);
            
            // Process messages
            while (try self.peer.readMessage()) |envelope| {
                var env = envelope;
                defer env.deinit();
                try self.handleMessage(env);
            }
        }
        
        self.peer.state = .disconnected;
    }
    
    /// Send handshake message
    fn sendHandshake(self: *Self) !void {
        const user_agent = "ZeiCoin/1.0.0";
        var handshake = try messages.HandshakeMessage.init(self.allocator, user_agent);
        defer handshake.deinit(self.allocator);
        
        handshake.listen_port = protocol.DEFAULT_PORT;
        handshake.start_height = try self.message_handler.getHeight();
        
        std.log.info("Sending handshake to peer {} with height {}", .{ self.peer.id, handshake.start_height });
        const data = try self.peer.sendMessage(.handshake, handshake);
        try self.stream.writeAll(data);
        std.log.info("Handshake sent to peer {}", .{self.peer.id});
    }
    
    /// Send ping message
    fn sendPing(self: *Self) !void {
        const ping = messages.PingMessage.init();
        self.peer.ping_nonce = ping.nonce;
        self.peer.last_ping = std.time.timestamp();
        
        const data = try self.peer.sendMessage(.ping, ping);
        try self.stream.writeAll(data);
    }
    
    /// Handle incoming message
    fn handleMessage(self: *Self, envelope: message_mod.MessageEnvelope) !void {
        const msg_type = envelope.header.message_type;
        
        std.log.debug("Received {} from {}", .{ msg_type, self.peer });
        
        // Decode message
        var stream = std.io.fixedBufferStream(envelope.payload);
        var msg = try messages.Message.decode(msg_type, self.allocator, stream.reader());
        defer msg.deinit(self.allocator);
        
        switch (msg) {
            .handshake => |handshake| try self.handleHandshake(handshake),
            .handshake_ack => try self.handleHandshakeAck(),
            .ping => |ping| try self.handlePing(ping),
            .pong => |pong| try self.handlePong(pong),
            .get_headers => |get_headers| try self.handleGetHeaders(get_headers),
            .headers => |headers| try self.handleHeaders(headers),
            .announce => |announce| try self.handleAnnounce(announce),
            .request => |request| try self.handleRequest(request),
            .block => |block| try self.handleBlock(block),
            .transaction => |transaction| try self.handleTransaction(transaction),
            .get_blocks => |get_blocks| try self.handleGetBlocks(get_blocks),
            .blocks => |blocks| try self.handleBlocks(blocks),
            .get_peers => |get_peers| try self.handleGetPeers(get_peers),
            .peers => |peers| try self.handlePeers(peers),
            .not_found => |not_found| try self.handleNotFound(not_found),
            .reject => |reject| try self.handleReject(reject),
        }
    }
    
    fn handleHandshake(self: *Self, handshake: messages.HandshakeMessage) !void {
        std.log.info("Received handshake from peer {} with height {}", .{ self.peer.id, handshake.start_height });
        
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
        std.log.info("Sending handshake ack to peer {}", .{self.peer.id});
        const data = try self.peer.sendMessage(.handshake_ack, {});
        try self.stream.writeAll(data);
        
        self.peer.state = .connected;
        std.log.info("Handshake complete with {}: height={}, agent={s}", .{
            self.peer, handshake.start_height, handshake.user_agent
        });
        
        // Call handler
        std.log.info("Calling onPeerConnected handler for peer {}", .{self.peer.id});
        try self.message_handler.onPeerConnected(self.peer);
    }
    
    fn handleHandshakeAck(self: *Self) !void {
        if (self.peer.state == .handshaking) {
            self.peer.state = .connected;
            try self.message_handler.onPeerConnected(self.peer);
        }
    }
    
    fn handlePing(self: *Self, ping: messages.PingMessage) !void {
        const pong = messages.PongMessage.init(ping.nonce);
        const data = try self.peer.sendMessage(.pong, pong);
        try self.stream.writeAll(data);
    }
    
    fn handlePong(self: *Self, pong: messages.PongMessage) !void {
        if (self.peer.ping_nonce) |nonce| {
            if (pong.nonce == nonce) {
                const latency = std.time.timestamp() - self.peer.last_ping;
                std.log.debug("Peer {} latency: {}ms", .{ self.peer, latency * 1000 });
                self.peer.ping_nonce = null;
            }
        }
    }
    
    fn handleGetHeaders(self: *Self, get_headers: messages.GetHeadersMessage) !void {
        try self.message_handler.onGetHeaders(self.peer, get_headers);
    }
    
    fn handleHeaders(self: *Self, headers: messages.HeadersMessage) !void {
        try self.message_handler.onHeaders(self.peer, headers);
    }
    
    fn handleAnnounce(self: *Self, announce: messages.AnnounceMessage) !void {
        try self.message_handler.onAnnounce(self.peer, announce);
    }
    
    fn handleRequest(self: *Self, request: messages.RequestMessage) !void {
        try self.message_handler.onRequest(self.peer, request);
    }
    
    fn handleBlock(self: *Self, block: messages.BlockMessage) !void {
        try self.message_handler.onBlock(self.peer, block);
    }
    
    fn handleTransaction(self: *Self, transaction: messages.TransactionMessage) !void {
        try self.message_handler.onTransaction(self.peer, transaction);
    }
    
    fn handleGetBlocks(self: *Self, get_blocks: messages.GetBlocksMessage) !void {
        try self.message_handler.onGetBlocks(self.peer, get_blocks);
    }
    
    fn handleBlocks(self: *Self, blocks: void) !void {
        _ = blocks; // blocks is void type - handled separately 
        // This might be for streaming large block payloads
        std.log.debug("Received blocks message from {}", .{self.peer});
    }
    
    fn handleGetPeers(self: *Self, get_peers: messages.GetPeersMessage) !void {
        try self.message_handler.onGetPeers(self.peer, get_peers);
    }
    
    fn handlePeers(self: *Self, peers: messages.PeersMessage) !void {
        try self.message_handler.onPeers(self.peer, peers);
    }
    
    fn handleNotFound(self: *Self, not_found: messages.NotFoundMessage) !void {
        try self.message_handler.onNotFound(self.peer, not_found);
    }
    
    fn handleReject(self: *Self, reject: messages.RejectMessage) !void {
        try self.message_handler.onReject(self.peer, reject);
    }
};

/// Message handler interface
pub const MessageHandler = struct {
    /// Get current blockchain height
    getHeight: *const fn () anyerror!u32,
    
    /// Called when peer connects
    onPeerConnected: *const fn (peer: *Peer) anyerror!void,
    
    /// Handle get headers request
    onGetHeaders: *const fn (peer: *Peer, msg: messages.GetHeadersMessage) anyerror!void,
    
    /// Handle headers message
    onHeaders: *const fn (peer: *Peer, msg: messages.HeadersMessage) anyerror!void,
    
    /// Handle inventory announcement
    onAnnounce: *const fn (peer: *Peer, msg: messages.AnnounceMessage) anyerror!void,
    
    /// Handle data request
    onRequest: *const fn (peer: *Peer, msg: messages.RequestMessage) anyerror!void,
    
    /// Handle block data
    onBlock: *const fn (peer: *Peer, msg: messages.BlockMessage) anyerror!void,
    
    /// Handle transaction data
    onTransaction: *const fn (peer: *Peer, msg: messages.TransactionMessage) anyerror!void,
    
    /// Handle get blocks request
    onGetBlocks: *const fn (peer: *Peer, msg: messages.GetBlocksMessage) anyerror!void,
    
    /// Handle get peers request
    onGetPeers: *const fn (peer: *Peer, msg: messages.GetPeersMessage) anyerror!void,
    
    /// Handle peers message
    onPeers: *const fn (peer: *Peer, msg: messages.PeersMessage) anyerror!void,
    
    /// Handle not found message
    onNotFound: *const fn (peer: *Peer, msg: messages.NotFoundMessage) anyerror!void,
    
    /// Handle reject message
    onReject: *const fn (peer: *Peer, msg: messages.RejectMessage) anyerror!void,
};