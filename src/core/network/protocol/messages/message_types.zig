// message_types.zig - Message type registry and union
// Central place for all protocol message type definitions

const std = @import("std");
const protocol = @import("../protocol.zig");

// Import all message types
pub const HandshakeMessage = @import("handshake.zig").HandshakeMessage;
pub const HandshakeAckMessage = @import("handshake.zig").HandshakeAckMessage;
pub const PingMessage = @import("ping.zig").PingMessage;
pub const PongMessage = @import("pong.zig").PongMessage;
// Headers-first messages removed per ZSP-001 (batch sync only)
// pub const GetHeadersMessage = @import("get_headers.zig").GetHeadersMessage;
// pub const HeadersMessage = @import("headers.zig").HeadersMessage;
pub const GetBlocksMessage = @import("get_blocks.zig").GetBlocksMessage;
pub const BlockMessage = @import("block.zig").BlockMessage;
pub const TransactionMessage = @import("transaction.zig").TransactionMessage;


// Peer discovery messages (kept for network functionality)
pub const GetPeersMessage = @import("get_peers.zig").GetPeersMessage;
pub const PeersMessage = @import("peers.zig").PeersMessage;
pub const PeerAddress = @import("peers.zig").PeerAddress;

// Consensus verification messages
pub const GetBlockHashMessage = @import("get_block_hash.zig").GetBlockHashMessage;
pub const BlockHashMessage = @import("block_hash.zig").BlockHashMessage;

/// Union of all message types - clean batch sync protocol
pub const Message = union(protocol.MessageType) {
    handshake: HandshakeMessage,
    handshake_ack: HandshakeAckMessage, // Now includes height payload
    ping: PingMessage,
    pong: PongMessage,
    // Headers-first messages removed per ZSP-001
    // get_headers: GetHeadersMessage,
    // headers: HeadersMessage,
    get_blocks: GetBlocksMessage,
    blocks: void, // Uses streaming for large payloads
    
    // Transaction/Block transfer
    transaction: TransactionMessage,
    block: BlockMessage,
    
    // Peer discovery (essential for network)
    get_peers: GetPeersMessage,
    peers: PeersMessage,
    
    // Consensus verification
    get_block_hash: GetBlockHashMessage,
    block_hash: BlockHashMessage,
    
    /// Encode any message type
    pub fn encode(self: Message, writer: anytype) !void {
        switch (self) {
            .handshake_ack => |msg| try msg.serialize(writer),
            .blocks => {}, // Handled separately
            inline else => |msg| try msg.encode(writer),
        }
    }
    
    /// Decode message based on type
    pub fn decode(
        msg_type: protocol.MessageType,
        allocator: std.mem.Allocator,
        reader: anytype,
    ) !Message {
        return switch (msg_type) {
            .handshake => .{ .handshake = try HandshakeMessage.decode(allocator, reader) },
            .handshake_ack => .{ .handshake_ack = try HandshakeAckMessage.deserialize(reader) },
            .ping => .{ .ping = try PingMessage.decode(reader) },
            .pong => .{ .pong = try PongMessage.decode(reader) },
            // Headers-first messages removed per ZSP-001
            // .get_headers => .{ .get_headers = try GetHeadersMessage.decode(allocator, reader) },
            // .headers => .{ .headers = try HeadersMessage.decode(allocator, reader) },
            .get_blocks => .{ .get_blocks = try GetBlocksMessage.decode(allocator, reader) },
            .blocks => .{ .blocks = {} }, // Handled separately
            
            // Transaction/Block transfer
            .transaction => .{ .transaction = try TransactionMessage.decode(allocator, reader) },
            .block => .{ .block = try BlockMessage.decode(allocator, reader) },
            
            // Peer discovery (essential for network)
            .get_peers => .{ .get_peers = try GetPeersMessage.decode(reader) },
            .peers => .{ .peers = try PeersMessage.decode(allocator, reader) },
            
            // Consensus verification
            .get_block_hash => .{ .get_block_hash = try GetBlockHashMessage.deserialize(reader) },
            .block_hash => .{ .block_hash = try BlockHashMessage.deserialize(reader) },
            
            _ => error.UnknownMessageType,
        };
    }
    
    /// Estimate encoded size
    pub fn estimateSize(self: Message) usize {
        return switch (self) {
            .handshake_ack => |msg| msg.getSize(),
            .blocks => 0,
            inline else => |msg| msg.estimateSize(),
        };
    }
    
    /// Clean up any allocated memory
    pub fn deinit(self: *Message, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .handshake_ack, .blocks => {},
            inline else => |*msg| {
                if (@hasDecl(@TypeOf(msg.*), "deinit")) {
                    msg.deinit(allocator);
                }
            },
        }
    }
    
    /// Get the message type
    pub fn getType(self: Message) protocol.MessageType {
        return @as(protocol.MessageType, self);
    }
};