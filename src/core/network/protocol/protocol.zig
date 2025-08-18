// protocol.zig - Core protocol constants and types for ZeiCoin

const std = @import("std");

// Protocol version - start fresh at 1
pub const PROTOCOL_VERSION: u16 = 101; // 1.01 represented as 101

// Network magic bytes - "ZEIC"
pub const MAGIC: u32 = 0x5A454943;

// Default network port
pub const DEFAULT_PORT: u16 = 10801;

// Message size limits
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;
pub const MAX_BLOCKS_PER_MESSAGE: usize = 500;
pub const MAX_INV_PER_MESSAGE: usize = 50000;

// Connection limits
pub const MAX_PEERS: usize = 125;
pub const MAX_PENDING_MESSAGES: usize = 1000;
pub const CONNECTION_TIMEOUT_SECONDS: u64 = 120; // 2 minutes - reasonable for small syncs
pub const PING_INTERVAL_SECONDS: u64 = 30;

// Memory limits per connection
pub const MAX_MEMORY_PER_CONNECTION: usize = 100 * 1024 * 1024; // 100MB

// Clean message type enum - no string padding needed
pub const MessageType = enum(u8) {
    // Core messages
    handshake = 0,
    handshake_ack = 1,
    ping = 2,
    pong = 3,

    // Sync messages (ZSP-001 batch sync only)
    // get_headers = 4,  // Removed per ZSP-001
    // headers = 5,      // Removed per ZSP-001
    get_blocks = 6,
    blocks = 7,

    // ZSP-001: Inventory messages disabled for batch sync
    // announce = 8,     // Disabled
    // request = 9,      // Disabled
    // not_found = 10,   // Disabled

    // Transaction/Block transfer (ZSP-001 core messages)
    transaction = 11,
    block = 12,

    // Peer discovery (essential for network)
    get_peers = 13,
    peers = 14,

    // Error handling (disabled for ZSP-001 simplicity)
    // reject = 15,      // Disabled
    
    // Consensus verification messages
    get_block_hash = 16,
    block_hash = 17,

    _,

    pub fn isValid(self: MessageType) bool {
        // ZSP-001: Updated valid range to exclude disabled messages
        return @intFromEnum(self) <= @intFromEnum(MessageType.block_hash);
    }
};

// Service flags for node capabilities - clean, modern design
pub const ServiceFlags = struct {
    // Core node capabilities
    pub const NETWORK: u64 = 0x1; // Full node with complete blockchain
    pub const WITNESS: u64 = 0x2; // Supports witness data
    pub const PRUNED: u64 = 0x4; // Pruned node (partial chain storage)
    pub const MEMPOOL: u64 = 0x8; // Has active mempool

    // Sync protocol capabilities
    // pub const HEADERS_FIRST: u64 = 0x10;    // Removed per ZSP-001
    pub const PARALLEL_DOWNLOAD: u64 = 0x20; // Can handle parallel block requests
    pub const FAST_SYNC: u64 = 0x40; // Supports optimized fast sync
    pub const CHECKPOINT_SYNC: u64 = 0x80; // Supports checkpoint-based sync

    // Network optimization capabilities
    pub const COMPACT_BLOCKS: u64 = 0x100; // Supports compact block relay
    pub const BLOOM_FILTER: u64 = 0x200; // Supports bloom filtered connections
    pub const FEE_FILTER: u64 = 0x400; // Supports fee filtering

    // Mining and validation
    pub const MINING: u64 = 0x1000; // Active miner
    pub const VALIDATION: u64 = 0x2000; // Full transaction validation

    // ZSP-001: Service combinations for common node types (headers-first removed)
    pub const FULL_NODE: u64 = NETWORK | MEMPOOL | VALIDATION;
    pub const FAST_NODE: u64 = FULL_NODE | PARALLEL_DOWNLOAD | FAST_SYNC;
    pub const PRUNED_NODE: u64 = PRUNED | MEMPOOL | VALIDATION;
    pub const MINING_NODE: u64 = FULL_NODE | MINING;

    /// Check if a service set represents a full node
    pub fn isFullNode(services: u64) bool {
        return (services & NETWORK) != 0 and (services & VALIDATION) != 0;
    }

    /// Check if a service set supports ZSP-001 batch sync
    pub fn supportsBatchSync(services: u64) bool {
        return (services & PARALLEL_DOWNLOAD) != 0 or (services & FAST_SYNC) != 0;
    }

    /// Check if a service set is suitable for sync peer (ZSP-001 compliant)
    pub fn isSuitableForSync(services: u64) bool {
        return isFullNode(services) and supportsBatchSync(services);
    }

    /// Get human-readable service description
    pub fn describe(services: u64, allocator: std.mem.Allocator) ![]const u8 {
        if (services == 0) return try allocator.dupe(u8, "NONE");
        if (services == FAST_NODE) return try allocator.dupe(u8, "FAST_NODE");
        if (services == FULL_NODE) return try allocator.dupe(u8, "FULL_NODE");
        if (services == MINING_NODE) return try allocator.dupe(u8, "MINING_NODE");
        if (services == PRUNED_NODE) return try allocator.dupe(u8, "PRUNED_NODE");

        var parts = std.ArrayList([]const u8).init(allocator);
        defer parts.deinit();

        if ((services & NETWORK) != 0) try parts.append("NETWORK");
        if ((services & PRUNED) != 0) try parts.append("PRUNED");
        if ((services & MEMPOOL) != 0) try parts.append("MEMPOOL");
        if ((services & PARALLEL_DOWNLOAD) != 0) try parts.append("PARALLEL");
        if ((services & FAST_SYNC) != 0) try parts.append("FAST_SYNC");
        if ((services & MINING) != 0) try parts.append("MINING");

        return try std.mem.join(allocator, "|", parts.items);
    }
};

// Inventory types for announcements
pub const InventoryType = enum(u32) {
    transaction = 1,
    block = 2,
    filtered_block = 3, // For light clients
    compact_block = 4, // For bandwidth optimization

    pub fn isValid(self: InventoryType) bool {
        return @intFromEnum(self) >= 1 and @intFromEnum(self) <= 4;
    }
};

// Reject codes for error handling
pub const RejectCode = enum(u8) {
    malformed = 0x01,
    invalid = 0x10,
    obsolete = 0x11,
    duplicate = 0x12,
    nonstandard = 0x40,
    dust = 0x41,
    insufficient_fee = 0x42,
    checkpoint = 0x43,
};

// Clean message header - no legacy padding
pub const MessageHeader = packed struct {
    magic: u32,
    message_type: MessageType,
    payload_length: u32,
    checksum: u32,

    pub const SIZE = @sizeOf(MessageHeader);

    pub fn init(msg_type: MessageType, payload_len: u32) MessageHeader {
        return .{
            .magic = MAGIC,
            .message_type = msg_type,
            .payload_length = payload_len,
            .checksum = 0, // Set after payload serialization
        };
    }

    pub fn setChecksum(self: *MessageHeader, payload: []const u8) void {
        self.checksum = calculateChecksum(payload);
    }

    pub fn verifyChecksum(self: MessageHeader, payload: []const u8) bool {
        return self.checksum == calculateChecksum(payload);
    }

    pub fn serialize(self: MessageHeader, writer: anytype) !void {
        try writer.writeInt(u32, self.magic, .little);
        try writer.writeByte(@intFromEnum(self.message_type));
        try writer.writeInt(u32, self.payload_length, .little);
        try writer.writeInt(u32, self.checksum, .little);
    }

    pub fn deserialize(reader: anytype) !MessageHeader {
        const magic = try reader.readInt(u32, .little);
        if (magic != MAGIC) return error.InvalidMagic;

        const msg_type = try reader.readEnum(MessageType, .little);
        const payload_length = try reader.readInt(u32, .little);
        if (payload_length > MAX_MESSAGE_SIZE) return error.MessageTooLarge;

        const checksum = try reader.readInt(u32, .little);

        return MessageHeader{
            .magic = magic,
            .message_type = msg_type,
            .payload_length = payload_length,
            .checksum = checksum,
        };
    }
};

// Modern CRC32 checksum instead of double-SHA256
pub fn calculateChecksum(data: []const u8) u32 {
    var crc: u32 = 0xFFFFFFFF;
    for (data) |byte| {
        crc = crc ^ @as(u32, byte);
        for (0..8) |_| {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// Test checksum calculation
test "calculateChecksum" {
    const data = "hello";
    const checksum = calculateChecksum(data);
    try std.testing.expectEqual(@as(u32, 0x3610a686), checksum);
}

// Test message header
test "MessageHeader serialization" {
    var header = MessageHeader.init(.ping, 8);
    header.setChecksum(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });

    var buffer: [MessageHeader.SIZE]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    try header.serialize(stream.writer());

    stream.reset();
    const decoded = try MessageHeader.deserialize(stream.reader());

    try std.testing.expectEqual(header.magic, decoded.magic);
    try std.testing.expectEqual(header.message_type, decoded.message_type);
    try std.testing.expectEqual(header.payload_length, decoded.payload_length);
    try std.testing.expectEqual(header.checksum, decoded.checksum);
}
