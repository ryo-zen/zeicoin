// handshake.zig - Initial handshake message
// Establishes protocol version and node capabilities

const std = @import("std");
const protocol = @import("../protocol.zig");
const types = @import("../../../types/types.zig");

pub const HandshakeMessage = struct {
    /// Protocol version
    version: u16,
    /// Services this node provides
    services: u64,
    /// Current time
    timestamp: i64,
    /// Our listening port (0 if not accepting connections)
    listen_port: u16,
    /// Random nonce to detect self-connections
    nonce: u64,
    /// User agent string
    user_agent: []const u8,
    /// Our current blockchain height
    start_height: u32,
    /// Network ID to prevent cross-network connections
    network_id: u32,
    /// Hash of our best block at start_height
    best_block_hash: [32]u8,
    /// Current difficulty target for consensus compatibility checking
    current_difficulty: u64,
    /// Genesis block hash to ensure chain compatibility
    genesis_hash: [32]u8,
    
    const Self = @This();
    const MAX_USER_AGENT_LEN = 256;
    
    pub fn init(allocator: std.mem.Allocator, user_agent: []const u8) !Self {
        const agent_copy = try allocator.dupe(u8, user_agent[0..@min(user_agent.len, MAX_USER_AGENT_LEN)]);
        
        return Self{
            .version = protocol.PROTOCOL_VERSION,
            .services = protocol.ServiceFlags.FAST_NODE, // Modern full node with all optimizations
            .timestamp = std.time.timestamp(),
            .listen_port = 0, // Set by caller if listening
            .nonce = std.crypto.random.int(u64),
            .user_agent = agent_copy,
            .start_height = 0, // Set by caller
            .network_id = types.CURRENT_NETWORK.getNetworkId(),
            .best_block_hash = [_]u8{0} ** 32, // Set by caller with actual best block hash
            .current_difficulty = types.ZenMining.initialDifficultyTarget().toU64(), // Set by caller
            .genesis_hash = [_]u8{0} ** 32, // Set by caller with genesis hash
        };
    }
    
    /// Create handshake with custom service flags
    pub fn initWithServices(allocator: std.mem.Allocator, user_agent: []const u8, services: u64) !Self {
        var handshake = try init(allocator, user_agent);
        handshake.services = services;
        return handshake;
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.user_agent);
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        try writer.writeInt(u16, self.version, .little);
        try writer.writeInt(u64, self.services, .little);
        try writer.writeInt(i64, self.timestamp, .little);
        try writer.writeInt(u16, self.listen_port, .little);
        try writer.writeInt(u64, self.nonce, .little);
        
        // Write user agent with length prefix
        try writer.writeInt(u16, @intCast(self.user_agent.len), .little);
        try writer.writeAll(self.user_agent);
        
        try writer.writeInt(u32, self.start_height, .little);
        try writer.writeInt(u32, self.network_id, .little);
        try writer.writeAll(&self.best_block_hash);
        try writer.writeInt(u64, self.current_difficulty, .little);
        try writer.writeAll(&self.genesis_hash);
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Self {
        const version = try reader.readInt(u16, .little);
        const services = try reader.readInt(u64, .little);
        const timestamp = try reader.readInt(i64, .little);
        const listen_port = try reader.readInt(u16, .little);
        const nonce = try reader.readInt(u64, .little);
        
        // Read user agent
        const agent_len = try reader.readInt(u16, .little);
        if (agent_len > MAX_USER_AGENT_LEN) {
            return error.UserAgentTooLong;
        }
        
        const user_agent = try allocator.alloc(u8, agent_len);
        errdefer allocator.free(user_agent);
        try reader.readNoEof(user_agent);
        
        const start_height = try reader.readInt(u32, .little);
        const network_id = try reader.readInt(u32, .little);
        
        var best_block_hash: [32]u8 = undefined;
        try reader.readNoEof(&best_block_hash);
        
        const current_difficulty = try reader.readInt(u64, .little);
        
        var genesis_hash: [32]u8 = undefined;
        try reader.readNoEof(&genesis_hash);
        
        return Self{
            .version = version,
            .services = services,
            .timestamp = timestamp,
            .listen_port = listen_port,
            .nonce = nonce,
            .user_agent = user_agent,
            .start_height = start_height,
            .network_id = network_id,
            .best_block_hash = best_block_hash,
            .current_difficulty = current_difficulty,
            .genesis_hash = genesis_hash,
        };
    }
    
    pub fn estimateSize(self: Self) usize {
        return 2 + 8 + 8 + 2 + 8 + // Fixed fields
            2 + self.user_agent.len + // User agent
            4 + 4 + 32 + 8 + 32; // Height, network, best block hash, difficulty, and genesis hash
    }
    
    /// Check if this node supports a specific service
    pub fn hasService(self: Self, service: u64) bool {
        return (self.services & service) != 0;
    }
    
    /// Validate handshake for compatibility and usefulness
    pub fn validate(self: Self) !void {
        // Check protocol version compatibility
        std.log.info("🔍 Protocol Version Check: Peer version={}, Our version={}", .{ self.version, protocol.PROTOCOL_VERSION });
        
        if (self.version > protocol.PROTOCOL_VERSION) {
            std.log.warn("❌ Protocol version mismatch: Peer version {} > our version {}", .{ self.version, protocol.PROTOCOL_VERSION });
            return error.IncompatibleProtocolVersion;
        }
        if (self.version == 0) {
            std.log.warn("❌ Invalid protocol version: Peer version is 0", .{});
            return error.InvalidProtocolVersion;
        }
        
        std.log.info("✅ Protocol version compatible: Peer={}, Ours={}", .{ self.version, protocol.PROTOCOL_VERSION });
        
        // Check network ID to prevent cross-network connections
        if (self.network_id != types.CURRENT_NETWORK.getNetworkId()) {
            return error.WrongNetwork;
        }
        
        // Validate timestamp (reject if too far in future or past)
        const now = std.time.timestamp();
        const time_diff = @abs(self.timestamp - now);
        if (time_diff > 2 * 60 * 60) { // 2 hours tolerance
            return error.InvalidTimestamp;
        }
        
        // Check for minimum useful services
        if (self.services == 0) {
            return error.NoServicesOffered;
        }
        
        // Validate user agent length
        if (self.user_agent.len > MAX_USER_AGENT_LEN) {
            return error.UserAgentTooLong;
        }
    }
    
    /// Check if this peer would be useful for syncing
    pub fn isGoodSyncPeer(self: Self) bool {
        return protocol.ServiceFlags.isSuitableForSync(self.services);
    }
    
    /// Check if this peer supports parallel downloads
    pub fn supportsParallelDownload(self: Self) bool {
        return protocol.ServiceFlags.supportsFastSync(self.services);
    }
    
    /// Check genesis block compatibility with peer
    pub fn checkGenesisCompatibility(self: Self, our_genesis_hash: [32]u8) !void {
        if (!std.mem.eql(u8, &self.genesis_hash, &our_genesis_hash)) {
            std.log.err("🚫 [CHAIN INCOMPATIBLE] Peer is on a different blockchain!", .{});
            std.log.err("   ⛓️  Our genesis: {s}", .{std.fmt.fmtSliceHexLower(&our_genesis_hash)});
            std.log.err("   ⛓️  Peer genesis: {s}", .{std.fmt.fmtSliceHexLower(&self.genesis_hash)});
            std.log.err("   ℹ️  Cannot sync with this peer - incompatible chain", .{});
            return error.IncompatibleGenesis;
        }
        std.log.info("✅ [GENESIS] Compatible genesis block with peer", .{});
    }
    
    /// ENHANCED: Check difficulty consensus compatibility with peer
    pub fn checkDifficultyConsensus(self: Self, our_difficulty: u64, our_height: u32) !void {
        // Allow some tolerance for nodes at different heights
        if (self.start_height == our_height) {
            // Same height - difficulty must match exactly
            if (self.current_difficulty != our_difficulty) {
                // Extract threshold from difficulty for proper hex display
                const our_threshold = @as(u32, @intCast(our_difficulty & 0xFFFFFFFF));
                const peer_threshold = @as(u32, @intCast(self.current_difficulty & 0xFFFFFFFF));
                
                std.log.warn("❌ CONSENSUS: Peer difficulty mismatch at height {}", .{our_height});
                std.log.warn("   📊 Our difficulty: {} (0x{X})", .{ our_difficulty, our_threshold });
                std.log.warn("   📦 Peer difficulty: {} (0x{X})", .{ self.current_difficulty, peer_threshold });
                std.log.warn("   🔍 Peer info: {s} at {}:{}", .{ self.user_agent, self.start_height, self.listen_port });
                return error.DifficultyConsensusMismatch;
            }
            std.log.info("✅ CONSENSUS: Difficulty match with peer at height {} ({})", .{ our_height, our_difficulty });
        } else if (@abs(@as(i64, @intCast(self.start_height)) - @as(i64, @intCast(our_height))) <= 1) {
            // Within 1 block - log but allow connection
            std.log.info("ℹ️ CONSENSUS: Peer height {} vs our height {}, difficulty {} vs {}", .{
                self.start_height, our_height, self.current_difficulty, our_difficulty
            });
        } else {
            // Different heights - difficulty comparison not meaningful
            std.log.info("ℹ️ CONSENSUS: Peer at different height ({} vs {}), skipping difficulty check", .{
                self.start_height, our_height
            });
        }
    }

    /// ENHANCED: Check overall peer compatibility including difficulty consensus
    pub fn checkPeerCompatibility(self: Self, our_height: u32, our_difficulty: u64) !void {
        // Run standard validation first
        try self.validate();
        
        // Check difficulty consensus
        try self.checkDifficultyConsensus(our_difficulty, our_height);
        
        std.log.info("✅ COMPATIBILITY: Peer {s} passed all compatibility checks", .{self.user_agent});
    }

    /// Get quality score for peer selection (0-100)
    pub fn getQualityScore(self: Self, our_height: u32) u8 {
        var score: u32 = 0;
        
        // Base score for being a full node
        if (protocol.ServiceFlags.isFullNode(self.services)) {
            score += 40;
        } else {
            return 0; // Not useful for sync
        }
        
        // Bonus for modern sync capabilities
        if (self.hasService(protocol.ServiceFlags.HEADERS_FIRST)) score += 20;
        if (self.hasService(protocol.ServiceFlags.PARALLEL_DOWNLOAD)) score += 15;
        if (self.hasService(protocol.ServiceFlags.FAST_SYNC)) score += 10;
        
        // Bonus for having a mempool
        if (self.hasService(protocol.ServiceFlags.MEMPOOL)) score += 10;
        
        // Height bonus/penalty
        if (self.start_height >= our_height) {
            score += 5; // Peer is ahead or equal
        } else if (our_height - self.start_height > 1000) {
            score = score / 2; // Peer is far behind
        }
        
        return @min(100, @as(u8, @intCast(score)));
    }
};

/// Handshake acknowledgment message containing server's current blockchain height
/// Sent in response to a handshake to communicate the responding node's height
pub const HandshakeAckMessage = struct {
    /// Current blockchain height of the responding node
    current_height: u32,
    
    /// Initialize handshake ack with current height
    pub fn init(current_height: u32) HandshakeAckMessage {
        return .{
            .current_height = current_height,
        };
    }
    
    /// Validate handshake ack message (basic sanity checks)
    pub fn validate(self: *const HandshakeAckMessage) !void {
        // Height validation - allow any valid height including 0 (genesis)
        if (self.current_height > 0xFFFFFF) { // Reasonable max height check
            return error.InvalidHeight;
        }
    }
    
    /// Serialize handshake ack to bytes
    pub fn serialize(self: *const HandshakeAckMessage, writer: anytype) !void {
        try writer.writeInt(u32, self.current_height, .little);
    }
    
    /// Encode method for compatibility with wire protocol
    pub fn encode(self: *const HandshakeAckMessage, writer: anytype) !void {
        try self.serialize(writer);
    }
    
    /// Deserialize handshake ack from bytes
    pub fn deserialize(reader: anytype) !HandshakeAckMessage {
        const current_height = try reader.readInt(u32, .little);
        
        const msg = HandshakeAckMessage.init(current_height);
        try msg.validate();
        return msg;
    }
    
    /// Get serialized size in bytes
    pub fn getSize(self: *const HandshakeAckMessage) usize {
        _ = self;
        return @sizeOf(u32); // Just the height field
    }
    
    /// Estimate encoded size for wire protocol compatibility
    pub fn estimateSize(self: *const HandshakeAckMessage) usize {
        return self.getSize();
    }
};

// Tests
test "HandshakeMessage encode/decode" {
    const allocator = std.testing.allocator;
    
    var msg = try HandshakeMessage.init(allocator, "ZeiCoin/1.0.0");
    defer msg.deinit(allocator);
    
    msg.listen_port = 10801;
    msg.start_height = 12345;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try msg.encode(buffer.writer());
    
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try HandshakeMessage.decode(allocator, stream.reader());
    defer decoded.deinit(allocator);
    
    try std.testing.expectEqual(msg.version, decoded.version);
    try std.testing.expectEqual(msg.services, decoded.services);
    try std.testing.expectEqual(msg.listen_port, decoded.listen_port);
    try std.testing.expectEqual(msg.start_height, decoded.start_height);
    try std.testing.expectEqualStrings(msg.user_agent, decoded.user_agent);
    
    // Validate the decoded message
    try decoded.validate();
    
    // Test service flag functionality
    try std.testing.expect(decoded.isGoodSyncPeer());
    try std.testing.expect(decoded.supportsParallelDownload());
    
    const quality = decoded.getQualityScore(10000);
    try std.testing.expect(quality > 80); // Should be high quality with FAST_NODE services
}

test "ServiceFlags functionality" {
    const allocator = std.testing.allocator;
    
    // Test different service combinations
    var full_node = try HandshakeMessage.initWithServices(allocator, "ZeiCoin/1.0.0", protocol.ServiceFlags.FULL_NODE);
    defer full_node.deinit(allocator);
    
    var mining_node = try HandshakeMessage.initWithServices(allocator, "ZeiCoin/1.0.0", protocol.ServiceFlags.MINING_NODE);
    defer mining_node.deinit(allocator);
    
    var pruned_node = try HandshakeMessage.initWithServices(allocator, "ZeiCoin/1.0.0", protocol.ServiceFlags.PRUNED_NODE);
    defer pruned_node.deinit(allocator);
    
    // Test sync peer suitability
    try std.testing.expect(full_node.isGoodSyncPeer());
    try std.testing.expect(mining_node.isGoodSyncPeer());
    try std.testing.expect(pruned_node.isGoodSyncPeer());
    
    // Test quality scoring
    full_node.start_height = 12345;
    mining_node.start_height = 12345;
    pruned_node.start_height = 10000; // Behind
    
    const full_quality = full_node.getQualityScore(12000);
    const mining_quality = mining_node.getQualityScore(12000);
    const pruned_quality = pruned_node.getQualityScore(12000);
    
    try std.testing.expect(mining_quality >= full_quality); // Mining nodes often have good sync capabilities
    try std.testing.expect(full_quality > pruned_quality); // Full node better than pruned when behind
}

test "HandshakeAckMessage creation and validation" {
    const testing = std.testing;
    
    // Test valid handshake ack
    const ack = HandshakeAckMessage.init(42);
    try testing.expect(ack.current_height == 42);
    try ack.validate();
    
    // Test genesis height
    const genesis_ack = HandshakeAckMessage.init(0);
    try genesis_ack.validate();
    
    // Test invalid height (too high)
    const invalid_ack = HandshakeAckMessage.init(0xFFFFFFFF);
    try testing.expectError(error.InvalidHeight, invalid_ack.validate());
}

test "HandshakeAckMessage serialization" {
    const testing = std.testing;
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    
    // Test serialization
    const original = HandshakeAckMessage.init(100);
    try original.serialize(fbs.writer());
    
    // Test deserialization  
    fbs.reset();
    const deserialized = try HandshakeAckMessage.deserialize(fbs.reader());
    try testing.expect(deserialized.current_height == 100);
}