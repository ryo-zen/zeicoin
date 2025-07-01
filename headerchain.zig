const std = @import("std");
const types = @import("types.zig");
const util = @import("util.zig");
const genesis = @import("genesis.zig");

/// HeaderChain manages and validates block headers for headers-first sync
pub const HeaderChain = struct {
    allocator: std.mem.Allocator,
    headers: std.ArrayList(types.BlockHeader),
    height_to_hash: std.AutoHashMap(u32, types.BlockHash),
    hash_to_height: std.AutoHashMap(types.BlockHash, u32),
    total_work: u256,
    validated_height: u32,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .headers = std.ArrayList(types.BlockHeader).init(allocator),
            .height_to_hash = std.AutoHashMap(u32, types.BlockHash).init(allocator),
            .hash_to_height = std.AutoHashMap(types.BlockHash, u32).init(allocator),
            .total_work = 0,
            .validated_height = 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.height_to_hash.deinit();
        self.hash_to_height.deinit();
    }
    
    /// Validate a header at a specific height
    pub fn validateHeader(self: *Self, header: types.BlockHeader, height: u32) !bool {
        // Special case for genesis block
        if (height == 0) {
            const genesis_hash = header.hash();
            const expected = genesis.getCanonicalGenesisHash();
            if (!std.mem.eql(u8, &genesis_hash, &expected)) {
                std.debug.print("❌ Invalid genesis block hash\n", .{});
                return false;
            }
            return true;
        }
        
        // Check version
        if (header.version > types.CURRENT_BLOCK_VERSION) {
            std.debug.print("❌ Invalid block version: {}\n", .{header.version});
            return false;
        }
        
        // Check previous block linkage
        if (height > 0) {
            if (height - 1 >= self.headers.items.len) {
                std.debug.print("❌ Missing previous header for height {}\n", .{height});
                return error.MissingPreviousHeader;
            }
            
            const prev_header = self.headers.items[height - 1];
            const prev_hash = prev_header.hash();
            
            if (!std.mem.eql(u8, &header.previous_hash, &prev_hash)) {
                std.debug.print("❌ Invalid previous hash at height {}\n", .{height});
                return false;
            }
        }
        
        // Validate timestamp not too far in future (2 hours)
        const now = @as(u64, @intCast(util.getTime()));
        if (header.timestamp > now + 7200) {
            std.debug.print("❌ Header timestamp too far in future: {}\n", .{header.timestamp});
            return false;
        }
        
        // Validate timestamp against median time past (MTP)
        if (height >= 11) {
            const mtp = try self.calculateMedianTimePast(height);
            if (header.timestamp <= mtp) {
                std.debug.print("❌ Header timestamp {} not greater than MTP {}\n", .{header.timestamp, mtp});
                return false;
            }
        }
        
        // Validate proof of work
        const block_hash = header.hash();
        const target = types.DifficultyTarget.fromU64(header.difficulty);
        if (!target.meetsDifficulty(block_hash)) {
            std.debug.print("❌ Invalid proof of work at height {}\n", .{height});
            return false;
        }
        
        // TODO: Validate difficulty adjustment at adjustment heights
        
        return true;
    }
    
    /// Add a validated header to the chain
    pub fn addHeader(self: *Self, header: types.BlockHeader, height: u32) !void {
        // Ensure we're adding headers in order
        if (height != self.headers.items.len) {
            return error.HeadersOutOfOrder;
        }
        
        try self.headers.append(header);
        const hash = header.hash();
        try self.height_to_hash.put(height, hash);
        try self.hash_to_height.put(hash, height);
        
        // Update cumulative work
        const target = types.DifficultyTarget.fromU64(header.difficulty);
        const work = target.toWork();
        self.total_work = self.total_work + work;
        
        self.validated_height = height;
        
        // Log progress every 1000 headers
        if (height % 1000 == 0 and height > 0) {
            std.debug.print("📊 Validated {} headers, total work: {}\n", .{height, self.total_work});
        }
    }
    
    /// Calculate median time past for timestamp validation
    fn calculateMedianTimePast(self: *Self, height: u32) !u64 {
        if (height < 11) return 0;
        
        var timestamps: [11]u64 = undefined;
        const start_height = height - 11;
        
        for (0..11) |i| {
            const h = start_height + i;
            if (h >= self.headers.items.len) return error.InvalidHeight;
            timestamps[i] = self.headers.items[h].timestamp;
        }
        
        // Sort and return median
        std.mem.sort(u64, &timestamps, {}, comptime std.sort.asc(u64));
        return timestamps[5]; // Middle element
    }
    
    /// Get the current height of the header chain
    pub fn getHeight(self: *Self) u32 {
        if (self.headers.items.len == 0) return 0;
        return @as(u32, @intCast(self.headers.items.len - 1));
    }
    
    /// Get header at specific height
    pub fn getHeader(self: *Self, height: u32) ?types.BlockHeader {
        if (height >= self.headers.items.len) return null;
        return self.headers.items[height];
    }
    
    /// Get header by hash
    pub fn getHeaderByHash(self: *Self, hash: types.BlockHash) ?types.BlockHeader {
        if (self.hash_to_height.get(hash)) |height| {
            return self.getHeader(height);
        }
        return null;
    }
    
    /// Check if we have all headers up to target
    pub fn isComplete(self: *Self, target_height: u32) bool {
        return self.getHeight() >= target_height;
    }
    
    /// Get total cumulative work
    pub fn getTotalWork(self: *Self) u256 {
        return self.total_work;
    }
    
    /// Serialize headers for network transmission
    pub fn serializeHeaders(self: *Self, start: u32, count: u32, writer: anytype) !void {
        const end = @min(start + count, self.headers.items.len);
        if (start >= self.headers.items.len) return;
        
        for (start..end) |i| {
            try self.headers.items[i].serialize(writer);
        }
    }
};

// Tests
test "HeaderChain basic operations" {
    const allocator = std.testing.allocator;
    var chain = HeaderChain.init(allocator);
    defer chain.deinit();
    
    // Test empty chain
    try std.testing.expectEqual(@as(u32, 0), chain.getHeight());
    try std.testing.expectEqual(@as(?types.BlockHeader, null), chain.getHeader(0));
}

test "HeaderChain validation" {
    const allocator = std.testing.allocator;
    var chain = HeaderChain.init(allocator);
    defer chain.deinit();
    
    // Create a test header
    const header = types.BlockHeader{
        .version = types.CURRENT_BLOCK_VERSION,
        .previous_hash = std.mem.zeroes([32]u8),
        .merkle_root = std.mem.zeroes([32]u8),
        .timestamp = @as(u64, @intCast(util.getTime())),
        .difficulty = 0xFF000000, // Easy difficulty for testing
        .nonce = 0,
        .witness_root = std.mem.zeroes([32]u8),
        .state_root = std.mem.zeroes([32]u8),
        .extra_nonce = 0,
        .extra_data = std.mem.zeroes([32]u8),
    };
    
    // Should fail validation without proper genesis
    const result = try chain.validateHeader(header, 0);
    try std.testing.expectEqual(false, result);
}

test "HeaderChain median time past" {
    const allocator = std.testing.allocator;
    var chain = HeaderChain.init(allocator);
    defer chain.deinit();
    
    // Add 12 headers with increasing timestamps
    const base_time: u64 = 1000000;
    for (0..12) |i| {
        const header = types.BlockHeader{
            .version = 0,
            .previous_hash = if (i == 0) std.mem.zeroes([32]u8) else chain.headers.items[i-1].hash(),
            .merkle_root = std.mem.zeroes([32]u8),
            .timestamp = base_time + i * 600, // 10 minutes apart
            .difficulty = 0xFF000000, // Easy difficulty for testing
            .nonce = @as(u32, @intCast(i)),
            .witness_root = std.mem.zeroes([32]u8),
            .state_root = std.mem.zeroes([32]u8),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        };
        
        try chain.headers.append(header);
    }
    
    // Calculate MTP at height 11 (should be timestamp of header 5)
    const mtp = try chain.calculateMedianTimePast(11);
    try std.testing.expectEqual(base_time + 5 * 600, mtp);
}