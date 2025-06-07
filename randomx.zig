// randomx.zig - RandomX integration for ZeiCoin proof-of-work
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const RandomXError = error{
    InitFailed,
    HashFailed,
    InvalidMode,
    ProcessFailed,
};

pub const RandomXMode = enum {
    light, // 256MB memory
    fast,  // 2GB memory (not implemented yet)
};

// RandomX context using subprocess approach
pub const RandomXContext = struct {
    allocator: Allocator,
    key: []u8,
    mode: RandomXMode,

    pub fn init(allocator: Allocator, key: []const u8, mode: RandomXMode) !RandomXContext {
        const key_copy = try allocator.dupe(u8, key);
        return RandomXContext{
            .allocator = allocator,
            .key = key_copy,
            .mode = mode,
        };
    }

    pub fn deinit(self: *RandomXContext) void {
        self.allocator.free(self.key);
    }

    pub fn hash(self: *RandomXContext, input: []const u8, output: *[32]u8) !void {
        // Convert input to hex string
        var hex_input = try self.allocator.alloc(u8, input.len * 2);
        defer self.allocator.free(hex_input);
        
        for (input, 0..) |byte, i| {
            _ = std.fmt.bufPrint(hex_input[i*2..i*2+2], "{x:0>2}", .{byte}) catch unreachable;
        }
        
        // Get mode string
        const mode_str = if (self.mode == .light) "light" else "fast";
        
        // Run RandomX helper subprocess
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "./randomx/randomx_helper",
                hex_input,
                self.key,
                "1", // difficulty bytes (will be passed from caller)
                mode_str,
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        
        if (result.term != .Exited or result.term.Exited != 0) {
            std.debug.print("RandomX helper failed: {s}\n", .{result.stderr});
            return RandomXError.ProcessFailed;
        }
        
        // Parse result: hash_hex:meets_difficulty
        const colon_pos = std.mem.indexOf(u8, result.stdout, ":") orelse return RandomXError.HashFailed;
        const hash_hex = result.stdout[0..colon_pos];
        
        if (hash_hex.len != 64) return RandomXError.HashFailed;
        
        // Convert hex hash to bytes
        for (0..32) |i| {
            const hex_byte = hash_hex[i*2..i*2+2];
            output[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return RandomXError.HashFailed;
        }
    }
};

// Check if hash meets difficulty target (configurable leading zeros) - Legacy function
pub fn hashMeetsDifficulty(hash: [32]u8, difficulty_bytes: u8) bool {
    if (difficulty_bytes == 0 or difficulty_bytes > 32) return false;
    
    // Check if first N bytes are zero
    for (0..difficulty_bytes) |i| {
        if (hash[i] != 0) return false;
    }
    
    return true;
}

// Check if hash meets new dynamic difficulty target
pub fn hashMeetsDifficultyTarget(hash: [32]u8, target: @import("types.zig").DifficultyTarget) bool {
    return target.meetsDifficulty(hash);
}

// Helper to create blockchain-specific RandomX key
pub fn createRandomXKey(chain_id: []const u8) [32]u8 {
    var key: [32]u8 = undefined;
    const key_string = std.fmt.allocPrint(
        std.heap.page_allocator,
        "ZeiCoin-{s}-RandomX",
        .{chain_id},
    ) catch "ZeiCoin-MainNet-RandomX";
    defer std.heap.page_allocator.free(key_string);
    
    // Hash the key string to get fixed-size key
    std.crypto.hash.sha2.Sha256.hash(key_string, &key, .{});
    return key;
}

test "RandomX integration" {
    // Test key generation
    const key = createRandomXKey("TestNet");
    try std.testing.expect(key.len == 32);
    
    // Test difficulty checking
    var easy_hash: [32]u8 = .{0} ** 32;
    easy_hash[0] = 0x00;
    easy_hash[1] = 0xFF;
    try std.testing.expect(hashMeetsDifficulty(easy_hash, 1));
    try std.testing.expect(!hashMeetsDifficulty(easy_hash, 2));
    
    const hard_hash: [32]u8 = .{0xFF} ** 32;
    try std.testing.expect(!hashMeetsDifficulty(hard_hash, 1));
}