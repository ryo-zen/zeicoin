// validation.zig - Mining Validation Logic
// Handles proof-of-work validation for mined blocks
// Security: Always uses RandomX for consistent validation across all networks

const std = @import("std");
const log = std.log.scoped(.mining);

const types = @import("../types/types.zig");
const randomx = @import("../crypto/randomx.zig");
const MiningContext = @import("context.zig").MiningContext;

// Global mutex to prevent concurrent RandomX validation
// This prevents OOM errors when multiple validations run simultaneously
var randomx_validation_mutex = std.Thread.Mutex{};

/// Validate block proof-of-work using RandomX
/// This function is critical for network security - always uses RandomX regardless of build mode
pub fn validateBlockPoW(ctx: MiningContext, block: types.Block) !bool {
    // Performance: Serialize validation to prevent concurrent RandomX instances (OOM protection)
    randomx_validation_mutex.lock();
    defer randomx_validation_mutex.unlock();
    
    // Early exit: Check if block claims correct difficulty before expensive RandomX validation
    const difficulty_target = block.header.getDifficultyTarget();
    if (difficulty_target.base_bytes == 0 or difficulty_target.base_bytes > 32) {
        log.warn("❌ Invalid difficulty target: {} bytes", .{difficulty_target.base_bytes});
        return false;
    }
    
    // Initialize RandomX with network-specific parameters
    const network_name = switch (types.CURRENT_NETWORK) {
        .testnet => "TestNet",
        .mainnet => "MainNet",
    };
    const chain_key = randomx.createRandomXKey(network_name);

    // Performance: Stack-allocated hex conversion
    var hex_key: [64]u8 = undefined;
    for (chain_key, 0..) |byte, i| {
        _ = std.fmt.bufPrint(hex_key[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }

    // Use appropriate RandomX mode based on network configuration
    const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
    
    // Initialize RandomX context with proper error handling
    var rx_ctx = randomx.RandomXContext.init(ctx.allocator, &hex_key, mode) catch |err| {
        log.warn("❌ RandomX initialization failed: {}", .{err});
        return false;
    };
    defer rx_ctx.deinit();

    // Serialize block header efficiently
    var buffer: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    block.header.serialize(stream.writer()) catch |err| {
        log.warn("❌ Block header serialization failed: {}", .{err});
        return false;
    };
    const header_data = stream.getWritten();

    // Calculate RandomX hash with network-appropriate difficulty
    var hash: [32]u8 = undefined;
    rx_ctx.hashWithDifficulty(header_data, &hash, difficulty_target.base_bytes) catch |err| {
        log.warn("❌ RandomX hash calculation failed: {}", .{err});
        return false;
    };

    // Verify hash meets the required difficulty target
    const valid = randomx.hashMeetsDifficultyTarget(hash, difficulty_target);
    
    // Optional: Log validation result for debugging
    if (!valid) {
        const hash_hex = std.fmt.fmtSliceHexLower(&hash);
        log.warn("⚠️ Block hash {} does not meet difficulty target {}", .{ hash_hex, difficulty_target.toU64() });
    }
    
    return valid;
}
