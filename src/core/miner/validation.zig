// validation.zig - Mining Validation Logic
// Handles proof-of-work validation for mined blocks

const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const randomx = @import("../crypto/randomx.zig");
const MiningContext = @import("context.zig").MiningContext;

// Global mutex to prevent concurrent RandomX validation (prevents OOM)
var randomx_validation_mutex = std.Thread.Mutex{};

/// Validate block proof-of-work using RandomX
pub fn validateBlockPoW(ctx: MiningContext, block: types.Block) !bool {
    // Serialize RandomX validation to prevent concurrent subprocess OOM
    randomx_validation_mutex.lock();
    defer randomx_validation_mutex.unlock();
    // Initialize RandomX context for validation
    const network_name = switch (types.CURRENT_NETWORK) {
        .testnet => "TestNet",
        .mainnet => "MainNet",
    };
    const chain_key = randomx.createRandomXKey(network_name);

    // Convert binary key to hex string for RandomX helper
    var hex_key: [64]u8 = undefined;
    for (chain_key, 0..) |byte, i| {
        _ = std.fmt.bufPrint(hex_key[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }

    const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
    var rx_ctx = randomx.RandomXContext.init(ctx.allocator, &hex_key, mode) catch {
        print("❌ Failed to initialize RandomX for validation\n", .{});
        return false;
    };
    defer rx_ctx.deinit();

    // Serialize block header for RandomX input
    var buffer: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try block.header.serialize(stream.writer());
    const header_data = stream.getWritten();

    // Calculate RandomX hash with proper difficulty
    var hash: [32]u8 = undefined;
    const difficulty_target = block.header.getDifficultyTarget();
    rx_ctx.hashWithDifficulty(header_data, &hash, difficulty_target.base_bytes) catch {
        print("❌ RandomX hash calculation failed during validation\n", .{});
        return false;
    };

    // Check if hash meets difficulty target
    return randomx.hashMeetsDifficultyTarget(hash, difficulty_target);
}
