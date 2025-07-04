// randomx.zig - RandomX Mining Algorithm
// Production RandomX proof-of-work implementation with ASIC resistance

const std = @import("std");
const print = std.debug.print;

const types = @import("../../types/types.zig");
const util = @import("../../util/util.zig");
const randomx = @import("../../crypto/randomx.zig");
const MiningContext = @import("../context.zig").MiningContext;

/// Zen Proof-of-Work using RandomX for production mining
pub fn zenProofOfWorkRandomX(ctx: MiningContext, block: *types.Block) bool {
    // Initialize RandomX context for production
    const network_name = switch (types.CURRENT_NETWORK) {
        .testnet => "TestNet",
        .mainnet => "MainNet",
    };
    const chain_key = randomx.createRandomXKey(network_name);
    
    // Convert binary key to hex string for RandomX helper
    var hex_key: [64]u8 = undefined;
    for (chain_key, 0..) |byte, i| {
        _ = std.fmt.bufPrint(hex_key[i*2..i*2+2], "{x:0>2}", .{byte}) catch unreachable;
    }
    
    const mode: randomx.RandomXMode = if (types.ZenMining.RANDOMX_MODE) .fast else .light;
    var rx_ctx = randomx.RandomXContext.init(ctx.allocator, &hex_key, mode) catch {
        print("❌ Failed to initialize RandomX context\n", .{});
        return false;
    };
    defer rx_ctx.deinit();

    print("🔍 Starting RandomX mining with {} threads, difficulty {x}\n", .{ types.ZenMining.THREADS, block.header.difficulty });

    // Capture the starting height to detect if a new block arrives from network
    const starting_height = ctx.mining_state.current_height.load(.acquire);
    print("🔍 zenProofOfWorkRandomX: starting at height {}\n", .{starting_height});

    var nonce: u32 = 0;
    const difficulty_target = block.header.getDifficultyTarget();
    
    while (nonce < types.ZenMining.MAX_NONCE) {
        // Check if blockchain height changed (another miner found a block)
        const current_height = ctx.blockchain.getHeight() catch starting_height;
        if (current_height > starting_height) {
            print("🛑 Mining stopped - new block received at height {}\n", .{current_height});
            return false; // Stop mining this obsolete block
        }

        // Check if we should stop mining
        if (!ctx.mining_state.active.load(.acquire)) {
            print("🛑 Mining stopped by request\n", .{});
            return false;
        }

        block.header.nonce = nonce;

        // Serialize block header for RandomX input
        var buffer: [256]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        block.header.serialize(stream.writer()) catch |err| {
            print("❌ Failed to serialize block header: {}\n", .{err});
            return false;
        };
        const header_data = stream.getWritten();

        // Calculate RandomX hash with proper difficulty
        var hash: [32]u8 = undefined;
        rx_ctx.hashWithDifficulty(header_data, &hash, difficulty_target.base_bytes) catch |err| {
            print("❌ RandomX hash calculation failed: {}\n", .{err});
            return false;
        };

        // Check if hash meets difficulty target
        if (randomx.hashMeetsDifficultyTarget(hash, difficulty_target)) {
            print("✨ RandomX nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
            return true;
        }

        nonce += 1;

        // Progress indicator (every 10k tries for RandomX due to slower speed)
        if (nonce % types.PROGRESS.RANDOMX_REPORT_INTERVAL == 0) {
            print("⛏️  RandomX mining... tried {} nonces ({d:.1} nonces/sec)\n", .{ nonce, @as(f64, @floatFromInt(nonce)) / (@as(f64, @floatFromInt(util.getTime() - starting_height)) + 1.0) });
        }
    }

    print("😔 RandomX mining exhausted nonce space\n", .{});
    return false;
}