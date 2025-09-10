// randomx.zig - RandomX Mining Algorithm
// Production RandomX proof-of-work implementation with ASIC resistance

const std = @import("std");
const log = std.log.scoped(.mining);

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
        log.info("❌ Failed to initialize RandomX context", .{});
        return false;
    };
    defer rx_ctx.deinit();

    log.info("🔍 Starting RandomX mining, difficulty {x}", .{block.header.difficulty});

    // Capture the starting height to detect if a new block arrives from network
    const starting_height = ctx.mining_state.current_height.load(.acquire);
    log.info("🔍 zenProofOfWorkRandomX: starting at height {}", .{starting_height});

    var nonce: u32 = 0;
    const difficulty_target = block.header.getDifficultyTarget();
    const mining_start_time = std.time.milliTimestamp();
    
    while (nonce < types.ZenMining.MAX_NONCE) {
        // Check if blockchain height changed (another miner found a block)
        const current_height = ctx.blockchain.getHeight() catch starting_height;
        if (current_height > starting_height) {
            log.info("🛑 [MINING PREEMPTED] New block received at height {} (was mining height {})", .{current_height, starting_height});
            return false; // Stop mining this obsolete block
        }

        // Check if we should stop mining
        if (!ctx.mining_state.active.load(.acquire)) {
            log.info("🛑 Mining stopped by request", .{});
            return false;
        }

        block.header.nonce = nonce;

        // Serialize block header for RandomX input
        var buffer: [256]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        block.header.serialize(stream.writer()) catch |err| {
            log.info("❌ Failed to serialize block header: {}", .{err});
            return false;
        };
        const header_data = stream.getWritten();

        // Calculate RandomX hash with proper difficulty
        var hash: [32]u8 = undefined;
        rx_ctx.hashWithDifficulty(header_data, &hash, difficulty_target.base_bytes) catch |err| {
            log.info("❌ RandomX hash calculation failed: {}", .{err});
            return false;
        };

        // Check if hash meets difficulty target
        if (randomx.hashMeetsDifficultyTarget(hash, difficulty_target)) {
            log.info("✨ RandomX nonce found: {} (hash: {s})", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
            return true;
        }

        nonce += 1;

        // Progress indicator (every 10k tries for RandomX due to slower speed)
        if (nonce % types.PROGRESS.RANDOMX_REPORT_INTERVAL == 0) {
            const elapsed_ms = std.time.milliTimestamp() - mining_start_time;
            const elapsed_sec = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
            const hash_rate = if (elapsed_sec > 0) @as(f64, @floatFromInt(nonce)) / elapsed_sec else 0;
            const elapsed_min = @divFloor(elapsed_ms, 60000);
            const elapsed_sec_remainder = @rem(@divFloor(elapsed_ms, 1000), 60);
            
            log.info("⛏️  Mining block #{} | {} hashes tried | {d:.1} H/s | {}m {}s elapsed", .{ 
                starting_height + 1,
                nonce, 
                hash_rate,
                elapsed_min,
                elapsed_sec_remainder
            });
        }
    }

    log.info("😔 RandomX mining exhausted nonce space", .{});
    return false;
}