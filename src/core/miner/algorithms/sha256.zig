// sha256.zig - SHA256 Mining Algorithm
// Fast SHA256 proof-of-work implementation for debug/testing

const std = @import("std");
const print = std.debug.print;

const types = @import("../../types/types.zig");
const MiningContext = @import("../context.zig").MiningContext;

/// Legacy SHA256 proof-of-work for tests (faster)
pub fn zenProofOfWorkSHA256(ctx: MiningContext, block: *types.Block) bool {
    _ = ctx; // Temporarily disable height check
    print("🔍 zenProofOfWorkSHA256: Using SHA256 mining\n", .{});
    var nonce: u32 = 0;
    while (nonce < types.ZenMining.MAX_NONCE) {

        block.header.nonce = nonce;

        // Calculate block hash using SHA256
        const hash = block.header.hash();

        // Check if hash meets zen difficulty
        const difficulty_target = block.header.getDifficultyTarget();
        if (difficulty_target.meetsDifficulty(hash)) {
            print("✨ Zen nonce found: {} (hash: {s})\n", .{ nonce, std.fmt.fmtSliceHexLower(hash[0..8]) });
            return true;
        }

        nonce += 1;

        // Check more frequently for SHA256 (every 100k nonces)
        // Temporarily disabled

        // Progress indicator (every 100k tries)
        if (nonce % types.PROGRESS.SHA256_REPORT_INTERVAL == 0) {
            print("Zen mining... tried {} nonces\n", .{nonce});
        }
    }

    return false;
}