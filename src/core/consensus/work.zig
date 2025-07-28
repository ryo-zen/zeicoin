// work.zig - ZeiCoin Proof-of-Work Calculation
// Mission-critical consensus code that CANNOT fail
// Implements industry-standard work calculation: work = 2^256 / (target + 1)

const std = @import("std");
const print = std.debug.print;
const testing = std.testing;

/// 256-bit chain work type - maximum precision for consensus
pub const ChainWork = u256;

/// 256-bit difficulty target - industry standard precision
pub const DifficultyTarget = u256;

/// ZeiCoin consensus constants
pub const CONSENSUS = struct {
    /// Maximum possible target (all bits set) - industry standard
    pub const MAX_TARGET: DifficultyTarget = std.math.maxInt(u256);

    /// Minimum work value (when target = MAX_TARGET)
    pub const MIN_WORK: ChainWork = 1;

    /// Maximum work value (when target = 1) - theoretical maximum
    pub const MAX_WORK: ChainWork = std.math.maxInt(u256);
};

/// ZeiCoin work calculation with zero tolerance for error
/// Formula: work = ~target / (target + 1) + 1
/// Industry-standard proof-of-work calculation for Nakamoto consensus
pub fn calculateWork(target: DifficultyTarget) ChainWork {
    // Handle edge case: target = 0 would cause division by zero
    if (target == 0) {
        return 0; // Invalid targets return zero work
    }

    // Handle edge case: target = MAX_TARGET would cause overflow in target + 1
    if (target == CONSENSUS.MAX_TARGET) {
        return 1; // Minimum work for maximum target
    }

    // Industry-standard algorithm for proof-of-work:
    // We need to compute 2**256 / (target+1), but we can't represent 2**256
    // as it's too large for a u256. However, as 2**256 is at least as large
    // as target+1, it is equal to ((2**256 - target - 1) / (target+1)) + 1,
    // or ~target / (target+1) + 1.

    const inverted_target = ~target; // Bitwise NOT of target
    const denominator = target + 1;

    return (inverted_target / denominator) + 1;
}

/// Convert ZeiCoin difficulty format to 256-bit target
/// ZeiCoin uses: base_bytes (leading zeros) + threshold (next 4 bytes)
/// Output: full 256-bit target value for work calculation
///
/// ZeiCoin format: [base_bytes zeros][threshold 4 bytes][remaining 0xFF bytes]
/// More leading zeros = smaller target = higher difficulty = more work
pub fn zeiCoinToTarget(base_bytes: u8, threshold: u32) DifficultyTarget {
    // Validate inputs to prevent overflow
    if (base_bytes >= 31) { // Leave room for threshold bytes
        // Too many leading zero bytes - return minimum target (maximum difficulty)
        return 1;
    }

    if (threshold == 0) {
        // Zero threshold - return minimum target (maximum difficulty)
        return 1;
    }

    // Build target step by step: [zeros][threshold][fill]
    var target: DifficultyTarget = 0;

    // Position threshold after the leading zero bytes
    // Each base_byte represents 8 bits of leading zeros
    const threshold_position = @as(u16, base_bytes) * 8;

    if (threshold_position + 32 <= 256) { // Ensure we don't overflow
        // Place threshold at the correct bit position
        const shift_amount: u16 = 256 - threshold_position - 32;
        target = @as(DifficultyTarget, threshold) << @intCast(shift_amount);

        // Fill the remaining lower bits with 0xFF pattern (except the threshold area)
        if (threshold_position + 32 < 256) {
            const fill_bits: u16 = 256 - threshold_position - 32;
            if (fill_bits <= 64) { // Safety limit for shift operations
                const fill_mask = (@as(DifficultyTarget, 1) << @intCast(fill_bits)) - 1;
                target = target | fill_mask;
            } else {
                // For large fills, set maximum possible value in lower bits
                target = target | 0xFFFFFFFFFFFFFFFF; // Fill lower 64 bits
            }
        }
    } else {
        // Fallback: if positioning would overflow, just use threshold value
        target = threshold;
    }

    // Ensure target is never zero (would cause division by zero)
    if (target == 0) {
        return 1;
    }

    return target;
}

/// Cumulative work tracker for efficient chain comparison
/// Stores cumulative work from genesis to avoid O(n) recalculation
pub const CumulativeWork = struct {
    work: ChainWork,

    /// Initialize with genesis work
    pub fn init(genesis_work: ChainWork) CumulativeWork {
        return .{ .work = genesis_work };
    }

    /// Add work from a new block - this is the ONLY way to update cumulative work
    /// Returns error if overflow would occur (blockchain too long)
    pub fn addBlockWork(self: *CumulativeWork, block_work: ChainWork) !void {
        // Check for overflow before adding
        if (self.work > CONSENSUS.MAX_WORK - block_work) {
            return error.ChainWorkOverflow;
        }

        self.work += block_work;
    }

    /// Compare two cumulative work values
    /// Returns true if this chain has more work (should be selected)
    pub fn hasMoreWork(self: CumulativeWork, other: CumulativeWork) bool {
        return self.work > other.work;
    }

    /// Get the raw work value (for debugging only)
    pub fn getValue(self: CumulativeWork) ChainWork {
        return self.work;
    }
};

/// Work calculation error types
pub const WorkError = error{
    ChainWorkOverflow,
    InvalidTarget,
    InvalidDifficulty,
};

// =============================================================================
// COMPREHENSIVE TEST SUITE
// =============================================================================

test "work calculation basic functionality" {
    // Test minimum difficulty (maximum target)
    const max_target = CONSENSUS.MAX_TARGET;
    const min_work = calculateWork(max_target);
    try testing.expect(min_work == CONSENSUS.MIN_WORK);

    // Test maximum difficulty (minimum target)
    const min_target: DifficultyTarget = 1;
    const max_work = calculateWork(min_target);
    try testing.expect(max_work > min_work);

    // Test that higher target = lower work
    const target1: DifficultyTarget = 1000;
    const target2: DifficultyTarget = 2000;
    const work1 = calculateWork(target1);
    const work2 = calculateWork(target2);
    try testing.expect(work1 > work2); // Lower target = higher work
}

test "work calculation edge cases" {
    // Test target = 0 (should not crash)
    const zero_work = calculateWork(0);
    try testing.expect(zero_work == 0);

    // Test target = 1 (maximum difficulty)
    const one_work = calculateWork(1);
    try testing.expect(one_work > 0);

    // Test target = MAX_TARGET - 1
    const near_max_work = calculateWork(CONSENSUS.MAX_TARGET - 1);
    try testing.expect(near_max_work >= 1); // Should be at least 1
}

test "ZeiCoin difficulty conversion" {
    // Test basic conversion
    const target1 = zeiCoinToTarget(1, 0xF0000000);
    try testing.expect(target1 > 0);

    // Test with more leading zeros (higher difficulty)
    const target2 = zeiCoinToTarget(2, 0xF0000000);
    const work1 = calculateWork(target1);
    const work2 = calculateWork(target2);

    // Verify that more leading zeros = higher difficulty = more work

    try testing.expect(work2 > work1); // More leading zeros = higher work

    // Test edge cases
    const edge_target1 = zeiCoinToTarget(0, 0xFFFFFFFF); // No leading zeros, max threshold
    const edge_target2 = zeiCoinToTarget(31, 1); // Max leading zeros, min threshold
    try testing.expect(edge_target1 > 0);
    try testing.expect(edge_target2 > 0);
}

test "cumulative work tracking" {
    var cumulative = CumulativeWork.init(100);
    try testing.expect(cumulative.getValue() == 100);

    // Add block work
    try cumulative.addBlockWork(50);
    try testing.expect(cumulative.getValue() == 150);

    // Test work comparison
    var other = CumulativeWork.init(120);
    try testing.expect(cumulative.hasMoreWork(other));
    try testing.expect(!other.hasMoreWork(cumulative));
}

test "cumulative work overflow protection" {
    var cumulative = CumulativeWork.init(CONSENSUS.MAX_WORK - 10);

    // This should succeed
    try cumulative.addBlockWork(5);
    try testing.expect(cumulative.getValue() == CONSENSUS.MAX_WORK - 5);

    // This should fail with overflow
    try testing.expectError(error.ChainWorkOverflow, cumulative.addBlockWork(10));
}

// ZeiCoin consensus validation test
test "ZeiCoin consensus compatibility" {
    // Test with ZeiCoin testnet difficulty settings
    const testnet_target = zeiCoinToTarget(1, 0x00ffff00);
    const testnet_work = calculateWork(testnet_target);
    try testing.expect(testnet_work > 0);

    // Test work ordering: lower target should give higher work
    const higher_diff_target = zeiCoinToTarget(2, 0x00ffff00); // More leading zeros
    const higher_diff_work = calculateWork(higher_diff_target);
    try testing.expect(higher_diff_work > testnet_work);
}

test "work calculation mathematical properties" {
    // Test that work is inversely proportional to target
    const targets = [_]DifficultyTarget{ 1000, 2000, 4000, 8000 };
    var prev_work: ChainWork = std.math.maxInt(ChainWork);

    for (targets) |target| {
        const work = calculateWork(target);
        try testing.expect(work < prev_work); // Work should decrease as target increases
        prev_work = work;
    }
}

test "deterministic work calculation" {
    // Same target should always produce same work
    const target: DifficultyTarget = 12345;
    const work1 = calculateWork(target);
    const work2 = calculateWork(target);
    const work3 = calculateWork(target);

    try testing.expect(work1 == work2);
    try testing.expect(work2 == work3);
}
