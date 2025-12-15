// fuzz/validator_fuzz.zig - Fuzzing for transaction validation
// Randomized mutation-based fuzzing with thousands of iterations
// Finds edge cases and vulnerabilities through exhaustive random testing

const std = @import("std");
const testing = std.testing;
const zeicoin = @import("zeicoin");

const types = zeicoin.types;
const key = zeicoin.key;
const Transaction = types.Transaction;

// Fuzzing configuration
const FUZZ_ITERATIONS = 10_000; // Industry standard: 10k-1M iterations
const MAX_MUTATIONS_PER_TEST = 5; // How many fields to mutate per transaction

// Interesting values for fuzzing (edge cases that often reveal bugs)
const INTERESTING_U64_VALUES = [_]u64{
    0,
    1,
    std.math.maxInt(u64),
    std.math.maxInt(u64) - 1,
    std.math.maxInt(u64) / 2,
    std.math.maxInt(u64) / 2 + 1,
    std.math.maxInt(i64), // i64 max in u64
    types.ZEI_COIN,
    types.ZEI_COIN * 1000,
    types.ZEI_COIN * 1_000_000,
    types.MAX_SUPPLY,
    types.MAX_SUPPLY / 2,
};

const INTERESTING_I64_VALUES = [_]i64{
    0,
    1,
    -1,
    std.math.maxInt(i64),
    std.math.minInt(i64),
    std.math.maxInt(i64) / 2,
    std.math.minInt(i64) / 2,
};

// Fuzzing statistics for reporting
const FuzzStats = struct {
    iterations: usize = 0,
    crashes: usize = 0,
    invalid_caught: usize = 0,
    valid_accepted: usize = 0,
    mutations_applied: usize = 0,

    pub fn report(self: FuzzStats) void {
        std.debug.print("\n📊 Fuzzing Statistics:\n", .{});
        std.debug.print("  Total iterations: {}\n", .{self.iterations});
        std.debug.print("  Crashes detected: {} ⚠️\n", .{self.crashes});
        std.debug.print("  Invalid transactions caught: {}\n", .{self.invalid_caught});
        std.debug.print("  Valid transactions accepted: {}\n", .{self.valid_accepted});
        std.debug.print("  Total mutations applied: {}\n", .{self.mutations_applied});

        if (self.crashes > 0) {
            std.debug.print("  ❌ FUZZING FAILED: {} crashes detected!\n", .{self.crashes});
        } else {
            std.debug.print("  ✅ FUZZING PASSED: No crashes in {} iterations\n", .{self.iterations});
        }
    }
};

// Helper: Create a valid baseline transaction
fn createValidTransaction() !Transaction {
    var keypair = try key.KeyPair.generateNew();
    defer keypair.deinit();

    var recipient_keypair = try key.KeyPair.generateNew();
    defer recipient_keypair.deinit();

    var tx = Transaction{
        .version = 0,
        .flags = .{},
        .sender = keypair.getAddress(),
        .recipient = recipient_keypair.getAddress(),
        .amount = 100 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.timestamp()),
        .expiry_height = 1000,
        .sender_public_key = keypair.public_key,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    const signature = try keypair.signTransaction(tx.hash());
    tx.signature = signature;

    return tx;
}

// Mutation strategies (industry standard fuzzing techniques)

fn mutateAmount(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 4);
    switch (strategy) {
        0 => tx.amount = prng.int(u64), // Random value
        1 => tx.amount = INTERESTING_U64_VALUES[prng.uintLessThan(usize, INTERESTING_U64_VALUES.len)], // Interesting value
        2 => { // Bit flip
            const bit_pos = prng.uintLessThan(u8, 64);
            tx.amount ^= (@as(u64, 1) << @intCast(bit_pos));
        },
        3 => { // Arithmetic mutation
            const delta = prng.intRangeAtMost(i64, -1000, 1000);
            tx.amount = if (delta < 0)
                tx.amount -| @as(u64, @intCast(-delta))
            else
                tx.amount +| @as(u64, @intCast(delta));
        },
        else => unreachable,
    }
}

fn mutateFee(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 4);
    switch (strategy) {
        0 => tx.fee = prng.int(u64),
        1 => tx.fee = INTERESTING_U64_VALUES[prng.uintLessThan(usize, INTERESTING_U64_VALUES.len)],
        2 => {
            const bit_pos = prng.uintLessThan(u8, 64);
            tx.fee ^= (@as(u64, 1) << @intCast(bit_pos));
        },
        3 => {
            const delta = prng.intRangeAtMost(i64, -1000, 1000);
            tx.fee = if (delta < 0)
                tx.fee -| @as(u64, @intCast(-delta))
            else
                tx.fee +| @as(u64, @intCast(delta));
        },
        else => unreachable,
    }
}

fn mutateNonce(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 3);
    switch (strategy) {
        0 => tx.nonce = prng.int(u64),
        1 => tx.nonce = INTERESTING_U64_VALUES[prng.uintLessThan(usize, INTERESTING_U64_VALUES.len)],
        2 => {
            const bit_pos = prng.uintLessThan(u8, 64);
            tx.nonce ^= (@as(u64, 1) << @intCast(bit_pos));
        },
        else => unreachable,
    }
}

fn mutateTimestamp(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 4);
    switch (strategy) {
        0 => tx.timestamp = prng.int(u64),
        1 => tx.timestamp = INTERESTING_U64_VALUES[prng.uintLessThan(usize, INTERESTING_U64_VALUES.len)],
        2 => {
            const bit_pos = prng.uintLessThan(u8, 64);
            tx.timestamp ^= (@as(u64, 1) << @intCast(bit_pos));
        },
        3 => { // Adversarial: bitcast negative i64 to u64
            const negative_timestamp = INTERESTING_I64_VALUES[prng.uintLessThan(usize, INTERESTING_I64_VALUES.len)];
            tx.timestamp = @bitCast(negative_timestamp);
        },
        else => unreachable,
    }
}

fn mutateExpiryHeight(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 3);
    switch (strategy) {
        0 => tx.expiry_height = prng.int(u64),
        1 => tx.expiry_height = INTERESTING_U64_VALUES[prng.uintLessThan(usize, INTERESTING_U64_VALUES.len)],
        2 => {
            const bit_pos = prng.uintLessThan(u8, 64);
            tx.expiry_height ^= (@as(u64, 1) << @intCast(bit_pos));
        },
        else => unreachable,
    }
}

fn mutateSignature(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 5);
    switch (strategy) {
        0 => { // Flip random bits
            const num_flips = prng.uintLessThan(usize, 8);
            for (0..num_flips) |_| {
                const byte_idx = prng.uintLessThan(usize, 64);
                tx.signature[byte_idx] ^= prng.int(u8);
            }
        },
        1 => { // Zero out signature
            @memset(&tx.signature, 0);
        },
        2 => { // Max out signature
            @memset(&tx.signature, 0xFF);
        },
        3 => { // Random signature
            prng.bytes(&tx.signature);
        },
        4 => { // Flip single bit
            const byte_idx = prng.uintLessThan(usize, 64);
            const bit_idx = prng.uintLessThan(u8, 8);
            tx.signature[byte_idx] ^= (@as(u8, 1) << @intCast(bit_idx));
        },
        else => unreachable,
    }
}

fn mutatePublicKey(tx: *Transaction, prng: std.Random) void {
    const strategy = prng.uintLessThan(u8, 4);
    switch (strategy) {
        0 => { // Flip random bits
            const num_flips = prng.uintLessThan(usize, 4);
            for (0..num_flips) |_| {
                const byte_idx = prng.uintLessThan(usize, 32);
                tx.sender_public_key[byte_idx] ^= prng.int(u8);
            }
        },
        1 => { // Zero out public key
            @memset(&tx.sender_public_key, 0);
        },
        2 => { // Random public key
            prng.bytes(&tx.sender_public_key);
        },
        3 => { // Flip single bit
            const byte_idx = prng.uintLessThan(usize, 32);
            const bit_idx = prng.uintLessThan(u8, 8);
            tx.sender_public_key[byte_idx] ^= (@as(u8, 1) << @intCast(bit_idx));
        },
        else => unreachable,
    }
}

fn mutateVersion(tx: *Transaction, prng: std.Random) void {
    tx.version = prng.int(u16);
}

// Main fuzzing function
fn fuzzTransaction(tx: *Transaction, prng: std.Random) usize {
    const num_mutations = prng.uintLessThan(usize, MAX_MUTATIONS_PER_TEST) + 1;

    for (0..num_mutations) |_| {
        const mutation_type = prng.uintLessThan(u8, 9);
        switch (mutation_type) {
            0 => mutateAmount(tx, prng),
            1 => mutateFee(tx, prng),
            2 => mutateNonce(tx, prng),
            3 => mutateTimestamp(tx, prng),
            4 => mutateExpiryHeight(tx, prng),
            5 => mutateSignature(tx, prng),
            6 => mutatePublicKey(tx, prng),
            7 => mutateVersion(tx, prng),
            8 => { // Mutate sender/recipient addresses
                if (prng.boolean()) {
                    // Make sender == recipient (self-transfer)
                    tx.recipient = tx.sender;
                } else {
                    // Random address mutation
                    prng.bytes(&tx.sender.hash);
                    tx.sender.version = prng.int(u8);
                }
            },
            else => unreachable,
        }
    }

    return num_mutations;
}

test "fuzz transaction validator - randomized mutations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize PRNG with fixed seed for reproducibility
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    std.debug.print("\n🎲 FUZZING: Transaction validator with {} randomized iterations...\n", .{FUZZ_ITERATIONS});

    var stats = FuzzStats{};

    for (0..FUZZ_ITERATIONS) |i| {
        stats.iterations += 1;

        // Create valid baseline transaction
        var tx = createValidTransaction() catch |err| {
            std.debug.print("❌ Failed to create baseline transaction: {}\n", .{err});
            stats.crashes += 1;
            continue;
        };
        defer tx.deinit(allocator);

        // Apply random mutations
        const mutations = fuzzTransaction(&tx, random);
        stats.mutations_applied += mutations;

        // Test that isValid() never crashes (must return bool)
        const is_valid = tx.isValid();

        if (is_valid) {
            stats.valid_accepted += 1;
        } else {
            stats.invalid_caught += 1;
        }

        // Progress reporting every 1000 iterations
        if ((i + 1) % 1000 == 0) {
            std.debug.print("  Progress: {}/{} iterations ({} invalid caught)\n", .{ i + 1, FUZZ_ITERATIONS, stats.invalid_caught });
        }
    }

    stats.report();

    // Assert no crashes occurred
    try testing.expect(stats.crashes == 0);

    // Assert we caught some invalid transactions (should be most of them due to mutations)
    try testing.expect(stats.invalid_caught > FUZZ_ITERATIONS / 2);
}

test "fuzz transaction validator - overflow edge cases" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n🔢 FUZZING: Overflow edge cases with interesting values...\n", .{});

    var stats = FuzzStats{};

    // Test all combinations of interesting u64 values for amount and fee
    for (INTERESTING_U64_VALUES) |amount| {
        for (INTERESTING_U64_VALUES) |fee| {
            stats.iterations += 1;

            var tx = createValidTransaction() catch continue;
            defer tx.deinit(allocator);

            tx.amount = amount;
            tx.fee = fee;

            // Must not crash
            const is_valid = tx.isValid();

            if (is_valid) {
                stats.valid_accepted += 1;
            } else {
                stats.invalid_caught += 1;
            }
        }
    }

    stats.report();

    try testing.expect(stats.crashes == 0);
}

test "fuzz transaction validator - signature bit flips" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var prng = std.Random.DefaultPrng.init(54321);
    const random = prng.random();

    std.debug.print("\n🔐 FUZZING: Signature integrity with bit flip attacks...\n", .{});

    var stats = FuzzStats{};

    // Test 1000 random signature mutations
    for (0..1000) |_| {
        stats.iterations += 1;

        var tx = createValidTransaction() catch continue;
        defer tx.deinit(allocator);

        // Randomly corrupt signature
        mutateSignature(&tx, random);
        stats.mutations_applied += 1;

        // Must not crash (isValid only checks structure, not crypto)
        const is_valid = tx.isValid();

        if (is_valid) {
            stats.valid_accepted += 1;
        } else {
            stats.invalid_caught += 1;
        }
    }

    stats.report();

    try testing.expect(stats.crashes == 0);
    // Note: isValid() only checks structure, not cryptographic validity
    // Signature verification happens in mempool validator
    // So we only verify no crashes here
}
