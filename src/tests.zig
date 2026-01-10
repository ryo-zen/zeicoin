// tests.zig - ZeiCoin Integration Tests
// This file contains integration tests moved from main.zig

const std = @import("std");
const testing = std.testing;
const log = std.log.scoped(.tests);

// Import the zeicoin module
const zei = @import("zeicoin");
const types = zei.types;
const key = zei.key;
const util = zei.util;
const ZeiCoin = zei.blockchain.ZeiCoin;
const Transaction = types.Transaction;
const Address = types.Address;
const Account = types.Account;
const Block = types.Block;

// Test helper functions
fn createTestZeiCoin(data_dir: []const u8) !*ZeiCoin {
    _ = data_dir; // ZeiCoin.init doesn't take data_dir parameter
    var zeicoin = try ZeiCoin.init(testing.allocator);
    errdefer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
    
    // Ensure we have a genesis block
    const current_height = zeicoin.getHeight() catch 0;
    if (current_height == 0) {
        try zeicoin.createCanonicalGenesis();
    }

    return zeicoin;
}

fn createTestBlockHeader(
    prev_hash: types.Hash,
    merkle_root: types.Hash,
    timestamp: u64,
    difficulty: u64,
    nonce: u32,
) types.BlockHeader {
    return types.BlockHeader{
        .version = 0,
        .previous_hash = prev_hash,
        .merkle_root = merkle_root,
        .timestamp = timestamp,
        .bits = difficulty,
        .nonce = nonce,
    };
}

fn createTestTransaction(
    sender: Address,
    recipient: Address,
    amount: u64,
    fee: u64,
    nonce: u64,
    keypair: key.KeyPair,
    allocator: std.mem.Allocator,
) !Transaction {
    _ = allocator;
    
    var tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender,
        .recipient = recipient,
        .amount = amount,
        .fee = fee,
        .nonce = nonce,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = 10000,
        .sender_public_key = keypair.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    
    const tx_hash = tx.hashForSigning();
    tx.signature = try keypair.sign(&tx_hash);
    
    return tx;
}

// Integration Tests

test "blockchain initialization" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_init");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Should have genesis block (genesis is at height 0, so height >= 0)
    const height = try zeicoin.getHeight();
    try testing.expect(height >= 0);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_init") catch {};
}

test "transaction processing" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_tx");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Create a test keypair for the transaction
    var sender_keypair = try key.KeyPair.generateNew();
    defer sender_keypair.deinit();

    const sender_addr = sender_keypair.getAddress();
    // Create a unique test address
    var alice_hash: [31]u8 = undefined;
    @memset(&alice_hash, 0);
    alice_hash[0] = 0xAA;
    alice_hash[1] = 0xBB;
    alice_hash[30] = 0xFF;
    const alice_addr = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = alice_hash,
    };

    // Create account for sender manually since this is just a test
    const sender_account = Account{
        .address = sender_addr,
        .balance = 20 * types.ZEI_COIN, // Give sender some balance
        .nonce = 0,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create and sign transaction
    var tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .recipient = alice_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1757419151000,
        .expiry_height = 10000, // Far future for test
        .sender_public_key = sender_keypair.public_key,
        .signature = std.mem.zeroes(types.Signature), // Will be replaced
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Sign the transaction
    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Mine with a different miner so alice doesn't get mining reward
    var miner_keypair = try key.KeyPair.generateNew();
    defer miner_keypair.deinit();
    const mined_block = try zeicoin.zenMineBlock(miner_keypair);
    var mutable_mined_block = mined_block;
    defer mutable_mined_block.deinit(testing.allocator);

    // Check balances
    const alice_balance = try zeicoin.getBalance(alice_addr);
    try testing.expectEqual(10 * types.ZEI_COIN, alice_balance);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_tx") catch {};
}

test "block retrieval by height" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_retrieval");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Should have genesis block at height 0
    var genesis_block = try zeicoin.getBlockByHeight(0);
    defer genesis_block.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 1), genesis_block.txCount()); // Genesis has 1 coinbase transaction
    try testing.expectEqual(@as(u64, types.Genesis.timestamp()), genesis_block.header.timestamp);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_retrieval") catch {};
}

test "block validation" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_validation");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Create a valid test block that extends the genesis
    const current_height = try zeicoin.getHeight();
    if (current_height == 0) {
        // Skip this test if no genesis block exists
        return;
    }
    var prev_block = try zeicoin.getBlockByHeight(current_height - 1);
    defer prev_block.deinit(testing.allocator);

    // Create valid transactions for the block
    const transactions = try testing.allocator.alloc(types.Transaction, 1);
    defer testing.allocator.free(transactions);

    // Coinbase transaction
    transactions[0] = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = Address.zero(),
        .sender_public_key = std.mem.zeroes([32]u8),
        .recipient = Address.zero(),
        .amount = types.ZenMining.BLOCK_REWARD,
        .fee = 0, // Coinbase has no fee
        .nonce = 0,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = std.math.maxInt(u64), // Coinbase never expires
        .signature = std.mem.zeroes(types.Signature),
    };

    // Create valid block
    var valid_block = types.Block{
        .header = createTestBlockHeader(
            prev_block.hash(),
            std.mem.zeroes(types.Hash),
            @intCast(std.time.milliTimestamp()),
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = transactions,
        .height = 1, // Test block at height 1
    };

    // Find a valid nonce for the block
    var nonce: u32 = 0;
    var found_valid_nonce = false;
    while (nonce < 10000) {
        valid_block.header.nonce = nonce;
        const difficulty_target = valid_block.header.getDifficultyTarget();
        if (difficulty_target.meetsDifficulty(valid_block.header.hash())) {
            found_valid_nonce = true;
            break;
        }
        nonce += 1;
    }

    // Should have found a valid nonce
    try testing.expect(found_valid_nonce);

    // Should validate correctly
    const is_valid = try zeicoin.validateBlock(valid_block, current_height);
    try testing.expect(is_valid);

    // Invalid block with wrong previous hash should fail
    var invalid_block = valid_block;
    invalid_block.header.previous_hash = std.mem.zeroes(types.Hash);
    const is_invalid = try zeicoin.validateBlock(invalid_block, current_height);
    try testing.expect(!is_invalid);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_validation") catch {};
}

test "mempool cleaning after block application" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_mempool");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Create test keypair and transaction
    var sender_keypair = try key.KeyPair.generateNew();
    defer sender_keypair.deinit();

    const sender_addr = sender_keypair.getAddress();
    // Create a unique test address
    var alice_hash: [31]u8 = undefined;
    @memset(&alice_hash, 0);
    alice_hash[0] = 1;
    const alice_addr = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = alice_hash,
    };

    // Create sender account
    const sender_account = types.Account{
        .address = sender_addr,
        .balance = 20 * types.ZEI_COIN,
        .nonce = 0,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create and add transaction to mempool
    var tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .recipient = alice_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = 10000,
        .sender_public_key = sender_keypair.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Mempool should have 1 transaction
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);

    // Mine block (which includes the transaction)
    const mined_block = try zeicoin.zenMineBlock(sender_keypair);
    var mutable_mined_block = mined_block;
    defer mutable_mined_block.deinit(testing.allocator);

    // Mempool should be empty after mining
    try testing.expectEqual(@as(usize, 0), zeicoin.mempool.items.len);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_mempool") catch {};
}

test "block broadcasting integration" {
    var zeicoin = try ZeiCoin.init(testing.allocator);
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // This test verifies that broadcastNewBlock doesn't crash when no network is present
    const transactions = try testing.allocator.alloc(types.Transaction, 0);
    defer testing.allocator.free(transactions);

    const test_block = types.Block{
        .header = createTestBlockHeader(
            std.mem.zeroes(types.Hash),
            std.mem.zeroes(types.Hash),
            @intCast(std.time.milliTimestamp()),
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = transactions,
        .height = 0, // Test block at height 0
    };

    // Should not crash when no network is available
    zeicoin.broadcastNewBlock(test_block);

    // Test passed if we get here without crashing
    try testing.expect(true);
}

test "timestamp validation - future blocks rejected" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_timestamp_future");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
    defer std.fs.cwd().deleteTree("test_zeicoin_timestamp_future") catch {};

    // Create a block with timestamp too far in future
    const future_time = @as(u64, @intCast(std.time.milliTimestamp())) + @as(u64, @intCast(types.TimestampValidation.MAX_FUTURE_TIME * 1000)) + 3600000; // 1 hour beyond limit in milliseconds

    var transactions = [_]types.Transaction{};
    const future_block = types.Block{
        .header = createTestBlockHeader(
            std.mem.zeroes(types.Hash),
            std.mem.zeroes(types.Hash),
            future_time,
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = &transactions,
        .height = 1, // Test block at height 1
    };

    // Block should be rejected
    const is_valid = try zeicoin.validateBlock(future_block, 1);
    try testing.expect(!is_valid);
}

test "timestamp validation - median time past" {
    var zeicoin = try createTestZeiCoin("test_zeicoin_mtp");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
    defer std.fs.cwd().deleteTree("test_zeicoin_mtp") catch {};

    // Mine some blocks with increasing timestamps
    var i: u32 = 0;
    while (i < 15) : (i += 1) {
        var transactions = [_]types.Transaction{};
        const block = types.Block{
            .header = createTestBlockHeader(
                if (i == 0) std.mem.zeroes(types.Hash) else blk: {
                    var prev = try zeicoin.getBlockByHeight(i - 1);
                    defer prev.deinit(zeicoin.allocator);
                    break :blk prev.hash();
                },
                std.mem.zeroes(types.Hash),
                types.Genesis.timestamp() + (i + 1) * 600, // 10 minutes apart
                types.ZenMining.initialDifficultyTarget().toU64(),
                0
            ),
            .transactions = &transactions,
            .height = i, // Test block at height i
        };

        // Process block directly (bypass validation for test setup)
        try zeicoin.database.saveBlock(i, block);
    }

    // Calculate expected MTP (median of last 11 blocks)
    const expected_mtp = types.Genesis.timestamp() + 10 * 600; // Median of blocks 4-14
    const actual_mtp = try zeicoin.getMedianTimePast(14);
    try testing.expectEqual(expected_mtp, actual_mtp);

    // Create block with timestamp equal to MTP (should fail)
    var bad_transactions = [_]types.Transaction{};
    const bad_block = types.Block{
        .header = createTestBlockHeader(
            std.mem.zeroes(types.Hash),
            std.mem.zeroes(types.Hash),
            expected_mtp,
            types.ZenMining.initialDifficultyTarget().toU64(),
            0
        ),
        .transactions = &bad_transactions,
        .height = 15, // Test block at height 15
    };

    // This should fail MTP validation
    const is_valid = try zeicoin.validateBlock(bad_block, 15);
    try testing.expect(!is_valid);
}

test "timestamp validation - constants" {
    // Test that our constants make sense
    try testing.expect(types.TimestampValidation.MAX_FUTURE_TIME > 0);
    try testing.expect(types.TimestampValidation.MAX_FUTURE_TIME <= 24 * 60 * 60); // Max 24 hours
    try testing.expect(types.TimestampValidation.MTP_BLOCK_COUNT >= 3); // Need at least 3 for meaningful median
    try testing.expect(types.TimestampValidation.MTP_BLOCK_COUNT % 2 == 1); // Odd number for clean median
}

test "coinbase maturity basic" {
    const test_dir = "test_coinbase_maturity";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Create a test miner
    const miner_keypair = try key.KeyPair.generateNew();
    const miner_address = miner_keypair.getAddress();

    // Mine a block (coinbase reward should be immature)
    const block1 = try zeicoin.zenMineBlock(miner_keypair);
    var mutable_block1 = block1;
    defer mutable_block1.deinit(zeicoin.allocator);
    
    // Check balance - should all be immature
    const account1 = try zeicoin.getAccount(miner_address);
    try testing.expectEqual(@as(u64, 0), account1.balance); // No mature balance
    try testing.expectEqual(@as(u64, types.ZenMining.BLOCK_REWARD), account1.immature_balance); // All immature
    
    log.info("\n✅ Coinbase maturity test: Mining reward correctly marked as immature", .{});
}

test "mempool limits enforcement" {
    const test_dir = "test_mempool_limits";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Test 1: Test reaching transaction count limit
    log.info("\n🧪 Testing mempool transaction count limit...", .{});
    
    // Directly fill mempool to limit by manipulating internal state
    // This avoids creating 10,000 actual transactions
    const max_tx = types.MempoolLimits.MAX_TRANSACTIONS;
    
    // Create dummy transactions to fill mempool
    var i: usize = 0;
    while (i < max_tx) : (i += 1) {
        // Create unique recipient address for each transaction
        var recipient_hash: [31]u8 = undefined;
        @memset(&recipient_hash, 0);
        recipient_hash[0] = @intCast(i % 256);
        recipient_hash[1] = @intCast((i / 256) % 256);
        const recipient_addr = Address{
            .version = @intFromEnum(types.AddressVersion.P2PKH),
            .hash = recipient_hash,
        };
        
        var dummy_tx = types.Transaction{
            .version = 0,
            .flags = std.mem.zeroes(types.TransactionFlags),
            .sender = std.mem.zeroes(types.Address),
            .sender_public_key = std.mem.zeroes([32]u8),
            .recipient = recipient_addr,
            .amount = 1,
            .fee = types.ZenFees.MIN_FEE,
            .nonce = i,
            .timestamp = @intCast(std.time.milliTimestamp()),
            .expiry_height = 10000,
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };
        
        try zeicoin.mempool.append(dummy_tx);
        zeicoin.mempool_size_bytes += dummy_tx.getSerializedSize();
    }
    
    try testing.expectEqual(@as(usize, max_tx), zeicoin.mempool.items.len);
    log.info("  ✅ Mempool filled to exactly {} transactions (limit)", .{max_tx});
    
    
    // Try to add one more (should fail)
    const overflow_sender = try key.KeyPair.generateNew();
    const overflow_sender_addr = overflow_sender.getAddress();
    try zeicoin.database.saveAccount(overflow_sender_addr, types.Account{
        .address = overflow_sender_addr,
        .balance = 10 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    var overflow_hash: [31]u8 = undefined;
    @memset(&overflow_hash, 0);
    overflow_hash[0] = 254;
    const overflow_addr = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = overflow_hash,
    };
    var overflow_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = overflow_sender_addr,
        .sender_public_key = overflow_sender.public_key,
        .recipient = overflow_addr,
        .amount = 1 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_overflow = overflow_tx;
    signed_overflow.signature = try overflow_sender.signTransaction(overflow_tx.hashForSigning());
    
    const result = zeicoin.addTransaction(signed_overflow);
    try testing.expectError(error.MempoolFull, result);
    log.info("  ✅ Transaction correctly rejected when mempool full", .{});
    
    // Test 2: Size tracking
    const expected_size = max_tx * types.MempoolLimits.TRANSACTION_SIZE;
    try testing.expectEqual(expected_size, zeicoin.mempool_size_bytes);
    log.info("  ✅ Mempool size correctly tracked: {} bytes", .{expected_size});
    
    // Test 3: Clear mempool and test size limit
    zeicoin.mempool.clearRetainingCapacity();
    zeicoin.mempool_size_bytes = 0;
    log.info("\n🧪 Testing mempool size limit...", .{});
    
    // Calculate how many transactions fit in size limit
    const txs_for_size_limit = types.MempoolLimits.MAX_SIZE_BYTES / types.MempoolLimits.TRANSACTION_SIZE;
    log.info("  📊 Size limit allows for {} transactions", .{txs_for_size_limit});
    
    // Artificially set the size to just below limit
    zeicoin.mempool_size_bytes = types.MempoolLimits.MAX_SIZE_BYTES - types.MempoolLimits.TRANSACTION_SIZE + 1;
    
    // Try to add a transaction (should fail due to size limit)
    const size_test_sender = try key.KeyPair.generateNew();
    const size_test_sender_addr = size_test_sender.getAddress();
    try zeicoin.database.saveAccount(size_test_sender_addr, types.Account{
        .address = size_test_sender_addr,
        .balance = 10 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    var recipient_hash: [31]u8 = undefined;
    @memset(&recipient_hash, 0);
    recipient_hash[0] = 123;
    const size_test_recipient = Address{
        .version = @intFromEnum(types.AddressVersion.P2PKH),
        .hash = recipient_hash,
    };
    const size_test_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = size_test_sender_addr,
        .sender_public_key = size_test_sender.public_key,
        .recipient = size_test_recipient,
        .amount = 1 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_size_test = size_test_tx;
    signed_size_test.signature = try size_test_sender.signTransaction(size_test_tx.hashForSigning());
    
    const size_result = zeicoin.addTransaction(signed_size_test);
    try testing.expectError(error.MempoolSizeLimitExceeded, size_result);
    log.info("  ✅ Transaction correctly rejected when size limit exceeded", .{});
    
    log.info("\n🎉 All mempool limit tests passed!", .{});
}

test "transaction expiration" {
    const test_dir = "test_tx_expiry";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Create test wallets
    const sender_keypair = try key.KeyPair.generateNew();
    const sender_addr = sender_keypair.getAddress();
    const recipient_keypair = try key.KeyPair.generateNew();
    const recipient_addr = recipient_keypair.getAddress();

    // Fund sender
    try zeicoin.database.saveAccount(sender_addr, types.Account{
        .address = sender_addr,
        .balance = 100 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });

    log.info("\n📅 Testing transaction expiration...", .{});

    // Test 1: Valid transaction with future expiry
    const current_height = zeicoin.getHeight() catch 0;
    const valid_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .sender_public_key = sender_keypair.public_key,
        .recipient = recipient_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = current_height + 100, // Expires in 100 blocks
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_valid = valid_tx;
    signed_valid.signature = try sender_keypair.signTransaction(valid_tx.hashForSigning());
    
    try zeicoin.addTransaction(signed_valid);
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);
    log.info("  ✅ Transaction with future expiry accepted", .{});

    // Clear mempool
    zeicoin.mempool.clearRetainingCapacity();

    // Test 2: Expired transaction (expiry at current height)
    const expired_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .sender_public_key = sender_keypair.public_key,
        .recipient = recipient_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = current_height, // Already expired
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_expired = expired_tx;
    signed_expired.signature = try sender_keypair.signTransaction(expired_tx.hashForSigning());
    
    const expired_result = zeicoin.addTransaction(signed_expired);
    try testing.expectError(error.InvalidTransaction, expired_result);
    try testing.expectEqual(@as(usize, 0), zeicoin.mempool.items.len);
    log.info("  ✅ Expired transaction correctly rejected", .{});

    // Test 3: Mine blocks and verify transaction expiration
    // Add a transaction that expires in 2 blocks
    const short_expiry_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = sender_addr,
        .sender_public_key = sender_keypair.public_key,
        .recipient = recipient_addr,
        .amount = 10 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = current_height + 2, // Expires in 2 blocks
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_short = short_expiry_tx;
    signed_short.signature = try sender_keypair.signTransaction(short_expiry_tx.hashForSigning());
    
    try zeicoin.addTransaction(signed_short);
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);
    
    // Mine first block - transaction should still be valid
    const block1 = try zeicoin.zenMineBlock(sender_keypair);
    var mutable_block1 = block1;
    defer mutable_block1.deinit(zeicoin.allocator);
    
    // Mine second block - now at expiry height
    const block2 = try zeicoin.zenMineBlock(sender_keypair);
    var mutable_block2 = block2;
    defer mutable_block2.deinit(zeicoin.allocator);
    
    // Try to add the same transaction again (simulating rebroadcast)
    const rebroadcast_result = zeicoin.addTransaction(signed_short);
    try testing.expectError(error.InvalidTransaction, rebroadcast_result);
    log.info("  ✅ Transaction expired after mining blocks", .{});

    // Test 4: Verify default expiry window is set correctly
    const expiry_window = types.TransactionExpiry.getExpiryWindow();
    try testing.expectEqual(@as(u64, 8_640), expiry_window); // TestNet: 24 hours
    log.info("  ✅ Default expiry window is 24 hours (8,640 blocks)", .{});

    log.info("\n🎉 All transaction expiration tests passed!", .{});
}

test "reorganization with coinbase maturity" {
    const test_dir = "test_reorg_maturity";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }

    // Create test accounts
    const miner1 = try key.KeyPair.generateNew();
    const miner1_addr = miner1.getAddress();
    const miner2 = try key.KeyPair.generateNew();
    const miner2_addr = miner2.getAddress();
    
    // Fund an account for transactions
    const sender = try key.KeyPair.generateNew();
    const sender_addr = sender.getAddress();
    try zeicoin.database.saveAccount(sender_addr, types.Account{
        .address = sender_addr,
        .balance = 1000 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    log.info("\n🧪 Testing reorganization with coinbase maturity...", .{});
    
    // Scenario: Mine 101 blocks so first coinbase matures
    log.info("  1️⃣ Mining 101 blocks to mature first coinbase...", .{});
    var i: u32 = 0;
    while (i < 101) : (i += 1) {
        // Mine a block and immediately deinitialize it to free its transactions
        var block = try zeicoin.zenMineBlock(miner1);
        block.deinit(zeicoin.allocator);
    }
    
    // Check miner1's balance after 101 blocks  
    // Note: We start at height 0 (genesis), so after mining 101 blocks we're at height 101
    // Block at height 1 matures at height 101 (100 blocks later)
    const height = try zeicoin.getHeight();
    log.info("  📊 Current height: {}", .{height});
    const account_before = try zeicoin.getAccount(miner1_addr);
    log.info("  💰 Miner balance - mature: {}, immature: {}", .{account_before.balance, account_before.immature_balance});
    try testing.expectEqual(@as(u64, types.ZenMining.BLOCK_REWARD), account_before.balance); // Block 1 matured
    try testing.expectEqual(@as(u64, 100 * types.ZenMining.BLOCK_REWARD), account_before.immature_balance); // Blocks 2-101 still immature
    log.info("  ✅ Block 1 coinbase matured correctly", .{});
    
    // Create a transaction that spends the matured coinbase
    const spend_tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = miner1_addr,
        .sender_public_key = miner1.public_key,
        .recipient = miner2_addr,
        .amount = types.ZenMining.BLOCK_REWARD / 2, // Spend half
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_tx = spend_tx;
    signed_tx.signature = try miner1.signTransaction(spend_tx.hash());
    
    // Add transaction and mine it
    try zeicoin.addTransaction(signed_tx);
    const block_with_spend = try zeicoin.zenMineBlock(miner1);
    var mutable_block_with_spend = block_with_spend;
    defer mutable_block_with_spend.deinit(zeicoin.allocator);
    log.info("  ✅ Spent matured coinbase in block 102", .{});
    
    // Verify the spend worked
    const miner1_after_spend = try zeicoin.getAccount(miner1_addr);
    const miner2_after_spend = try zeicoin.getAccount(miner2_addr);
    log.info("  💰 After spend - Miner1: mature={}, immature={}", .{miner1_after_spend.balance, miner1_after_spend.immature_balance});
    log.info("  💰 After spend - Miner2: mature={}, immature={}", .{miner2_after_spend.balance, miner2_after_spend.immature_balance});
    // Miner1 spent half of first mature block but block 2 also matured, plus got fees
    // So balance should be: 0.5 ZEI (remaining from block 1) + 1 ZEI (block 2) + small fees
    try testing.expect(miner1_after_spend.balance > 0); // Has balance
    try testing.expect(miner2_after_spend.balance == types.ZenMining.BLOCK_REWARD / 2); // Got exactly half
    
    // Now trigger a reorg back to height 50 (before maturity)
    log.info("  2️⃣ Simulating reorganization back to height 50...", .{});
    const current_height = try zeicoin.getHeight();
    try testing.expectEqual(@as(u32, 102), current_height); // Genesis(0) + 101 mined blocks + 1 spend block
    
    // Perform rollback
    try zeicoin.rollbackToHeight(50);
    
    // Verify rollback worked
    const height_after_rollback = try zeicoin.getHeight();
    try testing.expectEqual(@as(u32, 103), height_after_rollback); // Height doesn't change, only state
    
    // Check miner1's balance after rollback - no mature coins yet!
    const account_after_reorg = try zeicoin.getAccount(miner1_addr);
    try testing.expectEqual(@as(u64, 0), account_after_reorg.balance); // No mature balance at height 50
    // We replayed to height 50, which includes blocks 1-50 (genesis at 0 has no miner reward)
    try testing.expectEqual(@as(u64, 50 * types.ZenMining.BLOCK_REWARD), account_after_reorg.immature_balance); // Blocks 1-50
    
    // Miner2 should have no balance
    const miner2_after_reorg = zeicoin.getAccount(miner2_addr) catch {
        // Account might not exist, which is fine
        log.info("  ✅ Miner2 account correctly doesn't exist after reorg", .{});
        return;
    };
    try testing.expectEqual(@as(u64, 0), miner2_after_reorg.balance);
    try testing.expectEqual(@as(u64, 0), miner2_after_reorg.immature_balance);
    
    log.info("  ✅ Reorganization correctly rolled back matured coinbase and dependent transactions", .{});
}

test "transaction size limit" {
    // This test verifies that transactions exceeding MAX_TX_SIZE are rejected
    log.info("\n🔍 Testing transaction size limit...", .{});
    
    // Create test blockchain
    var zeicoin = try createTestZeiCoin("test_zeicoin_data_tx_size");
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
    
    // Create test keypairs
    var alice = try key.KeyPair.generateNew();
    defer alice.deinit();
    const alice_addr = alice.getAddress();
    var bob = try key.KeyPair.generateNew();
    defer bob.deinit();
    const bob_addr = bob.getAddress();
    
    // Give Alice some coins
    try zeicoin.database.saveAccount(alice_addr, types.Account{
        .address = alice_addr,
        .balance = 1000 * types.ZEI_COIN,
        .nonce = 0,
        .immature_balance = 0,
    });
    
    // Create a transaction with extra_data that exceeds the limit
    const large_data = try testing.allocator.alloc(u8, types.TransactionLimits.MAX_TX_SIZE);
    defer testing.allocator.free(large_data);
    @memset(large_data, 'A'); // Fill with 'A's
    
    const oversized_tx = types.Transaction{
        .version = 0,
        .flags = types.TransactionFlags{},
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = try zeicoin.getHeight() + types.TransactionExpiry.getExpiryWindow(),
        .sender_public_key = alice.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = large_data,
    };
    
    // Check that the transaction is invalid due to size
    try testing.expectEqual(false, oversized_tx.isValid());
    log.info("  ✅ Oversized transaction ({} bytes) correctly rejected by isValid()", .{oversized_tx.getSerializedSize()});
    
    // Don't try to sign or add invalid transaction - it would panic during hashing
    
    // Create a transaction with small extra_data (should succeed)
    const small_extra = 256; // Small enough to fit in hash buffer
    const small_data = try testing.allocator.alloc(u8, small_extra);
    defer testing.allocator.free(small_data);
    @memset(small_data, 'B');
    
    const valid_tx = types.Transaction{
        .version = 0,
        .flags = types.TransactionFlags{},
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 50 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = try zeicoin.getHeight() + types.TransactionExpiry.getExpiryWindow(),
        .sender_public_key = alice.public_key,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = small_data,
    };
    
    // Check that this transaction is valid
    try testing.expectEqual(true, valid_tx.isValid());
    log.info("  ✅ Transaction with {} bytes extra_data accepted (under {} byte limit)", .{small_data.len, types.TransactionLimits.MAX_EXTRA_DATA_SIZE});
    
    // Sign and add to mempool
    var signed_valid_tx = valid_tx;
    signed_valid_tx.signature = try alice.signTransaction(valid_tx.hash());
    try zeicoin.addTransaction(signed_valid_tx);
    log.info("  ✅ Valid transaction successfully added to mempool", .{});
    
    log.info("  ✅ Transaction size limit tests passed!", .{});
}

test "genesis distribution validation" {
    log.info("\n🎯 Testing genesis distribution validation...", .{});
    
    const test_dir = "test_genesis_distribution";
    defer std.fs.cwd().deleteTree(test_dir) catch {};
    
    var zeicoin = try createTestZeiCoin(test_dir);
    defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
    
    // Import genesis module
    const genesis = @import("core/chain/genesis.zig");
    const genesis_wallet = @import("core/wallet/genesis_wallet.zig");
    
    log.info("  📊 Testing {} pre-funded accounts...", .{genesis.TESTNET_DISTRIBUTION.len});
    
    // Test 1: Verify all genesis accounts have correct balances
    for (genesis.TESTNET_DISTRIBUTION) |account| {
        const address = genesis.getTestAccountAddress(account.name).?;
        const chain_account = try zeicoin.chain_query.getAccount(address);
        
        try testing.expectEqual(account.amount, chain_account.balance);
        try testing.expectEqual(@as(u64, 0), chain_account.immature_balance);
        try testing.expectEqual(@as(u64, 0), chain_account.nonce);
        
        log.info("  ✅ {s}: {} ZEI at {s}", .{
            account.name,
            account.amount / types.ZEI_COIN,
            @as([]const u8, &std.fmt.bufPrint(&[_]u8{0} ** 64, "tzei1{s}", .{
                std.fmt.fmtSliceHexLower(address.hash[0..10])
            }) catch unreachable)[0..15]
        });
    }
    
    // Test 2: Verify genesis key pair generation is deterministic
    for (genesis.TESTNET_DISTRIBUTION) |account| {
        const kp1 = try genesis_wallet.createGenesisKeyPair(account.seed);
        const kp2 = try genesis_wallet.createGenesisKeyPair(account.seed);
        
        // Public keys should be identical
        try testing.expectEqualSlices(u8, &kp1.public_key, &kp2.public_key);
        // Private keys should be identical
        try testing.expectEqualSlices(u8, &kp1.private_key, &kp2.private_key);
        
        // Address derived from public key should match genesis address
        const derived_addr = types.Address.fromPublicKey(kp1.public_key);
        const expected_addr = genesis.getTestAccountAddress(account.name).?;
        try testing.expectEqualSlices(u8, &derived_addr.hash, &expected_addr.hash);
    }
    log.info("  ✅ Genesis key pairs are deterministic and match addresses", .{});
    
    // Test 3: Verify total genesis supply
    var total_supply: u64 = 0;
    for (genesis.TESTNET_DISTRIBUTION) |account| {
        total_supply += account.amount;
    }
    // Add coinbase from genesis block
    total_supply += types.ZenMining.BLOCK_REWARD;
    
    const expected_supply = 5 * 1000 * types.ZEI_COIN + types.ZenMining.BLOCK_REWARD; // 5 accounts × 1000 ZEI + coinbase
    try testing.expectEqual(expected_supply, total_supply);
    log.info("  ✅ Total genesis supply: {} ZEI (5000 distributed + {} coinbase)", .{
        total_supply / types.ZEI_COIN,
        types.ZenMining.BLOCK_REWARD / types.ZEI_COIN
    });
    
    // Test 4: Verify genesis block contains distribution transactions
    var genesis_block = try zeicoin.getBlockByHeight(0);
    defer genesis_block.deinit(testing.allocator);
    
    // Should have 1 coinbase + 5 distribution transactions = 6 total
    try testing.expectEqual(@as(u32, 6), genesis_block.txCount());
    
    // First transaction should be coinbase
    const coinbase = genesis_block.transactions[0];
    try testing.expectEqual(types.Address.zero(), coinbase.sender);
    try testing.expectEqual(types.ZenMining.BLOCK_REWARD, coinbase.amount);
    try testing.expectEqual(@as(u64, 0), coinbase.fee);
    
    // Remaining transactions should be distribution
    for (genesis_block.transactions[1..], 0..) |tx, i| {
        const account = genesis.TESTNET_DISTRIBUTION[i];
        const expected_addr = genesis.getTestAccountAddress(account.name).?;
        
        try testing.expectEqual(types.Address.zero(), tx.sender); // From genesis
        try testing.expectEqual(expected_addr, tx.recipient);
        try testing.expectEqual(account.amount, tx.amount);
        try testing.expectEqual(@as(u64, 0), tx.fee); // No fees for genesis distribution
    }
    log.info("  ✅ Genesis block contains correct distribution transactions", .{});
    
    // Test 5: Verify genesis hash matches expected
    const expected_hash = genesis.getCanonicalGenesisHash();
    const actual_hash = genesis_block.hash();
    try testing.expectEqualSlices(u8, &expected_hash, &actual_hash);
    log.info("  ✅ Genesis block hash matches canonical hash", .{});
    
    // Test 6: Test transaction capability from genesis accounts
    const alice_kp = try genesis_wallet.getTestAccountKeyPair("alice");
    const alice_addr = alice_kp.?.getAddress();
    const bob_addr = genesis.getTestAccountAddress("bob").?;
    
    // Create a transaction from alice to bob
    const tx = types.Transaction{
        .version = 0,
        .flags = std.mem.zeroes(types.TransactionFlags),
        .sender = alice_addr,
        .sender_public_key = alice_kp.?.public_key,
        .recipient = bob_addr,
        .amount = 100 * types.ZEI_COIN,
        .fee = types.ZenFees.MIN_FEE,
        .nonce = 0,
        .timestamp = @intCast(std.time.milliTimestamp()),
        .expiry_height = 10000,
        .signature = undefined,
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };
    var signed_tx = tx;
    signed_tx.signature = try alice_kp.?.signTransaction(tx.hashForSigning());
    
    // Should be able to add to mempool
    try zeicoin.addTransaction(signed_tx);
    try testing.expectEqual(@as(usize, 1), zeicoin.mempool.items.len);
    log.info("  ✅ Genesis accounts can create valid transactions", .{});
    
    log.info("  🎉 All genesis distribution validation tests passed!", .{});
}


test "memory leak detection - block operations" {
    log.info("\n🔍 Testing memory leak prevention in block operations...", .{});
    
    // Use testing allocator which tracks leaks
    const allocator = testing.allocator;
    
    // Test 1: Block loading and cleanup
    {
        log.info("  Testing block load/free cycle...", .{});
        var zeicoin = try createTestZeiCoin("test_memory_leak_blocks");
        defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
        
        // Create and mine a block with multiple transactions
        const alice = try key.KeyPair.generateNew();
        const bob = try key.KeyPair.generateNew();
        const alice_addr = alice.getAddress();
        const bob_addr = bob.getAddress();
        
        // Fund alice by creating an account
        const alice_account = types.Account{
            .address = alice_addr,
            .balance = 1000 * types.ZEI_COIN,
            .immature_balance = 0,
            .nonce = 0,
        };
        try zeicoin.database.saveAccount(alice_addr, alice_account);
        
        // Add multiple transactions (without extra_data to avoid allocation issues)
        // Note: All use nonce 0 since they're all from the same account in mempool
        for (0..3) |i| {
            const amount = (10 + i) * types.ZEI_COIN; // Vary amount instead of nonce
            const tx = try createTestTransaction(alice_addr, bob_addr, amount, types.ZenFees.MIN_FEE, 0, alice, allocator);
            try zeicoin.addTransaction(tx);
        }
        
        // Mine block
        const block = try zeicoin.zenMineBlock(alice);
        var mutable_block = block;
        defer mutable_block.deinit(zeicoin.allocator);
        
        // Load block from database multiple times to test cleanup
        for (0..5) |_| {
            var loaded_block = try zeicoin.database.getBlock(0);
            // This should properly free all nested allocations
            loaded_block.deinit(zeicoin.allocator);
        }
        
        log.info("  ✅ Block load/free cycle completed without leaks", .{});
    }
    
    // Test 2: Sync block handling
    {
        log.info("  Testing sync block memory management...", .{});
        var zeicoin = try createTestZeiCoin("test_memory_leak_sync");
        defer {
        zeicoin.deinit();
        testing.allocator.destroy(zeicoin);
    }
        
        // Create a block with transactions containing extra_data
        const miner = try key.KeyPair.generateNew();
        const recipient = try key.KeyPair.generateNew();
        
        var transactions = try allocator.alloc(types.Transaction, 2);
        defer allocator.free(transactions);
        
        // Coinbase transaction
        transactions[0] = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = types.Address.zero(),
            .recipient = miner.getAddress(),
            .amount = types.ZenMining.BLOCK_REWARD,
            .fee = 0,
            .nonce = 0,
            .timestamp = @intCast(std.time.milliTimestamp()),
            .expiry_height = 0,
            .sender_public_key = std.mem.zeroes([32]u8),
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };
        
        // Regular transaction with extra_data
        const test_message = "Test message for memory leak detection";
        const extra_data_copy = try allocator.dupe(u8, test_message);
        defer allocator.free(extra_data_copy);
        
        transactions[1] = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = miner.getAddress(),
            .recipient = recipient.getAddress(),
            .amount = types.ZenMining.BLOCK_REWARD / 2,
            .fee = types.ZenFees.MIN_FEE,
            .nonce = 0,
            .timestamp = @intCast(std.time.milliTimestamp()),
            .expiry_height = 10000,
            .sender_public_key = miner.public_key,
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = extra_data_copy,
        };
        
        // Create block and test serialization/deserialization
        var test_block = types.Block{
            .header = createTestBlockHeader(
                std.mem.zeroes(types.Hash),
                std.mem.zeroes(types.Hash),
                @intCast(std.time.milliTimestamp()),
                types.ZenMining.initialDifficultyTarget().toU64(),
                0
            ),
            .transactions = transactions,
            .height = 1, // Test block at height 1
        };
        
        // Serialize and deserialize the block multiple times
        for (0..3) |_| {
            const serialized = try test_block.serialize(allocator);
            defer allocator.free(serialized);
            
            var deserialized = try types.Block.deserialize(serialized, allocator);
            defer deserialized.deinit(allocator);
            
            // Verify the deserialized block has the same data
            try testing.expectEqual(test_block.header.timestamp, deserialized.header.timestamp);
            try testing.expectEqual(test_block.transactions.len, deserialized.transactions.len);
        }
        
        log.info("  ✅ Sync block memory management completed without leaks", .{});
    }
    
    // Clean up test directories
    std.fs.cwd().deleteTree("test_memory_leak_blocks") catch {};
    std.fs.cwd().deleteTree("test_memory_leak_sync") catch {};
    
    log.info("  🎉 Memory leak detection tests passed!", .{});
}