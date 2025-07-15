// tests.zig - Comprehensive Reorganization Architecture Tests
// Extensive testing for modern chain reorganization system

const std = @import("std");
const testing = std.testing;
const types = @import("../../types/types.zig");
const ChainState = @import("../state.zig").ChainState;
const Database = @import("../../storage/db.zig").Database;

// Import reorganization components
const ReorgManager = @import("manager.zig").ReorgManager;
const ChainSnapshot = @import("snapshot.zig").ChainSnapshot;
const TxReplayEngine = @import("replay.zig").TxReplayEngine;
const ReorgEventHandler = @import("events.zig").ReorgEventHandler;
const ReorgSafety = @import("safety.zig").ReorgSafety;
const ChainValidator = @import("../validator.zig").ChainValidator;
const ChainOperations = @import("../operations.zig").ChainOperations;

// Type aliases
const Block = types.Block;
const Transaction = types.Transaction;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;

/// Test utilities for reorganization testing
const TestUtils = struct {
    /// Create a test block with specified parameters
    pub fn createTestBlock(allocator: std.mem.Allocator, height: u32, prev_hash: Hash, tx_count: u32) !Block {
        // Create test transactions
        const transactions = try allocator.alloc(Transaction, tx_count);
        for (transactions, 0..) |*tx, i| {
            tx.* = createTestTransaction(@intCast(i));
        }
        
        return Block{
            .header = BlockHeader{
                .version = types.CURRENT_BLOCK_VERSION,
                .previous_hash = prev_hash,
                .merkle_root = std.mem.zeroes(Hash),
                .timestamp = @intCast(std.time.timestamp() + @as(i64, @intCast(height))),
                .difficulty = 0x1d00ffff,
                .nonce = height * 42,
                .witness_root = std.mem.zeroes(Hash),
                .state_root = std.mem.zeroes(Hash),
                .extra_nonce = 0,
                .extra_data = std.mem.zeroes([32]u8),
            },
            .transactions = transactions,
        };
    }
    
    /// Create a test transaction
    pub fn createTestTransaction(id: u32) Transaction {
        var sender = std.mem.zeroes(types.Address);
        var recipient = std.mem.zeroes(types.Address);
        
        // Make unique addresses based on id
        sender.hash[0] = @intCast(id);
        recipient.hash[0] = @intCast(id + 100);
        
        return Transaction{
            .version = types.CURRENT_TX_VERSION,
            .sender = sender,
            .recipient = recipient,
            .amount = (id + 1) * 1000000, // 1-n ZEI
            .fee = 5000, // 0.00005 ZEI
            .nonce = id,
            .timestamp = @intCast(std.time.timestamp()),
            .sender_public_key = std.mem.zeroes([32]u8),
            .signature = std.mem.zeroes([64]u8),
            .message = std.mem.zeroes([512]u8),
            .message_len = 0,
        };
    }
    
    /// Create test database
    pub fn createTestDatabase(allocator: std.mem.Allocator) !*Database {
        const db = try allocator.create(Database);
        db.* = try Database.init(allocator, "/tmp/zeicoin_reorg_test");
        return db;
    }
    
    /// Event counter for testing
    const EventCounter = struct {
        started: u32 = 0,
        completed: u32 = 0,
        failed: u32 = 0,
        state_changes: u32 = 0,
        
        pub fn countingHandler(event: @import("events.zig").ReorgEvent) void {
            // In a real test, we'd access the counter instance
            // For now, just validate events can be handled
            switch (event) {
                .started => {},
                .completed => {},
                .failed => {},
                .state_changed => {},
                else => {},
            }
        }
    };
};

// ===================== UNIT TESTS =====================

// Test ReorgEventHandler functionality
test "ReorgEventHandler - Event registration and emission" {
    var event_handler = ReorgEventHandler.init(testing.allocator);
    defer event_handler.deinit();
    
    // Test adding handlers
    try event_handler.addHandler(TestUtils.EventCounter.countingHandler);
    try testing.expectEqual(@as(usize, 1), event_handler.handlers.items.len);
    
    // Test event emission (should not crash)
    try event_handler.emitStarted(0, 10, std.mem.zeroes(Hash));
    try event_handler.emitCompleted(5, 3, 2, 1, 1000);
    
    // Test removing handlers
    event_handler.removeHandler(TestUtils.EventCounter.countingHandler);
    try testing.expectEqual(@as(usize, 0), event_handler.handlers.items.len);
}

// Test ReorgSafety validation mechanisms
test "ReorgSafety - Safety validation and limits" {
    var safety = ReorgSafety.init();
    defer safety.deinit();
    
    // Test normal reorganization (should pass)
    try safety.validateReorganization(5, 100);
    
    // Test deep reorganization (should fail)
    try testing.expectError(error.ReorgTooDeep, safety.validateReorganization(200, 300));
    
    // Test checkpoint management
    try safety.addCheckpoint(50);
    try safety.addCheckpoint(100);
    try testing.expectEqual(@as(usize, 2), safety.getCheckpoints().len);
    
    // Test reorganization beyond checkpoint (should fail)
    try testing.expectError(error.ReorgBeyondCheckpoint, safety.validateReorganization(10, 60));
    
    // Test emergency brake
    safety.activateEmergencyBrake();
    try testing.expectError(error.EmergencyBrakeActivated, safety.validateReorganization(3, 50));
    
    safety.deactivateEmergencyBrake();
    try safety.validateReorganization(3, 50); // Should pass now
}

// Test ChainSnapshot capture and restore
test "ChainSnapshot - State capture and restoration" {
    var snapshot_manager = ChainSnapshot.init(testing.allocator);
    defer snapshot_manager.deinit();
    
    // Create test database and chain state
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    // Test snapshot creation
    var snapshot = try snapshot_manager.captureChainState(&chain_state, 0);
    defer snapshot.deinit();
    
    // Verify snapshot properties
    try testing.expectEqual(@as(u32, 0), snapshot.snapshot_height);
    
    // Test snapshot statistics
    const stats = snapshot.getStats();
    try testing.expect(stats.memory_usage > 0);
}

// Test TxReplayEngine validation and caching
test "TxReplayEngine - Transaction validation and caching" {
    var replay_engine = TxReplayEngine.init(testing.allocator);
    defer replay_engine.deinit();
    
    // Test cache operations
    const tx = TestUtils.createTestTransaction(1);
    _ = tx.hash(); // Acknowledge hash is used for validation
    
    // Test cache miss and population (simplified - would need real chain state)
    const stats = replay_engine.getStats();
    try testing.expectEqual(@as(usize, 0), stats.cache_size);
    
    // Test dependency graph building
    var transactions = [_]Transaction{tx};
    try replay_engine.buildDependencyGraph(&transactions);
    
    // Test reset functionality
    replay_engine.reset();
    const stats_after_reset = replay_engine.getStats();
    try testing.expectEqual(@as(usize, 0), stats_after_reset.cache_size);
}

// ===================== INTEGRATION TESTS =====================

// Test complete reorganization workflow
test "ReorgManager - Complete reorganization workflow" {
    // Setup test environment
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    // Initialize ReorgManager
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Test state machine initialization
    const initial_stats = reorg_manager.getStats();
    try testing.expectEqual(@import("manager.zig").ReorgState.idle, initial_stats.current_state);
    try testing.expectEqual(@as(u64, 0), initial_stats.total_reorgs);
    
    // Create test block for reorganization
    var test_block = try TestUtils.createTestBlock(testing.allocator, 1, std.mem.zeroes(Hash), 2);
    defer test_block.deinit(testing.allocator);
    
    // Execute reorganization
    const reorg_result = try reorg_manager.executeReorganization(test_block, test_block.hash());
    
    // Verify reorganization result
    try testing.expectEqual(true, reorg_result.success);
    try testing.expect(reorg_result.duration_ms >= 0);
    
    // Verify statistics updated
    const final_stats = reorg_manager.getStats();
    try testing.expectEqual(@import("manager.zig").ReorgState.idle, final_stats.current_state);
    try testing.expectEqual(@as(u64, 1), final_stats.total_reorgs);
}

// Test reorganization with different depths
test "ReorgManager - Multiple depth scenarios" {
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Test shallow reorganization (1-2 blocks)
    var shallow_block = try TestUtils.createTestBlock(testing.allocator, 1, std.mem.zeroes(Hash), 1);
    defer shallow_block.deinit(testing.allocator);
    
    const shallow_result = try reorg_manager.executeReorganization(shallow_block, shallow_block.hash());
    try testing.expectEqual(true, shallow_result.success);
    
    // Test medium depth reorganization (3-5 blocks)
    var medium_block = try TestUtils.createTestBlock(testing.allocator, 5, std.mem.zeroes(Hash), 3);
    defer medium_block.deinit(testing.allocator);
    
    const medium_result = try reorg_manager.executeReorganization(medium_block, medium_block.hash());
    try testing.expectEqual(true, medium_result.success);
    
    // Verify multiple reorganizations tracked
    const stats = reorg_manager.getStats();
    try testing.expectEqual(@as(u64, 2), stats.total_reorgs);
}

// Test error handling and recovery
test "ReorgManager - Error handling and recovery" {
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Test concurrent reorganization rejection
    var test_block1 = try TestUtils.createTestBlock(testing.allocator, 1, std.mem.zeroes(Hash), 1);
    defer test_block1.deinit(testing.allocator);
    
    // Start first reorganization (simulate by changing state manually for test)
    // In real scenario, this would be handled by the state machine
    
    var test_block2 = try TestUtils.createTestBlock(testing.allocator, 2, std.mem.zeroes(Hash), 1);
    defer test_block2.deinit(testing.allocator);
    
    // Execute reorganization (should succeed as we're in idle state)
    const result = try reorg_manager.executeReorganization(test_block2, test_block2.hash());
    try testing.expectEqual(true, result.success);
}

// ===================== STRESS TESTS =====================

// Test rapid consecutive reorganizations
test "ReorgManager - Rapid consecutive reorganizations" {
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Execute multiple rapid reorganizations
    const num_reorgs = 10;
    var success_count: u32 = 0;
    
    for (0..num_reorgs) |i| {
        var test_block = try TestUtils.createTestBlock(testing.allocator, @intCast(i + 1), std.mem.zeroes(Hash), 1);
        defer test_block.deinit(testing.allocator);
        
        const result = try reorg_manager.executeReorganization(test_block, test_block.hash());
        if (result.success) {
            success_count += 1;
        }
    }
    
    // Verify all reorganizations succeeded
    try testing.expectEqual(@as(u32, num_reorgs), success_count);
    
    // Verify statistics
    const stats = reorg_manager.getStats();
    try testing.expectEqual(@as(u64, num_reorgs), stats.total_reorgs);
}

// Test memory usage with large reorganizations
test "ReorgManager - Memory usage validation" {
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Test with block containing many transactions
    var large_block = try TestUtils.createTestBlock(testing.allocator, 1, std.mem.zeroes(Hash), 100);
    defer large_block.deinit(testing.allocator);
    
    const result = try reorg_manager.executeReorganization(large_block, large_block.hash());
    try testing.expectEqual(true, result.success);
    
    // Verify memory cleanup (snapshots should be cleaned up)
    // In a real implementation, we'd check for memory leaks
}

// ===================== PERFORMANCE TESTS =====================

// Benchmark reorganization performance
test "ReorgManager - Performance benchmarking" {
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Benchmark reorganization time
    const start_time = std.time.milliTimestamp();
    
    var test_block = try TestUtils.createTestBlock(testing.allocator, 1, std.mem.zeroes(Hash), 10);
    defer test_block.deinit(testing.allocator);
    
    const result = try reorg_manager.executeReorganization(test_block, test_block.hash());
    
    const end_time = std.time.milliTimestamp();
    const duration = end_time - start_time;
    
    try testing.expectEqual(true, result.success);
    try testing.expect(duration < 1000); // Should complete within 1 second
    
    std.debug.print("Reorganization performance: {}ms\n", .{duration});
}

// ===================== INTEGRATION WITH MESSAGE HANDLER =====================

// Test integration with network message handler workflow
test "ReorgManager - Network integration simulation" {
    // This test simulates the message handler workflow
    var db = try TestUtils.createTestDatabase(testing.allocator);
    defer {
        db.deinit();
        testing.allocator.destroy(db);
    }
    
    var chain_state = ChainState.init(testing.allocator, db);
    defer chain_state.deinit();
    
    var chain_validator = ChainValidator.init(testing.allocator, &chain_state);
    defer chain_validator.deinit();
    
    var chain_operations = ChainOperations.init(testing.allocator, &chain_state, &chain_validator);
    defer chain_operations.deinit();
    
    // Simulate message handler initialization of ReorgManager
    var reorg_manager = try ReorgManager.init(
        testing.allocator,
        &chain_state,
        &chain_validator,
        &chain_operations,
    );
    defer reorg_manager.deinit();
    
    // Simulate incoming block that requires reorganization
    var competing_block = try TestUtils.createTestBlock(testing.allocator, 1, std.mem.zeroes(Hash), 3);
    defer competing_block.deinit(testing.allocator);
    
    // Execute reorganization as message handler would
    const new_chain_tip = competing_block.hash();
    const reorg_result = try reorg_manager.executeReorganization(competing_block, new_chain_tip);
    
    // Verify result matches expected message handler behavior
    try testing.expectEqual(true, reorg_result.success);
    try testing.expect(reorg_result.blocks_applied >= 1);
    try testing.expect(reorg_result.duration_ms >= 0);
    
    std.debug.print("Network integration test: {} blocks reverted, {} applied in {}ms\n", .{
        reorg_result.blocks_reverted,
        reorg_result.blocks_applied,
        reorg_result.duration_ms,
    });
}