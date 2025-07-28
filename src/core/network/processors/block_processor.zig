// block_processor.zig - Block Processing Module
// Handles all block-related processing logic including validation, chain operations, and reorganization

const std = @import("std");
const print = std.debug.print;

const types = @import("../../types/types.zig");
const net = @import("../peer.zig");
const ZeiCoin = @import("../../node.zig").ZeiCoin;

const Block = types.Block;
const Transaction = types.Transaction;

/// Result of block processing
pub const BlockProcessingResult = enum {
    accepted, // Block was accepted and added to chain
    reorganized, // Block caused chain reorganization
    stored_as_orphan, // Block stored as orphan
    stored_as_sidechain, // Block stored in side chain
    ignored, // Block was ignored (duplicate)
    rejected, // Block was rejected (invalid)
};

/// Block processing context
pub const BlockProcessingContext = struct {
    block: Block,
    block_height: u32,
    cumulative_work: types.ChainWork, // Upgraded to u256 consensus
    peer: ?*net.Peer,
};

/// Block processor handles all block-related network operations
pub const BlockProcessor = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,

    const Self = @This();

    /// Initialize block processor
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
        };
    }

    /// Process incoming block from network
    pub fn processIncomingBlock(self: *Self, block: Block, peer: ?*net.Peer) !BlockProcessingResult {
        print("🔧 [BLOCK PROCESSOR] processIncomingBlock() ENTRY\n", .{});
        var owned_block = block;
        errdefer owned_block.deinit(self.allocator);

        // Log incoming block
        self.logIncomingBlock(peer, block.transactions.len);

        // Validate block
        const block_height = try self.blockchain.getHeight() + 1;
        print("🔧 [BLOCK PROCESSOR] About to validate block at height {}\n", .{block_height});
        if (!try self.validateBlock(&owned_block, block_height)) {
            print("🔧 [BLOCK PROCESSOR] Block validation FAILED, returning rejected\n", .{});
            return .rejected;
        }
        print("🔧 [BLOCK PROCESSOR] Block validation PASSED\n", .{});

        // Calculate cumulative work
        const cumulative_work = try self.calculateCumulativeWork(&owned_block, block_height - 1);

        // Create processing context
        const context = BlockProcessingContext{
            .block = owned_block,
            .block_height = block_height,
            .cumulative_work = cumulative_work,
            .peer = peer,
        };

        // Check if we're currently syncing to use sync-aware block processing
        const is_syncing = if (self.blockchain.sync_manager) |sync_manager|
            sync_manager.isActive()
        else
            false;

        print("🔧 [BLOCK PROCESSOR] Sync status: {}, using {s} evaluation\n", .{ is_syncing, if (is_syncing) "SYNC-AWARE" else "NORMAL" });

        // Evaluate block using fork manager (sync-aware if syncing)
        const decision = if (is_syncing)
            try self.blockchain.fork_manager.evaluateBlockWithSyncFlag(context.block, context.block_height, context.cumulative_work, true)
        else
            try self.blockchain.fork_manager.evaluateBlock(context.block, context.block_height, context.cumulative_work);

        // Process based on fork decision
        return try self.processBasedOnDecision(decision, context);
    }

    /// Process block based on fork manager decision
    fn processBasedOnDecision(self: *Self, decision: anytype, context: BlockProcessingContext) !BlockProcessingResult {
        var owned_block = context.block;

        switch (decision) {
            .ignore => {
                print("🌊 Block already seen - gracefully ignored\n", .{});
                return .ignored;
            },
            .store_orphan => {
                print("🔀 Block stored as orphan - waiting for parent\n", .{});
                self.handleOrphanBlock();
                return .stored_as_orphan;
            },
            .extends_chain => |chain_info| {
                if (chain_info.requires_reorg) {
                    print("🔄 [FORK DECISION] Block requires reorganization - delegating to reorg handler\n", .{});
                    try self.handleReorganization(&owned_block);
                    return .reorganized;
                } else {
                    print("📈 [FORK DECISION] Block extends current chain - checking continuity\n", .{});
                    // Only check chain continuity for blocks extending current chain without reorg
                    if (!try self.validateChainContinuity(&owned_block, context.block_height)) {
                        print("❌ [CHAIN CONTINUITY] Block rejected - doesn't connect properly\n", .{});
                        return .rejected;
                    }
                    try self.handleMainChainExtension(&owned_block, context.block_height);
                    return .accepted;
                }
            },
            .new_best_chain => |chain_index| {
                print("🏆 New best chain {} detected!\n", .{chain_index});
                if (chain_index == 0) {
                    try self.handleMainChainExtension(&owned_block, context.block_height);
                    return .accepted;
                } else {
                    try self.handleSideChainBlock(&owned_block, context.block_height);
                    return .stored_as_sidechain;
                }
            },
        }
    }

    /// Validate incoming block
    fn validateBlock(self: *Self, owned_block: *Block, block_height: u32) !bool {
        print("🔧 [BLOCK PROCESSOR] validateBlock called for height {}\n", .{block_height});
        // Check if we're currently syncing - if so, use sync-aware validation
        const current_height = self.blockchain.getHeight() catch 0;
        const is_syncing = if (self.blockchain.sync_manager) |sync_manager|
            sync_manager.isActive() or (current_height < block_height and block_height <= current_height + 10)
        else
            (current_height < block_height and block_height <= current_height + 10);

        print("🔧 [BLOCK PROCESSOR] Validation mode: {s} (current_height: {}, block_height: {}, syncing: {})\n", .{ if (is_syncing) "SYNC" else "NORMAL", current_height, block_height, is_syncing });

        // NOTE: Chain continuity check moved to processBasedOnDecision()
        // to allow fork evaluation before rejection

        const is_valid = if (is_syncing) blk: {
            print("🔧 [BLOCK PROCESSOR] Using SYNC validation for block {}\n", .{block_height});
            break :blk self.blockchain.validateSyncBlock(owned_block, block_height) catch |err| {
                print("❌ Sync block validation failed: {}\n", .{err});
                return false;
            };
        } else blk: {
            print("🔧 [BLOCK PROCESSOR] Using NORMAL validation for block {}\n", .{block_height});
            break :blk self.blockchain.validateBlock(owned_block.*, block_height) catch |err| {
                print("❌ Block validation failed: {}\n", .{err});
                return false;
            };
        };

        if (!is_valid) {
            print("❌ Invalid block rejected\n", .{});
            return false;
        }

        return true;
    }

    /// Validate chain continuity for blocks extending current chain
    fn validateChainContinuity(self: *Self, owned_block: *Block, block_height: u32) !bool {
        print("🔍 [CHAIN CONTINUITY] Checking block {} connects to current chain\n", .{block_height});

        if (block_height == 0) {
            print("✅ [CHAIN CONTINUITY] Genesis block - no parent required\n", .{});
            return true;
        }

        // Verify parent block exists
        const parent_exists = blk: {
            var parent = self.blockchain.database.getBlock(block_height - 1) catch break :blk false;
            parent.deinit(self.allocator);
            break :blk true;
        };
        if (!parent_exists) {
            print("❌ [CHAIN CONTINUITY] Missing parent block for height {}\n", .{block_height});
            return false;
        }

        // Verify block connects to parent
        var parent_block = self.blockchain.database.getBlock(block_height - 1) catch {
            print("❌ [CHAIN CONTINUITY] Cannot read parent block at height {}\n", .{block_height - 1});
            return false;
        };
        defer parent_block.deinit(self.allocator);

        const parent_hash = parent_block.hash();
        if (!std.mem.eql(u8, &owned_block.header.previous_hash, &parent_hash)) {
            print("❌ [CHAIN CONTINUITY] Block {} doesn't connect to parent\n", .{block_height});
            print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&parent_hash)});
            print("   Got:      {s}\n", .{std.fmt.fmtSliceHexLower(&owned_block.header.previous_hash)});
            return false;
        }

        print("✅ [CHAIN CONTINUITY] Block {} connects properly to parent\n", .{block_height});
        return true;
    }

    /// Calculate cumulative work for a block using consensus
    /// Uses O(1) work calculation with industry-standard u256 precision
    fn calculateCumulativeWork(_: *Self, owned_block: *Block, previous_height: u32) !types.ChainWork {
        const block_work = owned_block.header.getWork();

        // Genesis block: work is just this block's work
        if (previous_height == 0 and std.mem.eql(u8, &owned_block.header.previous_hash, &std.mem.zeroes(types.Hash))) {
            return block_work;
        }

        // TODO: Integrate with consensus ChainManager
        // For now, just return this block's work as a transitional measure
        // The full consensus system will be integrated in the next phase
        return block_work;
    }

    /// Handle orphan block detection
    fn handleOrphanBlock(self: *Self) void {
        print("🔄 Orphan block detected - we may be behind, triggering auto-sync\n", .{});

        // Trigger auto-sync
        self.triggerAutoSync() catch |err| {
            print("⚠️  Auto-sync trigger failed: {}\n", .{err});
        };
    }

    /// Handle chain reorganization
    fn handleReorganization(self: *Self, owned_block: *Block) !void {
        print("🏆 New best chain detected! Starting reorganization...\n", .{});

        // Import modern reorganization architecture
        const ReorgManager = @import("../../chain/reorganization/manager.zig").ReorgManager;
        const ChainValidator = @import("../../chain/validator.zig").ChainValidator;
        const ChainOperations = @import("../../chain/operations.zig").ChainOperations;

        // Initialize reorganization components
        var chain_validator = ChainValidator.init(self.allocator, &self.blockchain.chain_state);
        defer chain_validator.deinit();

        var chain_operations = ChainOperations.init(self.allocator, &self.blockchain.chain_state, &chain_validator);
        defer chain_operations.deinit();

        // Initialize modern reorganization manager
        var reorg_manager = ReorgManager.init(
            self.allocator,
            &self.blockchain.chain_state,
            &chain_validator,
            &chain_operations,
        ) catch |err| {
            print("❌ Failed to initialize reorganization manager: {}\n", .{err});
            return;
        };
        defer reorg_manager.deinit();

        // Execute complete reorganization
        const new_chain_tip = owned_block.hash();
        const reorg_result = reorg_manager.executeReorganization(owned_block.*, new_chain_tip) catch |err| {
            print("❌ Chain reorganization failed: {}\n", .{err});
            return;
        };

        // Handle reorganization result
        if (reorg_result.success) {
            print("✅ Modern reorganization completed successfully!\n", .{});
            print("📊 Stats: {} blocks reverted, {} applied, {} txs replayed ({} ms)\n", .{ reorg_result.blocks_reverted, reorg_result.blocks_applied, reorg_result.transactions_replayed, reorg_result.duration_ms });

            // Block will be cleaned up by caller
        } else {
            print("❌ Reorganization failed: {s}\n", .{reorg_result.error_message orelse "Unknown error"});
            owned_block.deinit(self.allocator);
        }
    }

    /// Handle main chain extension
    fn handleMainChainExtension(self: *Self, owned_block: *Block, block_height: u32) !void {
        print("📈 Block extends main chain - adding to blockchain\n", .{});

        // Create a deep copy of the block for chain processor
        var block_copy = try owned_block.dupe(self.allocator);

        // Transfer ownership to chain processor
        self.blockchain.chain_processor.addBlockToChain(block_copy, block_height) catch |err| {
            print("❌ Failed to add block to chain: {}\n", .{err});
            block_copy.deinit(self.allocator);
            return;
        };
        // Ownership transferred to chain_processor
        // Note: chain_processor now owns block_copy

        // Block will be cleaned up by caller for broadcasting
    }

    /// Handle side chain block
    fn handleSideChainBlock(self: *Self, owned_block: *Block, block_height: u32) !void {
        print("📦 Processing side chain block\n", .{});

        const side_block_work = owned_block.header.getWork();

        // Add to side chain manager
        const side_chain_action = self.blockchain.fork_manager.handleSideChainBlock(owned_block.*, owned_block.header.previous_hash, block_height - 1, side_block_work) catch |err| {
            print("❌ Failed to handle side chain block: {}\n", .{err});
            return;
        };

        // Handle the result
        switch (side_chain_action) {
            .stored => {
                print("✅ Side chain block stored successfully\n", .{});
                // Check if this side chain should trigger reorganization
                if (self.blockchain.fork_manager.getActiveChain()) |active_chain| {
                    if (self.blockchain.fork_manager.evaluateSideChains(active_chain.cumulative_work)) |_| {
                        print("🏆 Side chain has more work! Triggering reorganization\n", .{});
                        // TODO: Implement side chain reorganization
                        print("⚠️ Side chain reorganization not yet implemented\n", .{});
                    }
                }
            },
            .rejected => {
                print("❌ Side chain block rejected (capacity/limits)\n", .{});
            },
            else => {
                // Block cleanup handled by errdefer
            },
        }
    }

    /// Log incoming block information
    fn logIncomingBlock(self: *Self, peer: ?*net.Peer, tx_count: usize) void {
        _ = self;
        if (peer) |p| {
            print("🌊 Block flows in from peer {} with {} transactions\n", .{ p.id, tx_count });
        } else {
            print("🌊 Block flows in from network peer with {} transactions\n", .{tx_count});
        }
    }

    /// Trigger auto-sync when orphan blocks are detected
    fn triggerAutoSync(self: *Self) !void {
        if (self.blockchain.sync_manager) |sync_manager| {
            // Find the best peer to sync with
            if (self.blockchain.network_coordinator.getNetworkManager()) |network| {
                if (network.peer_manager.getBestPeerForSync()) |best_peer| {
                    // Use libp2p-powered batch sync for improved performance
                    try sync_manager.startSync(best_peer, best_peer.height);
                    print("🚀 libp2p batch auto-sync triggered due to orphan block with peer height {}\n", .{best_peer.height});
                } else {
                    print("⚠️ No peers available for auto-sync\n", .{});
                }
            } else {
                print("⚠️ No network manager available for auto-sync\n", .{});
            }
        } else {
            print("⚠️ No sync manager available for auto-sync\n", .{});
        }
    }
};

// Tests
test "BlockProcessor initialization" {
    const testing = std.testing;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Mock blockchain (we can't easily create a real one in tests)
    var mock_blockchain: ZeiCoin = undefined;

    const processor = BlockProcessor.init(allocator, &mock_blockchain);
    try testing.expectEqual(allocator, processor.allocator);
}
