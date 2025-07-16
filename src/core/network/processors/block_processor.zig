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
    accepted,           // Block was accepted and added to chain
    reorganized,        // Block caused chain reorganization
    stored_as_orphan,   // Block stored as orphan
    stored_as_sidechain, // Block stored in side chain
    ignored,            // Block was ignored (duplicate)
    rejected,           // Block was rejected (invalid)
};

/// Block processing context
pub const BlockProcessingContext = struct {
    block: Block,
    block_height: u32,
    cumulative_work: u128,
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
        var owned_block = block;
        errdefer owned_block.deinit(self.allocator);
        
        // Log incoming block
        self.logIncomingBlock(peer, block.transactions.len);
        
        // Validate block
        const block_height = try self.blockchain.getHeight() + 1;
        if (!try self.validateBlock(&owned_block, block_height)) {
            return .rejected;
        }
        
        // Calculate cumulative work
        const cumulative_work = try self.calculateCumulativeWork(&owned_block, block_height - 1);
        
        // Create processing context
        const context = BlockProcessingContext{
            .block = owned_block,
            .block_height = block_height,
            .cumulative_work = cumulative_work,
            .peer = peer,
        };
        
        // Evaluate block using fork manager
        const decision = try self.blockchain.fork_manager.evaluateBlock(
            context.block, 
            context.block_height, 
            context.cumulative_work
        );
        
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
                    try self.handleReorganization(&owned_block);
                    return .reorganized;
                } else {
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
        const is_valid = self.blockchain.validateBlock(owned_block.*, block_height) catch |err| {
            print("❌ Block validation failed: {}\n", .{err});
            owned_block.deinit(self.allocator);
            return false;
        };
        
        if (!is_valid) {
            print("❌ Invalid block rejected\n", .{});
            owned_block.deinit(self.allocator);
            return false;
        }
        
        return true;
    }
    
    /// Calculate cumulative work for a block
    fn calculateCumulativeWork(self: *Self, owned_block: *Block, current_height: u32) !u128 {
        const block_work = owned_block.header.getWork();
        
        if (current_height == 0) {
            return block_work;
        }
        
        // Get parent block work
        var parent_block = self.blockchain.database.getBlock(current_height - 1) catch {
            print("❌ Cannot find parent block for height {}\n", .{current_height - 1});
            owned_block.deinit(self.allocator);
            return error.ParentBlockNotFound;
        };
        defer parent_block.deinit(self.allocator);

        // Get current total work from chain operations
        const parent_work = self.blockchain.getTotalWork() catch 0;
        return parent_work + block_work;
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
        
        var chain_operations = ChainOperations.init(
            self.allocator,
            &self.blockchain.chain_state,
            &chain_validator
        );
        defer chain_operations.deinit();
        
        // Initialize modern reorganization manager
        var reorg_manager = ReorgManager.init(
            self.allocator,
            &self.blockchain.chain_state,
            &chain_validator,
            &chain_operations,
        ) catch |err| {
            print("❌ Failed to initialize reorganization manager: {}\n", .{err});
            owned_block.deinit(self.allocator);
            return;
        };
        defer reorg_manager.deinit();
        
        // Execute complete reorganization
        const new_chain_tip = owned_block.hash();
        const reorg_result = reorg_manager.executeReorganization(owned_block.*, new_chain_tip) catch |err| {
            print("❌ Chain reorganization failed: {}\n", .{err});
            owned_block.deinit(self.allocator);
            return;
        };
        
        // Handle reorganization result
        if (reorg_result.success) {
            print("✅ Modern reorganization completed successfully!\n", .{});
            print("📊 Stats: {} blocks reverted, {} applied, {} txs replayed ({} ms)\n", .{
                reorg_result.blocks_reverted,
                reorg_result.blocks_applied,
                reorg_result.transactions_replayed,
                reorg_result.duration_ms
            });
            
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
            owned_block.deinit(self.allocator);
            return;
        };
        // Note: chain_processor now owns block_copy
        
        // Block will be cleaned up by caller for broadcasting
    }
    
    /// Handle side chain block
    fn handleSideChainBlock(self: *Self, owned_block: *Block, block_height: u32) !void {
        print("📦 Processing side chain block\n", .{});
        
        const side_block_work = owned_block.header.getWork();
        
        // Add to side chain manager
        const side_chain_action = self.blockchain.fork_manager.handleSideChainBlock(
            owned_block.*,
            owned_block.header.previous_hash,
            block_height - 1,
            side_block_work
        ) catch |err| {
            print("❌ Failed to handle side chain block: {}\n", .{err});
            owned_block.deinit(self.allocator);
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
                owned_block.deinit(self.allocator);
            },
            else => {
                owned_block.deinit(self.allocator);
            },
        }
    }
    
    /// Log incoming block information
    fn logIncomingBlock(self: *Self, peer: ?*net.Peer, tx_count: usize) void {
        _ = self;
        if (peer) |p| {
            print("🌊 Block flows in from peer {} with {} transactions\n", .{p.id, tx_count});
        } else {
            print("🌊 Block flows in from network peer with {} transactions\n", .{tx_count});
        }
    }
    
    /// Trigger auto-sync when orphan blocks are detected
    fn triggerAutoSync(self: *Self) !void {
        if (self.blockchain.sync_manager) |sync_manager| {
            try sync_manager.startSync();
            print("🔄 Auto-sync triggered due to orphan block\n", .{});
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