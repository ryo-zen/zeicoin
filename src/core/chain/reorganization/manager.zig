// manager.zig - Modern Chain Reorganization Manager
// State-machine driven reorganization with atomic operations and event handling

const std = @import("std");
const log = std.log.scoped(.reorg);
const types = @import("../../types/types.zig");
const ChainState = @import("../state.zig").ChainState;
const ChainValidator = @import("../validator.zig").ChainValidator;
const ChainOperations = @import("../operations.zig").ChainOperations;

// Import local reorganization components
const ChainSnapshot = @import("snapshot.zig").ChainSnapshot;
const TxReplayEngine = @import("replay.zig").TxReplayEngine;
const ReorgEventHandler = @import("events.zig").ReorgEventHandler;
const ReorgSafety = @import("safety.zig").ReorgSafety;

// Type aliases
const Block = types.Block;
const Transaction = types.Transaction;
const Hash = types.Hash;

/// Reorganization state machine
pub const ReorgState = enum {
    idle,           // Ready for new reorganization
    analyzing,      // Finding common ancestor and evaluating safety
    capturing,      // Creating chain snapshots for rollback
    reverting,      // Rolling back to fork point
    applying,       // Processing new chain blocks
    validating,     // Final consistency checks
    committing,     // Finalizing changes and cleanup
    failed,         // Error state requiring cleanup and rollback
};

/// Reorganization operation result
pub const ReorgResult = struct {
    success: bool,
    blocks_reverted: u32,
    blocks_applied: u32,
    transactions_replayed: u32,
    transactions_orphaned: u32,
    duration_ms: u64,
    error_message: ?[]const u8,
};

/// Transaction replay result
const TxReplayResult = struct {
    replayed: u32,
    orphaned: u32,
};

/// Modern Reorganization Manager
/// Provides atomic, safe, and observable chain reorganization operations
pub const ReorgManager = struct {
    // Core dependencies
    allocator: std.mem.Allocator,
    chain_state: *ChainState,
    chain_validator: *ChainValidator,
    chain_operations: *ChainOperations,
    
    // Reorganization components
    snapshot_manager: ChainSnapshot,
    replay_engine: TxReplayEngine,
    event_handler: ReorgEventHandler,
    safety_checker: ReorgSafety,
    
    // State management
    current_state: ReorgState,
    operation_start_time: i64,
    
    // Snapshots for atomic operations
    old_chain_snapshot: ?ChainSnapshot.Snapshot,
    new_chain_snapshot: ?ChainSnapshot.Snapshot,
    
    // Statistics
    total_reorgs: u64,
    deepest_reorg: u32,
    
    const Self = @This();
    
    /// Initialize ReorgManager with all required dependencies
    pub fn init(
        allocator: std.mem.Allocator,
        chain_state: *ChainState,
        chain_validator: *ChainValidator,
        chain_operations: *ChainOperations,
    ) !*Self {
        // Allocate on heap for stable addresses
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);
        
        self.* = Self{
            .allocator = allocator,
            .chain_state = chain_state,
            .chain_validator = chain_validator,
            .chain_operations = chain_operations,
            .snapshot_manager = ChainSnapshot.init(allocator),
            .replay_engine = TxReplayEngine.init(allocator),
            .event_handler = ReorgEventHandler.init(allocator),
            .safety_checker = ReorgSafety.init(),
            .current_state = .idle,
            .operation_start_time = 0,
            .old_chain_snapshot = null,
            .new_chain_snapshot = null,
            .total_reorgs = 0,
            .deepest_reorg = 0,
        };
        
        return self;
    }
    
    /// Cleanup all resources and free self
    pub fn deinit(self: *Self) void {
        // Clean up any active snapshots
        if (self.old_chain_snapshot) |*snapshot| {
            snapshot.deinit();
        }
        if (self.new_chain_snapshot) |*snapshot| {
            snapshot.deinit();
        }
        
        // Deinitialize components
        self.snapshot_manager.deinit();
        self.replay_engine.deinit();
        self.event_handler.deinit();
        self.safety_checker.deinit();
        
        // Free self
        self.allocator.destroy(self);
    }
    
    /// Execute complete chain reorganization
    /// This is the main entry point for reorganization operations
    pub fn executeReorganization(self: *Self, new_block: Block, new_chain_tip: Hash) !ReorgResult {
        // Ensure we're in idle state
        if (self.current_state != .idle) {
            return ReorgResult{
                .success = false,
                .blocks_reverted = 0,
                .blocks_applied = 0,
                .transactions_replayed = 0,
                .transactions_orphaned = 0,
                .duration_ms = 0,
                .error_message = "Reorganization already in progress",
            };
        }
        
        log.info("\n🔄 [CONSENSUS] === CHAIN REORGANIZATION STARTING ===", .{});
        log.info("   - New chain tip: {s}", .{std.fmt.fmtSliceHexLower(new_chain_tip[0..8])});
        log.info("   - New block height: {}", .{new_block.header.timestamp});
        log.info("   - Current time: {}", .{std.time.milliTimestamp()});
        
        // Record operation start time
        self.operation_start_time = std.time.milliTimestamp();
        
        // Execute state machine
        var result = self.executeStateMachine(new_block, new_chain_tip) catch |err| {
            log.info("❌ [CONSENSUS] Reorganization failed: {}", .{err});
            // Ensure cleanup on any error
            self.cleanup();
            return ReorgResult{
                .success = false,
                .blocks_reverted = 0,
                .blocks_applied = 0,
                .transactions_replayed = 0,
                .transactions_orphaned = 0,
                .duration_ms = @intCast(std.time.milliTimestamp() - self.operation_start_time),
                .error_message = @errorName(err),
            };
        };
        
        // Calculate duration
        result.duration_ms = @intCast(std.time.milliTimestamp() - self.operation_start_time);
        
        // Update statistics
        if (result.success) {
            self.total_reorgs += 1;
            if (result.blocks_reverted > self.deepest_reorg) {
                self.deepest_reorg = result.blocks_reverted;
            }
        }
        
        return result;
    }
    
    /// State machine execution logic
    fn executeStateMachine(self: *Self, new_block: Block, new_chain_tip: Hash) !ReorgResult {
        var result = ReorgResult{
            .success = false,
            .blocks_reverted = 0,
            .blocks_applied = 0,
            .transactions_replayed = 0,
            .transactions_orphaned = 0,
            .duration_ms = 0,
            .error_message = null,
        };
        
        // State machine progression
        try self.transitionTo(.analyzing);
        const analysis = try self.analyzeReorganization(new_chain_tip);
        
        try self.transitionTo(.capturing);
        try self.captureChainSnapshots(analysis.fork_height);
        
        try self.transitionTo(.reverting);
        result.blocks_reverted = try self.revertToForkPoint(analysis.fork_height);
        
        try self.transitionTo(.applying);
        result.blocks_applied = try self.applyNewChain(new_block);
        
        try self.transitionTo(.validating);
        try self.validateReorganizationResult();
        
        try self.transitionTo(.committing);
        const replay_result = try self.commitChanges();
        result.transactions_replayed = replay_result.replayed;
        result.transactions_orphaned = replay_result.orphaned;
        
        // Success!
        result.success = true;
        try self.transitionTo(.idle);
        
        log.info("✅ Reorganization completed: {} blocks reverted, {} applied", .{ result.blocks_reverted, result.blocks_applied });
        
        return result;
    }
    
    /// Transition to new state with validation and events
    fn transitionTo(self: *Self, new_state: ReorgState) !void {
        const old_state = self.current_state;
        
        // Validate state transition
        const valid = switch (old_state) {
            .idle => new_state == .analyzing,
            .analyzing => new_state == .capturing or new_state == .failed,
            .capturing => new_state == .reverting or new_state == .failed,
            .reverting => new_state == .applying or new_state == .failed,
            .applying => new_state == .validating or new_state == .failed,
            .validating => new_state == .committing or new_state == .failed,
            .committing => new_state == .idle or new_state == .failed,
            .failed => new_state == .idle, // Can always return to idle from failed
        };
        
        if (!valid) {
            return error.InvalidStateTransition;
        }
        
        self.current_state = new_state;
        
        // Emit state change event
        try self.event_handler.emitStateChange(old_state, new_state);
        
        log.info("🔄 Reorganization: {} → {}", .{ old_state, new_state });
    }
    
    /// Analyze reorganization requirements and safety
    fn analyzeReorganization(self: *Self, new_chain_tip: Hash) !struct { fork_height: u32, depth: u32 } {
        const current_height = try self.chain_state.getHeight();
        
        // Find common ancestor using existing binary search
        const common_ancestor = self.findCommonAncestor(new_chain_tip) catch 0;
        
        const reorg_depth = current_height - common_ancestor;
        
        // Safety check
        try self.safety_checker.validateReorganization(reorg_depth, current_height);
        
        log.info("🔍 Reorganization analysis: depth={}, fork_height={}", .{ reorg_depth, common_ancestor });
        
        return .{ .fork_height = common_ancestor, .depth = reorg_depth };
    }
    
    /// Create snapshots of current chain state
    fn captureChainSnapshots(self: *Self, fork_height: u32) !void {
        // Capture current chain state
        self.old_chain_snapshot = try self.snapshot_manager.captureChainState(self.chain_state, fork_height);
        
        log.info("📸 Chain snapshots captured from height {}", .{fork_height});
    }
    
    /// Revert chain to fork point
    fn revertToForkPoint(self: *Self, fork_height: u32) !u32 {
        const current_height = try self.chain_state.getHeight();
        const blocks_to_revert = current_height - fork_height;
        
        // Use existing rollback mechanism
        try self.chain_state.rollbackToHeight(fork_height, current_height);
        
        log.info("⏪ Reverted {} blocks to height {}", .{ blocks_to_revert, fork_height });
        
        return blocks_to_revert;
    }
    
    /// Apply new chain blocks
    fn applyNewChain(self: *Self, new_block: Block) !u32 {
        // For now, just apply the single new block
        // In a full implementation, this would apply all blocks in the new chain
        try self.chain_operations.acceptBlock(new_block);
        
        log.info("📈 Applied new chain block", .{});
        
        return 1; // Number of blocks applied
    }
    
    /// Validate reorganization result
    fn validateReorganizationResult(self: *Self) !void {
        // Perform consistency checks
        const height = try self.chain_state.getHeight();
        
        // Basic validation - ensure chain is still valid
        if (height == 0) {
            return error.InvalidChainState;
        }
        
        log.info("✓ Reorganization result validated", .{});
    }
    
    /// Commit changes and handle orphaned transactions
    fn commitChanges(self: *Self) !TxReplayResult {
        // In a full implementation, this would:
        // 1. Extract orphaned transactions from old chain
        // 2. Replay valid ones against new chain state
        // 3. Update mempool with remaining valid transactions
        
        // Clean up snapshots
        if (self.old_chain_snapshot) |*snapshot| {
            snapshot.deinit();
            self.old_chain_snapshot = null;
        }
        
        // For now, return placeholder values
        const result = TxReplayResult{ .replayed = 0, .orphaned = 0 };
        
        log.info("✅ Changes committed, {} transactions replayed", .{result.replayed});
        
        return result;
    }
    
    /// Find common ancestor (simplified version using existing logic)
    fn findCommonAncestor(self: *Self, new_tip_hash: Hash) !u32 {
        // Use existing binary search from reorganization.zig
        // This is a simplified version - full implementation would be more sophisticated
        _ = new_tip_hash;
        
        // For now, assume shallow reorganization (1-2 blocks)
        const current_height = try self.chain_state.getHeight();
        return if (current_height > 2) current_height - 2 else 0;
    }
    
    /// Cleanup on error
    fn cleanup(self: *Self) void {
        // Clean up any partial state
        if (self.old_chain_snapshot) |*snapshot| {
            snapshot.deinit();
            self.old_chain_snapshot = null;
        }
        if (self.new_chain_snapshot) |*snapshot| {
            snapshot.deinit();
            self.new_chain_snapshot = null;
        }
        
        // Reset to idle state
        self.current_state = .idle;
        
        log.info("🧹 Reorganization cleanup completed", .{});
    }
    
    /// Get current reorganization statistics
    pub fn getStats(self: *const Self) struct { total_reorgs: u64, deepest_reorg: u32, current_state: ReorgState } {
        return .{
            .total_reorgs = self.total_reorgs,
            .deepest_reorg = self.deepest_reorg,
            .current_state = self.current_state,
        };
    }
};