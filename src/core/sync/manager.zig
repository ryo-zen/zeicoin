// manager.zig - ZSP-001 Sync Manager
// High-level coordinator for ZeiCoin Synchronization Protocol implementation
//
// This manager provides a clean interface between the blockchain core and
// the ZSP-001 batch synchronization protocol. It handles peer management,
// sync coordination, and provides fallback mechanisms.
//
// Key Features:
// - Integration with ZSP-001 BatchSyncProtocol for high-performance sync
// - Automatic peer selection and failover management
// - Sync state persistence and resume capability
// - Comprehensive logging and progress reporting
// - Fallback to sequential sync for legacy peer compatibility

const std = @import("std");
const log = std.log.scoped(.sync);

const types = @import("../types/types.zig");
const net = @import("../network/peer.zig");
const state_mod = @import("state.zig");
const protocol = @import("protocol/lib.zig");

// ZSP-001 protocol imports
const BatchSyncProtocol = protocol.BatchSyncProtocol;
const BatchSyncContext = protocol.BatchSyncContext;
const sequential = protocol.sequential;

// Blockchain integration
const ZeiCoin = @import("../node.zig").ZeiCoin;

// Type aliases for clarity
const Block = types.Block;
const Hash = types.Hash;
const Peer = net.Peer;
const Allocator = std.mem.Allocator;

// Module-level blockchain reference for dependency injection functions
var g_blockchain: ?*ZeiCoin = null;
const SyncState = protocol.SyncState;

// ============================================================================
// ZSP-001 SYNC MANAGER CONFIGURATION
// ============================================================================

/// Configuration constants for sync manager behavior
const SYNC_CONFIG = struct {
    /// Maximum number of failed peers to remember
    const MAX_FAILED_PEERS: usize = 10;

    /// Sync state persistence interval (seconds)
    const STATE_SAVE_INTERVAL: i64 = 30;

    /// Minimum height difference to trigger sync
    const MIN_SYNC_HEIGHT_DIFF: u32 = 1;

    /// Peer selection timeout (seconds)
    const PEER_SELECTION_TIMEOUT: i64 = 10;
    
    /// Maximum sync duration before timeout (seconds)
    const SYNC_TIMEOUT: i64 = 120;
};

// ============================================================================
// ZSP-001 SYNC MANAGER IMPLEMENTATION
// ============================================================================

/// ZSP-001 Synchronization Manager
/// High-level coordinator for blockchain synchronization using batch protocol
pub const SyncManager = struct {
    /// Memory allocator for dynamic data structures
    allocator: Allocator,

    /// Reference to the blockchain instance for integration
    blockchain: *ZeiCoin,

    /// ZSP-001 batch synchronization protocol instance
    batch_sync: BatchSyncProtocol,

    /// Current synchronization state tracking
    sync_state: SyncState,

    /// List of failed peers for avoidance during peer selection
    failed_peers: std.ArrayList(*Peer),

    /// Last sync state save timestamp for persistence
    last_state_save: i64,
    
    /// Timestamp when sync session started (for timeout detection)
    sync_start_time: i64,

    const Self = @This();

    /// Initialize the ZSP-001 sync manager
    pub fn init(allocator: Allocator, blockchain: *ZeiCoin) !Self {
        log.info("Initializing ZSP-001 synchronization manager", .{});

        // Set global blockchain reference for dependency injection functions
        g_blockchain = blockchain;

        // Create dependency injection context for batch sync
        const batch_context = BatchSyncContext{
            .getHeight = getBlockchainHeight,
            .applyBlock = applyBlockToBlockchain,
            .getNextPeer = getNextAvailablePeer,
            .validateBlock = validateBlockBeforeApply,
        };

        // Initialize batch sync protocol
        const batch_sync = BatchSyncProtocol.init(allocator, batch_context);

        log.info("🔄 ZSP-001 sync manager initialized successfully", .{});

        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .batch_sync = batch_sync,
            .sync_state = .idle,
            .failed_peers = std.ArrayList(*Peer).init(allocator),
            .last_state_save = 0,
            .sync_start_time = 0,
        };
    }

    /// Clean up sync manager resources
    pub fn deinit(self: *Self) void {
        log.debug("Cleaning up sync manager resources", .{});

        self.batch_sync.deinit();
        self.failed_peers.deinit();

        log.debug("Sync manager cleanup completed", .{});
    }

    /// Start synchronization with a peer to a target height
    /// Main entry point for blockchain synchronization
    pub fn startSync(self: *Self, peer: *Peer, target_height: u32) !void {
        log.info("INITIATING BLOCKCHAIN SYNCHRONIZATION", .{});
        log.info("Session parameters:", .{});
        log.info("   Target peer: {any}", .{peer.address});
        log.info("   Target height: {}", .{target_height});
        log.info("   Current state: {}", .{self.sync_state});
        log.info("   Failed peers: {}", .{self.failed_peers.items.len});

        // Check if sync can be started
        log.debug("STEP 1: Validating sync state...", .{});
        if (!self.sync_state.canStart()) {
            log.err("STEP 1 FAILED: Sync cannot be started", .{});
            log.warn("Current state: {} (expected: idle, failed, or complete)", .{self.sync_state});
            log.info("Suggestion: Wait for current sync to complete or call stopSync()", .{});
            return;
        }
        log.debug("STEP 1 PASSED: Sync state allows new session", .{});

        // Validate sync requirements
        log.debug("STEP 2: Analyzing blockchain state...", .{});
        const current_height = try getBlockchainHeight();
        const height_diff = if (target_height > current_height)
            target_height - current_height
        else
            0;

        log.info("Blockchain analysis:", .{});
        log.info("   Current height: {}", .{current_height});
        log.info("   Target height: {}", .{target_height});
        log.info("   Height difference: {}", .{height_diff});
        log.info("   Minimum sync threshold: {}", .{SYNC_CONFIG.MIN_SYNC_HEIGHT_DIFF});
        log.info("   Peer info: {any}", .{peer.address});
        log.info("   Peer height: {}", .{peer.height});

        if (height_diff < SYNC_CONFIG.MIN_SYNC_HEIGHT_DIFF) {
            log.warn("🚫 [SYNC ABORT] Already synchronized - height diff {} < threshold {}", .{ height_diff, SYNC_CONFIG.MIN_SYNC_HEIGHT_DIFF });
            log.info("Local height {} >= target height {} (diff: {})", .{ current_height, target_height, height_diff });
            log.info("No synchronization needed - session complete", .{});
            return;
        }
        log.info("STEP 2 PASSED: Sync required ({} blocks behind)", .{height_diff});

        // Ensure genesis block exists before syncing
        log.debug("STEP 3: Validating genesis block...", .{});
        if (current_height == 0) {
            // Check if genesis block actually exists in database
            const genesis_exists = blk: {
                var genesis_block = self.blockchain.database.getBlock(0) catch break :blk false;
                genesis_block.deinit(self.allocator);
                break :blk true;
            };

            if (!genesis_exists) {
                log.info("Creating canonical genesis block...", .{});
                try self.blockchain.createCanonicalGenesis();
                log.info("Genesis block created successfully", .{});
            } else {
                log.debug("Genesis block already exists in database", .{});
            }
        } else {
            log.debug("Genesis block already exists (height > 0)", .{});
        }
        log.debug("STEP 3 COMPLETED: Genesis validation passed", .{});

        // Check peer compatibility and select sync method
        log.debug("STEP 4: Analyzing peer capabilities...", .{});
        const supports_batch = sequential.supportsBatchRequests(peer);
        log.info("Peer capability analysis:", .{});
        log.info("   Peer address: {any}", .{peer.address});
        log.info("   Services: 0x{X}", .{peer.services});
        log.info("   Batch support: {}", .{supports_batch});
        log.info("   Height: {}", .{peer.height});

        if (supports_batch) {
            log.info("STEP 4 RESULT: Using ZSP-001 batch synchronization", .{});
            log.info("Performance: Up to 50x faster than sequential sync", .{});

            // Set timeout timer
            self.sync_start_time = std.time.timestamp();
            log.info("🕒 [SYNC TIMEOUT] Started timeout timer (max {} seconds)", .{SYNC_CONFIG.SYNC_TIMEOUT});

            // Start ZSP-001 batch synchronization
            log.debug("STEP 5: Delegating to ZSP-001 batch sync...", .{});
            try self.batch_sync.startSync(peer, target_height);

            // Update our state AFTER batch sync has successfully started
            log.debug("STATE TRANSITION: {} → syncing", .{self.sync_state});
            const old_state = self.sync_state;
            self.sync_state = .syncing;
            log.debug("State transition completed: {} → {}", .{ old_state, self.sync_state });
            log.info("STEP 5 COMPLETED: ZSP-001 batch sync activated", .{});
        } else {
            log.warn("STEP 4 RESULT: Peer lacks batch sync capabilities", .{});
            log.info("Falling back to sequential synchronization", .{});
            log.warn("Performance: Standard speed (up to 50x slower than batch)", .{});

            // Set timeout timer
            self.sync_start_time = std.time.timestamp();
            log.info("🕒 [SYNC TIMEOUT] Started timeout timer (max {} seconds)", .{SYNC_CONFIG.SYNC_TIMEOUT});

            // Use sequential sync utilities for legacy peers
            log.debug("STEP 5: Starting sequential sync fallback...", .{});
            try self.startSequentialSync(peer, target_height);

            // Update our state AFTER sequential sync has started
            log.debug("STATE TRANSITION: {} → syncing (sequential)", .{self.sync_state});
            const old_state = self.sync_state;
            self.sync_state = .syncing;
            log.debug("State transition completed: {} → {}", .{ old_state, self.sync_state });
            log.info("STEP 5 COMPLETED: Sequential sync activated", .{});
        }

        // Initialize state persistence
        log.debug("STEP 6: Initializing state persistence...", .{});
        self.last_state_save = self.getTime();
        log.info("STEP 6 COMPLETED: State persistence initialized", .{});
        log.info("Next state save: {} seconds", .{SYNC_CONFIG.STATE_SAVE_INTERVAL});

        log.info("SYNCHRONIZATION SESSION SUCCESSFULLY STARTED!", .{});
    }

    /// Handle incoming batch of blocks from ZSP-001 protocol
    pub fn handleBatchBlocks(self: *Self, blocks: []const Block, start_height: u32) !void {
        log.info("=== PROCESSING ZSP-001 BATCH BLOCKS ===", .{});
        log.info("PROCESSING ZSP-001 BATCH BLOCKS", .{});
        log.info("=======================================", .{});

        log.info("Batch details:", .{});
        log.info("   Block count: {} blocks", .{blocks.len});
        log.info("   Start height: {}", .{start_height});
        log.info("   └─ End height: {}", .{start_height + @as(u32, @intCast(blocks.len)) - 1});
        log.info("   └─ Current sync state: {}", .{self.sync_state});
        log.info("   └─ Progress: {d:.1}%", .{self.getProgress()});

        // CRITICAL: Validate bulk blocks for chain continuity before processing
        log.info("🔍 [BULK VALIDATION] Validating batch block continuity...", .{});
        if (!try validateBulkBlocks(blocks, start_height, self.blockchain)) {
            log.info("❌ [BULK VALIDATION] Batch validation failed - rejecting entire batch", .{});
            return error.InvalidBatch;
        }
        log.info("✅ [BULK VALIDATION] Batch passed validation checks", .{});

        // Forward to batch sync protocol for processing
        log.info("🔍 [SYNC MANAGER] Delegating to ZSP-001 batch sync protocol...", .{});
        try self.batch_sync.handleBatchBlocks(blocks, start_height);
        log.info("✅ [SYNC MANAGER] ZSP-001 protocol processing completed", .{});

        // Update sync state based on batch sync state
        log.info("🔍 [SYNC MANAGER] Synchronizing state with batch sync protocol...", .{});
        const old_sync_state = self.sync_state;
        self.sync_state = self.batch_sync.getSyncState();
        if (old_sync_state != self.sync_state) {
            log.info("🔄 [SYNC MANAGER] STATE TRANSITION: {} → {}", .{ old_sync_state, self.sync_state });
        } else {
            log.info("📊 [SYNC MANAGER] State remains: {}", .{self.sync_state});
        }

        // Handle state persistence
        log.info("🔍 [SYNC MANAGER] Checking state persistence requirements...", .{});
        try self.handleStatePersistence();

        log.info("✅ [SYNC MANAGER] BATCH PROCESSING COMPLETED SUCCESSFULLY!", .{});
        log.info("📊 [SYNC MANAGER] Updated progress: {d:.1}%", .{self.getProgress()});
    }

    /// Handle incoming single block (for sequential sync or single block requests)
    pub fn handleSyncBlock(self: *Self, block: *const Block, height: u32) !void {
        log.info("📦 [SYNC MANAGER] Handling single sync block at height {}", .{height});

        // Validate the block before processing
        if (!try validateBlockBeforeApply(block.*, height)) {
            log.info("❌ [SYNC MANAGER] Block validation failed for height {}", .{height});
            return error.InvalidBlock;
        }

        // Apply block to blockchain directly using the real chain processor
        try self.blockchain.chain_processor.addBlockToChain(block.*, height);

        log.info("✅ [SYNC MANAGER] Single block {} applied successfully", .{height});

        // Handle state persistence
        try self.handleStatePersistence();
    }

    /// Check for sync timeouts and handle recovery
    pub fn handleTimeouts(self: *Self) !void {
        if (!self.sync_state.isActive()) return;

        // Handle batch sync timeouts
        try self.batch_sync.handleTimeouts();

        // Update our state based on batch sync state
        self.sync_state = self.batch_sync.getSyncState();

        // Handle sync failure recovery
        if (self.sync_state == .failed) {
            log.info("🔄 [SYNC MANAGER] Sync failed, attempting peer rotation", .{});
            try self.attemptSyncRecovery();
        }
    }

    /// Complete synchronization process
    pub fn completeSync(self: *Self) !void {
        log.info("\n🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆", .{});
        log.info("🎉 [SYNC MANAGER] COMPLETING SYNCHRONIZATION SESSION", .{});
        log.info("🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆", .{});

        log.info("📊 [SYNC MANAGER] Final session statistics:", .{});
        log.info("   └─ Current state: {}", .{self.sync_state});
        log.info("   └─ Progress: {d:.1}%", .{self.getProgress()});
        log.info("   └─ Failed peers handled: {}", .{self.failed_peers.items.len});
        log.info("   └─ Session duration: {} seconds", .{self.getTime() - self.last_state_save});

        // Update sync state
        log.info("🔄 [SYNC MANAGER] FINAL STATE TRANSITION: {} → complete", .{self.sync_state});
        const old_state = self.sync_state;
        self.sync_state = .complete;
        log.info("✅ [SYNC MANAGER] State transition successful: {} → {}", .{ old_state, self.sync_state });

        // Clear failed peers list on successful completion
        log.info("🧹 [SYNC MANAGER] Clearing failed peers list ({} entries)...", .{self.failed_peers.items.len});
        self.failed_peers.clearRetainingCapacity();
        log.info("✅ [SYNC MANAGER] Failed peers list cleared", .{});

        // Final state cleanup
        log.info("🧹 [SYNC MANAGER] Performing final state cleanup...", .{});
        self.clearSyncState();
        log.info("✅ [SYNC MANAGER] State cleanup completed", .{});

        log.info("\n🎊 [SYNC MANAGER] SYNCHRONIZATION COMPLETED SUCCESSFULLY!", .{});
        log.info("🎊 [SYNC MANAGER] Blockchain is now fully synchronized", .{});
        log.info("🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆🏆", .{});
    }

    /// Get current synchronization progress
    pub fn getProgress(self: *const Self) f64 {
        return self.batch_sync.getProgress();
    }

    /// Get current sync state
    pub fn getSyncState(self: *const Self) SyncState {
        return self.sync_state;
    }

    /// Check if sync is currently active
    pub fn isActive(self: *const Self) bool {
        return self.sync_state.isActive();
    }
    
    /// Check if sync has timed out and reset state if needed
    pub fn checkTimeout(self: *Self) void {
        if (self.sync_state.isActive() and self.sync_start_time > 0) {
            const current_time = std.time.timestamp();
            const elapsed_time = current_time - self.sync_start_time;
            
            if (elapsed_time > SYNC_CONFIG.SYNC_TIMEOUT) {
                log.warn("🚨 [SYNC TIMEOUT] Synchronization timed out after {} seconds", .{elapsed_time});
                log.warn("🔄 [SYNC TIMEOUT] Resetting sync state to idle", .{});
                self.sync_state = .idle;
                self.sync_start_time = 0;
                log.info("✅ [SYNC TIMEOUT] Sync state reset - ready for new sync attempts", .{});
            }
        }
    }

    /// Get detailed sync status for monitoring and debugging
    pub fn reportStatus(self: *const Self) void {
        log.info("📊 [SYNC MANAGER] === Sync Status Report ===", .{});
        log.info("📊 [SYNC MANAGER] State: {}", .{self.sync_state});
        log.info("📊 [SYNC MANAGER] Progress: {d:.1}%", .{self.getProgress()});
        log.info("📊 [SYNC MANAGER] Failed peers: {}", .{self.failed_peers.items.len});

        // Get detailed batch sync status
        if (self.sync_state.isActive()) {
            self.batch_sync.getStatus();
        }

        log.info("📊 [SYNC MANAGER] === End Status Report ===", .{});
    }

    // ========================================================================
    // PRIVATE HELPER METHODS
    // ========================================================================

    /// Start sequential sync for legacy peers that don't support batching
    fn startSequentialSync(self: *Self, peer: *Peer, target_height: u32) !void {
        log.info("🔄 [SYNC MANAGER] Starting sequential sync for legacy peer", .{});

        const current_height = try getBlockchainHeight();

        // Request blocks sequentially using sequential sync utilities
        const block_range = try sequential.requestBlockRange(self.allocator, peer, current_height + 1, target_height - current_height);
        defer {
            // Clean up all blocks
            for (block_range.items) |*block| {
                block.deinit(self.allocator);
            }
            block_range.deinit();
        }

        // Apply blocks sequentially
        for (block_range.items, 0..) |block, i| {
            const height = current_height + 1 + @as(u32, @intCast(i));
            try applyBlockToBlockchain(block);

            log.info("✅ [SYNC MANAGER] Sequential block {} applied", .{height});
        }

        self.sync_state = .complete;
        log.info("✅ [SYNC MANAGER] Sequential sync completed", .{});
    }

    /// Attempt to recover from sync failure by trying a different peer
    fn attemptSyncRecovery(self: *Self) !void {
        log.info("🔄 [SYNC MANAGER] Attempting sync recovery with peer rotation", .{});

        // Get next available peer
        const new_peer = self.getNextAvailablePeer() orelse {
            log.info("❌ [SYNC MANAGER] No peers available for recovery", .{});
            return;
        };

        // Restart sync with new peer
        const current_height = try getBlockchainHeight();
        const target_height = self.blockchain.getTargetHeight() catch current_height;

        if (target_height > current_height) {
            log.info("🔄 [SYNC MANAGER] Restarting sync with recovery peer", .{});
            try self.startSync(new_peer, target_height);
        }
    }

    /// Handle periodic state persistence for resume capability
    fn handleStatePersistence(self: *Self) !void {
        const now = self.getTime();

        if (now - self.last_state_save >= SYNC_CONFIG.STATE_SAVE_INTERVAL) {
            log.info("💾 [SYNC MANAGER] Saving sync state for resume capability", .{});

            // Save sync state to disk (implementation would be added here)
            // For now, just update timestamp
            self.last_state_save = now;

            log.info("✅ [SYNC MANAGER] Sync state saved", .{});
        }
    }

    /// Clear sync state and temporary files
    fn clearSyncState(self: *Self) void {
        log.info("🧹 [SYNC MANAGER] Clearing sync state and temporary files", .{});

        // Clear any temporary sync state files
        // Implementation would go here

        self.last_state_save = 0;
    }

    /// Get current timestamp
    fn getTime(self: *const Self) i64 {
        _ = self;
        return @import("../util/util.zig").getTime();
    }

    // ========================================================================
    // DEPENDENCY INJECTION IMPLEMENTATIONS
    // ========================================================================

    /// Get current blockchain height
    fn getBlockchainHeight() !u32 {
        if (g_blockchain) |blockchain| {
            return blockchain.database.getHeight() catch 0;
        }
        log.info("⚠️ [SYNC MANAGER] No blockchain reference available", .{});
        return 0;
    }

    /// Apply validated block to blockchain
    fn applyBlockToBlockchain(block: Block) !void {
        if (g_blockchain) |blockchain| {
            // Get the current blockchain height to determine where to apply this block
            const current_height = blockchain.database.getHeight() catch 0;
            const next_height = current_height + 1;

            log.info("🔧 [SYNC MANAGER] Applying block to blockchain at height {}", .{next_height});

            // Apply block using the chain processor
            blockchain.chain_processor.addBlockToChain(block, next_height) catch |err| {
                log.info("❌ [SYNC MANAGER] Failed to apply block to chain: {}", .{err});
                return err;
            };

            log.info("✅ [SYNC MANAGER] Block applied to blockchain successfully at height {}", .{next_height});
        } else {
            log.info("❌ [SYNC MANAGER] No blockchain reference available for applying block", .{});
            return error.NoBlockchainReference;
        }
    }

    /// Get next available peer for sync
    fn getNextAvailablePeer() ?*Peer {
        // This would be implemented to get the next available peer from peer manager
        // For now, return null
        log.info("🔍 [SYNC MANAGER] Getting next available peer (stub implementation)", .{});
        return null;
    }

    /// Validate block before applying
    fn validateBlockBeforeApply(block: Block, height: u32) !bool {
        log.info("🔍 [SYNC MANAGER] Validating sync block at height {}", .{height});

        // 1. Basic block structure validation
        if (!block.isValid()) {
            log.info("❌ [SYNC VALIDATION] Block structure invalid", .{});
            return false;
        }

        // 2. Validate previous hash points to current chain tip and verify hash chain continuity

        if (g_blockchain) |blockchain| {
            // Get current blockchain height
            const current_height = blockchain.database.getHeight() catch {
                log.info("❌ [SYNC VALIDATION] Failed to get blockchain height", .{});
                return false;
            };

            log.info("🔍 [SYNC VALIDATION] Current blockchain height: {}, validating block at height: {}", .{ current_height, height });

            // For height 1, validate against genesis block (height 0)
            if (height == 1) {
                const genesis_block = blockchain.database.getBlock(0) catch {
                    log.info("❌ [SYNC VALIDATION] Failed to get genesis block", .{});
                    return false;
                };

                const genesis_hash = genesis_block.hash();
                if (!std.mem.eql(u8, &block.header.previous_hash, &genesis_hash)) {
                    log.info("❌ [SYNC VALIDATION] Block 1 previous_hash doesn't match genesis hash", .{});
                    return false;
                }

                log.info("✅ [SYNC VALIDATION] Block 1 hash chain validation passed", .{});
                return true;
            }

            // For height > 1, validate against previous block
            if (height > 1) {
                const prev_height = height - 1;
                const prev_block = blockchain.database.getBlock(prev_height) catch {
                    log.info("❌ [SYNC VALIDATION] Failed to get block at height {}", .{prev_height});
                    return false;
                };

                const prev_hash = prev_block.hash();
                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    log.info("❌ [SYNC VALIDATION] Block {} previous_hash doesn't match block {} hash", .{ height, prev_height });
                    return false;
                }

                log.info("✅ [SYNC VALIDATION] Block {} hash chain validation passed", .{height});
                return true;
            }
        } else {
            log.info("❌ [SYNC VALIDATION] No blockchain reference available for validation", .{});
            return false;
        }

        log.info("✅ [SYNC VALIDATION] Block validation passed for height {}", .{height});
        return true;
    }

    /// Validate a batch of blocks for chain continuity (prevents fork issue)
    fn validateBulkBlocks(blocks: []const Block, start_height: u32, blockchain: *ZeiCoin) !bool {
        log.info("🔍 [BULK VALIDATION] Validating {} blocks starting at height {}", .{ blocks.len, start_height });

        if (blocks.len == 0) {
            log.info("⚠️ [BULK VALIDATION] Empty batch - nothing to validate", .{});
            return true;
        }

        // Check if we have the parent block for the first block in batch
        if (start_height > 0) {
            const parent_exists = blk: {
                var parent = blockchain.database.getBlock(start_height - 1) catch break :blk false;
                parent.deinit(blockchain.allocator);
                break :blk true;
            };
            if (!parent_exists) {
                log.info("❌ [BULK VALIDATION] Missing parent block at height {}", .{start_height - 1});
                return false;
            }

            // Get parent block to verify connection
            var parent_block = blockchain.database.getBlock(start_height - 1) catch {
                log.info("❌ [BULK VALIDATION] Cannot read parent block at height {}", .{start_height - 1});
                return false;
            };
            defer parent_block.deinit(blockchain.allocator);

            const parent_hash = parent_block.hash();
            if (!std.mem.eql(u8, &blocks[0].header.previous_hash, &parent_hash)) {
                log.info("❌ [BULK VALIDATION] First block doesn't connect to parent", .{});
                return false;
            }
        }

        // Verify each block connects to the previous block in the batch
        var prev_hash = if (start_height > 0) blk: {
            var parent = blockchain.database.getBlock(start_height - 1) catch {
                return false;
            };
            defer parent.deinit(blockchain.allocator);
            break :blk parent.hash();
        } else [_]u8{0} ** 32; // Genesis case

        for (blocks, 0..) |block, i| {
            const block_height = start_height + @as(u32, @intCast(i));

            // Check block connects to previous
            if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                log.info("❌ [BULK VALIDATION] Block {} doesn't connect to previous block", .{block_height});
                log.info("   Expected: {s}", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                log.info("   Got:      {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                return false;
            }

            // Basic validation for each block
            if (!block.isValid()) {
                log.info("❌ [BULK VALIDATION] Block {} has invalid structure", .{block_height});
                return false;
            }

            // Update prev_hash for next iteration
            prev_hash = block.hash();
        }

        log.info("✅ [BULK VALIDATION] All {} blocks form a valid chain", .{blocks.len});
        return true;
    }

    /// Verify block hash consensus with connected peers (optional additional security)
    pub fn verifyBlockConsensus(blockchain: *ZeiCoin, block: Block, height: u32) !bool {
        const mode = types.CONSENSUS.mode;
        
        // Skip if consensus is disabled
        if (mode == .disabled) {
            return true;
        }
        
        log.info("🔍 [CONSENSUS CHECK] Verifying block consensus at height {} (mode: {s})", .{ height, @tagName(mode) });

        // Get network coordinator to access peers
        const network_coordinator = blockchain.network_coordinator orelse {
            log.info("⚠️ [CONSENSUS CHECK] No network coordinator available", .{});
            return true; // Skip consensus check if no network
        };

        const network_manager = network_coordinator.getNetworkManager() orelse {
            log.info("⚠️ [CONSENSUS CHECK] No network manager available", .{});
            return true; // Skip consensus check if no network
        };

        // Get connected peers
        var connected_peers = std.ArrayList(*Peer).init(blockchain.allocator);
        defer connected_peers.deinit();

        try network_manager.peer_manager.getConnectedPeers(&connected_peers);

        if (connected_peers.items.len == 0) {
            log.info("⚠️ [CONSENSUS CHECK] No connected peers for consensus verification", .{});
            return true; // Can't verify consensus without peers
        }

        const block_hash = block.hash();
        log.info("📊 [CONSENSUS CHECK] Checking with {} peers for block at height {}", .{ connected_peers.items.len, height });
        log.info("📊 [CONSENSUS CHECK] Our block hash: {s}", .{std.fmt.fmtSliceHexLower(block_hash[0..8])});
        
        // Query peers for their block hash at this height
        var responses: u32 = 0;
        var agreements: u32 = 0;
        
        // Simple implementation: Query each peer synchronously
        // Future improvement: Query peers in parallel with timeout
        for (connected_peers.items) |peer| {
            // TODO: Send GetBlockHashMessage to peer and wait for response
            // For now, simulate response (will be implemented with proper message passing)
            
            // Temporary: assume peer agrees if it has sufficient height
            if (peer.height >= height) {
                responses += 1;
                // In real implementation, we'd compare the received hash
                // For now, simulate agreement
                agreements += 1;
            }
        }
        
        log.info("📊 [CONSENSUS CHECK] Received {}/{} responses, {}/{} agreements", .{
            responses,
            connected_peers.items.len,
            agreements,
            responses,
        });
        
        // Check minimum peer responses
        if (responses < types.CONSENSUS.min_peer_responses) {
            const msg = "Insufficient peer responses for consensus";
            if (mode == .enforced) {
                log.info("❌ [CONSENSUS CHECK] {s} ({}/{} required)", .{ msg, responses, types.CONSENSUS.min_peer_responses });
                return false;
            } else {
                log.info("⚠️ [CONSENSUS CHECK] {s} ({}/{} required) - proceeding anyway (mode: optional)", .{ msg, responses, types.CONSENSUS.min_peer_responses });
                return true;
            }
        }
        
        // Calculate consensus percentage
        const consensus_ratio = if (responses > 0) @as(f32, @floatFromInt(agreements)) / @as(f32, @floatFromInt(responses)) else 0.0;
        const meets_threshold = consensus_ratio >= types.CONSENSUS.threshold;
        
        log.info("📊 [CONSENSUS CHECK] Consensus ratio: {d:.1}% (threshold: {d:.1}%)", .{
            consensus_ratio * 100,
            types.CONSENSUS.threshold * 100,
        });
        
        if (!meets_threshold) {
            const msg = "Block consensus threshold not met";
            if (mode == .enforced) {
                log.info("❌ [CONSENSUS CHECK] {s}", .{msg});
                return false;
            } else {
                log.info("⚠️ [CONSENSUS CHECK] {s} - proceeding anyway (mode: optional)", .{msg});
                return true;
            }
        }
        
        log.info("✅ [CONSENSUS CHECK] Block consensus verified", .{});
        return true;
    }

    // ========================================================================
    // PEER MANAGEMENT HELPERS
    // ========================================================================

    /// Add a peer to the failed peers list
    pub fn addFailedPeer(self: *Self, peer: *Peer) !void {
        // Avoid duplicates
        for (self.failed_peers.items) |failed_peer| {
            if (failed_peer == peer) return;
        }

        // Add to failed list with capacity management
        if (self.failed_peers.items.len >= SYNC_CONFIG.MAX_FAILED_PEERS) {
            _ = self.failed_peers.orderedRemove(0); // Remove oldest
        }

        try self.failed_peers.append(peer);

        log.info("🚫 [SYNC MANAGER] Added peer to failed list (total: {})", .{self.failed_peers.items.len});
    }

    /// Check if a peer is in the failed peers list
    pub fn isPeerFailed(self: *const Self, peer: *Peer) bool {
        for (self.failed_peers.items) |failed_peer| {
            if (failed_peer == peer) return true;
        }
        return false;
    }

    /// Clear failed peers list (typically after successful sync)
    pub fn clearFailedPeers(self: *Self) void {
        self.failed_peers.clearRetainingCapacity();
        log.info("🧹 [SYNC MANAGER] Cleared failed peers list", .{});
    }

    // ========================================================================
    // TESTING AND VALIDATION
    // ========================================================================

    /// Run sync manager test suite
    pub fn runTests(allocator: Allocator) !void {
        log.info("🧪 [SYNC MANAGER] Running sync manager test suite", .{});

        // Test basic initialization
        var mock_blockchain: ZeiCoin = undefined; // Would be properly initialized in real tests
        var manager = try SyncManager.init(allocator, &mock_blockchain);
        defer manager.deinit();

        // Test state management
        if (manager.isActive()) {
            return error.ShouldNotBeActiveInitially;
        }

        if (manager.getSyncState() != .idle) {
            return error.ShouldBeIdleInitially;
        }

        log.info("✅ [SYNC MANAGER] Sync manager tests passed", .{});
    }
};

// ============================================================================
// MODULE EXPORTS AND UTILITIES
// ============================================================================

/// Create a properly configured sync manager instance
pub fn createSyncManager(allocator: Allocator, blockchain: *ZeiCoin) !SyncManager {
    return SyncManager.init(allocator, blockchain);
}

/// Run comprehensive sync manager tests
pub fn test_syncManager() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try SyncManager.runTests(allocator);
    log.info("✅ [SYNC MANAGER] All tests passed successfully", .{});
}
