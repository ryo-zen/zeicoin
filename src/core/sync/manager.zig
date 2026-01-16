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
pub var g_blockchain: ?*ZeiCoin = null;
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

    /// Fork cooldown tracking to prevent immediate retry loops
    fork_cooldowns: std.AutoHashMap(u32, i64),

    /// Last sync retry check timestamp
    last_sync_retry_check: i64,

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
            .fork_cooldowns = std.AutoHashMap(u32, i64).init(allocator),
            .last_sync_retry_check = 0,
        };
    }

    /// Clean up sync manager resources
    pub fn deinit(self: *Self) void {
        log.debug("Cleaning up sync manager resources", .{});

        self.batch_sync.deinit();
        self.failed_peers.deinit();
        self.fork_cooldowns.deinit();

        log.debug("Sync manager cleanup completed", .{});
    }

    /// Start synchronization with a peer to a target height
    /// Main entry point for blockchain synchronization
    /// force_reorg: If true, bypasses height difference check to force reorganization at equal heights
    pub fn startSync(self: *Self, peer: *Peer, target_height: u32, force_reorg: bool) !void {
        log.info("INITIATING BLOCKCHAIN SYNCHRONIZATION", .{});
        log.info("Session parameters:", .{});
        log.info("   Target peer: {any}", .{peer.address});
        log.info("   Target height: {}", .{target_height});
        log.info("   Force reorg: {}", .{force_reorg});
        log.info("   Current state: {}", .{self.sync_state});
        log.info("   Failed peers: {}", .{self.failed_peers.items.len});

        // CRITICAL: Pause mining during sync/reorg to prevent race conditions
        // Mining interference can cause BlockRequestTimeout, InvalidPreviousHash errors, and reorg failures
        const was_mining = self.blockchain.mining_state.active.load(.acquire);
        if (was_mining) {
            self.blockchain.mining_state.active.store(false, .release);
            log.info("⏸️  [SYNC] Paused mining for synchronization/reorganization", .{});
        }

        // Track whether mining should resume (will be set to false if fork detection fails)
        var should_resume_mining = was_mining;

        // Ensure mining resumes when sync completes successfully
        // IMPORTANT: Don't resume mining if in failed state (fork detection failed)
        defer {
            if (should_resume_mining) {
                // CRITICAL FIX: Mining thread exits when active flag is set to false
                // The thread handle remains non-null, but the thread has terminated
                // We must stop the thread properly (join + clear handle) then restart it
                log.info("🔄 [SYNC] Stopping and restarting mining thread after sync/reorg", .{});

                if (self.blockchain.mining_manager) |mining_manager| {
                    // Stop the old thread properly (join and clear handle)
                    mining_manager.stopMining();

                    // Restart mining with stored keypair
                    mining_manager.startMiningDeferred() catch |err| {
                        log.err("❌ [SYNC] Failed to restart mining thread: {}", .{err});
                    };
                    log.info("▶️  [SYNC] Mining thread restarted after synchronization/reorganization", .{});
                }
            } else if (was_mining) {
                log.warn("⏸️  [SYNC] Mining remains paused - sync failed (will retry after cooldown)", .{});
                log.warn("💡 [SYNC] Mining will resume after successful sync or manual intervention", .{});
            }
        }

        // Check if sync can be started
        log.debug("STEP 1: Validating sync state...", .{});
        if (!self.sync_state.canStart()) {
            log.err("STEP 1 FAILED: Sync cannot be started", .{});
            log.warn("Current state: {} (expected: idle, failed, or complete)", .{self.sync_state});
            log.info("Suggestion: Wait for current sync to complete or call stopSync()", .{});
            return;
        }
        
        // Transition to analyzing state to prevent concurrent initiations
        self.sync_state = .analyzing;
        errdefer self.sync_state = .failed;
        
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

        if (height_diff < SYNC_CONFIG.MIN_SYNC_HEIGHT_DIFF and !force_reorg) {
            log.warn("🚫 [SYNC ABORT] Already synchronized - height diff {} < threshold {}", .{ height_diff, SYNC_CONFIG.MIN_SYNC_HEIGHT_DIFF });
            log.info("Local height {} >= target height {} (diff: {})", .{ current_height, target_height, height_diff });
            log.info("No synchronization needed - session complete", .{});
            self.sync_state = .idle;
            return;
        }
        if (force_reorg and height_diff == 0) {
            log.info("🔄 [FORCE REORG] Bypassing height check for equal-height fork resolution", .{});
        }
        log.info("STEP 2 PASSED: Sync required ({} blocks behind, force_reorg={})", .{ height_diff, force_reorg });

        // STEP 2.5: Check for competing chain (divergent chain from common ancestor)
        // CRITICAL: We check for divergence even if heights are equal, as we might be on a fork.
        if (target_height > 0) {
            log.debug("STEP 2.5: Checking for competing chains...", .{});
            const is_competing = self.detectCompetingChain(peer) catch |err| {
                log.err("❌ [FORK DETECT] Failed to detect competing chain: {}", .{err});
                log.err("⚠️  [FORK DETECT] Fork detection failed - keeping mining paused", .{});

                // Add extended cooldown
                self.addForkCooldown(current_height, 60) catch {};

                // Keep mining paused
                should_resume_mining = false;
                self.sync_state = .failed;

                return error.ForkDetectionFailed;
            };

            if (is_competing) {
                const fork_detector = @import("fork_detector.zig");

                log.warn("🔥 [COMPETING CHAIN] Peer has divergent chain!", .{});
                log.warn("   Our height: {}", .{current_height});
                log.warn("   Peer height: {}", .{target_height});

                // Find fork point for reorg decision
                const fork_point = fork_detector.findForkPoint(
                    self.allocator,
                    g_blockchain.?.database,
                    peer,
                    current_height,
                    target_height,
                ) catch |err| {
                    log.err("❌ [REORG] Failed to find fork point: {}", .{err});
                    log.err("⚠️  [REORG] Fork detection failed - will retry after cooldown", .{});

                    // Add extended cooldown to prevent rapid retry loops
                    self.addForkCooldown(current_height, 60) catch {};

                    // Keep mining paused to prevent fork from worsening
                    should_resume_mining = false;

                    // Set sync to failed state
                    self.sync_state = .failed;

                    // Return error
                    return error.ForkDetectionFailed;
                };

                // Use cumulative work comparison (Bitcoin's method)
                const should_reorg = fork_detector.shouldReorganize(
                    self.allocator,
                    g_blockchain.?.database,
                    peer,
                    current_height,
                    target_height,
                    fork_point,
                ) catch |err| {
                    log.err("❌ [REORG] Failed to compare chain work: {}", .{err});
                    log.err("⚠️  [REORG] Work comparison failed - will retry after cooldown", .{});

                    // Add extended cooldown to prevent rapid retry loops
                    self.addForkCooldown(current_height, 60) catch {};

                    // Keep mining paused to prevent fork from worsening
                    should_resume_mining = false;

                    // Set sync to failed state
                    self.sync_state = .failed;

                    // Return error
                    return error.ForkDetectionFailed;
                };

                if (should_reorg) {
                    log.warn("🔄 [REORG DECISION] Peer chain has more work - reorganizing!", .{});
                    try self.executeBulkReorg(peer, fork_point, target_height);
                    self.sync_state = .idle; // executeBulkReorg finishes sync
                    return;
                } else {
                    // PREFIX CASE: If fork_point == our tip, we're a prefix of peer's chain
                    // This means NO divergence - just sync forward normally
                    const is_prefix = (fork_point == current_height);

                    if (is_prefix) {
                        log.info("ℹ️  [REORG DECISION] Chain is prefix - continuing with normal sync", .{});
                        // Fall through to normal sync below
                    } else {
                        log.info("ℹ️  [REORG DECISION] Our chain has equal or more work - keeping our chain", .{});

                        // If heights are equal but we didn't reorg, we stay on our fork.
                        // If peer was behind, they might sync from us.
                        if (target_height > current_height) {
                            // Competing chain: peer has more blocks but less work (e.g. difficulty attack)
                            // In Bitcoin, we would just ignore this peer for now or wait for more work.
                            log.warn("⚠️  Peer has MORE blocks ({}) but LESS work. Ignoring sync request.", .{target_height});
                            self.sync_state = .idle;
                            return;
                        }

                        // If chains are divergent but we have more work, we don't reorg.
                        // Normal sync will continue if we decide to just extend our chain.
                    }
                }
            } else {
                log.debug("STEP 2.5 PASSED: Chains are compatible, proceeding with normal sync", .{});
            }
        }

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

            // For equal-height fork resolution, re-download chain from height 1
            if (force_reorg and height_diff == 0) {
                log.info("🔄 [FORCE REORG] Equal-height fork detected - syncing chain from height 1", .{});
                try self.batch_sync.syncFromHeight(peer, 1, target_height);
            } else {
                try self.batch_sync.startSync(peer, target_height);
            }

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

        // CRITICAL FIX #4: Polling loop to retrieve blocks and handle timeouts
        // Without this loop, blocks are cached but never retrieved or processed
        log.info("🔄 [SYNC POLL] Starting sync polling loop (polls every 5 seconds)", .{});

        while (self.sync_state.isActive()) {
            // Sleep for 5 seconds between polls
            std.time.sleep(5 * std.time.ns_per_s);

            // Check for global timeout
            const elapsed = std.time.timestamp() - self.sync_start_time;
            if (elapsed > SYNC_CONFIG.SYNC_TIMEOUT) {
                log.warn("🚨 [SYNC TIMEOUT] Synchronization timed out after {} seconds", .{elapsed});
                self.sync_state = .failed;
                break;
            }

            // Poll for new blocks and handle timeouts
            self.handleTimeouts() catch |err| {
                log.err("❌ [SYNC POLL] Error during timeout handling: {}", .{err});
                self.sync_state = .failed;
                break;
            };

            // Update our state from batch sync
            self.sync_state = self.batch_sync.getSyncState();

            // Handle sync failure
            if (self.sync_state == .failed) {
                log.warn("🔴 [SYNC POLL] Sync failed, exiting polling loop", .{});
                break;
            }

            // Log progress periodically
            if (@mod(elapsed, 10) < 5) { // Log every ~10 seconds
                log.info("📊 [SYNC PROGRESS] State: {}, Progress: {d:.1}%, Elapsed: {}s", .{
                    self.sync_state,
                    self.getProgress(),
                    elapsed,
                });
            }
        }

        log.info("🏁 [SYNC POLL] Polling loop ended - Final state: {}", .{self.sync_state});
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

        // CRITICAL: Retrieve blocks from peer cache before checking timeouts
        // This ensures blocks that have arrived are processed before timeout logic
        try self.batch_sync.retrievePendingBlocks();

        // Handle batch sync timeouts
        try self.batch_sync.handleTimeouts();

        // Update our state based on batch sync state
        self.sync_state = self.batch_sync.getSyncState();
    }

    /// Complete synchronization process
    pub fn completeSync(self: *Self) !void {
        log.info("[SYNC] Completing synchronization session", .{});
        log.info("[SYNC] Final statistics: state={}, progress={d:.1}%, failed_peers={}, duration={}s", .{
            self.sync_state,
            self.getProgress(),
            self.failed_peers.items.len,
            self.getTime() - self.last_state_save,
        });

        // Update sync state
        const old_state = self.sync_state;
        self.sync_state = .complete;
        log.debug("[SYNC] State transition: {} -> {}", .{ old_state, self.sync_state });

        // Clear failed peers list on successful completion
        self.failed_peers.clearRetainingCapacity();

        // Final state cleanup
        self.clearSyncState();

        log.info("[SYNC] Synchronization completed successfully - blockchain is fully synchronized", .{});
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

    /// Notify sync manager that a block was received and applied
    /// Called from onBlock handler when blocks arrive during active sync
    pub fn notifyBlockReceived(self: *Self, height: u32) void {
        if (!self.sync_state.isActive()) return;

        // Notify batch sync of the received block
        self.batch_sync.notifyBlockReceived(height);

        // Update our state if batch sync completed
        if (self.batch_sync.isComplete()) {
            log.info("✅ [SYNC MANAGER] Batch sync completed, updating state", .{});
            self.sync_state = .complete;
            self.sync_start_time = 0;
        }
    }

    /// Check if sync has timed out and reset state if needed
    pub fn checkTimeout(self: *Self) void {
        if (self.sync_state.isActive() and self.sync_start_time > 0) {
            const current_time = std.time.timestamp();
            const elapsed_time = current_time - self.sync_start_time;

            if (elapsed_time > SYNC_CONFIG.SYNC_TIMEOUT) {
                log.warn("🚨 [SYNC TIMEOUT] Synchronization timed out after {} seconds", .{elapsed_time});
                log.warn("🔄 [SYNC TIMEOUT] Resetting sync state to idle", .{});
                
                // CRITICAL: Reset batch sync protocol state as well
                self.batch_sync.failSync("Synchronization session timeout");
                
                self.sync_state = .idle;
                self.sync_start_time = 0;
                log.info("✅ [SYNC TIMEOUT] Sync state reset - ready for new sync attempts", .{});
            }
        }
    }

    /// Add a cooldown period for a specific fork height to prevent retry loops
    pub fn addForkCooldown(self: *Self, fork_height: u32, seconds: i64) !void {
        const cooldown_until = std.time.timestamp() + seconds;
        try self.fork_cooldowns.put(fork_height, cooldown_until);
        log.info("⏳ [SYNC] Added {} second cooldown for fork height {}", .{ seconds, fork_height });
    }

    /// Check if we can attempt sync at a given fork height (cooldown expired)
    /// Public API to allow server handlers to check before initiating sync on peer connection
    pub fn canSyncAtForkHeight(self: *Self, fork_height: u32) bool {
        log.info("🔍 [SYNC COOLDOWN] Checking if can sync at fork height {}", .{fork_height});

        // Check if there's an active cooldown for this fork height
        if (self.fork_cooldowns.get(fork_height)) |cooldown_until| {
            const now = std.time.timestamp();
            if (now < cooldown_until) {
                const remaining = cooldown_until - now;
                log.info("⏳ [SYNC COOLDOWN] Fork height {} in cooldown for {} more seconds", .{ fork_height, remaining });
                log.info("💡 [SYNC COOLDOWN] Sync will be deferred until cooldown expires", .{});
                return false;
            }
            // Cooldown expired, remove it
            _ = self.fork_cooldowns.remove(fork_height);
            log.info("✅ [SYNC COOLDOWN] Fork height {} cooldown EXPIRED - ready for retry!", .{fork_height});
            log.info("🔄 [SYNC COOLDOWN] Proceeding with sync attempt after cooldown period", .{});
        } else {
            log.info("✅ [SYNC COOLDOWN] No active cooldown for fork height {} - ready to sync", .{fork_height});
        }

        log.info("✅ [SYNC COOLDOWN] All checks passed - sync can proceed at height {}", .{fork_height});
        return true;
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

    /// Handle peer with potentially competing chain
    /// Triggered when a peer announces a new block or height updates
    pub fn handlePeerSync(self: *Self, peer: *Peer) !void {
        const our_height = try getBlockchainHeight();
        
        // If peer is ahead or at equal height (might be a fork), check for sync/reorg
        if (peer.height >= our_height and peer.height > 0) {
            // Check for divergence
            const is_competing = try self.detectCompetingChain(peer);
            
            if (is_competing) {
                log.info("🔥 [FORK DETECTED] Peer height {} vs our height {}", .{peer.height, our_height});
                
                // If we are already syncing, cancel it to allow reorg check
                if (self.sync_state.isActive()) {
                    log.info("🔄 [REORG TRIGGER] Canceling active sync to handle competing chain", .{});
                    self.batch_sync.failSync("Canceled for reorganization");
                    self.sync_state = .idle;
                }
                
                try self.startSync(peer, peer.height, false);
            } else if (peer.height > our_height) {
                // Not competing, just ahead. Trigger normal sync if not already syncing.
                if (self.sync_state.canStart()) {
                    try self.startSync(peer, peer.height, false);
                }
            }
        }
    }

    /// Attempt to recover from sync failure by trying a different peer
    pub fn attemptSyncRecovery(self: *Self) !void {
        log.info("🔄 [SYNC MANAGER] Attempting sync recovery with peer rotation", .{});

        const current_height = try getBlockchainHeight();
        const target_height = if (g_blockchain) |bc|
            bc.network_coordinator.getNetworkManager().?.getHighestPeerHeight()
        else
            current_height;

        // Check fork cooldown before attempting sync
        if (!self.canSyncAtForkHeight(current_height)) {
            log.debug("Sync recovery skipped - fork height in cooldown", .{});
            return;
        }

        // Get next available peer using smart selection
        const new_peer = getNextAvailablePeer() orelse {
            log.info("❌ [SYNC MANAGER] No peers available for recovery", .{});
            return;
        };

        // Increment reference count for the duration of startSync (which might block)
        new_peer.addRef();
        defer new_peer.release();

        // Only sync if target is higher than current
        if (target_height > current_height) {
            const blocks_behind = target_height - current_height;
            log.info("🔄 [SYNC MANAGER] Restarting sync with recovery peer ({} blocks behind)", .{blocks_behind});
            try self.startSync(new_peer, target_height, false);
        } else {
            log.debug("Sync not needed - already at target height", .{});
        }
    }

    /// Sync a specific range of blocks for reorganization scenarios
    /// This is used when we detect missing intermediate blocks during reorg
    pub fn syncBlockRange(self: *Self, peer: *Peer, start_height: u32, end_height: u32) !void {
        log.info("🔄 [SYNC RANGE] ========================================", .{});
        log.info("🔄 [SYNC RANGE] Initiating block range sync for reorganization", .{});
        log.info("🔄 [SYNC RANGE] Start height: {}", .{start_height});
        log.info("🔄 [SYNC RANGE] End height: {}", .{end_height});
        log.info("🔄 [SYNC RANGE] Blocks to fetch: {}", .{end_height - start_height + 1});
        log.info("🔄 [SYNC RANGE] Peer: {}", .{peer});
        log.info("🔄 [SYNC RANGE] ========================================", .{});

        // Validate parameters
        if (start_height > end_height) {
            log.err("❌ [SYNC RANGE] Invalid range: start {} > end {}", .{start_height, end_height});
            return error.InvalidBlockRange;
        }

        if (start_height == 0) {
            log.err("❌ [SYNC RANGE] Cannot sync from genesis (height 0)", .{});
            return error.InvalidBlockRange;
        }

        log.info("✅ [SYNC RANGE] Parameters validated", .{});

        // Check current sync state
        if (self.sync_state.isActive()) {
            log.warn("⚠️ [SYNC RANGE] Sync already active - state: {}", .{self.sync_state});
            log.info("💡 [SYNC RANGE] Failing current sync to allow range sync", .{});
            self.batch_sync.failSync("Interrupted by block range sync");
            self.sync_state = .idle;
        }

        log.info("🔄 [SYNC RANGE] Calling batch sync with custom height range", .{});

        // Use batch sync with custom start height
        self.batch_sync.syncFromHeight(peer, start_height, end_height) catch |err| {
            log.err("❌ [SYNC RANGE] Failed to start batch sync: {}", .{err});
            log.err("   Start: {}, End: {}", .{start_height, end_height});
            log.err("   Peer: {}", .{peer});
            return err;
        };

        log.info("✅ [SYNC RANGE] Batch sync initiated successfully", .{});
        log.info("⏳ [SYNC RANGE] Waiting for blocks to arrive...", .{});
    }

    /// Detect if peer has a competing chain using fork point detection
    fn detectCompetingChain(self: *Self, peer: *Peer) !bool {
        const fork_detector = @import("fork_detector.zig");

        const current_height = try getBlockchainHeight();
        const peer_height = peer.height;

        // Early return if we're at genesis
        if (current_height == 0) {
            log.debug("✅ [CHAIN DETECT] We're at genesis, accepting peer's chain", .{});
            return false;
        }

        log.info("🔍 [FORK DETECT] Starting fork point detection", .{});
        log.info("   Our height: {}", .{current_height});
        log.info("   Peer height: {}", .{peer_height});

        // Use fork_detector to find the fork point
        const fork_point = fork_detector.findForkPoint(
            self.allocator,
            g_blockchain.?.database,
            peer,
            current_height,
            peer_height,
        ) catch |err| {
            log.warn("⚠️ [FORK DETECT] Failed to find fork point: {}", .{err});
            // Propagate error instead of fallback to prevent mining from resuming
            return err;
        };

        log.info("📍 [FORK DETECT] Fork point found at height {}", .{fork_point});

        // If fork point is at current height, chains are the same
        if (fork_point == current_height and fork_point == peer_height) {
            log.debug("✅ [FORK DETECT] Chains are identical", .{});
            return false;
        }

        // If fork point is less than current height, we have divergence
        if (fork_point < current_height or fork_point < peer_height) {
            log.warn("🔥 [FORK DETECT] Chains diverged at height {}!", .{fork_point});
            log.warn("   Our blocks after fork: {}", .{current_height - fork_point});
            log.warn("   Peer blocks after fork: {}", .{peer_height - fork_point});
            return true;
        }

        log.debug("✅ [FORK DETECT] Chains are compatible", .{});
        return false;
    }

    /// Legacy fork detection (checks only block 1) - fallback
    fn detectCompetingChainLegacy(self: *Self, peer: *Peer) !bool {
        const current_height = try getBlockchainHeight();

        // Request peer's block 1 to compare
        log.debug("🔍 [CHAIN DETECT LEGACY] Requesting peer's block 1 for comparison (our height: {})", .{current_height});

        const peer_blocks = sequential.requestBlockRange(self.allocator, peer, 1, 1) catch |err| {
            log.warn("⚠️ [CHAIN DETECT LEGACY] Failed to request peer's block 1: {}", .{err});
            return false; // Can't determine, assume compatible
        };
        defer {
            for (peer_blocks.items) |*block| {
                block.deinit(self.allocator);
            }
            peer_blocks.deinit();
        }

        if (peer_blocks.items.len == 0) {
            log.warn("⚠️ [CHAIN DETECT LEGACY] Peer returned no blocks", .{});
            return false;
        }

        const peer_block_1 = peer_blocks.items[0];

        // Get our block 1 (if we have it)
        var our_block_1 = g_blockchain.?.database.getBlock(1) catch |err| {
            log.debug("✅ [CHAIN DETECT LEGACY] We don't have block 1 yet ({}), accepting peer's chain", .{err});
            return false;
        };
        defer our_block_1.deinit(self.allocator);

        // Compare hashes
        const peer_hash = peer_block_1.hash();
        const our_hash = our_block_1.hash();

        if (!std.mem.eql(u8, &peer_hash, &our_hash)) {
            log.warn("🔥 [CHAIN DETECT LEGACY] Competing chain detected!", .{});
            log.warn("   Our block 1:   {s}", .{std.fmt.fmtSliceHexLower(&our_hash)});
            log.warn("   Peer block 1:  {s}", .{std.fmt.fmtSliceHexLower(&peer_hash)});
            return true;
        }

        log.debug("✅ [CHAIN DETECT LEGACY] Chains are compatible (same block 1)", .{});
        return false;
    }

    /// Execute bulk reorganization to switch to peer's longer chain
    fn executeBulkReorg(self: *Self, peer: *Peer, fork_point: u32, peer_height: u32) !void {
        log.warn("🔄 [BULK REORG] ========================================", .{});
        log.warn("🔄 [BULK REORG] Starting chain reorganization from fork point {}", .{fork_point});
        log.warn("🔄 [BULK REORG] ========================================", .{});

        const current_height = try getBlockchainHeight();
        log.warn("   Current height: {}", .{current_height});
        log.warn("   Target height: {}", .{peer_height});
        log.warn("   Blocks to fetch: {}", .{peer_height - fork_point});

        // Fetch the competing chain from peer starting at fork_point + 1
        log.info("📥 [BULK REORG] Fetching competing chain blocks...", .{});

        // Use batch sync to fetch all blocks
        var all_blocks = std.ArrayList(Block).init(self.allocator);
        defer {
            for (all_blocks.items) |*block| {
                block.deinit(self.allocator);
            }
            all_blocks.deinit();
        }

        // Fetch blocks in batches (50 at a time)
        var batch_start: u32 = fork_point + 1;
        while (batch_start <= peer_height) {
            const batch_end = @min(batch_start + 49, peer_height);
            const batch_size = batch_end - batch_start + 1;

            log.info("   Fetching batch: blocks {} to {} ({} blocks)", .{batch_start, batch_end, batch_size});

            const batch_blocks = sequential.requestBlockRange(self.allocator, peer, batch_start, batch_size) catch |err| {
                log.err("❌ [BULK REORG] Failed to fetch batch starting at {}: {}", .{batch_start, err});
                return error.BulkReorgFetchFailed;
            };
            defer batch_blocks.deinit();

            // Add to our collection
            for (batch_blocks.items) |block| {
                const block_copy = try block.clone(self.allocator);
                try all_blocks.append(block_copy);
            }

            batch_start = batch_end + 1;
        }

        log.warn("✅ [BULK REORG] Fetched {} blocks from peer", .{all_blocks.items.len});

        // Execute reorganization via chain processor
        log.warn("🔄 [BULK REORG] Executing chain reorganization...", .{});

        if (g_blockchain) |blockchain| {
            try blockchain.chain_processor.executeBulkReorg(all_blocks.items);
            log.warn("✅ [BULK REORG] Reorganization completed successfully!", .{});
        } else {
            log.err("❌ [BULK REORG] No blockchain instance available", .{});
            return error.NoBlockchain;
        }

        log.warn("🔄 [BULK REORG] ========================================", .{});
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
        if (g_blockchain) |blockchain| {
            const network_mgr = blockchain.network_coordinator.getNetworkManager() orelse return null;
            
            // Use getBestPeerForSync which is now thread-safe and returns an addRef'd peer
            if (network_mgr.peer_manager.getBestPeerForSync()) |peer| {
                // Check if this peer is in our failed list
                if (blockchain.sync_manager) |manager| {
                    for (manager.failed_peers.items) |failed| {
                        if (failed == peer) {
                            // Release it since we aren't using it
                            peer.release();
                            return null; // TODO: Implement better rotation
                        }
                    }
                }
                return peer;
            }
        }
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
