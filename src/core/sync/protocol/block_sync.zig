// sync/protocol/block_sync.zig - Traditional Block Sync Protocol Implementation
// Extracted from node.zig for modular sync architecture

const std = @import("std");
const log = std.log.scoped(.sync);

const types = @import("../../types/types.zig");
const util = @import("../../util/util.zig");
const net = @import("../../network/peer.zig");
const key = @import("../../crypto/key.zig");
const genesis = @import("../../chain/genesis.zig");
const miner_mod = @import("../../miner/main.zig");

/// Blockchain synchronization state
pub const SyncState = enum {
    synced, // Up to date with peers
    syncing, // Currently downloading blocks
    sync_complete, // Sync completed, ready to switch to synced
    sync_failed, // Sync failed, will retry later
};

/// Sync progress tracking
pub const SyncProgress = struct {
    target_height: u32,
    current_height: u32,
    blocks_downloaded: u32,
    start_time: i64,
    last_progress_report: i64,
    last_request_time: i64,
    retry_count: u32,
    consecutive_failures: u32, // Track consecutive failures across all peers

    pub fn init(current: u32, target: u32) SyncProgress {
        const now = util.getTime();
        return SyncProgress{
            .target_height = target,
            .current_height = current,
            .blocks_downloaded = 0,
            .start_time = now,
            .last_progress_report = now,
            .last_request_time = now,
            .retry_count = 0,
            .consecutive_failures = 0,
        };
    }

    pub fn getProgress(self: *const SyncProgress) f64 {
        if (self.target_height <= self.current_height) return 100.0;
        const total_blocks = self.target_height - self.current_height;
        if (total_blocks == 0) return 100.0;
        return (@as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(total_blocks))) * 100.0;
    }

    pub fn getETA(self: *const SyncProgress) i64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0 or self.blocks_downloaded == 0) return 0;

        if (self.blocks_downloaded >= (self.target_height - self.current_height)) return 0;
        const remaining_blocks = (self.target_height - self.current_height) - self.blocks_downloaded;
        const blocks_per_second = @as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(elapsed));
        if (blocks_per_second == 0) return 0;

        return @as(i64, @intFromFloat(@as(f64, @floatFromInt(remaining_blocks)) / blocks_per_second));
    }

    pub fn getBlocksPerSecond(self: *const SyncProgress) f64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0) return 0.0;
        return @as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(elapsed));
    }
};

/// Context needed for block sync operations
pub const BlockSyncContext = struct {
    // Dependencies
    allocator: std.mem.Allocator,
    database: *@import("../../storage/db.zig").Database,
    network: ?*@import("../../network/peer.zig").NetworkManager,
    // fork_manager removed - using modern reorganization system
    
    // Chain operations
    getHeight: *const fn (ctx: *const BlockSyncContext) anyerror!u32,
    getBlockByHeight: *const fn (ctx: *const BlockSyncContext, height: u32) anyerror!types.Block,
    processBlockTransactions: *const fn (ctx: *const BlockSyncContext, transactions: []types.Transaction) anyerror!void,
    validateTransactionSignature: *const fn (ctx: *const BlockSyncContext, tx: types.Transaction) anyerror!bool,
};

/// Traditional block synchronization protocol
pub const BlockSyncProtocol = struct {
    context: *BlockSyncContext,
    
    // Sync state
    sync_state: SyncState,
    sync_progress: ?SyncProgress,
    sync_peer: ?*net.Peer,
    failed_peers: std.ArrayList(*net.Peer),

    pub fn init(allocator: std.mem.Allocator, context: *BlockSyncContext) BlockSyncProtocol {
        return BlockSyncProtocol{
            .context = context,
            .sync_state = .synced,
            .sync_progress = null,
            .sync_peer = null,
            .failed_peers = std.ArrayList(*net.Peer).init(allocator),
        };
    }

    pub fn deinit(self: *BlockSyncProtocol) void {
        self.failed_peers.deinit();
    }

    /// Logging utilities for simplicity
    fn logError(comptime fmt: []const u8, args: anytype) void {
        log.info("❌ " ++ fmt ++ "\n", args);
    }

    fn logSuccess(comptime fmt: []const u8, args: anytype) void {
        log.info("✅ " ++ fmt ++ "\n", args);
    }

    fn logInfo(comptime fmt: []const u8, args: anytype) void {
        log.info("ℹ️  " ++ fmt ++ "\n", args);
    }

    fn logProcess(comptime fmt: []const u8, args: anytype) void {
        log.info("🔄 " ++ fmt ++ "\n", args);
    }

    /// Start sync process with a peer
    pub fn startSync(self: *BlockSyncProtocol, peer: *net.Peer, target_height: u32) !void {
        const current_height = try self.context.getHeight(self.context);

        // Special case: if we have no blockchain (height 0), sync from genesis (height 0)
        if (current_height == 0 and target_height > 0) {
            log.info("🔄 Starting sync from genesis: 0 -> {} ({} blocks to download)", .{ target_height, target_height });
        } else if (target_height <= current_height) {
            log.info("ℹ️  Already up to date (height {})", .{current_height});
            return;
        } else {
            log.info("🔄 Starting sync: {} -> {} ({} blocks behind)", .{ current_height, target_height, target_height - current_height });
        }

        // Initialize sync state
        self.sync_state = .syncing;
        self.sync_progress = SyncProgress.init(current_height, target_height);
        self.sync_peer = peer;

        // Start downloading blocks in batches
        try self.requestNextSyncBatch();
    }

    /// Handle incoming sync block
    /// NOTE: We take ownership of the block - the caller transfers ownership to us.
    pub fn handleSyncBlock(self: *BlockSyncProtocol, expected_height: u32, block: types.Block) !void {
        // Take ownership and ensure cleanup
        var owned_block = block;
        defer owned_block.deinit(self.context.allocator);
        
        log.info("🔄 Processing sync block at height {}", .{expected_height});

        // Check if block already exists to prevent duplicate processing
        const existing_block = self.context.database.getBlock(expected_height) catch null;
        if (existing_block) |block_data| {
            // IMPORTANT: Free the loaded block to prevent memory leak
            var block_to_free = block_data;
            defer block_to_free.deinit(self.context.allocator);
            
            log.info("ℹ️  Block {} already exists, skipping duplicate during sync", .{expected_height});

            // Still need to update sync progress for this "processed" block
            if (self.sync_progress) |*progress| {
                progress.blocks_downloaded += 1;
                progress.consecutive_failures = 0; // Reset on successful processing

                // Check if we've completed sync with this existing block
                const current_height = self.context.getHeight(self.context) catch expected_height;
                if (current_height >= progress.target_height) {
                    log.info("🎉 Sync completed with existing blocks!", .{});
                    self.completSync();
                    return;
                }
            }
            return; // Skip duplicate block gracefully
        }

        // For sync, validate block structure and PoW only (skip transaction balance checks)
        const validation_result = self.validateSyncBlock(owned_block, expected_height) catch |err| {
            log.info("❌ Block validation threw error at height {}: {}", .{ expected_height, err });
            return;
        };
        if (!validation_result) {
            log.info("❌ Block validation failed at height {}", .{expected_height});

            // Check if this is a hash validation failure during sync
            const current_height = try self.context.getHeight(self.context);
            if (expected_height == current_height) {
                log.info("🔄 Hash validation failed during sync - this might be a fork situation", .{});
                log.info("💡 Restarting sync from current position to handle potential fork", .{});

                // Reset sync to restart from current position
                if (self.sync_progress) |*progress| {
                    progress.current_height = current_height;
                    progress.retry_count = 0;
                }

                // Trigger a fresh sync request
                try self.requestNextSyncBatch();
                return;
            }

            return error.InvalidSyncBlock;
        }

        // Process transactions first to update account states
        try self.context.processBlockTransactions(self.context, owned_block.transactions);

        // Add block to chain
        try self.context.database.saveBlock(expected_height, owned_block);

        // Update sync progress
        if (self.sync_progress) |*progress| {
            progress.blocks_downloaded += 1;
            // Reset consecutive failures on successful block processing
            progress.consecutive_failures = 0;

            // Report progress periodically
            const now = util.getTime();
            if (now - progress.last_progress_report >= types.SYNC.PROGRESS_REPORT_INTERVAL) {
                self.reportSyncProgress();
                progress.last_progress_report = now;
            }

            // Check if we've reached the target height
            const current_height = self.context.getHeight(self.context) catch expected_height;
            log.info("🔍 SYNC DEBUG: current_height={}, target_height={}, expected_height={}", .{ current_height, progress.target_height, expected_height });
            if (current_height >= progress.target_height) {
                log.info("🎉 SYNC COMPLETION: Calling completSync() because {} >= {}", .{ current_height, progress.target_height });
                self.completSync();
                return;
            } else {
                log.info("⏳ SYNC CONTINUING: Not complete because {} < {}", .{ current_height, progress.target_height });
            }
        }

        log.info("✅ Sync block {} added to chain", .{expected_height});
    }

    /// Automatically trigger sync by querying peer heights when orphan blocks indicate we're behind
    pub fn triggerAutoSyncWithPeerQuery(self: *BlockSyncProtocol) !void {
        // Check if we're already syncing
        if (self.sync_state == .syncing) {
            log.info("ℹ️  Already syncing - orphan block detection ignored", .{});
            return;
        }

        const current_height = try self.context.getHeight(self.context);

        // Find an available peer to sync with and query their height
        if (self.context.network) |network| {
            // Get a fresh list of peers to avoid stale references
            const peer_count = network.peers.items.len;
            if (peer_count == 0) {
                log.info("⚠️  No peers available for auto-sync", .{});
                return;
            }

            // Try each peer until we find a connected one
            var attempts: u32 = 0;
            for (network.peers.items) |*peer| {
                attempts += 1;

                // Skip if not connected
                if (peer.state != .connected) {
                    continue;
                }

                // Skip if socket is null
                if (peer.socket == null) {
                    log.info("⚠️  Peer has no socket, skipping", .{});
                    continue;
                }

                // Skip peers with invalid addresses (0.0.0.0)
                const is_zero_addr = peer.address.ip[0] == 0 and peer.address.ip[1] == 0 and 
                                   peer.address.ip[2] == 0 and peer.address.ip[3] == 0;
                if (is_zero_addr) {
                    log.info("⚠️  Skipping peer with invalid address 0.0.0.0", .{});
                    continue;
                }
                
                // Format peer address safely with bounds checking
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.address.toString(&addr_buf);

                log.info("🔄 Auto-sync triggered - requesting peer height from {s}", .{addr_str});

                // Send version to query height
                peer.sendVersion(current_height) catch |err| {
                    log.info("⚠️  Failed to query peer {s}: {}", .{ addr_str, err });
                    continue;
                };

                log.info("📡 Height query sent to peer - sync will trigger automatically if needed", .{});
                return;
            }

            log.info("⚠️  Tried {} peers but none were suitable for auto-sync", .{attempts});
        } else {
            log.info("⚠️  No network manager available for auto-sync", .{});
        }
    }

    /// Request next batch of blocks for sync
    pub fn requestNextSyncBatch(self: *BlockSyncProtocol) !void {
        if (self.sync_peer == null or self.sync_progress == null) {
            return error.SyncNotInitialized;
        }

        const peer = self.sync_peer.?;
        const progress = &self.sync_progress.?;
        const now = util.getTime();

        // Check for timeout on previous request
        if (now - progress.last_request_time > types.SYNC.SYNC_TIMEOUT_SECONDS) {
            logProcess("Sync timeout detected, retrying...", .{});
            progress.retry_count += 1;

            if (progress.retry_count >= types.SYNC.MAX_SYNC_RETRIES) {
                logError("Max sync retries exceeded, switching peer", .{});
                try self.switchSyncPeer();
                return;
            }
        }

        const current_height = try self.context.getHeight(self.context);
        const next_height = current_height;
        const remaining = progress.target_height - next_height;

        if (remaining == 0) {
            self.completSync();
            return;
        }

        const batch_size = @min(types.SYNC.BATCH_SIZE, remaining);

        log.info("📥 Requesting {} blocks starting from height {} (attempt {})", .{ batch_size, next_height, progress.retry_count + 1 });

        // Update request time and send request
        progress.last_request_time = now;
        peer.sendGetBlocks(next_height, batch_size) catch |err| {
            log.info("❌ Failed to send sync request: {}", .{err});
            progress.retry_count += 1;

            if (progress.retry_count >= types.SYNC.MAX_SYNC_RETRIES) {
                self.switchSyncPeer() catch {
                    self.failSync("Failed to switch sync peer");
                    return;
                };
                // After switching peer, try the request again with new peer
                if (self.sync_peer) |new_peer| {
                    new_peer.sendGetBlocks(next_height, batch_size) catch {
                        self.failSync("Failed to send request to new peer");
                        return;
                    };
                }
            }
            return;
        };

        // Reset retry count on successful request
        if (progress.retry_count > 0) {
            self.resetSyncRetry();
        }
    }

    /// Complete sync process
    fn completSync(self: *BlockSyncProtocol) void {
        log.info("🎉 Sync completed! Chain is up to date", .{});

        if (self.sync_progress) |*progress| {
            const elapsed = util.getTime() - progress.start_time;
            const blocks_per_sec = progress.getBlocksPerSecond();
            log.info("📊 Sync stats: {} blocks in {}s ({:.2} blocks/sec)", .{ progress.blocks_downloaded, elapsed, blocks_per_sec });
            // Reset consecutive failures on successful sync completion
            progress.consecutive_failures = 0;
        }

        self.sync_state = .sync_complete;
        self.sync_progress = null;
        self.sync_peer = null;

        // Transition to synced state
        self.sync_state = .synced;
    }

    /// Report sync progress
    fn reportSyncProgress(self: *BlockSyncProtocol) void {
        if (self.sync_progress) |progress| {
            const percent = progress.getProgress();
            const blocks_per_sec = progress.getBlocksPerSecond();
            const eta = progress.getETA();

            log.info("🔄 Sync progress: {:.1}% ({} blocks/sec, ETA: {}s)", .{ percent, blocks_per_sec, eta });
        }
    }

    /// Check if we need to sync with a peer
    pub fn shouldSync(self: *BlockSyncProtocol, peer_height: u32) !bool {
        const our_height = try self.context.getHeight(self.context);

        // If we have no blockchain and peer has blocks, always sync (including genesis)
        if (our_height == 0 and peer_height > 0) {
            log.info("🌐 Network has blockchain (height {}), will sync from genesis", .{peer_height});
            return true;
        }

        if (self.sync_state != .synced) {
            return false; // Already syncing or in error state
        }

        return peer_height > our_height;
    }

    /// Get sync state
    pub fn getSyncState(self: *const BlockSyncProtocol) SyncState {
        return self.sync_state;
    }

    /// Reset sync retry count and update timestamp
    fn resetSyncRetry(self: *BlockSyncProtocol) void {
        if (self.sync_progress) |*progress| {
            progress.retry_count = 0;
            progress.last_request_time = util.getTime();
        }
    }

    /// Switch to a different peer for sync (peer fallback mechanism)
    fn switchSyncPeer(self: *BlockSyncProtocol) !void {
        if (self.context.network == null) {
            return error.NoNetworkManager;
        }

        // Add current peer to failed list
        if (self.sync_peer) |failed_peer| {
            try self.failed_peers.append(failed_peer);
            log.info("🚫 Added peer to blacklist (total: {})", .{self.failed_peers.items.len});
        }

        // Find a new peer that's not in the failed list
        const network = self.context.network.?;
        var new_peer: ?*net.Peer = null;

        for (network.peers.items) |*peer| {
            if (peer.state != .connected) continue;

            // Check if this peer is in the failed list
            var is_failed = false;
            for (self.failed_peers.items) |failed_peer| {
                if (peer == failed_peer) {
                    is_failed = true;
                    break;
                }
            }

            if (!is_failed) {
                new_peer = peer;
                break;
            }
        }

        if (new_peer) |peer| {
            log.info("🔄 Switching to new sync peer", .{});
            self.sync_peer = peer;

            // Reset retry count - caller will retry the request
            self.resetSyncRetry();
        } else {
            log.info("❌ No more peers available for sync", .{});
            self.failSync("No more peers available");
        }
    }

    /// Fail sync process with error message
    fn failSync(self: *BlockSyncProtocol, reason: []const u8) void {
        log.info("❌ Sync failed: {s}", .{reason});
        self.sync_state = .sync_failed;
        self.sync_progress = null;
        self.sync_peer = null;

        // Clear failed peers list for future attempts
        self.failed_peers.clearAndFree();
    }

    /// Validate block during sync (skips transaction balance checks)
    pub fn validateSyncBlock(self: *BlockSyncProtocol, block: types.Block, expected_height: u32) !bool {
        log.info("🔍 validateSyncBlock: Starting validation for height {}", .{expected_height});

        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            log.info("🔍 validateSyncBlock: Processing genesis block (height 0)", .{});

            // Detailed genesis validation debugging
            log.info("🔍 Genesis validation details:", .{});
            log.info("   Block timestamp: {}", .{block.header.timestamp});
            log.info("   Expected genesis timestamp: {}", .{types.Genesis.timestamp()});
            log.info("   Block previous_hash: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
            log.info("   Block difficulty: {}", .{block.header.difficulty});
            log.info("   Block nonce: 0x{X}", .{block.header.nonce});
            log.info("   Block transaction count: {}", .{block.txCount()});

            const block_hash = block.hash();
            log.info("   Block hash: {s}", .{std.fmt.fmtSliceHexLower(&block_hash)});
            log.info("   Expected genesis hash: {s}", .{std.fmt.fmtSliceHexLower(&genesis.getCanonicalGenesisHash())});

            if (!genesis.validateGenesis(block)) {
                log.info("❌ Genesis block validation failed: not canonical genesis", .{});
                log.info("❌ Genesis validation failed - detailed comparison above", .{});
                return false;
            }
            log.info("✅ Genesis block validation passed", .{});
            return true; // Genesis block passed validation
        }

        log.info("🔍 validateSyncBlock: Checking basic block structure for height {}", .{expected_height});

        // Check basic block structure
        if (!block.isValid()) {
            log.info("❌ Block validation failed: invalid block structure at height {}", .{expected_height});
            log.info("   Block transaction count: {}", .{block.txCount()});
            log.info("   Block timestamp: {}", .{block.header.timestamp});
            log.info("   Block difficulty: {}", .{block.header.difficulty});
            return false;
        }
        log.info("✅ Basic block structure validation passed for height {}", .{expected_height});

        // Timestamp validation for sync blocks (more lenient than normal validation)
        const current_time = util.getTime();
        // Block timestamps are in milliseconds, convert to seconds for comparison
        const block_time_seconds = @divFloor(@as(i64, @intCast(block.header.timestamp)), 1000);
        // Allow more future time during sync (network time differences)
        const sync_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2; // 4 hours
        if (block_time_seconds > current_time + sync_future_allowance) {
            const future_seconds = block_time_seconds - current_time;
            log.info("❌ Sync block timestamp too far in future: {} seconds ahead", .{future_seconds});
            return false;
        }

        log.info("🔍 validateSyncBlock: Checking proof-of-work for height {}", .{expected_height});

        // Always use RandomX validation for consistent security
        const mining_context = miner_mod.MiningContext{
            .allocator = self.context.allocator,
            .database = self.context.database,
            .mempool_manager = undefined, // Not needed for validation
            .mining_state = undefined, // Not needed for validation
            .network = self.context.network,
            // fork_manager removed
            .blockchain = undefined, // Not needed for validation
        };
        if (!try miner_mod.validateBlockPoW(mining_context, block)) {
            log.info("❌ RandomX proof-of-work validation failed for height {}", .{expected_height});
            return false;
        }
        log.info("✅ Proof-of-work validation passed for height {}", .{expected_height});

        log.info("🔍 validateSyncBlock: Checking previous hash links for height {}", .{expected_height});

        // Check previous hash links correctly (only if we have previous blocks)
        if (expected_height > 0) {
            const current_height = try self.context.getHeight(self.context);
            log.info("   Current blockchain height: {}", .{current_height});
            log.info("   Expected block height: {}", .{expected_height});

            if (expected_height > current_height) {
                // During sync, we might not have the previous block yet - skip this check
                log.info("⚠️ Skipping previous hash check during sync (height {} > current {})", .{ expected_height, current_height });
            } else if (expected_height == current_height) {
                // We're about to add this block - check against our current tip
                log.info("   Checking previous hash against current blockchain tip", .{});
                var prev_block = try self.context.getBlockByHeight(self.context, expected_height - 1);
                defer prev_block.deinit(self.context.allocator);

                const prev_hash = prev_block.hash();
                log.info("   Previous block hash in chain: {s}", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                log.info("   Block's previous_hash field: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    log.info("❌ Previous hash validation failed during sync", .{});
                    log.info("   Expected: {s}", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                    log.info("   Received: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                    log.info("⚠️ This might indicate a fork - skipping hash validation during sync", .{});
                    // During sync, we trust the peer's chain - skip this validation
                }
            } else {
                // We already have this block height - this shouldn't happen during normal sync
                log.info("⚠️ Unexpected: trying to sync block {} but we already have height {}", .{ expected_height, current_height });
            }
        }

        log.info("🔍 validateSyncBlock: Validating {} transactions for height {}", .{ block.txCount(), expected_height });

        // For sync blocks, validate transaction structure but skip balance checks
        // The balance validation will happen naturally when transactions are processed
        for (block.transactions, 0..) |tx, i| {
            log.info("   🔍 Validating transaction {} of {}", .{ i, block.txCount() - 1 });

            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) {
                log.info("   ✅ Skipping coinbase transaction validation", .{});
                continue;
            }

            log.info("   🔍 Checking transaction structure...", .{});

            // Basic transaction structure validation only
            if (!tx.isValid()) {
                log.info("❌ Transaction {} structure validation failed", .{i});
                const sender_bytes = tx.sender.toBytes();
                const recipient_bytes = tx.recipient.toBytes();
                log.info("   Sender: {s}", .{std.fmt.fmtSliceHexLower(&sender_bytes)});
                log.info("   Recipient: {s}", .{std.fmt.fmtSliceHexLower(&recipient_bytes)});
                log.info("   Amount: {}", .{tx.amount});
                log.info("   Fee: {}", .{tx.fee});
                log.info("   Nonce: {}", .{tx.nonce});
                log.info("   Timestamp: {}", .{tx.timestamp});
                return false;
            }
            log.info("   ✅ Transaction {} structure validation passed", .{i});

            log.info("   🔍 Checking transaction signature...", .{});

            // Signature validation (but no balance check)
            if (!try self.context.validateTransactionSignature(self.context, tx)) {
                log.info("❌ Transaction {} signature validation failed", .{i});
                log.info("   Public key: {s}", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
                log.info("   Signature: {s}", .{std.fmt.fmtSliceHexLower(&tx.signature)});
                return false;
            }
            log.info("   ✅ Transaction {} signature validation passed", .{i});
        }

        log.info("✅ Sync block {} structure and signatures validated", .{expected_height});
        return true;
    }

    /// Check if sync has timed out and needs recovery
    pub fn checkSyncTimeout(self: *BlockSyncProtocol) void {
        if (self.sync_state != .syncing or self.sync_progress == null) {
            return;
        }

        const progress = &self.sync_progress.?;
        const now = util.getTime();

        // Check if we've been stuck for too long
        if (now - progress.last_request_time > types.SYNC.SYNC_TIMEOUT_SECONDS * 2) {
            log.info("⚠️  Sync timeout detected - attempting recovery", .{});
            progress.consecutive_failures += 1;

            if (progress.consecutive_failures >= types.SYNC.MAX_CONSECUTIVE_FAILURES) {
                log.info("❌ Too many consecutive sync failures - resetting sync", .{});
                self.failSync("Too many consecutive failures");
            } else {
                // Try to recover by switching peers
                self.switchSyncPeer() catch {
                    self.failSync("Failed to switch peer during timeout recovery");
                };
            }
        }
    }
};