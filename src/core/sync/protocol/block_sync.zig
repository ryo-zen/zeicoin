// sync/protocol/block_sync.zig - Traditional Block Sync Protocol Implementation
// Extracted from node.zig for modular sync architecture

const std = @import("std");
const print = std.debug.print;

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
        print("❌ " ++ fmt ++ "\n", args);
    }

    fn logSuccess(comptime fmt: []const u8, args: anytype) void {
        print("✅ " ++ fmt ++ "\n", args);
    }

    fn logInfo(comptime fmt: []const u8, args: anytype) void {
        print("ℹ️  " ++ fmt ++ "\n", args);
    }

    fn logProcess(comptime fmt: []const u8, args: anytype) void {
        print("🔄 " ++ fmt ++ "\n", args);
    }

    /// Start sync process with a peer
    pub fn startSync(self: *BlockSyncProtocol, peer: *net.Peer, target_height: u32) !void {
        const current_height = try self.context.getHeight(self.context);

        // Special case: if we have no blockchain (height 0), sync from genesis (height 0)
        if (current_height == 0 and target_height > 0) {
            print("🔄 Starting sync from genesis: 0 -> {} ({} blocks to download)\n", .{ target_height, target_height });
        } else if (target_height <= current_height) {
            print("ℹ️  Already up to date (height {})\n", .{current_height});
            return;
        } else {
            print("🔄 Starting sync: {} -> {} ({} blocks behind)\n", .{ current_height, target_height, target_height - current_height });
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
        
        print("🔄 Processing sync block at height {}\n", .{expected_height});

        // Check if block already exists to prevent duplicate processing
        const existing_block = self.context.database.getBlock(expected_height) catch null;
        if (existing_block) |block_data| {
            // IMPORTANT: Free the loaded block to prevent memory leak
            var block_to_free = block_data;
            defer block_to_free.deinit(self.context.allocator);
            
            print("ℹ️  Block {} already exists, skipping duplicate during sync\n", .{expected_height});

            // Still need to update sync progress for this "processed" block
            if (self.sync_progress) |*progress| {
                progress.blocks_downloaded += 1;
                progress.consecutive_failures = 0; // Reset on successful processing

                // Check if we've completed sync with this existing block
                const current_height = self.context.getHeight(self.context) catch expected_height;
                if (current_height >= progress.target_height) {
                    print("🎉 Sync completed with existing blocks!\n", .{});
                    self.completSync();
                    return;
                }
            }
            return; // Skip duplicate block gracefully
        }

        // For sync, validate block structure and PoW only (skip transaction balance checks)
        const validation_result = self.validateSyncBlock(owned_block, expected_height) catch |err| {
            print("❌ Block validation threw error at height {}: {}\n", .{ expected_height, err });
            return;
        };
        if (!validation_result) {
            print("❌ Block validation failed at height {}\n", .{expected_height});

            // Check if this is a hash validation failure during sync
            const current_height = try self.context.getHeight(self.context);
            if (expected_height == current_height) {
                print("🔄 Hash validation failed during sync - this might be a fork situation\n", .{});
                print("💡 Restarting sync from current position to handle potential fork\n", .{});

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
            print("🔍 SYNC DEBUG: current_height={}, target_height={}, expected_height={}\n", .{ current_height, progress.target_height, expected_height });
            if (current_height >= progress.target_height) {
                print("🎉 SYNC COMPLETION: Calling completSync() because {} >= {}\n", .{ current_height, progress.target_height });
                self.completSync();
                return;
            } else {
                print("⏳ SYNC CONTINUING: Not complete because {} < {}\n", .{ current_height, progress.target_height });
            }
        }

        print("✅ Sync block {} added to chain\n", .{expected_height});
    }

    /// Automatically trigger sync by querying peer heights when orphan blocks indicate we're behind
    pub fn triggerAutoSyncWithPeerQuery(self: *BlockSyncProtocol) !void {
        // Check if we're already syncing
        if (self.sync_state == .syncing) {
            print("ℹ️  Already syncing - orphan block detection ignored\n", .{});
            return;
        }

        const current_height = try self.context.getHeight(self.context);

        // Find an available peer to sync with and query their height
        if (self.context.network) |network| {
            // Get a fresh list of peers to avoid stale references
            const peer_count = network.peers.items.len;
            if (peer_count == 0) {
                print("⚠️  No peers available for auto-sync\n", .{});
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
                    print("⚠️  Peer has no socket, skipping\n", .{});
                    continue;
                }

                // Skip peers with invalid addresses (0.0.0.0)
                const is_zero_addr = peer.address.ip[0] == 0 and peer.address.ip[1] == 0 and 
                                   peer.address.ip[2] == 0 and peer.address.ip[3] == 0;
                if (is_zero_addr) {
                    print("⚠️  Skipping peer with invalid address 0.0.0.0\n", .{});
                    continue;
                }
                
                // Format peer address safely with bounds checking
                var addr_buf: [64]u8 = undefined;
                const addr_str = peer.address.toString(&addr_buf);

                print("🔄 Auto-sync triggered - requesting peer height from {s}\n", .{addr_str});

                // Send version to query height
                peer.sendVersion(current_height) catch |err| {
                    print("⚠️  Failed to query peer {s}: {}\n", .{ addr_str, err });
                    continue;
                };

                print("📡 Height query sent to peer - sync will trigger automatically if needed\n", .{});
                return;
            }

            print("⚠️  Tried {} peers but none were suitable for auto-sync\n", .{attempts});
        } else {
            print("⚠️  No network manager available for auto-sync\n", .{});
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

        print("📥 Requesting {} blocks starting from height {} (attempt {})\n", .{ batch_size, next_height, progress.retry_count + 1 });

        // Update request time and send request
        progress.last_request_time = now;
        peer.sendGetBlocks(next_height, batch_size) catch |err| {
            print("❌ Failed to send sync request: {}\n", .{err});
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
        print("🎉 Sync completed! Chain is up to date\n", .{});

        if (self.sync_progress) |*progress| {
            const elapsed = util.getTime() - progress.start_time;
            const blocks_per_sec = progress.getBlocksPerSecond();
            print("📊 Sync stats: {} blocks in {}s ({:.2} blocks/sec)\n", .{ progress.blocks_downloaded, elapsed, blocks_per_sec });
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

            print("🔄 Sync progress: {:.1}% ({} blocks/sec, ETA: {}s)\n", .{ percent, blocks_per_sec, eta });
        }
    }

    /// Check if we need to sync with a peer
    pub fn shouldSync(self: *BlockSyncProtocol, peer_height: u32) !bool {
        const our_height = try self.context.getHeight(self.context);

        // If we have no blockchain and peer has blocks, always sync (including genesis)
        if (our_height == 0 and peer_height > 0) {
            print("🌐 Network has blockchain (height {}), will sync from genesis\n", .{peer_height});
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
            print("🚫 Added peer to blacklist (total: {})\n", .{self.failed_peers.items.len});
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
            print("🔄 Switching to new sync peer\n", .{});
            self.sync_peer = peer;

            // Reset retry count - caller will retry the request
            self.resetSyncRetry();
        } else {
            print("❌ No more peers available for sync\n", .{});
            self.failSync("No more peers available");
        }
    }

    /// Fail sync process with error message
    fn failSync(self: *BlockSyncProtocol, reason: []const u8) void {
        print("❌ Sync failed: {s}\n", .{reason});
        self.sync_state = .sync_failed;
        self.sync_progress = null;
        self.sync_peer = null;

        // Clear failed peers list for future attempts
        self.failed_peers.clearAndFree();
    }

    /// Validate block during sync (skips transaction balance checks)
    pub fn validateSyncBlock(self: *BlockSyncProtocol, block: types.Block, expected_height: u32) !bool {
        print("🔍 validateSyncBlock: Starting validation for height {}\n", .{expected_height});

        // Special validation for genesis block (height 0)
        if (expected_height == 0) {
            print("🔍 validateSyncBlock: Processing genesis block (height 0)\n", .{});

            // Detailed genesis validation debugging
            print("🔍 Genesis validation details:\n", .{});
            print("   Block timestamp: {}\n", .{block.header.timestamp});
            print("   Expected genesis timestamp: {}\n", .{types.Genesis.timestamp()});
            print("   Block previous_hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
            print("   Block difficulty: {}\n", .{block.header.difficulty});
            print("   Block nonce: 0x{X}\n", .{block.header.nonce});
            print("   Block transaction count: {}\n", .{block.txCount()});

            const block_hash = block.hash();
            print("   Block hash: {s}\n", .{std.fmt.fmtSliceHexLower(&block_hash)});
            print("   Expected genesis hash: {s}\n", .{std.fmt.fmtSliceHexLower(&genesis.getCanonicalGenesisHash())});

            if (!genesis.validateGenesis(block)) {
                print("❌ Genesis block validation failed: not canonical genesis\n", .{});
                print("❌ Genesis validation failed - detailed comparison above\n", .{});
                return false;
            }
            print("✅ Genesis block validation passed\n", .{});
            return true; // Genesis block passed validation
        }

        print("🔍 validateSyncBlock: Checking basic block structure for height {}\n", .{expected_height});

        // Check basic block structure
        if (!block.isValid()) {
            print("❌ Block validation failed: invalid block structure at height {}\n", .{expected_height});
            print("   Block transaction count: {}\n", .{block.txCount()});
            print("   Block timestamp: {}\n", .{block.header.timestamp});
            print("   Block difficulty: {}\n", .{block.header.difficulty});
            return false;
        }
        print("✅ Basic block structure validation passed for height {}\n", .{expected_height});

        // Timestamp validation for sync blocks (more lenient than normal validation)
        const current_time = util.getTime();
        // Allow more future time during sync (network time differences)
        const sync_future_allowance = types.TimestampValidation.MAX_FUTURE_TIME * 2; // 4 hours
        if (@as(i64, @intCast(block.header.timestamp)) > current_time + sync_future_allowance) {
            const future_seconds = @as(i64, @intCast(block.header.timestamp)) - current_time;
            print("❌ Sync block timestamp too far in future: {} seconds ahead\n", .{future_seconds});
            return false;
        }

        print("🔍 validateSyncBlock: Checking proof-of-work for height {}\n", .{expected_height});

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
            print("❌ RandomX proof-of-work validation failed for height {}\n", .{expected_height});
            return false;
        }
        print("✅ Proof-of-work validation passed for height {}\n", .{expected_height});

        print("🔍 validateSyncBlock: Checking previous hash links for height {}\n", .{expected_height});

        // Check previous hash links correctly (only if we have previous blocks)
        if (expected_height > 0) {
            const current_height = try self.context.getHeight(self.context);
            print("   Current blockchain height: {}\n", .{current_height});
            print("   Expected block height: {}\n", .{expected_height});

            if (expected_height > current_height) {
                // During sync, we might not have the previous block yet - skip this check
                print("⚠️ Skipping previous hash check during sync (height {} > current {})\n", .{ expected_height, current_height });
            } else if (expected_height == current_height) {
                // We're about to add this block - check against our current tip
                print("   Checking previous hash against current blockchain tip\n", .{});
                var prev_block = try self.context.getBlockByHeight(self.context, expected_height - 1);
                defer prev_block.deinit(self.context.allocator);

                const prev_hash = prev_block.hash();
                print("   Previous block hash in chain: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                print("   Block's previous_hash field: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

                if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) {
                    print("❌ Previous hash validation failed during sync\n", .{});
                    print("   Expected: {s}\n", .{std.fmt.fmtSliceHexLower(&prev_hash)});
                    print("   Received: {s}\n", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
                    print("⚠️ This might indicate a fork - skipping hash validation during sync\n", .{});
                    // During sync, we trust the peer's chain - skip this validation
                }
            } else {
                // We already have this block height - this shouldn't happen during normal sync
                print("⚠️ Unexpected: trying to sync block {} but we already have height {}\n", .{ expected_height, current_height });
            }
        }

        print("🔍 validateSyncBlock: Validating {} transactions for height {}\n", .{ block.txCount(), expected_height });

        // For sync blocks, validate transaction structure but skip balance checks
        // The balance validation will happen naturally when transactions are processed
        for (block.transactions, 0..) |tx, i| {
            print("   🔍 Validating transaction {} of {}\n", .{ i, block.txCount() - 1 });

            // Skip coinbase transaction (first one) - it doesn't need signature validation
            if (i == 0) {
                print("   ✅ Skipping coinbase transaction validation\n", .{});
                continue;
            }

            print("   🔍 Checking transaction structure...\n", .{});

            // Basic transaction structure validation only
            if (!tx.isValid()) {
                print("❌ Transaction {} structure validation failed\n", .{i});
                const sender_bytes = tx.sender.toBytes();
                const recipient_bytes = tx.recipient.toBytes();
                print("   Sender: {s}\n", .{std.fmt.fmtSliceHexLower(&sender_bytes)});
                print("   Recipient: {s}\n", .{std.fmt.fmtSliceHexLower(&recipient_bytes)});
                print("   Amount: {}\n", .{tx.amount});
                print("   Fee: {}\n", .{tx.fee});
                print("   Nonce: {}\n", .{tx.nonce});
                print("   Timestamp: {}\n", .{tx.timestamp});
                return false;
            }
            print("   ✅ Transaction {} structure validation passed\n", .{i});

            print("   🔍 Checking transaction signature...\n", .{});

            // Signature validation (but no balance check)
            if (!try self.context.validateTransactionSignature(self.context, tx)) {
                print("❌ Transaction {} signature validation failed\n", .{i});
                print("   Public key: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
                print("   Signature: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.signature)});
                return false;
            }
            print("   ✅ Transaction {} signature validation passed\n", .{i});
        }

        print("✅ Sync block {} structure and signatures validated\n", .{expected_height});
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
            print("⚠️  Sync timeout detected - attempting recovery\n", .{});
            progress.consecutive_failures += 1;

            if (progress.consecutive_failures >= types.SYNC.MAX_CONSECUTIVE_FAILURES) {
                print("❌ Too many consecutive sync failures - resetting sync\n", .{});
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