const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const net = @import("../network/peer.zig");
const headerchain = @import("../network/headerchain.zig");
const state_mod = @import("state.zig");

const ZeiCoin = @import("../node.zig").ZeiCoin;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;
const SyncState = state_mod.SyncState;
const SyncProgress = state_mod.SyncProgress;
const HeadersProgress = state_mod.HeadersProgress;
const SyncStateManager = state_mod.SyncStateManager;

/// Sync Manager - Main coordinator for all synchronization operations
/// Manages traditional sync, headers-first sync, and peer coordination
pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    // State management
    state_manager: SyncStateManager,
    
    // Current sync peer
    sync_peer: ?*net.Peer,
    target_height: u32,
    failed_peers: std.ArrayList(*net.Peer),
    
    // Download management
    blocks_to_download: std.ArrayList(u32),
    active_block_downloads: std.AutoHashMap(u32, i64),
    
    // Headers-first sync support
    header_chain: ?*headerchain.HeaderChain,
    
    // Out-of-order block queue for sequential processing
    pending_blocks: std.AutoHashMap(u32, Block),
    
    const Self = @This();
    
    /// Initialize sync manager
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .state_manager = SyncStateManager.init(),
            .sync_peer = null,
            .target_height = 0,
            .failed_peers = std.ArrayList(*net.Peer).init(allocator),
            .blocks_to_download = std.ArrayList(u32).init(allocator),
            .active_block_downloads = std.AutoHashMap(u32, i64).init(allocator),
            .header_chain = null,
            .pending_blocks = std.AutoHashMap(u32, Block).init(allocator),
        };
    }

    /// Initialize sync manager in-place following ZeiCoin ownership principles
    pub fn initInPlace(self: *Self, allocator: std.mem.Allocator, blockchain: *ZeiCoin) void {
        // Initialize each field directly to avoid struct copying
        self.allocator = allocator;
        self.blockchain = blockchain;
        self.state_manager = SyncStateManager.init();
        self.sync_peer = null;
        self.target_height = 0;
        self.failed_peers = std.ArrayList(*net.Peer).init(allocator);
        self.blocks_to_download = std.ArrayList(u32).init(allocator);
        self.active_block_downloads = std.AutoHashMap(u32, i64).init(allocator);
        self.header_chain = null;
    }

    /// Cleanup sync manager resources
    pub fn deinit(self: *Self) void {
        self.failed_peers.deinit();
        self.blocks_to_download.deinit();
        self.active_block_downloads.deinit();
        
        // Clean up pending blocks
        var iter = self.pending_blocks.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.pending_blocks.deinit();
    }

    /// Start sync operation with a peer
    pub fn startSync(self: *Self, peer: *net.Peer, target_height: u32) !void {
        print("🔄 [SYNC] Starting sync operation...\n", .{});
        print("🔄 [SYNC] Peer: {any}, Target height: {}\n", .{peer.address, target_height});
        
        if (self.state_manager.isActive()) {
            print("⚠️ [SYNC] Sync already in progress, ignoring new request\n", .{});
            return;
        }

        // Try to resume from saved sync state first
        if (self.loadSyncState()) |saved_state| {
            if (saved_state.target_height == target_height and saved_state.blocks_downloaded > 0) {
                print("🔄 [SYNC RESUME] Resuming previous sync from {} blocks downloaded\n", .{saved_state.blocks_downloaded});
                self.state_manager.progress = saved_state;
                self.sync_peer = peer;
                
                // Continue sync from where we left off
                const current_height = try self.blockchain.getHeight();
                const next_height = current_height + 1;
                if (next_height <= target_height) {
                    try self.requestNextBlock(next_height);
                }
                return;
            }
        }

        // Ensure we have genesis block before syncing
        const current_height = self.blockchain.getHeight() catch 0;
        if (current_height == 0) {
            print("🌟 [SYNC] Creating genesis block before sync...\n", .{});
            try self.blockchain.createCanonicalGenesis();
        }

        // Get current height from blockchain
        const final_height = try self.blockchain.getHeight();
        print("📊 [SYNC] Current blockchain height: {}\n", .{final_height});
        
        // Check if sync is actually needed
        if (target_height <= final_height) {
            print("✅ [SYNC] Already synced or ahead of peer (local: {}, peer: {})\n", .{final_height, target_height});
            return;
        }

        print("🚀 [SYNC] Sync needed! Height difference: {}\n", .{target_height - final_height});
        
        // Initialize sync state
        self.state_manager.startSync(final_height, target_height);
        self.sync_peer = peer;
        self.target_height = target_height;
        
        const height_difference = target_height - final_height;
        print("🔍 [SYNC] Height difference: {} blocks\n", .{height_difference});
        
        if (height_difference > 100) {
            print("📋 [SYNC] Using headers-first sync (large difference)\n", .{});
            try self.startHeadersFirstSync();
        } else {
            print("🔗 [SYNC] Using traditional sync (small difference)\n", .{});
            try self.startTraditionalSync();
        }
    }

    /// Start headers-first sync operation
    pub fn startHeadersSync(self: *Self, peer: *net.Peer, target_height: u32) !void {
        if (self.state_manager.isActive()) {
            print("Sync already in progress.\n", .{});
            return;
        }

        const current_height = try self.blockchain.getHeight();
        
        if (target_height <= current_height) {
            print("Already synced or ahead of peer for headers sync.\n", .{});
            return;
        }

        self.state_manager.startHeadersSync(current_height, target_height);
        self.sync_peer = peer;
        
        print("🔄 Starting headers-first sync with peer to height {}\n", .{target_height});
        
        // Request headers from peer
        if (peer.sendGetHeaders) |sendHeaders| {
            const start_height = current_height + 1;
            const count = @min(target_height - current_height, 2000);
            try sendHeaders(start_height, count);
        }
    }

    /// Process incoming sync block
    pub fn handleSyncBlock(self: *Self, block: *const Block) !void {
        print("📦 [SYNC BLOCK] Received block for sync processing\n", .{});
        
        if (!self.state_manager.isActive()) {
            print("⚠️ [SYNC BLOCK] Not in sync mode, ignoring block\n", .{});
            return;
        }

        // Get expected height for this sync block
        const current_height = try self.blockchain.getHeight();
        const expected_height = current_height + 1;
        
        print("📊 [SYNC BLOCK] Current height: {}, expected block height: {}\n", .{current_height, expected_height});
        print("🔍 [SYNC BLOCK] Block hash: {}\n", .{std.fmt.fmtSliceHexLower(&block.hash())});
        print("🔍 [SYNC BLOCK] Block transactions: {}\n", .{block.transactions.len});
        
        // Validate the sync block
        print("🔍 [SYNC BLOCK] About to validate block...\n", .{});
        print("🔍 [SYNC BLOCK] Block pointer validity check: {*}\n", .{block});
        print("🔍 [SYNC BLOCK] Expected height: {}\n", .{expected_height});
        print("🔍 [SYNC BLOCK] Blockchain pointer: {*}\n", .{self.blockchain});
        
        // Try to access block fields to check memory validity
        print("🔍 [SYNC BLOCK] Checking block memory access...\n", .{});
        const block_tx_count = block.transactions.len;
        print("🔍 [SYNC BLOCK] Block transaction count accessible: {}\n", .{block_tx_count});
        
        const block_timestamp = block.header.timestamp;
        print("🔍 [SYNC BLOCK] Block timestamp accessible: {}\n", .{block_timestamp});
        
        print("🔍 [SYNC BLOCK] Memory access successful, calling validateSyncBlock...\n", .{});
        const is_valid = try self.blockchain.validateSyncBlock(block, expected_height);
        if (!is_valid) {
            print("❌ [SYNC BLOCK] Invalid sync block at height {} rejected\n", .{expected_height});
            return;
        }
        print("✅ [SYNC BLOCK] Block validation passed\n", .{});
        
        // Add block directly to chain processor during sync (bypasses duplicate checks)
        print("📝 [SYNC BLOCK] Adding block directly to chain processor (bypassing block processor)...\n", .{});
        print("🔧 [SYNC MANAGER] About to call blockchain.addSyncBlockToChain()\n", .{});
        
        // Create a deep copy for ownership transfer to avoid double-free
        const owned_block = try block.dupe(self.allocator);
        print("🔧 [SYNC MANAGER] Block duplicated, calling addSyncBlockToChain now\n", .{});
        try self.blockchain.addSyncBlockToChain(owned_block, expected_height);
        print("✅ [SYNC BLOCK] Block added successfully to blockchain\n", .{});
        print("🔧 [SYNC MANAGER] addSyncBlockToChain() completed without error\n", .{});

        // Update progress
        if (self.state_manager.progress) |*progress| {
            progress.updateProgress(1);
            
            const new_progress = self.getProgress();
            print("📊 [SYNC BLOCK] Progress updated: {d:.1}%\n", .{new_progress});
            print("📊 [SYNC BLOCK] Blocks downloaded: {}/{}\n", .{progress.blocks_downloaded, progress.target_height - progress.current_height});
            
            // Save sync state after each block
            self.saveSyncState();
            
            // Check if sync is complete
            if (progress.blocks_downloaded >= (progress.target_height - progress.current_height)) {
                print("🎉 [SYNC BLOCK] Sync progress complete! Finishing sync...\n", .{});
                try self.completeSync();
            } else {
                print("⏳ [SYNC BLOCK] Sync continuing, {} more blocks needed\n", .{(progress.target_height - progress.current_height) - progress.blocks_downloaded});
                
                // Automatically request next block to continue sync
                const next_height = (try self.blockchain.getHeight()) + 1;
                print("🔍 [SYNC DEBUG] next_height={}, target_height={}, condition: {}\n", .{next_height, self.target_height, next_height <= self.target_height});
                
                if (next_height <= self.target_height) {
                    print("🔄 [SYNC CONTINUATION] Requesting next block at height {}\n", .{next_height});
                    self.requestNextBlock(next_height) catch |err| {
                        print("❌ [SYNC CONTINUATION] Failed to request next block {}: {}\n", .{next_height, err});
                    };
                } else {
                    print("⚠️ [SYNC CONTINUATION] Skipping request: next_height {} > target_height {}\n", .{next_height, self.target_height});
                }
            }
        }

        print("📦 [SYNC BLOCK] Block processing complete, progress: {d:.1}%\n", .{self.getProgress()});
    }

    /// Process incoming headers for headers-first sync
    pub fn processIncomingHeaders(self: *Self, headers: []const BlockHeader, start_height: u32) !void {
        if (!self.state_manager.isActive()) {
            print("Not in sync mode, ignoring headers.\n", .{});
            return;
        }

        print("📋 Processing {} headers starting from height {}\n", .{headers.len, start_height});

        // Update headers progress
        if (self.state_manager.headers_progress) |*progress| {
            progress.updateProgress(@intCast(headers.len));
            
            // Check if headers sync is complete
            if (progress.isComplete()) {
                print("✅ Headers sync complete. Starting block download.\n", .{});
                try self.startBlockDownload();
            }
        }
    }

    /// Complete sync operation
    pub fn completeSync(self: *Self) !void {
        print("🎉 [SYNC COMPLETE] Completing sync operation...\n", .{});
        
        const final_height = try self.blockchain.getHeight();
        print("📊 [SYNC COMPLETE] Final blockchain height: {}\n", .{final_height});
        
        if (self.sync_peer) |peer| {
            print("👥 [SYNC COMPLETE] Synced with peer: {any} (peer height: {})\n", .{peer.address, peer.height});
        }
        
        self.state_manager.completeSync();
        self.sync_peer = null;
        
        // Clear saved sync state since sync is complete
        self.clearSyncState();
        
        print("✅ [SYNC COMPLETE] Sync operation completed successfully!\n", .{});
        print("🧹 [SYNC COMPLETE] Cleaning up failed peers list...\n", .{});
        
        // Clear failed peers list on successful sync
        self.failed_peers.clearRetainingCapacity();
        
        print("🎊 [SYNC COMPLETE] Blockchain is now fully synchronized!\n", .{});
    }

    /// Fail sync operation
    pub fn failSync(self: *Self) void {
        self.state_manager.failSync();
        
        // Add current peer to failed peers if exists
        if (self.sync_peer) |peer| {
            self.failed_peers.append(peer) catch {};
        }
        
        self.sync_peer = null;
        print("❌ Sync failed.\n", .{});
    }

    /// Switch to a different sync peer
    pub fn switchSyncPeer(self: *Self, new_peer: *net.Peer) void {
        if (self.sync_peer) |old_peer| {
            self.failed_peers.append(old_peer) catch {};
        }
        
        self.sync_peer = new_peer;
        print("🔄 Switched to new sync peer\n", .{});
    }

    /// Get current sync progress percentage
    pub fn getProgress(self: *const Self) f64 {
        if (self.state_manager.progress) |*progress| {
            return progress.getProgress();
        }
        if (self.state_manager.headers_progress) |*progress| {
            return progress.getProgress();
        }
        return 0.0;
    }

    /// Get sync state
    pub fn getSyncState(self: *const Self) SyncState {
        return self.state_manager.getState();
    }

    /// Check if sync is active
    pub fn isActive(self: *const Self) bool {
        return self.state_manager.isActive();
    }

    /// Check if sync should be started based on height difference
    pub fn shouldSync(self: *const Self, peer_height: u32) bool {
        const current_height = self.blockchain.getHeight() catch return false;
        const height_diff = if (peer_height > current_height) peer_height - current_height else 0;
        return height_diff > 0; // Sync if peer is ahead
    }

    /// Report sync progress to console
    pub fn reportProgress(self: *const Self) void {
        if (self.state_manager.progress) |*progress| {
            const percent = progress.getProgress();
            const eta = progress.getETA();
            const bps = progress.getBlocksPerSecond();
            
            print("📊 Sync Progress: {d:.1}% | ETA: {}s | Speed: {d:.1} blocks/s\n", .{percent, eta, bps});
        }
    }

    // Private helper methods
    
    /// Start traditional block-by-block sync
    fn startTraditionalSync(self: *Self) !void {
        print("🔗 [TRADITIONAL SYNC] Starting traditional block-by-block sync...\n", .{});
        
        // Use the peer that was already set when startSync was called
        if (self.sync_peer) |peer| {
            print("✅ [TRADITIONAL SYNC] Sync peer available: {any} (height: {})\n", .{peer.address, peer.height});
            print("🔍 [TRADITIONAL SYNC] Peer state: {}\n", .{peer.state});
            print("🔍 [TRADITIONAL SYNC] Peer connected: {}\n", .{peer.isConnected()});
            
            // Get current blockchain state
            const current_height = try self.blockchain.getHeight();
            const next_height = current_height + 1;
            
            print("📊 [TRADITIONAL SYNC] Current height: {}, requesting block: {}\n", .{current_height, next_height});
            print("🎯 [TRADITIONAL SYNC] Target height: {} (need {} more blocks)\n", .{peer.height, peer.height - current_height});
            
            // Request the next block directly
            print("📤 [TRADITIONAL SYNC] Sending getBlock request for height {}...\n", .{next_height});
            peer.sendGetBlock(next_height) catch |err| {
                print("❌ [TRADITIONAL SYNC] Failed to request block {}: {}\n", .{next_height, err});
                print("🔍 [TRADITIONAL SYNC] Peer state after error: {}\n", .{peer.state});
                return err;
            };
            print("✅ [TRADITIONAL SYNC] Block request sent successfully for height {}\n", .{next_height});
            print("⏳ [TRADITIONAL SYNC] Waiting for block response...\n", .{});
        } else {
            print("❌ [TRADITIONAL SYNC] No sync peer available!\n", .{});
            return error.NoPeersAvailable;
        }
    }

    /// Start headers-first sync operation
    fn startHeadersFirstSync(self: *Self) !void {
        if (self.sync_peer == null) {
            print("❌ No sync peer available for headers-first sync\n", .{});
            return error.NoPeersAvailable;
        }
        
        print("🔄 Starting headers-first sync...\n", .{});
        
        // For now, fall back to traditional sync since headers-first is complex
        // TODO: Implement proper headers-first sync protocol
        print("⚠️ Headers-first sync not fully implemented, falling back to traditional sync\n", .{});
        return self.startTraditionalSync();
    }

    /// Start block download phase for headers-first sync
    fn startBlockDownload(self: *Self) !void {
        print("📦 Starting block download phase...\n", .{});
        
        // Find best peer for headers-first sync
        if (self.blockchain.network_coordinator.getNetworkManager()) |network| {
            if (network.peer_manager.getBestPeerForSync()) |peer| {
                self.sync_peer = peer;
                self.target_height = peer.height;
                
                print("✅ Headers-first block download started with peer height {}\n", .{peer.height});
            } else {
                print("❌ No peers available for headers-first sync\n", .{});
                return error.NoPeersAvailable;
            }
        } else {
            print("❌ Network not initialized\n", .{});
            return error.NetworkNotInitialized;
        }
    }

    /// Check if we need to sync with a peer
    pub fn shouldSyncWithPeer(self: *Self, peer_height: u32) !bool {
        const our_height = try self.blockchain.getHeight();

        // If we have no blockchain and peer has blocks, always sync (including genesis)
        if (our_height == 0 and peer_height > 0) {
            print("🌐 Network has blockchain (height {}), will sync from genesis\n", .{peer_height});
            return true;
        }

        if (self.getSyncState() != .synced) {
            return false; // Already syncing or in error state
        }

        return peer_height > our_height;
    }

    /// Switch to a different peer for sync (peer fallback mechanism)
    pub fn switchToNewPeer(self: *Self) !void {
        const network = self.blockchain.network_coordinator.getNetworkManager() orelse {
            return error.NoNetworkManager;
        };

        // Add current peer to failed list
        if (self.sync_peer) |failed_peer| {
            try self.failed_peers.append(failed_peer);
            print("🚫 Added peer to blacklist (total: {})\n", .{self.failed_peers.items.len});
        }

        // Find a new peer that's not in the failed list
        var new_peer: ?*net.Peer = null;
        network.peer_manager.mutex.lock();
        defer network.peer_manager.mutex.unlock();

        for (network.peer_manager.peers.items) |peer| {
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
            self.failSyncWithReason("No more peers available");
        }
    }

    /// Fail sync process with error message
    pub fn failSyncWithReason(self: *Self, reason: []const u8) void {
        print("❌ Sync failed: {s}\n", .{reason});
        self.state_manager.failSync();
        self.sync_peer = null;

        // Clear failed peers list for future attempts
        self.failed_peers.clearAndFree();
    }

    /// Reset sync retry count and update timestamp
    fn resetSyncRetry(self: *Self) void {
        if (self.state_manager.progress) |*progress| {
            progress.retry_count = 0;
            progress.last_request_time = @import("../util/util.zig").getTime();
        }
    }

    /// Start block downloads for headers-first sync
    pub fn startBlockDownloads(self: *Self) !void {
        const current_block_height = try self.blockchain.getHeight();
        
        if (self.header_chain) |chain| {
            const header_height = chain.validated_height;

            if (current_block_height >= header_height) {
                @import("../util/util.zig").logInfo("Already have all blocks", .{});
                self.completeHeadersSync();
                return;
            }

            // Queue blocks for download
            self.blocks_to_download.clearRetainingCapacity();
            for (current_block_height + 1..header_height + 1) |height| {
                try self.blocks_to_download.append(@intCast(height));
            }

            @import("../util/util.zig").logInfo("Queued {} blocks for download", .{self.blocks_to_download.items.len});

            // Start parallel downloads
            try self.requestNextBlocks();
        }
    }

    /// Request next blocks for download
    pub fn requestNextBlocks(self: *Self) !void {
        const network = self.blockchain.network_coordinator.getNetworkManager() orelse return;
        const now = @import("../util/util.zig").getTime();

        // Clean up timed out downloads
        var iter = self.active_block_downloads.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.* > 60) { // 60 second timeout
                // Re-queue timed out block
                try self.blocks_to_download.append(entry.key_ptr.*);
                _ = self.active_block_downloads.remove(entry.key_ptr.*);
                print("❌ Block {} download timed out, re-queuing\n", .{entry.key_ptr.*});
            }
        }

        // Start new downloads up to concurrent limit
        while (self.active_block_downloads.count() < 5 and // Max 5 concurrent downloads
            self.blocks_to_download.items.len > 0)
        {
            const height = self.blocks_to_download.orderedRemove(0);

            // Find available peer
            var sent = false;
            network.peer_manager.mutex.lock();
            defer network.peer_manager.mutex.unlock();
            
            for (network.peer_manager.peers.items) |peer| {
                if (peer.state == .connected) {
                    peer.sendGetBlock(height) catch continue;
                    try self.active_block_downloads.put(height, now);
                    print("📤 Requested block {}\n", .{height});
                    sent = true;
                    break;
                }
            }

            if (!sent) {
                // No peers available, re-queue
                try self.blocks_to_download.insert(0, height);
                break;
            }
        }
    }

    /// Process downloaded block during headers-first sync
    pub fn processDownloadedBlock(self: *Self, block: Block, height: u32) !void {
        // Verify block matches expected header
        if (self.header_chain) |chain| {
            const expected_header = chain.getHeader(height);
            if (expected_header == null or !std.mem.eql(u8, &block.header.hash(), &expected_header.?.hash())) {
                print("❌ Block header mismatch at height {}\n", .{height});
                return error.BlockHeaderMismatch;
            }
        }

        // Process the block
        try self.blockchain.handleSyncBlock(height, block);

        // Remove from active downloads
        _ = self.active_block_downloads.remove(height);

        // Request more blocks
        try self.requestNextBlocks();

        // Check if sync is complete
        if (self.blocks_to_download.items.len == 0 and self.active_block_downloads.count() == 0) {
            self.completeHeadersSync();
        }
    }

    /// Complete headers-first sync
    fn completeHeadersSync(self: *Self) void {
        @import("../util/util.zig").logSuccess("Headers-first sync completed!", .{});

        if (self.state_manager.headers_progress) |progress| {
            const elapsed = @import("../util/util.zig").getTime() - progress.start_time;
            const headers_per_sec = progress.getHeadersPerSecond();
            @import("../util/util.zig").logInfo("Downloaded {} headers in {}s ({:.2} headers/sec)", .{ progress.headers_downloaded, elapsed, headers_per_sec });
        }

        // Clean up
        self.state_manager.headers_progress = null;
        if (self.header_chain) |chain| {
            chain.deinit();
            self.allocator.destroy(chain);
            self.header_chain = null;
        }

        self.state_manager.completeSync();
    }

    /// Request next block for sync continuation with retry logic
    fn requestNextBlock(self: *Self, height: u32) !void {
        if (self.sync_peer) |peer| {
            // Send keepalive ping before block request to maintain connection
            try self.sendKeepalivePing(peer);
            
            print("📤 [SYNC CONTINUATION] Sending getBlock request for height {} to peer {any}\n", .{height, peer.address});
            peer.sendGetBlock(height) catch |err| {
                print("❌ [SYNC CONTINUATION] Failed to request block {}: {}\n", .{height, err});
                
                // Implement retry logic with exponential backoff
                if (self.state_manager.progress) |*progress| {
                    progress.consecutive_failures += 1;
                    
                    if (progress.consecutive_failures <= 3) {
                        const backoff_delay = @as(u64, 1) << @intCast(progress.consecutive_failures); // 2, 4, 8 seconds
                        print("🔄 [SYNC RETRY] Retrying block request {} in {} seconds (attempt {})\n", .{height, backoff_delay, progress.consecutive_failures});
                        
                        // Schedule retry (in a real implementation, this would use a timer)
                        // For now, we'll save the state and let manual sync retry
                        self.saveSyncState();
                        return error.BlockRequestFailed;
                    } else {
                        print("❌ [SYNC RETRY] Max retries exceeded for block {}, switching peer\n", .{height});
                        try self.switchToNewPeer();
                        if (self.sync_peer) |_| {
                            progress.consecutive_failures = 0; // Reset on new peer
                            try self.requestNextBlock(height); // Retry with new peer
                        }
                    }
                }
                return err;
            };
            
            // Reset failure count on successful request
            if (self.state_manager.progress) |*progress| {
                progress.consecutive_failures = 0;
            }
            
            print("✅ [SYNC CONTINUATION] Block request sent successfully for height {}\n", .{height});
        } else {
            print("❌ [SYNC CONTINUATION] No sync peer available for block request\n", .{});
            return error.NoPeersAvailable;
        }
    }

    /// Send keepalive ping to maintain connection during sync
    fn sendKeepalivePing(self: *Self, peer: *net.Peer) !void {
        _ = self; // Mark as used
        // Only send ping if it's been more than 15 seconds since last activity
        const now = @import("../util/util.zig").getTime();
        if (now - peer.last_ping > 15) {
            print("💓 [SYNC KEEPALIVE] Sending keepalive ping to peer {any}\n", .{peer.address});
            // Note: sendPing method doesn't exist in current Peer implementation
            // This is a placeholder for future ping functionality
            // peer.sendPing() catch |err| {
            //     print("⚠️ [SYNC KEEPALIVE] Failed to send ping: {}\n", .{err});
            // };
            peer.last_ping = now;
            print("💓 [SYNC KEEPALIVE] Keepalive timestamp updated\n", .{});
        }
    }

    /// Save sync state to disk for resumption
    fn saveSyncState(self: *Self) void {
        if (self.state_manager.progress) |progress| {
            const sync_state_file = "sync_state.tmp";
            const file = std.fs.cwd().createFile(sync_state_file, .{}) catch {
                print("⚠️ [SYNC PERSIST] Failed to save sync state\n", .{});
                return;
            };
            defer file.close();
            
            var buffer = std.ArrayList(u8).init(self.allocator);
            defer buffer.deinit();
            
            // Simple binary serialization of sync progress
            const writer = buffer.writer();
            writer.writeInt(u32, progress.target_height, .little) catch return;
            writer.writeInt(u32, progress.current_height, .little) catch return;
            writer.writeInt(u32, progress.blocks_downloaded, .little) catch return;
            writer.writeInt(i64, progress.start_time, .little) catch return;
            
            file.writeAll(buffer.items) catch {
                print("⚠️ [SYNC PERSIST] Failed to write sync state\n", .{});
                return;
            };
            print("💾 [SYNC PERSIST] Sync state saved\n", .{});
        }
    }

    /// Load sync state from disk
    fn loadSyncState(self: *Self) ?SyncProgress {
        _ = self; // Mark as used
        const sync_state_file = "sync_state.tmp";
        const file = std.fs.cwd().openFile(sync_state_file, .{}) catch return null;
        defer file.close();
        
        const file_size = file.getEndPos() catch return null;
        if (file_size < 20) return null; // Invalid file size
        
        var buffer: [20]u8 = undefined;
        _ = file.readAll(&buffer) catch return null;
        
        var stream = std.io.fixedBufferStream(&buffer);
        const reader = stream.reader();
        
        const target_height = reader.readInt(u32, .little) catch return null;
        const current_height = reader.readInt(u32, .little) catch return null;
        const blocks_downloaded = reader.readInt(u32, .little) catch return null;
        const start_time = reader.readInt(i64, .little) catch return null;
        
        print("📁 [SYNC PERSIST] Loaded sync state: target={}, current={}, downloaded={}\n", .{target_height, current_height, blocks_downloaded});
        
        return SyncProgress{
            .target_height = target_height,
            .current_height = current_height,
            .blocks_downloaded = blocks_downloaded,
            .start_time = start_time,
            .last_progress_report = @import("../util/util.zig").getTime(),
            .last_request_time = @import("../util/util.zig").getTime(),
            .retry_count = 0,
            .consecutive_failures = 0,
        };
    }

    /// Clear saved sync state
    fn clearSyncState(self: *Self) void {
        _ = self;
        std.fs.cwd().deleteFile("sync_state.tmp") catch {};
        print("🗑️ [SYNC PERSIST] Sync state cleared\n", .{});
    }

    /// Check for stalled sync and take corrective action
    pub fn validateSyncProgress(self: *Self) !void {
        if (!self.state_manager.isActive()) return;
        
        if (self.state_manager.progress) |*progress| {
            const now = @import("../util/util.zig").getTime();
            const time_since_last_progress = now - progress.last_progress_report;
            const time_since_last_request = now - progress.last_request_time;
            
            // Check if sync has been stalled for more than 2 minutes
            if (time_since_last_progress > 120) {
                print("⚠️ [SYNC STALL] Sync stalled for {} seconds, taking corrective action\n", .{time_since_last_progress});
                
                // Check if we have a sync peer
                if (self.sync_peer == null) {
                    print("❌ [SYNC STALL] No sync peer, attempting to find new peer\n", .{});
                    try self.switchToNewPeer();
                    if (self.sync_peer == null) {
                        print("❌ [SYNC STALL] No peers available, failing sync\n", .{});
                        self.failSyncWithReason("No peers available after stall");
                        return;
                    }
                }
                
                // If no recent request, send a new one
                if (time_since_last_request > 60) {
                    const current_height = try self.blockchain.getHeight();
                    const next_height = current_height + 1;
                    if (next_height <= progress.target_height) {
                        print("🔄 [SYNC STALL] Sending recovery block request for height {}\n", .{next_height});
                        progress.last_request_time = now;
                        try self.requestNextBlock(next_height);
                    }
                }
                
                // Update timestamp to avoid constant stall detection
                progress.last_progress_report = now - 60; // Give it another minute
            }
            
            // Check for timeout (sync taking too long overall)
            const total_sync_time = now - progress.start_time;
            if (total_sync_time > 600) { // 10 minutes total timeout
                print("⏰ [SYNC TIMEOUT] Sync taking too long ({} seconds), restarting\n", .{total_sync_time});
                self.failSyncWithReason("Sync timeout");
                
                // Try to restart sync with a different peer
                try self.switchToNewPeer();
                if (self.sync_peer) |new_peer| {
                    print("🔄 [SYNC TIMEOUT] Restarting sync with new peer\n", .{});
                    try self.startSync(new_peer, progress.target_height);
                }
            }
        }
    }
};