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
    failed_peers: std.ArrayList(*net.Peer),
    
    // Download management
    blocks_to_download: std.ArrayList(u32),
    active_block_downloads: std.AutoHashMap(u32, i64),
    
    // Headers-first sync support
    header_chain: ?*headerchain.HeaderChain,
    
    const Self = @This();
    
    /// Initialize sync manager
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .state_manager = SyncStateManager.init(),
            .sync_peer = null,
            .failed_peers = std.ArrayList(*net.Peer).init(allocator),
            .blocks_to_download = std.ArrayList(u32).init(allocator),
            .active_block_downloads = std.AutoHashMap(u32, i64).init(allocator),
            .header_chain = null,
        };
    }

    /// Initialize sync manager in-place following ZeiCoin ownership principles
    pub fn initInPlace(self: *Self, allocator: std.mem.Allocator, blockchain: *ZeiCoin) void {
        // Initialize each field directly to avoid struct copying
        self.allocator = allocator;
        self.blockchain = blockchain;
        self.state_manager = SyncStateManager.init();
        self.sync_peer = null;
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
    }

    /// Start sync operation with a peer
    pub fn startSync(self: *Self, peer: *net.Peer, target_height: u32) !void {
        if (self.state_manager.isActive()) {
            print("Sync already in progress.\n", .{});
            return;
        }

        // Get current height from blockchain
        const current_height = try self.blockchain.getHeight();
        
        // Check if sync is actually needed
        if (target_height <= current_height) {
            print("Already synced or ahead of peer (local: {}, peer: {}).\n", .{current_height, target_height});
            return;
        }

        // Initialize sync state
        self.state_manager.startSync(current_height, target_height);
        self.sync_peer = peer;
        
        const height_difference = target_height - current_height;
        if (height_difference > 100) {
            try self.startHeadersFirstSync();
        } else {
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
    pub fn handleSyncBlock(self: *Self, block: Block) !void {
        if (!self.state_manager.isActive()) {
            print("Not in sync mode, ignoring block.\n", .{});
            block.deinit(self.allocator); // Clean up ignored block
            return;
        }

        // Get expected height for this sync block
        const current_height = try self.blockchain.getHeight();
        const expected_height = current_height + 1;
        
        // Validate the sync block
        const is_valid = try self.blockchain.validateSyncBlock(block, expected_height);
        if (!is_valid) {
            print("❌ Invalid sync block at height {} rejected\n", .{expected_height});
            block.deinit(self.allocator); // Clean up invalid block
            return;
        }
        
        // Forward the block to the blockchain for processing
        // The blockchain will handle adding it to the chain
        try self.blockchain.handleIncomingBlock(block, self.sync_peer);
        // Note: blockchain takes ownership of the block

        // Update progress
        if (self.state_manager.progress) |*progress| {
            progress.updateProgress(1);
            
            // Check if sync is complete
            if (progress.blocks_downloaded >= (progress.target_height - progress.current_height)) {
                try self.completeSync();
            }
        }

        print("📦 Received sync block, progress: {d:.1}%\n", .{self.getProgress()});
    }

    /// Process incoming headers for headers-first sync
    pub fn processIncomingHeaders(self: *Self, headers: []BlockHeader, start_height: u32) !void {
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
        self.state_manager.completeSync();
        self.sync_peer = null;
        
        print("✅ Sync complete!\n", .{});
        
        // Clear failed peers list on successful sync
        self.failed_peers.clearRetainingCapacity();
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
        print("🔄 Starting traditional sync...\n", .{});
        
        // Find best peer for sync
        if (self.blockchain.network) |network| {
            if (network.peer_manager.getBestPeerForSync()) |peer| {
                self.sync_peer = peer;
                self.target_height = peer.height;
                
                // Use the network sync manager for traditional sync
                if (self.blockchain.sync_manager) |sync_mgr| {
                    try sync_mgr.startSync();
                    print("✅ Traditional sync started with peer height {}\n", .{peer.height});
                } else {
                    print("⚠️ No sync manager available\n");
                }
            } else {
                print("❌ No peers available for traditional sync\n");
                return error.NoPeersAvailable;
            }
        } else {
            print("❌ Network not initialized\n");
            return error.NetworkNotInitialized;
        }
    }

    /// Start block download phase for headers-first sync
    fn startBlockDownload(self: *Self) !void {
        print("📦 Starting block download phase...\n", .{});
        
        // Find best peer for headers-first sync
        if (self.blockchain.network) |network| {
            if (network.peer_manager.getBestPeerForSync()) |peer| {
                self.sync_peer = peer;
                self.target_height = peer.height;
                
                // Use headers-first protocol
                if (self.blockchain.sync_manager) |sync_mgr| {
                    try sync_mgr.startHeadersFirstSync(peer, peer.height);
                    print("✅ Headers-first sync started with peer height {}\n", .{peer.height});
                } else {
                    print("⚠️ No sync manager available for headers-first sync\n");
                }
            } else {
                print("❌ No peers available for headers-first sync\n");
                return error.NoPeersAvailable;
            }
        } else {
            print("❌ Network not initialized\n");
            return error.NetworkNotInitialized;
        }
    }
};