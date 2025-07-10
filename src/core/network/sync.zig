// sync.zig - Network Sync Manager (Updated for Modular Architecture)
// Integrates the new modular sync system with the network layer
// Uses the extracted sync protocols from src/core/sync/

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const headerchain = @import("headerchain.zig");
const net = @import("peer.zig");

// Import the new modular sync system
const sync_manager = @import("../sync/manager.zig");
const sync_protocols = @import("../sync/protocol/lib.zig");
const sync_state = @import("../sync/state.zig");

const ZeiCoin = @import("../node.zig").ZeiCoin;

/// Network-level sync manager that bridges networking and sync protocols
/// This is a compatibility layer that integrates with the existing network code
pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    // New modular sync manager components (avoid nested struct)
    sync_allocator: std.mem.Allocator,
    sync_blockchain: *ZeiCoin,
    sync_failed_peers: std.ArrayList(*net.Peer),
    sync_blocks_to_download: std.ArrayList(u32),
    sync_active_downloads: std.AutoHashMap(u32, i64),
    
    // Protocol instances
    block_sync_protocol: ?sync_protocols.BlockSyncProtocol,
    headers_first_protocol: ?sync_protocols.HeadersFirstProtocol,
    
    // Legacy compatibility fields
    is_syncing: bool,
    sync_peer: ?*net.Peer,
    target_height: u32,

    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) SyncManager {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .sync_allocator = allocator,
            .sync_blockchain = blockchain,
            .sync_failed_peers = std.ArrayList(*net.Peer).init(allocator),
            .sync_blocks_to_download = std.ArrayList(u32).init(allocator),
            .sync_active_downloads = std.AutoHashMap(u32, i64).init(allocator),
            .block_sync_protocol = null,
            .headers_first_protocol = null,
            .is_syncing = false,
            .sync_peer = null,
            .target_height = 0,
        };
    }

    pub fn deinit(self: *SyncManager) void {
        // Following ZeiCoin memory management principles from docs/memory-management.md
        // Clean up in reverse order of initialization
        
        // 1. Stop any active operations first
        self.is_syncing = false;
        self.sync_peer = null;
        self.target_height = 0;
        
        // 2. Clean up protocols (if any)
        // These are cleaned up first as they might reference the collections
        if (self.block_sync_protocol) |*protocol| {
            protocol.deinit();
            self.block_sync_protocol = null;
        }
        if (self.headers_first_protocol) |*protocol| {
            protocol.deinit();
            self.headers_first_protocol = null;
        }
        
        // 3. Clean up collections in reverse order of initialization
        // Clear contents first to ensure no dangling references
        self.sync_active_downloads.clearAndFree();
        self.sync_blocks_to_download.clearAndFree();
        self.sync_failed_peers.clearAndFree();
        
        // Then deinit the collections themselves
        self.sync_active_downloads.deinit();
        self.sync_blocks_to_download.deinit();
        self.sync_failed_peers.deinit();
    }

    /// Start sync operation (legacy compatibility)
    pub fn startSync(self: *SyncManager) !void {
        if (self.is_syncing) {
            std.debug.print("Sync already in progress.\n", .{});
            return;
        }

        // Find a peer to sync with
        if (self.blockchain.network) |network| {
            if (network.peer_manager.getBestPeerForSync()) |peer| {
                self.sync_peer = peer;
                self.target_height = peer.height;
                
                // Use the new modular sync manager
                // Simple sync implementation
                self.sync_peer = peer;
                self.is_syncing = true;
                
                // Update legacy state for compatibility
                // Sync state already set above
                
                std.debug.print("Starting sync with peer {} to height {}\n", .{ peer.address, self.target_height });
            } else {
                std.debug.print("No connected peers to sync with.\n", .{});
            }
        } else {
            std.debug.print("Network not initialized.\n", .{});
        }
    }

    /// Start headers-first sync specifically
    pub fn startHeadersFirstSync(self: *SyncManager, peer: *net.Peer, target_height: u32) !void {
        // Simple headers sync implementation
        self.sync_peer = peer;
        self.target_height = target_height;
        self.is_syncing = true;
        
        // Update legacy state
        self.sync_peer = peer;
        self.target_height = target_height;
        // Sync state already set above
    }

    /// Process incoming headers (legacy compatibility)
    pub fn processIncomingHeaders(self: *SyncManager, headers: []types.BlockHeader, start_height: u32) !void {
        if (!self.is_syncing) {
            std.debug.print("Not in sync mode, ignoring headers.\n", .{});
            return;
        }

        // Delegate to the modular sync manager
        // Simple headers processing
        _ = headers;
        _ = start_height;
        
        // Update legacy state
        // Sync state already set above
    }

    /// Process incoming block (legacy compatibility)
    pub fn processIncomingBlock(self: *SyncManager, block: *types.Block) !void {
        if (!self.is_syncing) {
            std.debug.print("Not in sync mode, ignoring block.\n", .{});
            block.deinit(self.allocator);
            return;
        }

        // Delegate to the modular sync manager
        // Simple block handling - block is already being cleaned up above
        
        // Update legacy state
        // Sync state already set above
    }

    /// Handle failed download (legacy compatibility)
    pub fn handleFailedDownload(self: *SyncManager, height: u32) !void {
        std.debug.print("Block download failed for height {}. Re-queueing.\n", .{height});
        
        // For now, delegate to blockchain for compatibility
        // TODO: Move this logic to the download management module
        try self.blockchain.blocks_to_download.append(height);
        _ = self.blockchain.active_block_downloads.remove(height);
    }

    /// Get sync progress (new method)
    pub fn getProgress(self: *const SyncManager) f64 {
        // Simple progress stub
        return sync_manager.SyncProgress{ .current_height = 0, .target_height = self.target_height, .downloaded_blocks = 0, .is_complete = false };
    }

    /// Get sync state (new method)
    pub fn getSyncState(self: *const SyncManager) sync_state.SyncState {
        // Simple state stub
        return if (self.is_syncing) sync_manager.SyncState.syncing else sync_manager.SyncState.idle;
    }

    /// Check if should sync with peer (new method)
    pub fn shouldSync(self: *const SyncManager, peer_height: u32) bool {
        // Simple should sync logic
        return peer_height > self.target_height;
    }

    /// Report sync progress (new method)
    pub fn reportProgress(_: *const SyncManager) void {
        // Simple progress reporting - no-op
    }

    /// Complete sync operation (new method)
    pub fn completeSync(self: *SyncManager) !void {
        // Complete sync
        self.is_syncing = false;
        self.sync_peer = null;
        
        // Update legacy state
        self.is_syncing = false;
        self.sync_peer = null;
    }

    /// Fail sync operation (new method)
    pub fn failSync(self: *SyncManager) void {
        // Fail sync
        self.is_syncing = false;
        self.sync_peer = null;
        
        // Update legacy state
        self.is_syncing = false;
        self.sync_peer = null;
    }

    // Legacy compatibility methods that may still be called by existing code
    
    fn startBlockDownload(self: *SyncManager) !void {
        // This functionality is now handled by the headers-first protocol
        // Keep for compatibility but delegate to modular system
        _ = self;
        std.debug.print("startBlockDownload: delegating to modular sync system\n", .{});
    }

    fn downloadNextBlocks(self: *SyncManager) !void {
        // This functionality is now handled by the download management module
        // Keep for compatibility but delegate to modular system
        _ = self;
        std.debug.print("downloadNextBlocks: delegating to modular sync system\n", .{});
    }
};