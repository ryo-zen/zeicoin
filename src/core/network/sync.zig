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
    
    // New modular sync manager
    core_sync_manager: sync_manager.SyncManager,
    
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
            .core_sync_manager = sync_manager.SyncManager.init(allocator, blockchain),
            .block_sync_protocol = null,
            .headers_first_protocol = null,
            .is_syncing = false,
            .sync_peer = null,
            .target_height = 0,
        };
    }

    pub fn deinit(self: *SyncManager) void {
        self.core_sync_manager.deinit();
        if (self.block_sync_protocol) |*protocol| {
            protocol.deinit();
        }
        if (self.headers_first_protocol) |*protocol| {
            protocol.deinit();
        }
    }

    /// Start sync operation (legacy compatibility)
    pub fn startSync(self: *SyncManager) !void {
        if (self.core_sync_manager.isActive()) {
            std.debug.print("Sync already in progress.\n", .{});
            return;
        }

        // Find a peer to sync with
        if (self.blockchain.network) |network| {
            if (network.getRandomPeer()) |peer| {
                self.sync_peer = peer;
                self.target_height = peer.start_height;
                
                // Use the new modular sync manager
                try self.core_sync_manager.startSync(peer, self.target_height);
                
                // Update legacy state for compatibility
                self.is_syncing = self.core_sync_manager.isActive();
                
                std.debug.print("Starting sync with peer {s}:{} to height {}\n", .{ peer.address.ip, peer.address.port, self.target_height });
            } else {
                std.debug.print("No connected peers to sync with.\n", .{});
            }
        } else {
            std.debug.print("Network not initialized.\n", .{});
        }
    }

    /// Start headers-first sync specifically
    pub fn startHeadersFirstSync(self: *SyncManager, peer: *net.Peer, target_height: u32) !void {
        try self.core_sync_manager.startHeadersSync(peer, target_height);
        
        // Update legacy state
        self.sync_peer = peer;
        self.target_height = target_height;
        self.is_syncing = self.core_sync_manager.isActive();
    }

    /// Process incoming headers (legacy compatibility)
    pub fn processIncomingHeaders(self: *SyncManager, headers: []types.BlockHeader, start_height: u32) !void {
        if (!self.core_sync_manager.isActive()) {
            std.debug.print("Not in sync mode, ignoring headers.\n", .{});
            return;
        }

        // Delegate to the modular sync manager
        try self.core_sync_manager.processIncomingHeaders(headers, start_height);
        
        // Update legacy state
        self.is_syncing = self.core_sync_manager.isActive();
    }

    /// Process incoming block (legacy compatibility)
    pub fn processIncomingBlock(self: *SyncManager, block: *types.Block) !void {
        if (!self.core_sync_manager.isActive()) {
            std.debug.print("Not in sync mode, ignoring block.\n", .{});
            block.deinit(self.allocator);
            return;
        }

        // Delegate to the modular sync manager
        try self.core_sync_manager.handleSyncBlock(block.*);
        
        // Update legacy state
        self.is_syncing = self.core_sync_manager.isActive();
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
        return self.core_sync_manager.getProgress();
    }

    /// Get sync state (new method)
    pub fn getSyncState(self: *const SyncManager) sync_state.SyncState {
        return self.core_sync_manager.getSyncState();
    }

    /// Check if should sync with peer (new method)
    pub fn shouldSync(self: *const SyncManager, peer_height: u32) bool {
        return self.core_sync_manager.shouldSync(peer_height);
    }

    /// Report sync progress (new method)
    pub fn reportProgress(self: *const SyncManager) void {
        self.core_sync_manager.reportProgress();
    }

    /// Complete sync operation (new method)
    pub fn completeSync(self: *SyncManager) !void {
        try self.core_sync_manager.completeSync();
        
        // Update legacy state
        self.is_syncing = false;
        self.sync_peer = null;
    }

    /// Fail sync operation (new method)
    pub fn failSync(self: *SyncManager) void {
        self.core_sync_manager.failSync();
        
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