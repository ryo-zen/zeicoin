// sync.zig - Network Sync Manager (Updated for Modular Architecture)
// Integrates the new modular sync system with the network layer
// Uses the extracted sync protocols from src/core/sync/

const std = @import("std");
const print = std.debug.print;
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const headerchain = @import("headerchain.zig");
const net = @import("peer.zig");
const protocol = @import("protocol/protocol.zig");

// Import the new modular sync system
const sync_mod = @import("../sync/sync.zig");
const sync_protocols = @import("../sync/protocol/lib.zig");

const ZeiCoin = @import("../node.zig").ZeiCoin;

/// Network-level sync manager that bridges networking and sync protocols
/// This is a compatibility layer that integrates with the existing network code
pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    // Sync management collections
    failed_peers: std.ArrayList(*net.Peer),
    blocks_to_download: std.ArrayList(u32),
    active_downloads: std.AutoHashMap(u32, i64),
    
    // Protocol instances
    block_sync_protocol: ?sync_protocols.BlockSyncProtocol,
    headers_first_protocol: ?sync_protocols.HeadersFirstProtocol,
    
    // Legacy compatibility fields
    is_syncing: bool,
    sync_peer: ?*net.Peer,
    target_height: u32,
    current_height: u32,
    blocks_downloaded: u32,

    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) SyncManager {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .failed_peers = std.ArrayList(*net.Peer).init(allocator),
            .blocks_to_download = std.ArrayList(u32).init(allocator),
            .active_downloads = std.AutoHashMap(u32, i64).init(allocator),
            .block_sync_protocol = null,
            .headers_first_protocol = null,
            .is_syncing = false,
            .sync_peer = null,
            .target_height = 0,
            .current_height = 0,
            .blocks_downloaded = 0,
        };
    }

    pub fn deinit(self: *SyncManager) void {
        // Following ZeiCoin memory management principles from docs/memory-management.md
        // Clean up in reverse order of initialization
        
        // 1. Stop any active operations first
        self.is_syncing = false;
        self.sync_peer = null;
        self.target_height = 0;
        self.current_height = 0;
        self.blocks_downloaded = 0;
        
        // 2. Clean up protocols (if any)
        // These are cleaned up first as they might reference the collections
        if (self.block_sync_protocol) |*proto| {
            proto.deinit();
            self.block_sync_protocol = null;
        }
        if (self.headers_first_protocol) |*proto| {
            proto.deinit();
            self.headers_first_protocol = null;
        }
        
        // 3. Clean up collections in reverse order of initialization
        self.active_downloads.deinit();
        self.blocks_to_download.deinit();
        self.failed_peers.deinit();
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
                
                // Mark as syncing
                self.is_syncing = true;
                
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
        self.sync_peer = peer;
        self.target_height = target_height;
        self.current_height = try self.blockchain.getHeight();
        self.blocks_downloaded = 0;
        self.is_syncing = true;
    }

    /// Process incoming headers (legacy compatibility)
    pub fn processIncomingHeaders(self: *SyncManager, headers: []types.BlockHeader, start_height: u32) !void {
        if (!self.is_syncing) {
            std.debug.print("Not in sync mode, ignoring headers.\n", .{});
            return;
        }

        // Validate we have headers
        if (headers.len == 0) {
            std.debug.print("No headers received, ignoring.\n", .{});
            return;
        }

        std.debug.print("📥 Processing {} headers starting from height {}\n", .{headers.len, start_height});

        // Use the header chain
        const hc = &self.blockchain.header_chain;
        for (headers, 0..) |header, i| {
            const height = start_height + @as(u32, @intCast(i));
            
            // Try to add the header
            hc.addHeader(header, height) catch |err| {
                std.debug.print("❌ Header at height {} rejected: {}\n", .{height, err});
                break; // Stop processing further headers on error
            };
            
            std.debug.print("✅ Header at height {} accepted\n", .{height});
            // Queue this height for block download
            try self.blocks_to_download.append(height);
        }
        
        // After processing headers, check if we need to download blocks
        if (self.blocks_to_download.items.len > 0) {
            std.debug.print("📦 {} blocks queued for download\n", .{self.blocks_to_download.items.len});
            // Trigger block downloads
            try self.requestNextBlocks();
        }
    }

    /// Process incoming block (legacy compatibility)
    pub fn processIncomingBlock(self: *SyncManager, block: *types.Block) !void {
        if (!self.is_syncing) {
            std.debug.print("Not in sync mode, ignoring block.\n", .{});
            block.deinit(self.allocator);
            return;
        }

        // Get the block height from its hash
        const block_hash = block.hash();
        const block_height = self.getHeightForBlock(block_hash) catch {
            std.debug.print("⚠️  Cannot determine height for block, ignoring\n", .{});
            block.deinit(self.allocator);
            return;
        };

        // Remove from active downloads
        _ = self.active_downloads.remove(block_height);

        // Validate it's a block we're expecting
        var found = false;
        for (self.blocks_to_download.items, 0..) |height, i| {
            if (height == block_height) {
                _ = self.blocks_to_download.orderedRemove(i);
                found = true;
                break;
            }
        }

        if (!found) {
            std.debug.print("⚠️  Received unexpected block at height {}, ignoring\n", .{block_height});
            block.deinit(self.allocator);
            return;
        }

        std.debug.print("📦 Processing sync block at height {}\n", .{block_height});

        // Forward to the blockchain sync manager
        // Note: ownership is transferred to handleSyncBlock
        if (self.blockchain.sync_manager) |sm| {
            try sm.handleSyncBlock(block.*);
            // Block ownership transferred, just free the pointer
            self.allocator.destroy(block);
        } else {
            // No sync manager, process directly through blockchain
            try self.blockchain.handleIncomingBlock(block.*, self.sync_peer);
            // Block ownership transferred, just free the pointer
            self.allocator.destroy(block);
        }

        // Update progress
        self.blocks_downloaded += 1;
        const progress = @as(f64, @floatFromInt(self.blocks_downloaded)) / 
                        @as(f64, @floatFromInt(self.target_height - self.current_height)) * 100.0;
        std.debug.print("📊 Sync progress: {d:.1}%\n", .{progress});

        // Request next blocks if needed
        if (self.blocks_to_download.items.len > 0) {
            try self.requestNextBlocks();
        } else if (self.blocks_downloaded >= (self.target_height - self.current_height)) {
            // Sync complete
            std.debug.print("✅ Sync completed!\n", .{});
            try self.completeSync();
        }
    }

    /// Handle failed download (legacy compatibility)
    pub fn handleFailedDownload(self: *SyncManager, height: u32) !void {
        std.debug.print("Block download failed for height {}. Re-queueing.\n", .{height});
        
        // Re-queue the failed download
        try self.blocks_to_download.append(height);
        _ = self.active_downloads.remove(height);
    }

    /// Get sync progress percentage
    pub fn getProgress(self: *const SyncManager) f64 {
        if (self.target_height == 0) return 100.0;
        const current = self.blockchain.getHeight() catch 0;
        return @as(f64, @floatFromInt(current)) / @as(f64, @floatFromInt(self.target_height)) * 100.0;
    }

    /// Get sync state
    pub fn getSyncState(self: *const SyncManager) sync_mod.SyncState {
        return if (self.is_syncing) .syncing else .synced;
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

    /// Complete sync operation
    pub fn completeSync(self: *SyncManager) !void {
        self.is_syncing = false;
        self.sync_peer = null;
        self.target_height = 0;
        self.blocks_downloaded = 0;
        self.blocks_to_download.clearRetainingCapacity();
        self.active_downloads.clearRetainingCapacity();
        std.debug.print("🎉 Blockchain sync completed successfully!\n", .{});
    }

    /// Fail sync operation
    pub fn failSync(self: *SyncManager) void {
        self.is_syncing = false;
        self.sync_peer = null;
        self.target_height = 0;
        self.failed_peers.clearRetainingCapacity();
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
    
    /// Request next blocks for download
    fn requestNextBlocks(self: *SyncManager) !void {
        if (self.sync_peer == null) {
            std.debug.print("⚠️  No sync peer available for block requests\n", .{});
            return;
        }
        
        const MAX_CONCURRENT_DOWNLOADS = 16;
        const current_time = std.time.milliTimestamp();
        
        // Request blocks up to the limit
        var requested: usize = 0;
        for (self.blocks_to_download.items) |height| {
            // Skip if already downloading
            if (self.active_downloads.contains(height)) continue;
            
            // Check concurrent download limit
            if (self.active_downloads.count() >= MAX_CONCURRENT_DOWNLOADS) break;
            
            // Mark as active download
            try self.active_downloads.put(height, current_time);
            
            // Request the block from peer
            if (self.sync_peer) |peer| {
                // Get block hash from header chain if available
                if (self.blockchain.header_chain.getHeader(height)) |header| {
                    const block_hash = header.hash();
                    peer.sendGetBlockByHash(block_hash) catch |err| {
                        print("⚠️ Failed to request block {} by hash: {}\n", .{height, err});
                        // Fallback to height-based request
                        peer.sendGetBlockByHeight(height) catch continue;
                    };
                } else {
                    // Fallback to height-based request if no header available
                    peer.sendGetBlockByHeight(height) catch continue;
                }
                requested += 1;
            }
            
            if (requested >= 8) break; // Batch size limit
        }
    }
    
    /// Get height for a block by its hash
    fn getHeightForBlock(self: *SyncManager, block_hash: types.BlockHash) !u32 {
        // Try header chain lookup first
        if (self.blockchain.header_chain.getHeightForHash(block_hash)) |height| {
            return height;
        }
        
        // Fallback: scan our download queue for known heights
        for (self.blocks_to_download.items) |height| {
            if (self.blockchain.header_chain.getHeader(height)) |header| {
                const header_hash = header.hash();
                if (std.mem.eql(u8, &block_hash, &header_hash)) {
                    return height;
                }
            }
        }
        
        return error.HeightNotFound;
    }
    
};