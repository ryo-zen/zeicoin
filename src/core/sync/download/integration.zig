// sync/download/integration.zig - Integration layer for parallel downloads
// Connects parallel download manager to existing sync infrastructure

const std = @import("std");
const log = std.log.scoped(.sync);

const types = @import("../../types/types.zig");
const ParallelDownloadManager = @import("parallel.zig").ParallelDownloadManager;
const net = @import("../../network/peer.zig");

/// Enhanced sync manager with parallel download capability
pub const EnhancedSyncManager = struct {
    allocator: std.mem.Allocator,
    
    // Traditional sync fallback
    sync_manager: *@import("../manager.zig").SyncManager,
    
    // Parallel download system
    parallel_downloads: ParallelDownloadManager,
    
    // Configuration
    use_parallel_downloads: bool = true,
    min_peers_for_parallel: u8 = 2,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, sync_manager: *@import("../manager.zig").SyncManager) Self {
        return .{
            .allocator = allocator,
            .sync_manager = sync_manager,
            .parallel_downloads = ParallelDownloadManager.init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.parallel_downloads.deinit();
    }
    
    /// Add peer to both traditional and parallel sync systems
    pub fn addPeer(self: *Self, peer: *net.Peer) !void {
        // Add to parallel downloads if it supports fast sync
        if (peer.services) |services| {
            if (@import("../../network/protocol/protocol.zig").ServiceFlags.supportsFastSync(services)) {
                try self.parallel_downloads.addPeer(peer);
                log.info("Added peer to parallel download pool", .{});
            } else {
                log.debug("Peer added to traditional sync only (no fast sync support)", .{});
            }
        }
    }
    
    /// Remove peer from both systems
    pub fn removePeer(self: *Self, peer: *net.Peer) void {
        self.parallel_downloads.removePeer(peer);
        log.info("Removed peer from download systems", .{});
    }
    
    /// Start sync operation - intelligently chooses parallel vs traditional
    pub fn startSync(self: *Self, target_height: u32, available_peers: []const *net.Peer) !void {
        const current_height = try self.sync_manager.blockchain.getHeight();
        
        if (target_height <= current_height) {
            log.info("Already synced (height {})", .{current_height});
            return;
        }
        
        const blocks_needed = target_height - current_height;
        
        // Decision: Use parallel downloads if we have enough peers and blocks
        const can_use_parallel = self.use_parallel_downloads and 
                                available_peers.len >= self.min_peers_for_parallel and
                                blocks_needed > 20; // Worth the overhead
        
        if (can_use_parallel) {
            log.info("Starting parallel sync: {} -> {} ({} blocks, {} peers)", 
                  .{current_height, target_height, blocks_needed, available_peers.len});
            
            // Add all suitable peers to parallel downloads
            for (available_peers) |peer| {
                self.addPeer(peer) catch |err| {
                    log.warn("Failed to add peer to parallel downloads: {}", .{err});
                };
            }
            
            // Queue blocks for download
            try self.parallel_downloads.queueBlockRange(current_height + 1, target_height);
            
            log.info("Queued {} blocks for parallel download", .{blocks_needed});
        } else {
            log.info("Starting traditional sync: {} -> {} (fallback mode)", 
                  .{current_height, target_height});
            
            // Use traditional sync as fallback
            if (available_peers.len > 0) {
                try self.sync_manager.startBatchSync(available_peers[0], target_height);
            } else {
                return error.NoPeersAvailable;
            }
        }
    }
    
    /// Process sync tick - handles both parallel and traditional sync
    pub fn processTick(self: *Self) !void {
        if (self.parallel_downloads.isComplete()) {
            // No parallel downloads active, let traditional sync handle things
            return;
        }
        
        // Process parallel download queue
        try self.parallel_downloads.processDownloadQueue();
        
        // Process any completed blocks
        try self.processCompletedBlocks();
        
        // Report progress periodically
        self.reportProgress();
    }
    
    /// Handle incoming block - routes to appropriate handler
    pub fn handleIncomingBlock(self: *Self, height: u32, block: types.Block, from_peer: *net.Peer) !void {
        // Try parallel downloads first
        if (try self.parallel_downloads.handleIncomingBlock(height, block, from_peer)) {
            log.debug("Block {} handled by parallel downloads", .{height});
            return;
        }
        
        // Fall back to traditional sync handling
        log.debug("Block {} forwarded to traditional sync", .{height});
        
        // Forward to sync manager for traditional block processing
        if (self.sync_manager.sync_manager) |sm| {
            try sm.handleSyncBlock(block);
        } else {
            // Direct blockchain integration if no sync manager
            try self.sync_manager.blockchain.handleIncomingBlock(block, from_peer);
        }
    }
    
    /// Process completed blocks from parallel downloads
    fn processCompletedBlocks(self: *Self) !void {
        const current_height = try self.sync_manager.blockchain.getHeight();
        var next_height = current_height + 1;
        
        // Process blocks in order
        while (self.parallel_downloads.getNextCompletedBlock(next_height)) |block| {
            log.debug("Processing downloaded block at height {}", .{next_height});
            
            // Validate the block before adding to chain
            if (try self.sync_manager.blockchain.validateSyncBlock(block, next_height)) {
                // Check consensus with peers if enabled
                const sync = @import("../manager.zig");
                if (!try sync.verifyBlockConsensus(self.sync_manager.blockchain, block, next_height)) {
                    log.warn("Block {} consensus verification failed", .{next_height});
                    continue;
                }
                
                // Add validated block to chain
                try self.sync_manager.blockchain.chain_processor.addBlockToChain(block, next_height);
                log.info("Block {} successfully added to chain", .{next_height});
            } else {
                log.warn("Block {} validation failed, skipping", .{next_height});
                // Block cleanup handled by blockchain
            }
            
            next_height += 1;
        }
    }
    
    /// Report sync progress
    fn reportProgress(self: *Self) void {
        const stats = self.parallel_downloads.getProgress();
        
        if (stats.total_requests > 0) {
            const completion_rate = if (stats.total_requests > 0) 
                (@as(f64, @floatFromInt(stats.completed_downloads)) / @as(f64, @floatFromInt(stats.total_requests))) * 100.0
                else 0.0;
            
            log.info("Parallel sync: {d:.1}% complete ({}/{} blocks, {d:.2} blocks/sec, {d:.1}% success)", 
                  .{completion_rate, stats.completed_downloads, stats.total_requests, 
                    stats.blocks_per_second, stats.getSuccessRate()});
        }
    }
    
    /// Check if sync is complete
    pub fn isComplete(self: *Self) bool {
        return self.parallel_downloads.isComplete();
    }
    
    /// Get current sync statistics
    pub fn getStats(self: *Self) ParallelDownloadManager.DownloadStats {
        return self.parallel_downloads.getProgress();
    }
    
    /// Enable or disable parallel downloads
    pub fn setParallelDownloads(self: *Self, enabled: bool) void {
        self.use_parallel_downloads = enabled;
        if (enabled) {
            log.info("Parallel downloads enabled", .{});
        } else {
            log.warn("Parallel downloads disabled - using traditional sync only", .{});
        }
    }
    
    /// Set minimum peers required for parallel downloads
    pub fn setMinPeersForParallel(self: *Self, min_peers: u8) void {
        self.min_peers_for_parallel = min_peers;
        log.info("Set minimum peers for parallel downloads: {}", .{min_peers});
    }
};

/// Utility functions for sync optimization
pub const SyncOptimizer = struct {
    
    /// Analyze peer capabilities and recommend sync strategy
    pub fn analyzePeers(peers: []const *net.Peer) struct {
        total_peers: usize,
        fast_sync_peers: usize,
        full_node_peers: usize,
        recommended_strategy: enum { traditional, parallel, mixed },
    } {
        var fast_sync_count: usize = 0;
        var full_node_count: usize = 0;
        
        for (peers) |peer| {
            if (peer.services) |services| {
                const protocol = @import("../../network/protocol/protocol.zig");
                if (protocol.ServiceFlags.supportsFastSync(services)) {
                    fast_sync_count += 1;
                }
                if (protocol.ServiceFlags.isFullNode(services)) {
                    full_node_count += 1;
                }
            }
        }
        
        const recommended = if (fast_sync_count >= 3) 
            .parallel
        else if (fast_sync_count >= 1 and full_node_count >= 2)
            .mixed
        else
            .traditional;
        
        return .{
            .total_peers = peers.len,
            .fast_sync_peers = fast_sync_count,
            .full_node_peers = full_node_count,
            .recommended_strategy = recommended,
        };
    }
    
    /// Calculate optimal batch size based on network conditions
    pub fn calculateOptimalBatchSize(peer_count: usize, network_latency_ms: u32) u32 {
        // Base batch size
        var batch_size: u32 = 50;
        
        // Adjust for peer count
        if (peer_count > 5) {
            batch_size = batch_size * 2; // More peers = larger batches
        } else if (peer_count < 3) {
            batch_size = batch_size / 2; // Fewer peers = smaller batches
        }
        
        // Adjust for network latency
        if (network_latency_ms > 1000) {
            batch_size = batch_size / 2; // High latency = smaller batches
        } else if (network_latency_ms < 100) {
            batch_size = batch_size * 2; // Low latency = larger batches
        }
        
        // Clamp to reasonable bounds
        return @max(10, @min(500, batch_size));
    }
    
    /// Estimate sync completion time
    pub fn estimateSyncTime(blocks_remaining: u32, peer_count: usize, use_parallel: bool) struct {
        estimated_seconds: u32,
        confidence_level: enum { low, medium, high },
    } {
        // Base rate: blocks per second
        var blocks_per_second: f64 = 0.5; // Conservative estimate for traditional sync
        
        if (use_parallel and peer_count >= 3) {
            // Parallel sync is much faster
            blocks_per_second = 2.0 + (@as(f64, @floatFromInt(peer_count)) * 0.3);
        } else if (peer_count > 1) {
            // Multiple peers help even with traditional sync
            blocks_per_second = 0.5 + (@as(f64, @floatFromInt(peer_count)) * 0.1);
        }
        
        const estimated_time = @as(u32, @intFromFloat(@as(f64, @floatFromInt(blocks_remaining)) / blocks_per_second));
        
        const confidence = if (use_parallel and peer_count >= 5)
            .high
        else if (peer_count >= 3)
            .medium
        else
            .low;
        
        return .{
            .estimated_seconds = estimated_time,
            .confidence_level = confidence,
        };
    }
};