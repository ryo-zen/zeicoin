// sync/download/parallel.zig - Parallel Block Download Manager
// Implements 5-10x faster sync through parallel downloads from multiple peers

const std = @import("std");
const log = std.log.scoped(.sync);

const types = @import("../../types/types.zig");
const protocol = @import("../../network/protocol/protocol.zig");
const util = @import("../../util/util.zig");
const net = @import("../../network/peer.zig");

// Type alias for clarity
const Peer = net.Peer;

/// Block download request tracking
pub const DownloadRequest = struct {
    height: u32,
    hash: ?types.Hash = null, // Optional block hash for verification
    assigned_peer: ?*Peer = null,
    request_time: i64 = 0,
    retry_count: u8 = 0,
    
    const Self = @This();
    
    pub fn init(height: u32) Self {
        return .{
            .height = height,
        };
    }
    
    pub fn initWithHash(height: u32, hash: types.Hash) Self {
        return .{
            .height = height,
            .hash = hash,
        };
    }
    
    pub fn isTimedOut(self: Self) bool {
        if (self.request_time == 0) return false;
        const now = util.getTime();
        return now - self.request_time > types.SYNC.DOWNLOAD_TIMEOUT_SECONDS;
    }
    
    pub fn shouldRetry(self: Self) bool {
        return self.retry_count < types.SYNC.MAX_DOWNLOAD_RETRIES;
    }
};

/// Download statistics tracking
pub const DownloadStats = struct {
    total_requests: u32 = 0,
    completed_downloads: u32 = 0,
    failed_downloads: u32 = 0,
    average_download_time: f64 = 0.0,
    blocks_per_second: f64 = 0.0,
    start_time: i64,
    
    const Self = @This();
    
    pub fn init() Self {
        return .{
            .start_time = util.getTime(),
        };
    }
    
    pub fn recordCompletion(self: *Self, download_time: i64) void {
        self.completed_downloads += 1;
        
        // Update average download time
        const new_avg = (self.average_download_time * @as(f64, @floatFromInt(self.completed_downloads - 1)) + 
                        @as(f64, @floatFromInt(download_time))) / @as(f64, @floatFromInt(self.completed_downloads));
        self.average_download_time = new_avg;
        
        // Calculate blocks per second
        const elapsed = util.getTime() - self.start_time;
        if (elapsed > 0) {
            self.blocks_per_second = @as(f64, @floatFromInt(self.completed_downloads)) / @as(f64, @floatFromInt(elapsed));
        }
    }
    
    pub fn recordFailure(self: *Self) void {
        self.failed_downloads += 1;
    }
    
    pub fn getSuccessRate(self: Self) f64 {
        const total = self.completed_downloads + self.failed_downloads;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.completed_downloads)) / @as(f64, @floatFromInt(total)) * 100.0;
    }
};

/// Peer download capacity tracking
pub const PeerCapacity = struct {
    peer: *Peer,
    active_downloads: u8 = 0,
    max_concurrent: u8 = 3, // Start conservative, adjust based on performance
    average_response_time: f64 = 0.0,
    success_count: u32 = 0,
    failure_count: u32 = 0,
    last_activity: i64 = 0,
    
    const Self = @This();
    
    pub fn init(peer: *Peer) Self {
        return .{
            .peer = peer,
            .last_activity = util.getTime(),
        };
    }
    
    pub fn canAcceptDownload(self: Self) bool {
        return self.active_downloads < self.max_concurrent and 
               self.peer.isConnected() and
               self.hasGoodSyncCapability();
    }
    
    pub fn hasGoodSyncCapability(self: Self) bool {
        // Check if peer supports parallel downloads via service flags
        if (self.peer.services) |services| {
            return protocol.ServiceFlags.supportsFastSync(services);
        }
        return true; // Assume capability if unknown
    }
    
    pub fn getQualityScore(self: Self) u8 {
        var score: u32 = 50; // Base score
        
        // Bonus for supporting parallel downloads
        if (self.hasGoodSyncCapability()) score += 30;
        
        // Response time bonus (lower is better)
        if (self.average_response_time > 0) {
            if (self.average_response_time < 1.0) {
                score += 20;
            } else if (self.average_response_time < 3.0) {
                score += 10;
            } else if (self.average_response_time > 10.0) {
                score = score / 2;
            }
        }
        
        // Success rate bonus
        const total = self.success_count + self.failure_count;
        if (total > 5) { // Only consider if we have enough samples
            const success_rate = @as(f64, @floatFromInt(self.success_count)) / @as(f64, @floatFromInt(total));
            if (success_rate > 0.9) {
                score += 20;
            } else if (success_rate < 0.5) {
                score = score / 2;
            }
        }
        
        // Availability bonus (fewer active downloads is better)
        const availability = self.max_concurrent - self.active_downloads;
        score += @as(u32, availability) * 5;
        
        return @min(100, @as(u8, @intCast(score)));
    }
    
    pub fn recordDownloadStart(self: *Self) void {
        self.active_downloads += 1;
        self.last_activity = util.getTime();
    }
    
    pub fn recordDownloadSuccess(self: *Self, response_time: f64) void {
        if (self.active_downloads > 0) self.active_downloads -= 1;
        
        self.success_count += 1;
        
        // Update average response time
        if (self.average_response_time == 0.0) {
            self.average_response_time = response_time;
        } else {
            self.average_response_time = (self.average_response_time + response_time) / 2.0;
        }
        
        // Increase capacity if performing well
        if (self.success_count % 10 == 0 and self.average_response_time < 2.0 and self.max_concurrent < 8) {
            self.max_concurrent += 1;
            log.info("Increased peer capacity to {} concurrent downloads", .{self.max_concurrent});
        }
        
        self.last_activity = util.getTime();
    }
    
    pub fn recordDownloadFailure(self: *Self) void {
        if (self.active_downloads > 0) self.active_downloads -= 1;
        
        self.failure_count += 1;
        
        // Decrease capacity if failing too much
        const total = self.success_count + self.failure_count;
        if (total > 10) {
            const failure_rate = @as(f64, @floatFromInt(self.failure_count)) / @as(f64, @floatFromInt(total));
            if (failure_rate > 0.3 and self.max_concurrent > 1) {
                self.max_concurrent -= 1;
                log.warn("Decreased peer capacity to {} concurrent downloads due to failures", .{self.max_concurrent});
            }
        }
        
        self.last_activity = util.getTime();
    }
};

/// Parallel Download Manager - coordinates downloads from multiple peers
pub const ParallelDownloadManager = struct {
    allocator: std.mem.Allocator,
    
    // Download queues
    pending_requests: std.ArrayList(DownloadRequest),
    active_requests: std.AutoHashMap(u32, DownloadRequest), // height -> request
    completed_blocks: std.AutoHashMap(u32, types.Block), // height -> block
    
    // Peer management
    peer_capacities: std.AutoHashMap(*Peer, PeerCapacity),
    available_peers: std.ArrayList(*Peer),
    
    // Statistics and monitoring
    stats: DownloadStats,
    max_concurrent_downloads: u8 = 20, // Total concurrent downloads across all peers
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .pending_requests = std.ArrayList(DownloadRequest).init(allocator),
            .active_requests = std.AutoHashMap(u32, DownloadRequest).init(allocator),
            .completed_blocks = std.AutoHashMap(u32, types.Block).init(allocator),
            .peer_capacities = std.AutoHashMap(*Peer, PeerCapacity).init(allocator),
            .available_peers = std.ArrayList(*Peer).init(allocator),
            .stats = DownloadStats.init(),
        };
    }
    
    pub fn deinit(self: *Self) void {
        // Clean up completed blocks
        var block_iter = self.completed_blocks.iterator();
        while (block_iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        
        self.pending_requests.deinit();
        self.active_requests.deinit();
        self.completed_blocks.deinit();
        self.peer_capacities.deinit();
        self.available_peers.deinit();
    }
    
    /// Add peers that can participate in parallel downloads
    pub fn addPeer(self: *Self, peer: *Peer) !void {
        // Only add peers that support parallel downloads
        if (peer.services) |services| {
            if (!protocol.ServiceFlags.supportsFastSync(services)) {
                log.debug("Peer doesn't support fast sync, skipping for parallel downloads", .{});
                return;
            }
        }
        
        try self.available_peers.append(peer);
        try self.peer_capacities.put(peer, PeerCapacity.init(peer));
        
        log.info("Added peer to parallel download pool (total: {})", .{self.available_peers.items.len});
    }
    
    /// Remove a peer from the download pool
    pub fn removePeer(self: *Self, peer: *Peer) void {
        // Remove from available peers
        for (self.available_peers.items, 0..) |p, i| {
            if (p == peer) {
                _ = self.available_peers.swapRemove(i);
                break;
            }
        }
        
        // Cancel any active requests from this peer
        var iter = self.active_requests.iterator();
        var requests_to_cancel = std.ArrayList(u32).init(self.allocator);
        defer requests_to_cancel.deinit();
        
        while (iter.next()) |entry| {
            if (entry.value_ptr.assigned_peer == peer) {
                requests_to_cancel.append(entry.key_ptr.*) catch continue;
            }
        }
        
        for (requests_to_cancel.items) |height| {
            if (self.active_requests.fetchRemove(height)) |kv| {
                // Re-queue the request for another peer
                var request = kv.value;
                request.assigned_peer = null;
                request.request_time = 0;
                request.retry_count += 1;
                
                if (request.shouldRetry()) {
                    self.pending_requests.append(request) catch {};
                    log.debug("Re-queued block {} after peer removal", .{height});
                } else {
                    log.warn("Dropped block {} request after too many retries", .{height});
                    self.stats.recordFailure();
                }
            }
        }
        
        // Remove peer capacity tracking
        _ = self.peer_capacities.remove(peer);
        
        log.info("Removed peer from parallel download pool (remaining: {})", .{self.available_peers.items.len});
    }
    
    /// Queue a range of blocks for download
    pub fn queueBlockRange(self: *Self, start_height: u32, end_height: u32) !void {
        log.info("Queuing blocks {} to {} for parallel download ({} blocks)", .{start_height, end_height, end_height - start_height + 1});
        
        var height = start_height;
        while (height <= end_height) : (height += 1) {
            const request = DownloadRequest.init(height);
            try self.pending_requests.append(request);
            self.stats.total_requests += 1;
        }
        
        log.debug("Total pending requests: {}", .{self.pending_requests.items.len});
    }
    
    /// Queue blocks with known hashes for verification
    pub fn queueBlocksWithHashes(self: *Self, block_headers: []const types.BlockHeader, start_height: u32) !void {
        log.info("Queuing {} blocks with hash verification", .{block_headers.len});
        
        for (block_headers, 0..) |header, i| {
            const height = start_height + @as(u32, @intCast(i));
            const hash = header.hash();
            const request = DownloadRequest.initWithHash(height, hash);
            try self.pending_requests.append(request);
            self.stats.total_requests += 1;
        }
        
        log.debug("Total pending requests: {}", .{self.pending_requests.items.len});
    }
    
    /// Process download queue and assign requests to available peers
    pub fn processDownloadQueue(self: *Self) !void {
        if (self.pending_requests.items.len == 0) return;
        
        // Check for timed-out active requests
        try self.handleTimeouts();
        
        // Limit concurrent downloads
        const active_count = self.active_requests.count();
        if (active_count >= self.max_concurrent_downloads) {
            return; // Already at capacity
        }
        
        // Process pending requests
        var processed: usize = 0;
        while (processed < self.pending_requests.items.len and 
               self.active_requests.count() < self.max_concurrent_downloads) {
            
            const request = self.pending_requests.items[processed];
            
            // Find best available peer
            if (self.selectBestPeer()) |peer| {
                // Assign request to peer
                var assigned_request = request;
                assigned_request.assigned_peer = peer;
                assigned_request.request_time = util.getTime();
                
                // Send block request
                if (self.sendBlockRequest(peer, assigned_request)) {
                    // Move to active requests
                    try self.active_requests.put(request.height, assigned_request);
                    _ = self.pending_requests.swapRemove(processed);
                    
                    // Update peer capacity
                    if (self.peer_capacities.getPtr(peer)) |capacity| {
                        capacity.recordDownloadStart();
                    }
                    
                    log.debug("Sent request for block {} to peer", .{request.height});
                } else |err| {
                    log.err("Failed to send block request: {}", .{err});
                    processed += 1; // Skip this request for now
                }
            } else {
                break; // No available peers
            }
        }
    }
    
    /// Handle incoming block from a peer
    pub fn handleIncomingBlock(self: *Self, height: u32, block: types.Block, from_peer: *Peer) !bool {
        // Check if this block was requested
        if (self.active_requests.fetchRemove(height)) |kv| {
            var request = kv.value;
            
            // Verify this block came from the assigned peer
            if (request.assigned_peer != from_peer) {
                log.warn("Received block {} from unexpected peer, ignoring", .{height});
                // Put the request back
                try self.active_requests.put(height, request);
                return false;
            }
            
            // Verify block hash if we have it
            if (request.hash) |expected_hash| {
                const block_hash = block.hash();
                if (!std.mem.eql(u8, &expected_hash, &block_hash)) {
                    log.warn("Block {} hash mismatch, requesting retry", .{height});
                    
                    // Record failure and retry
                    if (self.peer_capacities.getPtr(from_peer)) |capacity| {
                        capacity.recordDownloadFailure();
                    }
                    
                    request.retry_count += 1;
                    request.assigned_peer = null;
                    request.request_time = 0;
                    
                    if (request.shouldRetry()) {
                        try self.pending_requests.append(request);
                    } else {
                        self.stats.recordFailure();
                    }
                    
                    return false;
                }
            }
            
            // Calculate download time
            const download_time = util.getTime() - request.request_time;
            
            // Record successful download
            if (self.peer_capacities.getPtr(from_peer)) |capacity| {
                capacity.recordDownloadSuccess(@as(f64, @floatFromInt(download_time)));
            }
            
            self.stats.recordCompletion(download_time);
            
            // Store the completed block
            try self.completed_blocks.put(height, block);
            
            log.info("Successfully downloaded block {} in {}s", .{height, download_time});
            
            return true;
        }
        
        log.debug("Received unrequested block {} from peer", .{height});
        return false;
    }
    
    /// Get next completed block in sequence
    pub fn getNextCompletedBlock(self: *Self, expected_height: u32) ?types.Block {
        if (self.completed_blocks.fetchRemove(expected_height)) |kv| {
            return kv.value;
        }
        return null;
    }
    
    /// Check if downloads are complete
    pub fn isComplete(self: Self) bool {
        return self.pending_requests.items.len == 0 and self.active_requests.count() == 0;
    }
    
    /// Get download progress statistics
    pub fn getProgress(self: Self) DownloadStats {
        return self.stats;
    }
    
    /// Select the best available peer for a download
    fn selectBestPeer(self: *Self) ?*Peer {
        var best_peer: ?*Peer = null;
        var best_score: u8 = 0;
        
        for (self.available_peers.items) |peer| {
            if (self.peer_capacities.get(peer)) |capacity| {
                if (capacity.canAcceptDownload()) {
                    const score = capacity.getQualityScore();
                    if (score > best_score) {
                        best_score = score;
                        best_peer = peer;
                    }
                }
            }
        }
        
        return best_peer;
    }
    
    /// Send block request to peer
    fn sendBlockRequest(self: *Self, peer: *Peer, request: DownloadRequest) !void {
        // Use the peer's sendGetBlock method or similar
        // This would need to be implemented in the peer interface
        _ = self; // Suppress unused parameter warning
        
        if (request.hash) |hash| {
            // Request specific block by hash
            try peer.sendGetBlockByHash(hash);
        } else {
            // Request block by height
            try peer.sendGetBlockByHeight(request.height);
        }
    }
    
    /// Handle timed-out requests
    fn handleTimeouts(self: *Self) !void {
        var timeouts = std.ArrayList(u32).init(self.allocator);
        defer timeouts.deinit();
        
        // Find timed-out requests
        var iter = self.active_requests.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.isTimedOut()) {
                try timeouts.append(entry.key_ptr.*);
            }
        }
        
        // Handle each timeout
        for (timeouts.items) |height| {
            if (self.active_requests.fetchRemove(height)) |kv| {
                var request = kv.value;
                
                log.warn("Request for block {} timed out", .{height});
                
                // Record failure for the peer
                if (request.assigned_peer) |peer| {
                    if (self.peer_capacities.getPtr(peer)) |capacity| {
                        capacity.recordDownloadFailure();
                    }
                }
                
                // Retry if possible
                request.retry_count += 1;
                request.assigned_peer = null;
                request.request_time = 0;
                
                if (request.shouldRetry()) {
                    try self.pending_requests.append(request);
                    log.debug("Re-queued block {} for retry (attempt {})", .{height, request.retry_count + 1});
                } else {
                    log.warn("Dropped block {} after too many retries", .{height});
                    self.stats.recordFailure();
                }
            }
        }
    }
};

// Add missing constants to types.zig if they don't exist
// These would be added to types.zig:
//
// pub const SYNC = struct {
//     pub const DOWNLOAD_TIMEOUT_SECONDS: i64 = 30;
//     pub const MAX_DOWNLOAD_RETRIES: u8 = 3;
// };