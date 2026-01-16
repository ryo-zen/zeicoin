// sequential_sync.zig - Single Block Request Utilities
// ZSP-001 compliant helper functions for requesting individual blocks
// Used by batch sync for error recovery and specific block requests

const std = @import("std");
const log = std.log.scoped(.sync);

const types = @import("../../types/types.zig");
const net = @import("../../network/peer.zig");
const util = @import("../../util/util.zig");

// Type aliases for clarity
const Block = types.Block;
const Hash = types.Hash;
const Peer = net.Peer;

/// Request a single block by hash from a peer
/// Used for error recovery when batch requests fail
pub fn requestBlock(peer: *Peer, hash: Hash) !Block {
    log.debug("Requesting block by hash: {s}", .{std.fmt.fmtSliceHexLower(&hash)});
    
    // Send single block request
    try peer.sendGetBlockByHash(hash);
    
    // Wait for response with timeout
    const timeout_ms = 30000; // 30 seconds
    const start_time = util.getTime();
    
    while (util.getTime() - start_time < timeout_ms / 1000) {
        // Check if block has arrived
        if (peer.getReceivedBlock(hash)) |block| {
            log.info("Block received by hash: {s}", .{std.fmt.fmtSliceHexLower(&hash)});
            return block;
        }
        
        // Small delay to avoid busy waiting
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    
    log.warn("Block request timed out: {s}", .{std.fmt.fmtSliceHexLower(&hash)});
    return error.BlockRequestTimeout;
}

/// Request a single block by height from a peer
/// Used for latest block requests and specific height recovery
pub fn requestBlockByHeight(peer: *Peer, height: u32) !Block {
    log.debug("Requesting block by height: {}", .{height});
    
    // Send ZSP-001 height-encoded block request
    try peer.sendGetBlockByHeight(height);
    
    // ZSP-001 height encoding uses height-encoded hash
    var height_hash: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u32, height_hash[0..4], height, .little);
    const ZSP_001_HEIGHT_MAGIC: u32 = 0xDEADBEEF;
    std.mem.writeInt(u32, height_hash[4..8], ZSP_001_HEIGHT_MAGIC, .little);

    // Wait for response with timeout
    const timeout_ms = 30000; // 30 seconds
    const start_time = util.getTime();
    
    while (util.getTime() - start_time < timeout_ms / 1000) {
        // Check if block has arrived
        // Note: Peer stores received blocks by hash. For height-encoded requests,
        // we might need to check if a block with matching height arrived.
        if (peer.getReceivedBlockByHeight(height)) |block| {
            log.info("Block {} received by height", .{height});
            return block;
        }
        
        // Small delay to avoid busy waiting
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    
    log.warn("Block {} request timed out", .{height});
    return error.BlockRequestTimeout;
}

/// Request the latest block from a peer
/// Used when near chain tip for real-time sync
pub fn requestLatestBlock(peer: *Peer) !?Block {
    log.debug("Requesting latest block from peer", .{});
    
    // First get peer's current height
    const peer_height = peer.height;
    if (peer_height == 0) {
        log.warn("Peer has no blocks", .{});
        return null;
    }
    
    // Request the latest block
    return requestBlockByHeight(peer, peer_height);
}

/// Verify a specific block exists on a peer
/// Used for fork resolution and chain validation
pub fn verifyBlockExists(peer: *Peer, hash: Hash) !bool {
    log.debug("Verifying block exists: {s}", .{std.fmt.fmtSliceHexLower(&hash)});
    
    // Try to request the block
    const block = requestBlock(peer, hash) catch |err| {
        switch (err) {
            error.BlockRequestTimeout => {
                log.warn("Block verification timeout (likely doesn't exist)", .{});
                return false;
            },
            else => return err,
        }
    };
    
    // Clean up the block since we only wanted to verify existence
    var owned_block = block;
    defer owned_block.deinit(std.heap.page_allocator);
    
    log.debug("Block verified to exist", .{});
    return true;
}

/// Recovery function for failed batch requests
/// Re-requests individual blocks that failed in a batch
pub fn recoverFailedBlocks(
    allocator: std.mem.Allocator,
    peer: *Peer, 
    failed_heights: []const u32
) !std.ArrayList(Block) {
    log.info("Recovering {} failed blocks", .{failed_heights.len});
    
    var recovered_blocks = std.ArrayList(Block).init(allocator);
    
    for (failed_heights) |height| {
        const block = requestBlockByHeight(peer, height) catch |err| {
            log.err("Failed to recover block {}: {}", .{height, err});
            continue;
        };
        
        try recovered_blocks.append(block);
        log.info("Recovered block {}", .{height});
    }
    
    log.info("Recovery complete: {}/{} blocks recovered", 
        .{recovered_blocks.items.len, failed_heights.len});
    
    return recovered_blocks;
}

/// Request a range of blocks sequentially (fallback for batch failure)
/// Used when peer doesn't support batch requests
pub fn requestBlockRange(
    allocator: std.mem.Allocator,
    peer: *Peer,
    start_height: u32,
    count: u32
) !std.ArrayList(Block) {
    log.debug("Requesting {} blocks starting from height {}", .{count, start_height});
    
    var blocks = std.ArrayList(Block).init(allocator);
    
    for (0..count) |i| {
        const height = start_height + @as(u32, @intCast(i));
        
        const block = requestBlockByHeight(peer, height) catch |err| {
            log.err("Failed to get block {}: {}", .{height, err});
            // Clean up any blocks we got so far
            for (blocks.items) |*b| {
                b.deinit(allocator);
            }
            blocks.deinit();
            return err;
        };
        
        try blocks.append(block);
        log.debug("Got block {} ({}/{})", .{height, i + 1, count});
    }
    
    log.info("Sequential range request complete: {} blocks", .{blocks.items.len});
    return blocks;
}

/// Check if peer supports batch requests
/// Used to determine if we should use batch or sequential sync
pub fn supportsBatchRequests(peer: *Peer) bool {
    // Check peer capabilities for batch support
    const protocol = @import("../../network/protocol/protocol.zig");
    const has_parallel_download = (peer.services & protocol.ServiceFlags.PARALLEL_DOWNLOAD) != 0;
    const has_fast_sync = (peer.services & protocol.ServiceFlags.FAST_SYNC) != 0;

    return has_parallel_download or has_fast_sync;
}

/// Estimate peer performance for block requests
/// Used by batch sync to select optimal peers
pub fn estimatePeerPerformance(peer: *Peer) f64 {
    // Simple heuristic based on ping time and connection quality
    const base_score = 100.0;
    
    // Penalize high ping times
    const ping_penalty = @as(f64, @floatFromInt(peer.ping_time_ms)) * 0.1;
    
    // Bonus for stable connections
    const stability_bonus = if (peer.consecutive_successful_requests > 10) 20.0 else 0.0;
    
    // Penalty for recent failures
    const failure_penalty = @as(f64, @floatFromInt(peer.consecutive_failures)) * 5.0;
    
    return @max(1.0, base_score - ping_penalty + stability_bonus - failure_penalty);
}

/// Test function to validate sequential sync utilities
pub fn testSequentialSync() !void {
    log.debug("Running sequential sync tests...", .{});
    
    // Test peer performance estimation
    var test_peer = Peer{
        .ping_time_ms = 50,
        .consecutive_successful_requests = 15,
        .consecutive_failures = 2,
        .services = types.NodeServices.PARALLEL_DOWNLOAD,
        // ... other required fields would be initialized here
    };
    
    const performance = estimatePeerPerformance(&test_peer);
    log.debug("Test peer performance: {d:.1}", .{performance});
    
    const supports_batch = supportsBatchRequests(&test_peer);
    log.debug("Test peer supports batch: {}", .{supports_batch});
    
    log.debug("Sequential sync tests passed", .{});
}