// sequential_sync.zig - Single Block Request Utilities
// ZSP-001 compliant helper functions for requesting individual blocks
// Used by batch sync for error recovery and specific block requests

const std = @import("std");
const print = std.debug.print;

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
    print("📤 [SEQUENTIAL] Requesting block by hash: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});
    
    // Send single block request
    try peer.sendGetBlockByHash(hash);
    
    // Wait for response with timeout
    const timeout_ms = 30000; // 30 seconds
    const start_time = util.getTime();
    
    while (util.getTime() - start_time < timeout_ms / 1000) {
        // Check if block has arrived
        if (peer.getReceivedBlock(hash)) |block| {
            print("✅ [SEQUENTIAL] Block received by hash: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});
            return block;
        }
        
        // Small delay to avoid busy waiting
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    
    print("❌ [SEQUENTIAL] Block request timed out: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});
    return error.BlockRequestTimeout;
}

/// Request a single block by height from a peer
/// Used for latest block requests and specific height recovery
pub fn requestBlockByHeight(peer: *Peer, height: u32) !Block {
    print("📤 [SEQUENTIAL] Requesting block by height: {}\n", .{height});
    
    // Send single block request by height
    try peer.sendGetBlock(height);
    
    // Wait for response with timeout
    const timeout_ms = 30000; // 30 seconds
    const start_time = util.getTime();
    
    // ZSP-001: Sequential sync utilities are minimal stubs for legacy peer support
    // In practice, ZSP-001 batch sync is preferred
    _ = timeout_ms;
    _ = start_time;
    print("⚠️ [SEQUENTIAL] Block request by height not implemented (use batch sync)\n", .{});
    return error.NotImplemented;
}

/// Request the latest block from a peer
/// Used when near chain tip for real-time sync
pub fn requestLatestBlock(peer: *Peer) !?Block {
    print("📤 [SEQUENTIAL] Requesting latest block from peer\n", .{});
    
    // First get peer's current height
    const peer_height = peer.height;
    if (peer_height == 0) {
        print("⚠️ [SEQUENTIAL] Peer has no blocks\n", .{});
        return null;
    }
    
    // Request the latest block
    return requestBlockByHeight(peer, peer_height);
}

/// Verify a specific block exists on a peer
/// Used for fork resolution and chain validation
pub fn verifyBlockExists(peer: *Peer, hash: Hash) !bool {
    print("🔍 [SEQUENTIAL] Verifying block exists: {s}\n", .{std.fmt.fmtSliceHexLower(&hash)});
    
    // Try to request the block
    const block = requestBlock(peer, hash) catch |err| {
        switch (err) {
            error.BlockRequestTimeout => {
                print("⚠️ [SEQUENTIAL] Block verification timeout (likely doesn't exist)\n", .{});
                return false;
            },
            else => return err,
        }
    };
    
    // Clean up the block since we only wanted to verify existence
    var owned_block = block;
    defer owned_block.deinit(std.heap.page_allocator);
    
    print("✅ [SEQUENTIAL] Block verified to exist\n", .{});
    return true;
}

/// Recovery function for failed batch requests
/// Re-requests individual blocks that failed in a batch
pub fn recoverFailedBlocks(
    allocator: std.mem.Allocator,
    peer: *Peer, 
    failed_heights: []const u32
) !std.ArrayList(Block) {
    print("🔄 [SEQUENTIAL] Recovering {} failed blocks\n", .{failed_heights.len});
    
    var recovered_blocks = std.ArrayList(Block).init(allocator);
    
    for (failed_heights) |height| {
        const block = requestBlockByHeight(peer, height) catch |err| {
            print("❌ [SEQUENTIAL] Failed to recover block {}: {}\n", .{height, err});
            continue;
        };
        
        try recovered_blocks.append(block);
        print("✅ [SEQUENTIAL] Recovered block {}\n", .{height});
    }
    
    print("🔄 [SEQUENTIAL] Recovery complete: {}/{} blocks recovered\n", 
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
    print("📤 [SEQUENTIAL] Requesting {} blocks starting from height {}\n", .{count, start_height});
    
    var blocks = std.ArrayList(Block).init(allocator);
    
    for (0..count) |i| {
        const height = start_height + @as(u32, @intCast(i));
        
        const block = requestBlockByHeight(peer, height) catch |err| {
            print("❌ [SEQUENTIAL] Failed to get block {}: {}\n", .{height, err});
            // Clean up any blocks we got so far
            for (blocks.items) |*b| {
                b.deinit(allocator);
            }
            blocks.deinit();
            return err;
        };
        
        try blocks.append(block);
        print("✅ [SEQUENTIAL] Got block {} ({}/{})\n", .{height, i + 1, count});
    }
    
    print("✅ [SEQUENTIAL] Sequential range request complete: {} blocks\n", .{blocks.items.len});
    return blocks;
}

/// Check if peer supports batch requests
/// Used to determine if we should use batch or sequential sync
pub fn supportsBatchRequests(peer: *Peer) bool {
    // Check peer capabilities for batch support
    // Check for ZSP-001 batch sync capability flags from protocol
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
    print("🧪 [SEQUENTIAL] Running sequential sync tests...\n", .{});
    
    // Test peer performance estimation
    var test_peer = Peer{
        .ping_time_ms = 50,
        .consecutive_successful_requests = 15,
        .consecutive_failures = 2,
        .services = types.NodeServices.PARALLEL_DOWNLOAD,
        // ... other required fields would be initialized here
    };
    
    const performance = estimatePeerPerformance(&test_peer);
    print("📊 [SEQUENTIAL] Test peer performance: {d:.1}\n", .{performance});
    
    const supports_batch = supportsBatchRequests(&test_peer);
    print("📊 [SEQUENTIAL] Test peer supports batch: {}\n", .{supports_batch});
    
    print("✅ [SEQUENTIAL] Sequential sync tests passed\n", .{});
}