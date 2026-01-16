// fork_detector.zig - Fork point detection using binary search
// Critical component for blockchain reorganization

const std = @import("std");
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const Peer = @import("../network/peer.zig").Peer;

const log = std.log.scoped(.fork_detector);

/// Find the fork point between our chain and a peer's chain using binary search
/// Returns the height of the last common block
pub fn findForkPoint(
    allocator: std.mem.Allocator,
    database: *db.Database,
    peer: *Peer,
    our_height: u32,
    peer_height: u32,
) !u32 {
    log.info("🔍 [FORK POINT] Starting binary search", .{});
    log.info("   Our height: {}, Peer height: {}", .{ our_height, peer_height });

    var low: u32 = 0;
    var high: u32 = @min(our_height, peer_height);
    var fork_point: u32 = 0;

    while (low <= high) {
        const mid = (low + high) / 2;

        // Get our block hash at height mid
        var our_block = database.getBlock(mid) catch |err| {
            log.warn("❌ [FORK POINT] Failed to get our block at height {}: {}", .{ mid, err });
            return error.DatabaseError;
        };
        defer our_block.deinit(allocator);
        const our_hash = our_block.hash();

        // Request peer's block hash at height mid
        const peer_hash = try requestBlockHashAtHeight(peer, mid);

        if (std.mem.eql(u8, &our_hash, &peer_hash)) {
            // Blocks match - fork is after this point
            fork_point = mid;
            low = mid + 1;
            log.debug("   ✅ Height {}: Blocks match, searching higher", .{mid});
        } else {
            // Blocks differ - fork is before this point
            if (mid == 0) {
                log.warn("❌ [FORK POINT] Genesis blocks differ! Incompatible chains.", .{});
                return error.IncompatibleChains;
            }
            high = mid - 1;
            log.debug("   ❌ Height {}: Blocks differ, searching lower", .{mid});
        }
    }

    log.info("📍 [FORK POINT] Found at height {}", .{fork_point});
    return fork_point;
}

/// Request block hash at specific height from peer
fn requestBlockHashAtHeight(peer: *Peer, height: u32) !types.BlockHash {
    const msg_types = @import("../network/protocol/messages/message_types.zig");

    // Retry configuration
    const max_retries = 3;
    var attempt: u32 = 0;

    while (attempt < max_retries) : (attempt += 1) {
        // Check connection before sending
        if (!peer.isConnected()) {
            log.warn("❌ [FORK POINT] Peer disconnected before request attempt {}", .{attempt + 1});
            return error.PeerDisconnected;
        }

        // Send GetBlockHash request
        const request = msg_types.GetBlockHashMessage{
            .height = height,
        };

        if (attempt > 0) {
            log.warn("⚠️ [FORK POINT] Retry attempt {}/{} for height {}", .{ attempt + 1, max_retries, height });
        } else {
            log.debug("📤 [FORK POINT] Requesting block hash at height {} from peer", .{height});
        }

        // Send the request
        _ = peer.sendMessage(.get_block_hash, request) catch |err| {
            log.warn("⚠️ [FORK POINT] Failed to send request: {}", .{err});
            // Don't return immediately, try to reconnect/retry if possible or just continue loop
            // But usually send failure means connection is dead.
            if (!peer.isConnected()) return error.PeerDisconnected;
            continue;
        };

        // Wait for response (with timeout)
        const timeout_ms: u64 = 5000; // 5 seconds per attempt (reduced from 15s to fail faster)
        const start_time = std.time.milliTimestamp();

        while (true) {
            // Check for timeout
            const elapsed = std.time.milliTimestamp() - start_time;
            if (elapsed > timeout_ms) {
                log.warn("⏱️ [FORK POINT] Timeout waiting for block hash at height {} (attempt {}/{})", .{ height, attempt + 1, max_retries });
                break; // Break inner loop to retry
            }

            // CRITICAL FIX: fail fast if peer disconnects
            if (!peer.isConnected()) {
                log.warn("❌ [FORK POINT] Peer disconnected while waiting for response", .{});
                return error.PeerDisconnected;
            }

            // Check if response is available in the peer's response queue
            if (peer.getBlockHashResponse(height)) |response| {
                // Clean up the response from the queue
                peer.removeBlockHashResponse(height);

                if (!response.exists) {
                    log.warn("❌ [FORK POINT] Peer doesn't have block at height {}", .{height});
                    // This is a definitive answer, don't retry
                    return error.BlockNotFound;
                }

                log.debug("✅ [FORK POINT] Received hash for height {}: {s}", .{
                    height,
                    std.fmt.fmtSliceHexLower(&response.hash),
                });

                return response.hash;
            }

            // Sleep briefly before checking again
            std.time.sleep(10 * std.time.ns_per_ms); // Sleep 10ms between checks
        }

        // Add backoff before retry
        if (attempt < max_retries - 1) {
             std.time.sleep(500 * std.time.ns_per_ms);
        }
    }

    log.warn("❌ [FORK POINT] All retry attempts failed for height {}", .{height});
    return error.Timeout;
}

/// Compare two chains using cumulative proof-of-work
/// Returns true if we should reorganize to the peer's chain
pub fn shouldReorganize(
    allocator: std.mem.Allocator,
    database: *db.Database,
    peer: *Peer,
    our_height: u32,
    peer_height: u32,
    fork_point: u32,
) !bool {
    log.info("🔄 [REORG DECISION] Comparing chain work", .{});
    log.info("   Fork point: {}", .{fork_point});
    log.info("   Our blocks after fork: {}", .{our_height - fork_point});
    log.info("   Peer blocks after fork: {}", .{peer_height - fork_point});

    // CRITICAL FIX: If fork_point == our_height, we are a prefix of the peer's chain.
    // We have 0 divergent work (our_work is 0), but this is NOT a reorg scenario.
    // We should just sync forward (append blocks) instead of triggering a heavy reorg.
    if (fork_point == our_height) {
        log.info("   Decision: Chain is prefix (fork_point == tip), sync forward ⛔", .{});
        return false;
    }

    // Calculate our cumulative work from fork point to tip
    const our_work = try calculateChainWork(allocator, database, fork_point + 1, our_height);

    // Request peer's cumulative work from fork point to tip
    const peer_work = try requestChainWork(peer, fork_point + 1, peer_height);

    log.info("   Our cumulative work:  {}", .{our_work});
    log.info("   Peer cumulative work: {}", .{peer_work});

    // Compare cumulative proof-of-work (NOT just height!)
    if (peer_work > our_work) {
        log.info("   Decision: REORGANIZE to peer chain ✅", .{});
        return true;
    }

    log.info("   Decision: Keep our chain ⛔", .{});
    return false;
}

/// Calculate cumulative chain work for a range of blocks
fn calculateChainWork(
    allocator: std.mem.Allocator,
    database: *db.Database,
    start_height: u32,
    end_height: u32,
) !types.ChainWork {
    var total_work: types.ChainWork = 0;

    var height = start_height;
    while (height <= end_height) : (height += 1) {
        var block = try database.getBlock(height);
        defer block.deinit(allocator);

        const block_work = block.header.getWork();
        total_work += block_work;
    }

    return total_work;
}

/// Request cumulative chain work from peer for a range of blocks
fn requestChainWork(peer: *Peer, start_height: u32, end_height: u32) !types.ChainWork {
    const msg_types = @import("../network/protocol/messages/message_types.zig");

    // Retry configuration
    const max_retries = 3;
    var attempt: u32 = 0;

    while (attempt < max_retries) : (attempt += 1) {
        // Check connection
        if (!peer.isConnected()) return error.PeerDisconnected;

        // Send GetChainWork request
        const request = msg_types.GetChainWorkMessage{
            .start_height = start_height,
            .end_height = end_height,
        };

        if (attempt > 0) {
            log.warn("⚠️ [CHAIN WORK] Retry attempt {}/{}", .{ attempt + 1, max_retries });
        } else {
            log.debug("📤 [CHAIN WORK] Requesting work from height {} to {} from peer", .{ start_height, end_height });
        }

        // Send the request
        _ = peer.sendMessage(.get_chain_work, request) catch |err| {
            log.warn("⚠️ [CHAIN WORK] Failed to send request: {}", .{err});
            if (!peer.isConnected()) return error.PeerDisconnected;
            continue;
        };

        // Wait for response
        const timeout_ms: u64 = 10000; // 10 seconds for work calculation
        const start_time = std.time.milliTimestamp();

        while (true) {
            // Check for timeout
            const elapsed = std.time.milliTimestamp() - start_time;
            if (elapsed > timeout_ms) {
                log.warn("⏱️ [CHAIN WORK] Timeout waiting for chain work response (attempt {}/{})", .{ attempt + 1, max_retries });
                break; // Retry
            }

            // CRITICAL FIX: fail fast
            if (!peer.isConnected()) return error.PeerDisconnected;

            // Check if response is available in the peer's response queue
            if (peer.getChainWorkResponse()) |work| {
                log.debug("✅ [CHAIN WORK] Received work: {}", .{work});
                return work;
            }

            // Sleep briefly before checking again
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        // Backoff
        if (attempt < max_retries - 1) {
             std.time.sleep(500 * std.time.ns_per_ms);
        }
    }

    log.warn("❌ [CHAIN WORK] All retry attempts failed", .{});
    return error.Timeout;
}
