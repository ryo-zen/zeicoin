// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// fork_detector.zig - Fork point detection using binary search
// Critical component for blockchain reorganization

const std = @import("std");
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const util = @import("../util/util.zig");
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
        var our_block = database.getBlock(std.Io.Threaded.global_single_threaded.ioBasic(), mid) catch |err| {
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
pub fn requestBlockHashAtHeight(peer: *Peer, height: u32) !types.BlockHash {
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
        const start_time = @as(u64, @intCast(util.getTime())) * 1000;

        while (true) {
            // Check for timeout
            const elapsed = @as(u64, @intCast(util.getTime())) * 1000 - start_time;
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

                log.debug("✅ [FORK POINT] Received hash for height {}: {x}", .{
                    height,
                    response.hash,
                });

                return response.hash;
            }

            // Sleep briefly before checking again
            const io = std.Io.Threaded.global_single_threaded.ioBasic();
            io.sleep(std.Io.Duration.fromMilliseconds(10), std.Io.Clock.awake) catch {}; // Sleep 10ms between checks
        }

        // Add backoff before retry
        if (attempt < max_retries - 1) {
            const io = std.Io.Threaded.global_single_threaded.ioBasic();
            io.sleep(std.Io.Duration.fromMilliseconds(500), std.Io.Clock.awake) catch {};
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
    our_height: u32,
    fork_point: u32,
    peer_blocks: []const types.Block,
) !bool {
    const peer_height = if (peer_blocks.len > 0) peer_blocks[peer_blocks.len - 1].height else fork_point;

    log.info("🔄 [REORG DECISION] Comparing chain work", .{});
    log.info("   Fork point: {}", .{fork_point});
    log.info("   Our blocks after fork: {}", .{our_height - fork_point});
    log.info("   Peer blocks after fork: {}", .{peer_blocks.len});
    log.info("   Peer tip height: {}", .{peer_height});

    // CRITICAL FIX: If fork_point == our_height, we are a prefix of the peer's chain.
    // We have 0 divergent work (our_work is 0), but this is NOT a reorg scenario.
    // We should just sync forward (append blocks) instead of triggering a heavy reorg.
    if (fork_point == our_height) {
        log.info("   Decision: Chain is prefix (fork_point == tip), sync forward ⛔", .{});
        return false;
    }

    // Calculate our cumulative work from fork point to tip
    const our_work = try calculateChainWork(allocator, database, fork_point + 1, our_height);

    // Calculate the peer chain work locally from the fetched competing branch.
    const peer_work = calculateFetchedChainWork(peer_blocks);

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

fn calculateFetchedChainWork(peer_blocks: []const types.Block) types.ChainWork {
    var total_work: types.ChainWork = 0;

    for (peer_blocks) |block| {
        total_work += block.header.getWork();
    }

    return total_work;
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
        var block = try database.getBlock(std.Io.Threaded.global_single_threaded.ioBasic(), height);
        defer block.deinit(allocator);

        const block_work = block.header.getWork();
        total_work += block_work;
    }

    return total_work;
}
