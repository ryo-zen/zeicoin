const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const headerchain = @import("headerchain.zig");
const net = @import("peer.zig");

const ZeiCoin = @import("../node.zig").ZeiCoin;

pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    is_syncing: bool,
    sync_peer: ?*net.Peer,
    target_height: u32,

    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) SyncManager {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .is_syncing = false,
            .sync_peer = null,
            .target_height = 0,
        };
    }

    pub fn deinit(self: *SyncManager) void {
        _ = self; // Suppress unused parameter warning
        // No owned fields to deinit yet
    }

    pub fn startSync(self: *SyncManager) !void {
        if (self.is_syncing) {
            std.debug.print("Sync already in progress.\n", .{});
            return;
        }

        // For now, pick a random peer. In future, more sophisticated peer selection.
        if (self.blockchain.network) |network| {
            if (network.getRandomPeer()) |peer| {
                self.sync_peer = peer;
                self.is_syncing = true;
                self.target_height = peer.start_height; // Assuming peer sends its height in version message

                std.debug.print("Starting sync with peer {s}:{} to height {}\n", .{ peer.address.ip, peer.address.port, self.target_height });

                // Request headers from our current height + 1 up to target height
                const our_height = try self.blockchain.getHeight();
                if (self.target_height > our_height) {
                    try peer.sendGetHeaders(our_height + 1, @min(self.target_height - our_height, 2000));
                } else {
                    std.debug.print("Already synced or ahead of peer.\n", .{});
                    self.is_syncing = false;
                }
            } else {
                std.debug.print("No connected peers to sync with.\n", .{});
            }
        } else {
            std.debug.print("Network not initialized.\n", .{});
        }
    }

    pub fn processIncomingHeaders(self: *SyncManager, headers: []types.BlockHeader, start_height: u32) !void {
        if (!self.is_syncing) {
            std.debug.print("Not in sync mode, ignoring headers.\n", .{});
            return;
        }

        std.debug.print("Processing {} headers starting from height {}\n", .{headers.len, start_height});

        var current_expected_height = start_height;
        for (headers) |header| {
            // Validate and add header to our header chain
            if (try self.blockchain.header_chain.validateHeader(header, current_expected_height)) {
                try self.blockchain.header_chain.addHeader(header, current_expected_height);
                current_expected_height += 1;
            } else {
                std.debug.print("Invalid header received at height {}. Aborting sync.\n", .{current_expected_height});
                self.is_syncing = false;
                return error.InvalidHeader;
            }
        }

        // Check if we have all headers
        if (self.blockchain.header_chain.getHeight() >= self.target_height) {
            std.debug.print("Headers sync complete. Starting block download.\n", .{});
            self.startBlockDownload() catch |err| {
                std.debug.print("Failed to start block download: {}\n", .{err});
                self.is_syncing = false;
            };
        } else {
            // Request next batch of headers
            const next_start_height = self.blockchain.header_chain.getHeight() + 1;
            const remaining_headers = self.target_height - next_start_height + 1;
            if (self.sync_peer) |peer| {
                try peer.sendGetHeaders(next_start_height, @min(remaining_headers, 2000));
            } else {
                std.debug.print("Sync peer disconnected. Aborting sync.\n", .{});
                self.is_syncing = false;
            }
        }
    }

    fn startBlockDownload(self: *SyncManager) !void {
        const our_current_height = try self.blockchain.getHeight();
        const header_chain_height = self.blockchain.header_chain.getHeight();

        // Queue all blocks we need to download
        for (our_current_height + 1..header_chain_height + 1) |height| {
            try self.blockchain.blocks_to_download.append(@intCast(height));
        }

        std.debug.print("Queued {} blocks for download.\n", .{self.blockchain.blocks_to_download.items.len});
        try self.downloadNextBlocks();
    }

    fn downloadNextBlocks(self: *SyncManager) !void {
        const max_concurrent_downloads = 5; // Limit concurrent downloads

        while (self.blockchain.active_block_downloads.count() < max_concurrent_downloads and
               self.blockchain.blocks_to_download.items.len > 0) {
            const height_to_download = self.blockchain.blocks_to_download.orderedRemove(0);

            if (self.sync_peer) |peer| {
                try peer.sendGetBlock(height_to_download);
                try self.blockchain.active_block_downloads.put(height_to_download, util.getTime());
                std.debug.print("Requested block {}\n", .{height_to_download});
            } else {
                std.debug.print("Sync peer disconnected. Cannot download blocks.\n", .{});
                self.is_syncing = false;
                return;
            }
        }

        if (self.blockchain.blocks_to_download.items.len == 0 and
            self.blockchain.active_block_downloads.count() == 0) {
            std.debug.print("All blocks downloaded. Sync complete.\n", .{});
            self.is_syncing = false;
            // Potentially trigger a final blockchain validation or state update here
        }
    }

    pub fn processIncomingBlock(self: *SyncManager, block: *types.Block) !void {
        if (!self.is_syncing) {
            std.debug.print("Not in sync mode, ignoring block.\n", .{});
            block.deinit(self.allocator); // Ensure block memory is freed
            return;
        }

        const block_hash = block.hash();
        const expected_height = self.blockchain.header_chain.hash_to_height.get(block_hash) orelse {
            std.debug.print("Received unexpected block (hash not in header chain). Aborting sync.\n", .{});
            block.deinit(self.allocator);
            self.is_syncing = false;
            return error.UnexpectedBlock;
        };

        std.debug.print("Processing incoming block {} (hash: {s})\n", .{expected_height, std.fmt.fmtSliceHexLower(block_hash[0..8])});

        // Validate the block against the header chain and our current state
        // This is a simplified validation for sync. Full validation happens when adding to main chain.
        if (try self.blockchain.validateSyncBlock(block.*, expected_height)) {
            // Remove from active downloads
            _ = self.blockchain.active_block_downloads.remove(expected_height);

            // Add block to blockchain
            try self.blockchain.addBlockToChain(block.*, expected_height);

            // Continue downloading next blocks
            try self.downloadNextBlocks();
        } else {
            std.debug.print("Invalid block received at height {}. Aborting sync.\n", .{expected_height});
            block.deinit(self.allocator);
            self.is_syncing = false;
            return error.InvalidBlock;
        }

    }

    pub fn handleFailedDownload(self: *SyncManager, height: u32) !void {
        std.debug.print("Block download failed for height {}. Re-queueing.\n", .{height});
        // Simple retry: re-add to the end of the queue
        try self.blockchain.blocks_to_download.append(height);
        self.blockchain.active_block_downloads.remove(height);
        try self.downloadNextBlocks();
    }
};