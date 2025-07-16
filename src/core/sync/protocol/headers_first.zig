// headers_first.zig - Headers-First Sync Protocol Implementation
// Extracted from node.zig for clean modular architecture
// Handles efficient blockchain synchronization by downloading headers first, then blocks

const std = @import("std");
const ArrayList = std.ArrayList;
const print = std.debug.print;

const types = @import("../../types/types.zig");
const util = @import("../../util/util.zig");
const net = @import("../../network/peer.zig");
const headerchain = @import("../../network/headerchain.zig");

// Type aliases for clarity
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;

/// Progress tracking for headers-first synchronization
pub const HeadersProgress = struct {
    target_height: u32,
    current_height: u32,
    headers_downloaded: u32,
    start_time: i64,
    last_header_time: i64,
    
    pub fn init(current: u32, target: u32) HeadersProgress {
        const now = util.getTime();
        return .{
            .target_height = target,
            .current_height = current,
            .headers_downloaded = 0,
            .start_time = now,
            .last_header_time = now,
        };
    }
    
    pub fn getProgress(self: *const HeadersProgress) f64 {
        if (self.target_height <= self.current_height) return 100.0;
        const total = self.target_height - self.current_height;
        if (total == 0) return 100.0;
        return (@as(f64, @floatFromInt(self.headers_downloaded)) / @as(f64, @floatFromInt(total))) * 100.0;
    }
    
    pub fn getHeadersPerSecond(self: *const HeadersProgress) f64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0) return 0.0;
        return @as(f64, @floatFromInt(self.headers_downloaded)) / @as(f64, @floatFromInt(elapsed));
    }
};

/// Synchronization state for headers-first protocol
pub const SyncState = enum {
    synced,        // Up to date with peers
    syncing,       // Currently downloading blocks
    sync_complete, // Sync completed, ready to switch to synced
    sync_failed,   // Sync failed, will retry later
};

/// Dependency injection interface for HeadersFirstProtocol
pub const ProtocolDependencies = struct {
    /// Get current blockchain height
    getHeightFn: *const fn(ctx: *anyopaque) anyerror!u32,
    
    /// Process a downloaded block during sync
    handleSyncBlockFn: *const fn(ctx: *anyopaque, height: u32, block: Block) anyerror!void,
    
    /// Get network manager for peer communication
    getNetworkFn: *const fn(ctx: *anyopaque) ?*net.NetworkManager,
    
    /// Context pointer for dependency functions
    context: *anyopaque,
    
    /// Allocator for memory management
    allocator: std.mem.Allocator,
};

/// Headers-First Sync Protocol implementation
pub const HeadersFirstProtocol = struct {
    // Dependencies
    deps: ProtocolDependencies,
    
    // State tracking
    sync_state: SyncState,
    sync_peer: ?*net.Peer,
    headers_progress: ?HeadersProgress,
    
    // Header chain for validation
    header_chain: ?*headerchain.HeaderChain,
    
    // Block download management
    blocks_to_download: ArrayList(u32),
    active_block_downloads: std.AutoHashMap(u32, i64), // height -> timestamp
    
    const Self = @This();
    
    /// Initialize headers-first protocol with dependencies
    pub fn init(deps: ProtocolDependencies) Self {
        return .{
            .deps = deps,
            .sync_state = .synced,
            .sync_peer = null,
            .headers_progress = null,
            .header_chain = null,
            .blocks_to_download = ArrayList(u32).init(deps.allocator),
            .active_block_downloads = std.AutoHashMap(u32, i64).init(deps.allocator),
        };
    }
    
    /// Clean up resources
    pub fn deinit(self: *Self) void {
        self.blocks_to_download.deinit();
        self.active_block_downloads.deinit();
        if (self.header_chain) |chain| {
            chain.deinit();
            self.deps.allocator.destroy(chain);
        }
    }
    
    /// Start headers-first sync with a peer
    pub fn startHeadersSync(self: *Self, peer: *net.Peer, target_height: u32) !void {
        const current_height = try self.deps.getHeightFn(self.deps.context);
        
        if (target_height <= current_height) {
            logInfo("Already up to date (height {})", .{current_height});
            return;
        }
        
        logProcess("Starting headers-first sync: {} -> {} ({} blocks behind)", .{
            current_height, target_height, target_height - current_height
        });
        
        // Initialize header chain
        try self.initHeaderChain();
        
        // Initialize sync state
        self.sync_state = .syncing;
        self.headers_progress = HeadersProgress.init(current_height, target_height);
        self.sync_peer = peer;
        
        // Request first batch of headers
        peer.sendGetHeaders(current_height + 1, types.HEADERS_SYNC.HEADERS_BATCH_SIZE) catch |err| {
            logError("Failed to request headers: {}", .{err});
            self.failSync("Failed to request headers");
        };
    }
    
    /// Complete headers-first sync
    pub fn completeHeadersSync(self: *Self) void {
        logSuccess("Headers-first sync completed!", .{});
        
        if (self.headers_progress) |progress| {
            const elapsed = util.getTime() - progress.start_time;
            const headers_per_sec = progress.getHeadersPerSecond();
            logInfo("Downloaded {} headers in {}s ({:.2} headers/sec)", .{
                progress.headers_downloaded, elapsed, headers_per_sec
            });
        }
        
        // Clean up
        self.headers_progress = null;
        if (self.header_chain) |chain| {
            chain.deinit();
            self.deps.allocator.destroy(chain);
            self.header_chain = null;
        }
        
        self.sync_state = .synced;
    }
    
    /// Start downloading blocks after headers are validated
    pub fn startBlockDownloads(self: *Self) !void {
        const current_block_height = try self.deps.getHeightFn(self.deps.context);
        
        if (self.header_chain == null) {
            logError("Header chain not initialized", .{});
            return error.HeaderChainNotInitialized;
        }
        
        const header_height = self.header_chain.?.validated_height;
        
        if (current_block_height >= header_height) {
            logInfo("Already have all blocks", .{});
            self.completeHeadersSync();
            return;
        }
        
        // Queue blocks for download
        self.blocks_to_download.clearRetainingCapacity();
        for (current_block_height + 1..header_height + 1) |height| {
            try self.blocks_to_download.append(@intCast(height));
        }
        
        logInfo("Queued {} blocks for download", .{self.blocks_to_download.items.len});
        
        // Start parallel downloads
        try self.requestNextBlocks();
    }
    
    /// Request next batch of blocks in parallel
    pub fn requestNextBlocks(self: *Self) !void {
        const network = self.deps.getNetworkFn(self.deps.context);
        if (network == null) return;
        
        const net_manager = network.?;
        const now = util.getTime();
        
        // Clean up timed out downloads
        var iter = self.active_block_downloads.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.* > types.HEADERS_SYNC.BLOCK_DOWNLOAD_TIMEOUT) {
                // Re-queue timed out block
                try self.blocks_to_download.append(entry.key_ptr.*);
                _ = self.active_block_downloads.remove(entry.key_ptr.*);
                logError("Block {} download timed out, re-queuing", .{entry.key_ptr.*});
            }
        }
        
        // Start new downloads up to concurrent limit
        while (self.active_block_downloads.count() < types.HEADERS_SYNC.MAX_CONCURRENT_DOWNLOADS and
               self.blocks_to_download.items.len > 0) {
            
            const height = self.blocks_to_download.orderedRemove(0);
            
            // Find available peer
            var sent = false;
            for (net_manager.peers.items) |*peer| {
                if (peer.state == .connected) {
                    peer.sendGetBlock(height) catch continue;
                    try self.active_block_downloads.put(height, now);
                    logProcess("Requested block {}", .{height});
                    sent = true;
                    break;
                }
            }
            
            if (!sent) {
                // No peers available, re-queue
                try self.blocks_to_download.insert(0, height);
                break;
            }
        }
    }
    
    /// Process a downloaded block during headers-first sync
    pub fn processDownloadedBlock(self: *Self, block: Block, height: u32) !void {
        // Verify block matches expected header
        if (self.header_chain) |chain| {
            const expected_header = chain.getHeader(height);
            if (expected_header == null or !std.mem.eql(u8, &block.header.hash(), &expected_header.?.hash())) {
                logError("Block header mismatch at height {}", .{height});
                return error.BlockHeaderMismatch;
            }
        }
        
        // Process the block using dependency injection
        try self.deps.handleSyncBlockFn(self.deps.context, height, block);
        
        // Remove from active downloads
        _ = self.active_block_downloads.remove(height);
        
        // Request more blocks
        try self.requestNextBlocks();
        
        // Check if sync is complete
        if (self.blocks_to_download.items.len == 0 and self.active_block_downloads.count() == 0) {
            self.completeHeadersSync();
        }
    }
    
    /// Initialize header chain for validation
    pub fn initHeaderChain(self: *Self) !void {
        if (self.header_chain == null) {
            const chain = try self.deps.allocator.create(headerchain.HeaderChain);
            chain.* = headerchain.HeaderChain.init(self.deps.allocator);
            self.header_chain = chain;
        }
    }
    
    /// Fail sync operation with reason
    pub fn failSync(self: *Self, reason: []const u8) void {
        logError("Sync failed: {s}", .{reason});
        self.sync_state = .sync_failed;
        self.headers_progress = null;
        self.sync_peer = null;
    }
    
    /// Get current sync state
    pub fn getSyncState(self: *const Self) SyncState {
        return self.sync_state;
    }
    
    /// Get headers progress information
    pub fn getHeadersProgress(self: *const Self) ?HeadersProgress {
        return self.headers_progress;
    }
    
    /// Check if currently syncing
    pub fn isSyncing(self: *const Self) bool {
        return self.sync_state == .syncing;
    }
    
    /// Get sync peer
    pub fn getSyncPeer(self: *const Self) ?*net.Peer {
        return self.sync_peer;
    }
    
    /// Get number of blocks queued for download
    pub fn getBlocksDownload(self: *const Self) usize {
        return self.blocks_to_download.items.len;
    }
    
    /// Get number of active block downloads
    pub fn getActiveDownloads(self: *const Self) usize {
        return self.active_block_downloads.count();
    }
};

// Logging functions for clean output
fn logError(comptime fmt: []const u8, args: anytype) void {
    print("❌ " ++ fmt ++ "\n", args);
}

fn logSuccess(comptime fmt: []const u8, args: anytype) void {
    print("✅ " ++ fmt ++ "\n", args);
}

fn logInfo(comptime fmt: []const u8, args: anytype) void {
    print("ℹ️  " ++ fmt ++ "\n", args);
}

fn logProcess(comptime fmt: []const u8, args: anytype) void {
    print("🔄 " ++ fmt ++ "\n", args);
}

// Tests
test "HeadersProgress calculation" {
    const progress = HeadersProgress.init(100, 200);
    try std.testing.expectEqual(@as(f64, 0.0), progress.getProgress());
    
    var mutable_progress = progress;
    mutable_progress.headers_downloaded = 50;
    try std.testing.expectEqual(@as(f64, 50.0), mutable_progress.getProgress());
}

test "HeadersFirstProtocol initialization" {
    const allocator = std.testing.allocator;
    
    // Mock dependencies
    const deps = ProtocolDependencies{
        .getHeightFn = mockGetHeight,
        .handleSyncBlockFn = mockHandleSyncBlock,
        .getNetworkFn = mockGetNetwork,
        .context = undefined,
        .allocator = allocator,
    };
    
    var protocol = HeadersFirstProtocol.init(deps);
    defer protocol.deinit();
    
    try std.testing.expectEqual(SyncState.synced, protocol.sync_state);
    try std.testing.expectEqual(@as(?*net.Peer, null), protocol.sync_peer);
    try std.testing.expectEqual(@as(usize, 0), protocol.getBlocksDownload());
}

// Mock functions for testing
fn mockGetHeight(ctx: *anyopaque) !u32 {
    _ = ctx;
    return 100;
}

fn mockHandleSyncBlock(ctx: *anyopaque, height: u32, block: Block) !void {
    _ = ctx;
    _ = height;
    _ = block;
}

fn mockGetNetwork(ctx: *anyopaque) ?*net.NetworkManager {
    _ = ctx;
    return null;
}