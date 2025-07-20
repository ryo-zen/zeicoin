// state.zig - Sync State Management and Progress Tracking
// Manages synchronization state transitions and progress monitoring
// Extracted from node.zig for modular sync architecture

const std = @import("std");
const util = @import("../util/util.zig");

/// Blockchain synchronization state
pub const SyncState = enum {
    synced, // Up to date with peers
    syncing, // Currently downloading blocks
    sync_complete, // Sync completed, ready to switch to synced
    sync_failed, // Sync failed, will retry later

    /// Check if sync is active
    pub fn isActive(self: SyncState) bool {
        return self == .syncing;
    }

    /// Check if sync is complete
    pub fn isComplete(self: SyncState) bool {
        return self == .sync_complete or self == .synced;
    }

    /// Check if sync failed
    pub fn isFailed(self: SyncState) bool {
        return self == .sync_failed;
    }
};

/// Sync progress tracking
pub const SyncProgress = struct {
    target_height: u32,
    current_height: u32,
    blocks_downloaded: u32,
    start_time: i64,
    last_progress_report: i64,
    last_request_time: i64,
    retry_count: u32,
    consecutive_failures: u32, // Track consecutive failures across all peers

    pub fn init(current: u32, target: u32) SyncProgress {
        const now = util.getTime();
        return SyncProgress{
            .target_height = target,
            .current_height = current,
            .blocks_downloaded = 0,
            .start_time = now,
            .last_progress_report = now,
            .last_request_time = now,
            .retry_count = 0,
            .consecutive_failures = 0,
        };
    }

    pub fn getProgress(self: *const SyncProgress) f64 {
        if (self.target_height <= self.current_height) return 100.0;
        const total_blocks = self.target_height - self.current_height;
        if (total_blocks == 0) return 100.0;
        return (@as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(total_blocks))) * 100.0;
    }

    pub fn getETA(self: *const SyncProgress) i64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0 or self.blocks_downloaded == 0) return 0;

        if (self.blocks_downloaded >= (self.target_height - self.current_height)) return 0;
        const remaining_blocks = (self.target_height - self.current_height) - self.blocks_downloaded;
        const blocks_per_second = @as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(elapsed));
        if (blocks_per_second == 0) return 0;

        return @as(i64, @intFromFloat(@as(f64, @floatFromInt(remaining_blocks)) / blocks_per_second));
    }

    pub fn getBlocksPerSecond(self: *const SyncProgress) f64 {
        const elapsed = util.getTime() - self.start_time;
        if (elapsed == 0) return 0.0;
        return @as(f64, @floatFromInt(self.blocks_downloaded)) / @as(f64, @floatFromInt(elapsed));
    }

    /// Update progress with new block
    pub fn updateProgress(self: *SyncProgress, blocks_received: u32) void {
        self.blocks_downloaded += blocks_received;
        self.last_request_time = util.getTime();
    }

    /// Reset retry counters
    pub fn resetRetry(self: *SyncProgress) void {
        self.retry_count = 0;
        self.consecutive_failures = 0;
    }

    /// Increment failure count
    pub fn incrementFailure(self: *SyncProgress) void {
        self.consecutive_failures += 1;
    }
};


/// Sync state manager for coordinating state transitions
pub const SyncStateManager = struct {
    state: SyncState,
    progress: ?SyncProgress,
    
    pub fn init() SyncStateManager {
        return .{
            .state = .synced,
            .progress = null,
        };
    }

    /// Start sync operation
    pub fn startSync(self: *SyncStateManager, current_height: u32, target_height: u32) void {
        self.state = .syncing;
        self.progress = SyncProgress.init(current_height, target_height);
    }

    /// Complete sync operation
    pub fn completeSync(self: *SyncStateManager) void {
        self.state = .sync_complete;
        self.progress = null;
    }

    /// Fail sync operation
    pub fn failSync(self: *SyncStateManager) void {
        self.state = .sync_failed;
        // Keep progress for potential retry
    }

    /// Reset to synced state
    pub fn resetToSynced(self: *SyncStateManager) void {
        self.state = .synced;
        self.progress = null;
    }

    /// Get current sync state
    pub fn getState(self: *const SyncStateManager) SyncState {
        return self.state;
    }

    /// Check if sync is active
    pub fn isActive(self: *const SyncStateManager) bool {
        return self.state.isActive();
    }

    /// Check if sync is complete
    pub fn isComplete(self: *const SyncStateManager) bool {
        return self.state.isComplete();
    }

    /// Check if sync failed
    pub fn isFailed(self: *const SyncStateManager) bool {
        return self.state.isFailed();
    }
};