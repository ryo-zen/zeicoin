// state_root.zig - Snapshot markers for replay-based rollback
// Canonical state-root calculation lives in ChainState.calculateStateRoot().

const std = @import("std");
const Database = @import("../storage/db.zig").Database;

/// Save a snapshot of the current state at a given height
/// This allows rollback during reorganization
/// NOTE: For now, this relies on ChainState.rollbackToHeight() which replays from genesis
/// TODO: Implement proper snapshot storage once Database has put/get methods for arbitrary keys
pub fn saveStateSnapshot(allocator: std.mem.Allocator, db: *Database, height: u32) !void {
    _ = allocator;
    _ = db;
    std.log.info("💾 [SNAPSHOT] Marking fork point at height {} (rollback will replay from genesis)", .{height});
    // Snapshot saving is handled by ChainState.rollbackToHeight() which replays blocks from genesis
}

/// Load a state snapshot and restore it
/// This is used during reorganization to rollback to a previous state
/// NOTE: Currently uses ChainState.rollbackToHeight() which replays blocks from genesis
/// TODO: Implement proper snapshot restoration once Database has get/delete methods
pub fn loadStateSnapshot(allocator: std.mem.Allocator, db: *Database, height: u32) !void {
    _ = allocator;
    _ = db;
    std.log.info("📥 [SNAPSHOT] Rollback to height {} will use ChainState.rollbackToHeight()", .{height});
    // Actual rollback is handled by ReorgExecutor.revertToHeight() -> ChainState.rollbackToHeight()
}

/// Delete a state snapshot to save space
/// NOTE: No-op for now since snapshots aren't explicitly stored
pub fn deleteStateSnapshot(allocator: std.mem.Allocator, db: *Database, height: u32) !void {
    _ = allocator;
    _ = db;
    std.log.info("🗑️  [SNAPSHOT] Cleanup for height {} complete", .{height});
    // No explicit snapshot cleanup needed with current approach
}
