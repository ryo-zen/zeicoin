// state_root.zig - State root calculation and snapshot management
// Provides cryptographic commitment to the entire account state (Merkle root equivalent)

const std = @import("std");
const types = @import("../types/types.zig");
const Database = @import("../storage/db.zig").Database;

/// Helper struct for state root calculation
const StateRootContext = struct {
    hasher: *std.crypto.hash.sha2.Sha256,
};

/// Callback for iterating accounts during state root calculation
fn hashAccountCallback(account: types.Account, user_data: ?*anyopaque) bool {
    const ctx = @as(*StateRootContext, @ptrCast(@alignCast(user_data.?)));

    // Hash: address || balance || nonce || immature_balance
    // Hash address version (1 byte) + hash (20 bytes)
    ctx.hasher.update(&[_]u8{account.address.version});
    ctx.hasher.update(&account.address.hash);

    var balance_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &balance_bytes, account.balance, .little);
    ctx.hasher.update(&balance_bytes);

    var nonce_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce_bytes, account.nonce, .little);
    ctx.hasher.update(&nonce_bytes);

    var immature_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &immature_bytes, account.immature_balance, .little);
    ctx.hasher.update(&immature_bytes);

    return true; // Continue iteration
}

/// Calculate state root hash from current account states
/// This is a cryptographic commitment to the entire account state
/// Note: iterateAccounts already sorts accounts by address for deterministic ordering
pub fn calculateStateRoot(allocator: std.mem.Allocator, db: *Database) !types.Hash {
    _ = allocator; // Not needed - iterateAccounts handles its own allocation

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var ctx = StateRootContext{ .hasher = &hasher };

    // Iterate all accounts (already sorted by address in iterateAccounts)
    try db.iterateAccounts(hashAccountCallback, @ptrCast(&ctx));

    // Double SHA256 for extra security (Bitcoin-style)
    var first_hash: [32]u8 = undefined;
    hasher.final(&first_hash);

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&first_hash);

    var final_hash: [32]u8 = undefined;
    hasher2.final(&final_hash);

    return final_hash;
}

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
