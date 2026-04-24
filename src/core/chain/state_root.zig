// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// state_root.zig - Persistent state snapshots for rollback and recovery
// Canonical state-root calculation lives in ChainState.calculateStateRoot().

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const serialize = @import("../storage/serialize.zig");
const Database = @import("../storage/db.zig").Database;
const DatabaseError = @import("../storage/db.zig").DatabaseError;

const Account = types.Account;
const Hash = types.Hash;
const log = std.log.scoped(.chain);

const SNAPSHOT_PREFIX = "SNAPSHOT:v1:";

pub const SnapshotAnchor = struct {
    height: u32,
    block_hash: Hash,
    state_root: Hash,
};

const StateSnapshot = struct {
    height: u32,
    block_hash: Hash,
    state_root: Hash,
    total_supply: u64,
    circulating_supply: u64,
    accounts: []Account,

    fn anchor(self: *const @This()) SnapshotAnchor {
        return .{
            .height = self.height,
            .block_hash = self.block_hash,
            .state_root = self.state_root,
        };
    }

    fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.accounts);
    }
};

const SnapshotCollector = struct {
    accounts: *std.array_list.Managed(Account),
    failed: bool = false,

    fn callback(account: Account, user_data: ?*anyopaque) bool {
        const collector = @as(*@This(), @ptrCast(@alignCast(user_data.?)));
        collector.accounts.append(account) catch {
            collector.failed = true;
            return false;
        };
        return true;
    }
};

const SnapshotHeightCollector = struct {
    target_height: u32,
    heights: *std.array_list.Managed(u32),
    failed: bool = false,

    fn callback(key: []const u8, user_data: ?*anyopaque) bool {
        const collector = @as(*@This(), @ptrCast(@alignCast(user_data.?)));
        const height = parseSnapshotHeightKey(key) catch {
            collector.failed = true;
            return false;
        };

        if (height > collector.target_height) {
            return false;
        }

        collector.heights.append(height) catch {
            collector.failed = true;
            return false;
        };
        return true;
    }
};

fn makeSnapshotKey(allocator: std.mem.Allocator, height: u32) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}{:0>10}", .{ SNAPSHOT_PREFIX, height });
}

fn parseSnapshotHeightKey(key: []const u8) !u32 {
    if (!std.mem.startsWith(u8, key, SNAPSHOT_PREFIX)) {
        return error.InvalidSnapshotKey;
    }

    const suffix = key[SNAPSHOT_PREFIX.len..];
    return std.fmt.parseInt(u32, suffix, 10);
}

fn collectAccounts(allocator: std.mem.Allocator, db: *Database) !std.array_list.Managed(Account) {
    var accounts = std.array_list.Managed(Account).init(allocator);
    errdefer accounts.deinit();

    var collector = SnapshotCollector{ .accounts = &accounts };
    try db.iterateAccounts(SnapshotCollector.callback, &collector);
    if (collector.failed) {
        return error.OutOfMemory;
    }

    return accounts;
}

fn calculateAccountsStateRoot(allocator: std.mem.Allocator, accounts: []const Account) !Hash {
    var account_hashes = std.array_list.Managed(Hash).init(allocator);
    defer account_hashes.deinit();

    try account_hashes.ensureTotalCapacity(accounts.len);
    for (accounts) |account| {
        try account_hashes.append(util.MerkleTree.hashAccountState(account));
    }

    return util.MerkleTree.calculateRoot(allocator, account_hashes.items);
}

fn readStateSnapshot(allocator: std.mem.Allocator, db: *Database, height: u32) !?StateSnapshot {
    const snapshot_key = try makeSnapshotKey(allocator, height);
    defer allocator.free(snapshot_key);

    const snapshot_bytes = db.getKey(snapshot_key) catch |err| switch (err) {
        DatabaseError.NotFound => return null,
        else => return err,
    };
    defer allocator.free(snapshot_bytes);

    var reader = std.Io.Reader.fixed(snapshot_bytes);
    return serialize.deserialize(&reader, StateSnapshot, allocator) catch DatabaseError.SerializationFailed;
}

fn appendSnapshotRestoreInternal(
    allocator: std.mem.Allocator,
    db: *Database,
    batch: *Database.WriteBatch,
    snapshot: *const StateSnapshot,
    expected_block_hash: ?Hash,
) !SnapshotAnchor {
    if (expected_block_hash) |block_hash| {
        if (!std.mem.eql(u8, &snapshot.block_hash, &block_hash)) {
            return error.SnapshotBlockHashMismatch;
        }
    }

    const calculated_state_root = try calculateAccountsStateRoot(allocator, snapshot.accounts);
    if (!std.mem.eql(u8, &snapshot.state_root, &calculated_state_root)) {
        return error.SnapshotStateRootMismatch;
    }

    _ = try db.appendDeleteAllAccountsToBatch(batch);

    for (snapshot.accounts) |account| {
        try batch.saveAccount(account.address, account);
    }

    batch.saveAccountCount(@intCast(snapshot.accounts.len));
    try batch.updateTotalSupply(snapshot.total_supply);
    try batch.updateCirculatingSupply(snapshot.circulating_supply);
    return snapshot.anchor();
}

/// Save a serialized snapshot of the persisted account state and supply metadata.
pub fn saveStateSnapshot(
    allocator: std.mem.Allocator,
    db: *Database,
    height: u32,
    block_hash: Hash,
    state_root: Hash,
) !void {
    const snapshot_key = try makeSnapshotKey(allocator, height);
    defer allocator.free(snapshot_key);

    var accounts = try collectAccounts(allocator, db);
    defer accounts.deinit();

    const snapshot = StateSnapshot{
        .height = height,
        .block_hash = block_hash,
        .state_root = state_root,
        .total_supply = db.getTotalSupply(),
        .circulating_supply = db.getCirculatingSupply(),
        .accounts = accounts.items,
    };

    var aw: std.Io.Writer.Allocating = .init(allocator);
    defer aw.deinit();
    serialize.serialize(&aw.writer, snapshot) catch return DatabaseError.SerializationFailed;

    try db.putKey(snapshot_key, aw.written());
    log.info("💾 [SNAPSHOT] Saved state snapshot at height {} ({} accounts)", .{ height, accounts.items.len });
}

/// Collect all snapshot heights up to a target so callers can try the nearest valid anchor first.
pub fn collectSnapshotHeightsAtOrBelow(
    allocator: std.mem.Allocator,
    db: *Database,
    target_height: u32,
) ![]u32 {
    var heights = std.array_list.Managed(u32).init(allocator);
    errdefer heights.deinit();

    var collector = SnapshotHeightCollector{
        .target_height = target_height,
        .heights = &heights,
    };
    try db.iterateKeysWithPrefix(SNAPSHOT_PREFIX, SnapshotHeightCollector.callback, &collector);
    if (collector.failed) {
        return error.OutOfMemory;
    }

    return try heights.toOwnedSlice();
}

/// Append snapshot restoration into an existing RocksDB write batch.
pub fn appendStateSnapshotRestoreToBatch(
    allocator: std.mem.Allocator,
    db: *Database,
    batch: *Database.WriteBatch,
    height: u32,
    expected_block_hash: ?Hash,
) !?SnapshotAnchor {
    var snapshot = (try readStateSnapshot(allocator, db, height)) orelse return null;
    defer snapshot.deinit(allocator);

    if (snapshot.height != height) {
        return error.SnapshotHeightMismatch;
    }

    return try appendSnapshotRestoreInternal(allocator, db, batch, &snapshot, expected_block_hash);
}

/// Restore a persisted snapshot into RocksDB atomically. Returns null when no snapshot exists.
pub fn loadStateSnapshot(
    allocator: std.mem.Allocator,
    db: *Database,
    height: u32,
    expected_block_hash: ?Hash,
) !?SnapshotAnchor {
    var batch = db.createWriteBatch();
    defer batch.deinit();

    const anchor = (try appendStateSnapshotRestoreToBatch(allocator, db, &batch, height, expected_block_hash)) orelse return null;
    try batch.commit();

    log.info("📥 [SNAPSHOT] Restored state snapshot at height {}", .{height});
    return anchor;
}

/// Delete a stored snapshot once it is no longer needed.
pub fn deleteStateSnapshot(allocator: std.mem.Allocator, db: *Database, height: u32) !void {
    const snapshot_key = try makeSnapshotKey(allocator, height);
    defer allocator.free(snapshot_key);

    db.deleteKey(snapshot_key) catch |err| switch (err) {
        DatabaseError.NotFound => return,
        else => return err,
    };

    log.info("🗑️  [SNAPSHOT] Deleted state snapshot at height {}", .{height});
}
