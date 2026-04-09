const std = @import("std");

pub const bucket_count: usize = 256;
pub const bucket_size: usize = 20;
const hash_len: usize = 32;

pub const KadMode = enum {
    client,
    server,
};

pub const ConnectionType = enum(u8) {
    not_connected = 0,
    connected = 1,
    can_connect = 2,
    cannot_connect = 3,
};

pub const PeerSnapshot = struct {
    peer_id: []u8,
    addrs: std.array_list.Managed([]u8),
    mode: KadMode,
    connection: ConnectionType,
    bucket_index: usize,
    last_seen_ms: u64,

    pub fn deinit(self: *PeerSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.peer_id);
        for (self.addrs.items) |addr| allocator.free(addr);
        self.addrs.deinit();
    }
};

pub const PendingEviction = struct {
    bucket_index: usize,
    incumbent_peer_id: []const u8,
};

pub const InsertResult = union(enum) {
    inserted: usize,
    updated: usize,
    rejected_client_mode,
    rejected_self,
    pending_eviction: PendingEviction,
};

const PeerEntry = struct {
    peer_id: []u8,
    hashed_key: [hash_len]u8,
    addrs: std.array_list.Managed([]u8),
    mode: KadMode,
    connection: ConnectionType,
    last_seen_ms: u64,

    fn init(
        allocator: std.mem.Allocator,
        peer_id: []const u8,
        hashed_key: [hash_len]u8,
        addrs: []const []const u8,
        mode: KadMode,
        connection: ConnectionType,
        now_ms: u64,
    ) !PeerEntry {
        var out = PeerEntry{
            .peer_id = try allocator.dupe(u8, peer_id),
            .hashed_key = hashed_key,
            .addrs = std.array_list.Managed([]u8).init(allocator),
            .mode = mode,
            .connection = connection,
            .last_seen_ms = now_ms,
        };
        errdefer out.deinit(allocator);

        try mergeOwnedAddrs(allocator, &out.addrs, addrs);
        return out;
    }

    fn deinit(self: *PeerEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.peer_id);
        for (self.addrs.items) |addr| allocator.free(addr);
        self.addrs.deinit();
    }
};

pub const RoutingTable = struct {
    allocator: std.mem.Allocator,
    local_peer_id: []u8,
    local_key: [hash_len]u8,
    buckets: [bucket_count]std.array_list.Managed(PeerEntry),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, local_peer_id: []const u8) !Self {
        var buckets: [bucket_count]std.array_list.Managed(PeerEntry) = undefined;
        for (&buckets) |*bucket| {
            bucket.* = std.array_list.Managed(PeerEntry).init(allocator);
        }

        return .{
            .allocator = allocator,
            .local_peer_id = try allocator.dupe(u8, local_peer_id),
            .local_key = hashKey(local_peer_id),
            .buckets = buckets,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.local_peer_id);
        for (&self.buckets) |*bucket| {
            for (bucket.items) |*entry| entry.deinit(self.allocator);
            bucket.deinit();
        }
    }

    pub fn peerCount(self: *const Self) usize {
        var total: usize = 0;
        for (self.buckets) |bucket| total += bucket.items.len;
        return total;
    }

    pub fn bucketLen(self: *const Self, bucket_index: usize) usize {
        return self.buckets[bucket_index].items.len;
    }

    pub fn bucketIndexForPeer(self: *const Self, peer_id: []const u8) !usize {
        if (std.mem.eql(u8, peer_id, self.local_peer_id)) return error.CannotInsertSelf;
        return bucketIndexForHashedKey(self.local_key, hashKey(peer_id));
    }

    pub fn insertOrUpdate(
        self: *Self,
        peer_id: []const u8,
        addrs: []const []const u8,
        mode: KadMode,
        connection: ConnectionType,
        now_ms: u64,
    ) !InsertResult {
        if (mode != .server) return .rejected_client_mode;
        if (std.mem.eql(u8, peer_id, self.local_peer_id)) return .rejected_self;

        const hashed_key = hashKey(peer_id);
        const bucket_index = try bucketIndexForHashedKey(self.local_key, hashed_key);
        const bucket = &self.buckets[bucket_index];

        if (findEntryIndex(bucket.items, peer_id)) |entry_index| {
            try refreshEntry(self.allocator, bucket, entry_index, addrs, connection, now_ms);
            return .{ .updated = bucket_index };
        }

        if (bucket.items.len < bucket_size) {
            try bucket.append(try PeerEntry.init(
                self.allocator,
                peer_id,
                hashed_key,
                addrs,
                mode,
                connection,
                now_ms,
            ));
            return .{ .inserted = bucket_index };
        }

        return .{ .pending_eviction = .{
            .bucket_index = bucket_index,
            .incumbent_peer_id = bucket.items[0].peer_id,
        } };
    }

    pub fn keepIncumbent(self: *Self, bucket_index: usize, incumbent_peer_id: []const u8) !void {
        const bucket = &self.buckets[bucket_index];
        if (bucket.items.len == 0) return error.BucketEmpty;
        if (!std.mem.eql(u8, bucket.items[0].peer_id, incumbent_peer_id)) return error.IncumbentMismatch;
    }

    pub fn replaceIncumbent(
        self: *Self,
        bucket_index: usize,
        incumbent_peer_id: []const u8,
        candidate_peer_id: []const u8,
        addrs: []const []const u8,
        mode: KadMode,
        connection: ConnectionType,
        now_ms: u64,
    ) !void {
        if (mode != .server) return error.CandidateNotServerMode;
        if (std.mem.eql(u8, candidate_peer_id, self.local_peer_id)) return error.CannotInsertSelf;

        const bucket = &self.buckets[bucket_index];
        if (bucket.items.len == 0) return error.BucketEmpty;
        if (!std.mem.eql(u8, bucket.items[0].peer_id, incumbent_peer_id)) return error.IncumbentMismatch;
        if (findEntryIndex(bucket.items, candidate_peer_id) != null) return error.CandidateAlreadyPresent;

        var removed = bucket.orderedRemove(0);
        removed.deinit(self.allocator);

        try bucket.append(try PeerEntry.init(
            self.allocator,
            candidate_peer_id,
            hashKey(candidate_peer_id),
            addrs,
            mode,
            connection,
            now_ms,
        ));
    }

    pub fn removePeer(self: *Self, peer_id: []const u8) bool {
        for (&self.buckets) |*bucket| {
            if (findEntryIndex(bucket.items, peer_id)) |entry_index| {
                var removed = bucket.orderedRemove(entry_index);
                removed.deinit(self.allocator);
                return true;
            }
        }
        return false;
    }

    pub fn getPeerSnapshot(self: *const Self, allocator: std.mem.Allocator, peer_id: []const u8) !?PeerSnapshot {
        for (self.buckets, 0..) |bucket, bucket_index| {
            if (findEntryIndex(bucket.items, peer_id)) |entry_index| {
                return try entryToSnapshot(allocator, &bucket.items[entry_index], bucket_index);
            }
        }
        return null;
    }

    pub fn closestPeers(
        self: *const Self,
        allocator: std.mem.Allocator,
        target_key: []const u8,
        count: usize,
    ) !std.array_list.Managed(PeerSnapshot) {
        var refs = std.array_list.Managed(PeerDistanceRef).init(allocator);
        defer refs.deinit();

        const hashed_target = hashKey(target_key);
        for (self.buckets, 0..) |bucket, bucket_index| {
            for (bucket.items, 0..) |entry, entry_index| {
                try refs.append(.{
                    .bucket_index = bucket_index,
                    .entry_index = entry_index,
                    .distance = xorDistance(entry.hashed_key, hashed_target),
                });
            }
        }

        std.sort.block(PeerDistanceRef, refs.items, {}, lessDistanceRef);

        var out = std.array_list.Managed(PeerSnapshot).init(allocator);
        errdefer {
            for (out.items) |*snapshot| snapshot.deinit(allocator);
            out.deinit();
        }

        const limit = @min(count, refs.items.len);
        for (refs.items[0..limit]) |ref| {
            const entry = &self.buckets[ref.bucket_index].items[ref.entry_index];
            try out.append(try entryToSnapshot(allocator, entry, ref.bucket_index));
        }

        return out;
    }
};

const PeerDistanceRef = struct {
    bucket_index: usize,
    entry_index: usize,
    distance: [hash_len]u8,
};

fn lessDistanceRef(_: void, lhs: PeerDistanceRef, rhs: PeerDistanceRef) bool {
    return compareDistance(lhs.distance, rhs.distance) == .lt;
}

fn compareDistance(lhs: [hash_len]u8, rhs: [hash_len]u8) std.math.Order {
    return std.mem.order(u8, &lhs, &rhs);
}

pub fn hashKey(key: []const u8) [hash_len]u8 {
    var out: [hash_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &out, .{});
    return out;
}

pub fn xorDistance(lhs: [hash_len]u8, rhs: [hash_len]u8) [hash_len]u8 {
    var out: [hash_len]u8 = undefined;
    for (lhs, rhs, 0..) |left, right, i| out[i] = left ^ right;
    return out;
}

pub fn commonPrefixLength(lhs: [hash_len]u8, rhs: [hash_len]u8) usize {
    var count: usize = 0;
    for (lhs, rhs) |left, right| {
        const diff = left ^ right;
        if (diff == 0) {
            count += 8;
            continue;
        }

        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            if ((diff & bit) != 0) return count;
            count += 1;
        }
    }
    return count;
}

fn bucketIndexForHashedKey(local_key: [hash_len]u8, peer_key: [hash_len]u8) !usize {
    const prefix_len = commonPrefixLength(local_key, peer_key);
    if (prefix_len >= bucket_count) return error.CannotInsertSelf;
    return prefix_len;
}

fn findEntryIndex(entries: []const PeerEntry, peer_id: []const u8) ?usize {
    for (entries, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.peer_id, peer_id)) return index;
    }
    return null;
}

fn refreshEntry(
    allocator: std.mem.Allocator,
    bucket: *std.array_list.Managed(PeerEntry),
    entry_index: usize,
    addrs: []const []const u8,
    connection: ConnectionType,
    now_ms: u64,
) !void {
    var updated = bucket.orderedRemove(entry_index);
    errdefer updated.deinit(allocator);

    try mergeOwnedAddrs(allocator, &updated.addrs, addrs);
    updated.connection = connection;
    updated.last_seen_ms = now_ms;

    try bucket.append(updated);
}

fn mergeOwnedAddrs(
    allocator: std.mem.Allocator,
    owned: *std.array_list.Managed([]u8),
    addrs: []const []const u8,
) !void {
    for (addrs) |addr| {
        if (containsAddr(owned.items, addr)) continue;
        try owned.append(try allocator.dupe(u8, addr));
    }
}

fn containsAddr(addrs: []const []const u8, candidate: []const u8) bool {
    for (addrs) |addr| {
        if (std.mem.eql(u8, addr, candidate)) return true;
    }
    return false;
}

fn entryToSnapshot(
    allocator: std.mem.Allocator,
    entry: *const PeerEntry,
    bucket_index: usize,
) !PeerSnapshot {
    var addrs = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (addrs.items) |addr| allocator.free(addr);
        addrs.deinit();
    }
    for (entry.addrs.items) |addr| {
        try addrs.append(try allocator.dupe(u8, addr));
    }

    return .{
        .peer_id = try allocator.dupe(u8, entry.peer_id),
        .addrs = addrs,
        .mode = entry.mode,
        .connection = entry.connection,
        .bucket_index = bucket_index,
        .last_seen_ms = entry.last_seen_ms,
    };
}

fn allocPeerIdForBucket(
    allocator: std.mem.Allocator,
    table: *const RoutingTable,
    prefix: []const u8,
    target_bucket: usize,
    start_counter: usize,
) ![]u8 {
    var counter = start_counter;
    while (true) : (counter += 1) {
        const peer_id = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ prefix, counter });
        errdefer allocator.free(peer_id);
        if ((try table.bucketIndexForPeer(peer_id)) == target_bucket) return peer_id;
        allocator.free(peer_id);
    }
}

test "routing table hashes keys before xor distance" {
    const allocator = std.testing.allocator;

    var table = try RoutingTable.init(allocator, "local-peer");
    defer table.deinit();

    const peer_id = "remote-peer-a";
    const target = "lookup-target-a";
    const peer_hash = hashKey(peer_id);
    const target_hash = hashKey(target);

    try std.testing.expect(!std.mem.eql(u8, peer_id, &peer_hash));
    try std.testing.expectEqual(xorDistance(peer_hash, target_hash), xorDistance(hashKey(peer_id), hashKey(target)));
    try std.testing.expectError(error.CannotInsertSelf, table.bucketIndexForPeer("local-peer"));
}

test "routing table rejects client-mode peers and inserts server peers" {
    const allocator = std.testing.allocator;

    var table = try RoutingTable.init(allocator, "local-peer");
    defer table.deinit();

    try std.testing.expectEqual(InsertResult.rejected_client_mode, try table.insertOrUpdate(
        "client-peer",
        &[_][]const u8{"/ip4/10.0.0.2/tcp/10001"},
        .client,
        .can_connect,
        1,
    ));
    try std.testing.expectEqual(@as(usize, 0), table.peerCount());

    const inserted = try table.insertOrUpdate(
        "server-peer",
        &[_][]const u8{"/ip4/10.0.0.3/tcp/10001"},
        .server,
        .connected,
        2,
    );
    try std.testing.expect(inserted == .inserted);
    try std.testing.expectEqual(@as(usize, 1), table.peerCount());
}

test "routing table updates duplicate peer recency and merges addresses" {
    const allocator = std.testing.allocator;

    var table = try RoutingTable.init(allocator, "local-peer");
    defer table.deinit();

    const peer_a = try allocPeerIdForBucket(allocator, &table, "peer-a", 0, 0);
    defer allocator.free(peer_a);
    const peer_b = try allocPeerIdForBucket(allocator, &table, "peer-b", 0, 1);
    defer allocator.free(peer_b);

    _ = try table.insertOrUpdate(
        peer_a,
        &[_][]const u8{"/ip4/10.0.0.2/tcp/10001"},
        .server,
        .can_connect,
        10,
    );
    _ = try table.insertOrUpdate(
        peer_b,
        &[_][]const u8{"/ip4/10.0.0.3/tcp/10001"},
        .server,
        .can_connect,
        20,
    );
    _ = try table.insertOrUpdate(
        peer_a,
        &[_][]const u8{
            "/ip4/10.0.0.2/tcp/10001",
            "/ip4/10.0.0.4/tcp/10002",
        },
        .server,
        .connected,
        30,
    );

    var snapshot = (try table.getPeerSnapshot(allocator, peer_a)).?;
    defer snapshot.deinit(allocator);

    try std.testing.expectEqual(ConnectionType.connected, snapshot.connection);
    try std.testing.expectEqual(@as(u64, 30), snapshot.last_seen_ms);
    try std.testing.expectEqual(@as(usize, 2), snapshot.addrs.items.len);

    const bucket_index = try table.bucketIndexForPeer(peer_a);
    const bucket = &table.buckets[bucket_index];
    try std.testing.expectEqualStrings(peer_b, bucket.items[0].peer_id);
    try std.testing.expectEqualStrings(peer_a, bucket.items[1].peer_id);
}

test "routing table surfaces pending eviction and can replace incumbent" {
    const allocator = std.testing.allocator;

    var table = try RoutingTable.init(allocator, "local-peer");
    defer table.deinit();

    var prefix_peer_ids = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (prefix_peer_ids.items) |peer_id| allocator.free(peer_id);
        prefix_peer_ids.deinit();
    }

    const target_bucket: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), target_bucket);

    var counter: usize = 0;
    while (prefix_peer_ids.items.len < bucket_size) : (counter += 1) {
        const peer_id = try std.fmt.allocPrint(allocator, "bucket-zero-{d}", .{counter});
        errdefer allocator.free(peer_id);
        if ((try table.bucketIndexForPeer(peer_id)) != target_bucket) {
            allocator.free(peer_id);
            continue;
        }
        if (containsAddr(prefix_peer_ids.items, peer_id)) {
            allocator.free(peer_id);
            continue;
        }

        try prefix_peer_ids.append(peer_id);
        _ = try table.insertOrUpdate(
            peer_id,
            &[_][]const u8{"/ip4/10.0.0.9/tcp/10001"},
            .server,
            .can_connect,
            @as(u64, @intCast(counter)),
        );
    }

    const incumbent_peer_id = prefix_peer_ids.items[0];

    const candidate_peer_id = blk: {
        var candidate_counter = counter;
        while (true) : (candidate_counter += 1) {
            const peer_id = try std.fmt.allocPrint(allocator, "bucket-zero-candidate-{d}", .{candidate_counter});
            errdefer allocator.free(peer_id);
            if ((try table.bucketIndexForPeer(peer_id)) != target_bucket) {
                allocator.free(peer_id);
                continue;
            }
            if (containsAddr(prefix_peer_ids.items, peer_id)) {
                allocator.free(peer_id);
                continue;
            }
            break :blk peer_id;
        }
    };
    defer allocator.free(candidate_peer_id);

    const pending = try table.insertOrUpdate(
        candidate_peer_id,
        &[_][]const u8{"/ip4/10.0.0.10/tcp/10001"},
        .server,
        .can_connect,
        999,
    );
    try std.testing.expect(pending == .pending_eviction);
    try std.testing.expectEqualStrings(incumbent_peer_id, pending.pending_eviction.incumbent_peer_id);

    try table.keepIncumbent(target_bucket, incumbent_peer_id);
    try std.testing.expect((try table.getPeerSnapshot(allocator, candidate_peer_id)) == null);

    try table.replaceIncumbent(
        target_bucket,
        incumbent_peer_id,
        candidate_peer_id,
        &[_][]const u8{"/ip4/10.0.0.10/tcp/10001"},
        .server,
        .connected,
        1000,
    );

    try std.testing.expect((try table.getPeerSnapshot(allocator, incumbent_peer_id)) == null);

    var candidate_snapshot = (try table.getPeerSnapshot(allocator, candidate_peer_id)).?;
    defer candidate_snapshot.deinit(allocator);
    try std.testing.expectEqual(ConnectionType.connected, candidate_snapshot.connection);
}

test "closest peers are returned sorted by kad distance" {
    const allocator = std.testing.allocator;

    var table = try RoutingTable.init(allocator, "local-peer");
    defer table.deinit();

    const peer_ids = [_][]const u8{ "peer-a", "peer-b", "peer-c", "peer-d" };
    for (peer_ids, 0..) |peer_id, index| {
        _ = try table.insertOrUpdate(
            peer_id,
            &[_][]const u8{"/ip4/10.0.0.2/tcp/10001"},
            .server,
            .can_connect,
            @as(u64, @intCast(index + 1)),
        );
    }

    var closest = try table.closestPeers(allocator, "lookup-target", 3);
    defer {
        for (closest.items) |*snapshot| snapshot.deinit(allocator);
        closest.deinit();
    }

    try std.testing.expectEqual(@as(usize, 3), closest.items.len);

    const target_hash = hashKey("lookup-target");
    var previous_distance = xorDistance(hashKey(closest.items[0].peer_id), target_hash);
    for (closest.items[1..]) |snapshot| {
        const current_distance = xorDistance(hashKey(snapshot.peer_id), target_hash);
        try std.testing.expect(compareDistance(previous_distance, current_distance) != .gt);
        previous_distance = current_distance;
    }
}
