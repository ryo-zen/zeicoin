// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const kad = @import("message.zig");

pub const max_record_age_ms: u64 = 48 * 60 * 60 * 1000;
pub const provider_validity_ms: u64 = 48 * 60 * 60 * 1000;
pub const republish_interval_ms: u64 = 22 * 60 * 60 * 1000;
pub const zei_namespace = "zei";

pub const RecordOrigin = enum {
    remote,
    local,
};

pub const PutRecordResult = enum {
    inserted,
    refreshed,
    replaced,
    rejected_older,
};

pub const LocalValueRepublish = struct {
    key: []u8,
    record: kad.Record,

    pub fn deinit(self: *LocalValueRepublish, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        self.record.deinit(allocator);
    }
};

pub const LocalProviderRepublish = struct {
    key: []u8,
    provider: kad.Peer,

    pub fn deinit(self: *LocalProviderRepublish, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        self.provider.deinit(allocator);
    }
};

const ValueEntry = struct {
    record: kad.Record,
    stored_at_ms: u64,
    expires_at_ms: u64,
    last_republish_ms: u64,
    locally_originated: bool,

    fn deinit(self: *ValueEntry, allocator: std.mem.Allocator) void {
        self.record.deinit(allocator);
    }
};

const ProviderEntry = struct {
    peer: kad.Peer,
    stored_at_ms: u64,
    expires_at_ms: u64,
    last_republish_ms: u64,
    locally_originated: bool,

    fn deinit(self: *ProviderEntry, allocator: std.mem.Allocator) void {
        self.peer.deinit(allocator);
    }
};

const ProviderSet = struct {
    providers: std.array_list.Managed(ProviderEntry),

    fn init(allocator: std.mem.Allocator) ProviderSet {
        return .{
            .providers = std.array_list.Managed(ProviderEntry).init(allocator),
        };
    }

    fn deinit(self: *ProviderSet, allocator: std.mem.Allocator) void {
        for (self.providers.items) |*entry| entry.deinit(allocator);
        self.providers.deinit();
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    values: std.StringHashMap(ValueEntry),
    providers: std.StringHashMap(ProviderSet),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .values = std.StringHashMap(ValueEntry).init(allocator),
            .providers = std.StringHashMap(ProviderSet).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var value_it = self.values.iterator();
        while (value_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.values.deinit();

        var provider_it = self.providers.iterator();
        while (provider_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.providers.deinit();
    }

    pub fn putRecord(
        self: *Self,
        key: []const u8,
        record: *const kad.Record,
        now_ms: u64,
        origin: RecordOrigin,
    ) !PutRecordResult {
        try validateRecordForStore(key, record);

        if (self.values.getPtr(key)) |entry| {
            if (entry.expires_at_ms <= now_ms) {
                entry.deinit(self.allocator);
                entry.* = try makeValueEntry(self.allocator, record, now_ms, origin);
                return .inserted;
            }

            switch (try selectRecord(key, record.value, entry.record.value)) {
                .lt => return .rejected_older,
                .eq => {
                    entry.stored_at_ms = now_ms;
                    entry.expires_at_ms = now_ms + max_record_age_ms;
                    if (origin == .local) entry.locally_originated = true;
                    return .refreshed;
                },
                .gt => {
                    entry.deinit(self.allocator);
                    entry.* = try makeValueEntry(self.allocator, record, now_ms, origin);
                    return .replaced;
                },
            }
        }

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.values.put(owned_key, try makeValueEntry(self.allocator, record, now_ms, origin));
        return .inserted;
    }

    pub fn getRecord(self: *Self, allocator: std.mem.Allocator, key: []const u8, now_ms: u64) !?kad.Record {
        if (self.values.getPtr(key)) |entry| {
            if (entry.expires_at_ms <= now_ms) {
                try self.removeValueKey(key);
                return null;
            }
            return try cloneRecord(allocator, &entry.record);
        }
        return null;
    }

    pub fn addProvider(
        self: *Self,
        key: []const u8,
        peer: *const kad.Peer,
        now_ms: u64,
        origin: RecordOrigin,
    ) !void {
        if (key.len == 0) return error.EmptyKadProviderKey;
        if (peer.id.len == 0) return error.EmptyKadProviderPeerId;
        if (peer.addrs.items.len == 0) return error.ProviderMissingAddress;

        const set = try self.getOrCreateProviderSet(key);
        const existing_index = findProviderIndex(set.providers.items, peer.id);
        if (existing_index) |index| {
            var existing = &set.providers.items[index];
            try mergePeerAddrs(self.allocator, &existing.peer, peer);
            if (@intFromEnum(peer.connection) > @intFromEnum(existing.peer.connection)) {
                existing.peer.connection = peer.connection;
            }
            existing.stored_at_ms = now_ms;
            existing.expires_at_ms = now_ms + provider_validity_ms;
            if (origin == .local) existing.locally_originated = true;
            return;
        }

        try set.providers.append(.{
            .peer = try clonePeer(self.allocator, peer),
            .stored_at_ms = now_ms,
            .expires_at_ms = now_ms + provider_validity_ms,
            .last_republish_ms = now_ms,
            .locally_originated = origin == .local,
        });
    }

    pub fn getProviders(
        self: *Self,
        allocator: std.mem.Allocator,
        key: []const u8,
        now_ms: u64,
    ) !std.array_list.Managed(kad.Peer) {
        var out = std.array_list.Managed(kad.Peer).init(allocator);
        errdefer {
            for (out.items) |*peer| peer.deinit(allocator);
            out.deinit();
        }

        if (self.providers.getPtr(key)) |set| {
            pruneProviderEntries(set, self.allocator, now_ms);
            for (set.providers.items) |*entry| {
                try out.append(try clonePeer(allocator, &entry.peer));
            }
            if (set.providers.items.len == 0) {
                try self.removeProviderKey(key);
            }
        }

        return out;
    }

    pub fn dueLocalValueRepublishes(
        self: *Self,
        allocator: std.mem.Allocator,
        now_ms: u64,
    ) !std.array_list.Managed(LocalValueRepublish) {
        var out = std.array_list.Managed(LocalValueRepublish).init(allocator);
        errdefer {
            for (out.items) |*item| item.deinit(allocator);
            out.deinit();
        }

        var it = self.values.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at_ms <= now_ms) continue;
            if (!entry.value_ptr.locally_originated) continue;
            if (now_ms - entry.value_ptr.last_republish_ms < republish_interval_ms) continue;

            try out.append(.{
                .key = try allocator.dupe(u8, entry.key_ptr.*),
                .record = try cloneRecord(allocator, &entry.value_ptr.record),
            });
        }

        return out;
    }

    pub fn dueLocalProviderRepublishes(
        self: *Self,
        allocator: std.mem.Allocator,
        now_ms: u64,
    ) !std.array_list.Managed(LocalProviderRepublish) {
        var out = std.array_list.Managed(LocalProviderRepublish).init(allocator);
        errdefer {
            for (out.items) |*item| item.deinit(allocator);
            out.deinit();
        }

        var it = self.providers.iterator();
        while (it.next()) |entry| {
            pruneProviderEntries(entry.value_ptr, self.allocator, now_ms);
            for (entry.value_ptr.providers.items) |*provider| {
                if (!provider.locally_originated) continue;
                if (now_ms - provider.last_republish_ms < republish_interval_ms) continue;
                try out.append(.{
                    .key = try allocator.dupe(u8, entry.key_ptr.*),
                    .provider = try clonePeer(allocator, &provider.peer),
                });
            }
        }

        return out;
    }

    pub fn markValueRepublished(self: *Self, key: []const u8, now_ms: u64) void {
        if (self.values.getPtr(key)) |entry| {
            entry.last_republish_ms = now_ms;
        }
    }

    pub fn markProviderRepublished(self: *Self, key: []const u8, peer_id: []const u8, now_ms: u64) void {
        if (self.providers.getPtr(key)) |set| {
            if (findProviderIndex(set.providers.items, peer_id)) |index| {
                set.providers.items[index].last_republish_ms = now_ms;
            }
        }
    }

    pub fn pruneExpired(self: *Self, now_ms: u64) void {
        var expired_value_keys = std.array_list.Managed([]u8).init(self.allocator);
        defer freeOwnedStrings(self.allocator, &expired_value_keys);

        var value_it = self.values.iterator();
        while (value_it.next()) |entry| {
            if (entry.value_ptr.expires_at_ms <= now_ms) {
                const owned_key = self.allocator.dupe(u8, entry.key_ptr.*) catch continue;
                expired_value_keys.append(owned_key) catch {
                    self.allocator.free(owned_key);
                };
            }
        }
        for (expired_value_keys.items) |key| self.removeValueKey(key) catch {};

        var empty_provider_keys = std.array_list.Managed([]u8).init(self.allocator);
        defer freeOwnedStrings(self.allocator, &empty_provider_keys);

        var provider_it = self.providers.iterator();
        while (provider_it.next()) |entry| {
            pruneProviderEntries(entry.value_ptr, self.allocator, now_ms);
            if (entry.value_ptr.providers.items.len == 0) {
                const owned_key = self.allocator.dupe(u8, entry.key_ptr.*) catch continue;
                empty_provider_keys.append(owned_key) catch {
                    self.allocator.free(owned_key);
                };
            }
        }
        for (empty_provider_keys.items) |key| self.removeProviderKey(key) catch {};
    }

    fn getOrCreateProviderSet(self: *Self, key: []const u8) !*ProviderSet {
        if (self.providers.getPtr(key)) |set| return set;

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);
        try self.providers.put(owned_key, ProviderSet.init(self.allocator));
        return self.providers.getPtr(key).?;
    }

    fn removeValueKey(self: *Self, key: []const u8) !void {
        const entry = self.values.fetchRemove(key) orelse return;
        self.allocator.free(entry.key);
        var value = entry.value;
        value.deinit(self.allocator);
    }

    fn removeProviderKey(self: *Self, key: []const u8) !void {
        const entry = self.providers.fetchRemove(key) orelse return;
        self.allocator.free(entry.key);
        var value = entry.value;
        value.deinit(self.allocator);
    }
};

fn validateRecordForStore(key: []const u8, record: *const kad.Record) !void {
    if (key.len == 0) return error.EmptyKadRecordKey;
    if (record.key.len == 0) return error.EmptyKadRecordKey;
    if (!std.mem.eql(u8, key, record.key)) return error.KadRecordKeyMismatch;
    if (record.value.len == 0) return error.EmptyKadRecordValue;
    const namespace = try recordNamespace(key);
    if (std.mem.eql(u8, namespace, zei_namespace)) {
        _ = try parseZeiRecordVersion(record.value);
        return;
    }
    return error.UnsupportedKadRecordNamespace;
}

fn makeValueEntry(
    allocator: std.mem.Allocator,
    record: *const kad.Record,
    now_ms: u64,
    origin: RecordOrigin,
) !ValueEntry {
    return .{
        .record = try cloneRecord(allocator, record),
        .stored_at_ms = now_ms,
        .expires_at_ms = now_ms + max_record_age_ms,
        .last_republish_ms = now_ms,
        .locally_originated = origin == .local,
    };
}

fn cloneRecord(allocator: std.mem.Allocator, record: *const kad.Record) !kad.Record {
    var out = kad.Record.init();
    errdefer out.deinit(allocator);
    out.key = try allocator.dupe(u8, record.key);
    out.value = try allocator.dupe(u8, record.value);
    if (record.time_received.len > 0) {
        out.time_received = try allocator.dupe(u8, record.time_received);
    }
    return out;
}

fn clonePeer(allocator: std.mem.Allocator, peer: *const kad.Peer) !kad.Peer {
    var out = kad.Peer.init(allocator);
    errdefer out.deinit(allocator);
    out.id = try allocator.dupe(u8, peer.id);
    out.connection = peer.connection;
    for (peer.addrs.items) |addr| {
        try out.addrs.append(try allocator.dupe(u8, addr));
    }
    return out;
}

fn mergePeerAddrs(
    allocator: std.mem.Allocator,
    existing: *kad.Peer,
    incoming: *const kad.Peer,
) !void {
    for (incoming.addrs.items) |addr| {
        for (existing.addrs.items) |candidate| {
            if (std.mem.eql(u8, candidate, addr)) break;
        } else {
            try existing.addrs.append(try allocator.dupe(u8, addr));
        }
    }
}

fn findProviderIndex(entries: []const ProviderEntry, peer_id: []const u8) ?usize {
    for (entries, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.peer.id, peer_id)) return index;
    }
    return null;
}

fn pruneProviderEntries(set: *ProviderSet, allocator: std.mem.Allocator, now_ms: u64) void {
    var index: usize = 0;
    while (index < set.providers.items.len) {
        if (set.providers.items[index].expires_at_ms <= now_ms) {
            var removed = set.providers.swapRemove(index);
            removed.deinit(allocator);
        } else {
            index += 1;
        }
    }
}

fn selectRecord(key: []const u8, incoming: []const u8, existing: []const u8) !std.math.Order {
    const namespace = try recordNamespace(key);
    if (std.mem.eql(u8, namespace, zei_namespace)) {
        const incoming_version = try parseZeiRecordVersion(incoming);
        const existing_version = try parseZeiRecordVersion(existing);
        if (incoming_version < existing_version) return .lt;
        if (incoming_version > existing_version) return .gt;
        if (std.mem.eql(u8, incoming, existing)) return .eq;
        return error.ConflictingKadRecordVersion;
    }
    return error.UnsupportedKadRecordNamespace;
}

fn recordNamespace(key: []const u8) ![]const u8 {
    if (key.len < 4 or key[0] != '/') return error.UnsupportedKadRecordNamespace;
    const rest = key[1..];
    const slash_index = std.mem.indexOfScalar(u8, rest, '/') orelse return error.UnsupportedKadRecordNamespace;
    if (slash_index == 0) return error.UnsupportedKadRecordNamespace;
    return rest[0..slash_index];
}

fn parseZeiRecordVersion(value: []const u8) !u64 {
    if (!std.mem.startsWith(u8, value, "seq:")) return error.InvalidZeiKadRecordValue;
    const after_prefix = value[4..];
    const sep_index = std.mem.indexOfScalar(u8, after_prefix, ':') orelse return error.InvalidZeiKadRecordValue;
    if (sep_index == 0 or sep_index == after_prefix.len - 1) return error.InvalidZeiKadRecordValue;
    return std.fmt.parseInt(u64, after_prefix[0..sep_index], 10) catch error.InvalidZeiKadRecordValue;
}

fn freeOwnedStrings(allocator: std.mem.Allocator, items: *std.array_list.Managed([]u8)) void {
    for (items.items) |item| allocator.free(item);
    items.deinit();
}

test "kad store keeps the lexicographically newer record and expires old entries" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var first = kad.Record.init();
    defer first.deinit(std.testing.allocator);
    first.key = try std.testing.allocator.dupe(u8, "/zei/record-key");
    first.value = try std.testing.allocator.dupe(u8, "seq:1:alpha");

    try std.testing.expectEqual(PutRecordResult.inserted, try store.putRecord("/zei/record-key", &first, 1_000, .remote));

    var older = kad.Record.init();
    defer older.deinit(std.testing.allocator);
    older.key = try std.testing.allocator.dupe(u8, "/zei/record-key");
    older.value = try std.testing.allocator.dupe(u8, "seq:0:older");
    try std.testing.expectEqual(PutRecordResult.rejected_older, try store.putRecord("/zei/record-key", &older, 2_000, .remote));

    var newer = kad.Record.init();
    defer newer.deinit(std.testing.allocator);
    newer.key = try std.testing.allocator.dupe(u8, "/zei/record-key");
    newer.value = try std.testing.allocator.dupe(u8, "seq:2:zulu");
    try std.testing.expectEqual(PutRecordResult.replaced, try store.putRecord("/zei/record-key", &newer, 3_000, .remote));

    var stored = (try store.getRecord(std.testing.allocator, "/zei/record-key", 3_000)).?;
    defer stored.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("seq:2:zulu", stored.value);

    try std.testing.expect((try store.getRecord(std.testing.allocator, "/zei/record-key", 3_000 + max_record_age_ms + 1)) == null);
}

test "kad store rejects unsupported namespaces and conflicting same-version zei values" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var unsupported = kad.Record.init();
    defer unsupported.deinit(std.testing.allocator);
    unsupported.key = try std.testing.allocator.dupe(u8, "plain-key");
    unsupported.value = try std.testing.allocator.dupe(u8, "seq:1:value");
    try std.testing.expectError(error.UnsupportedKadRecordNamespace, store.putRecord("plain-key", &unsupported, 1_000, .remote));

    var first = kad.Record.init();
    defer first.deinit(std.testing.allocator);
    first.key = try std.testing.allocator.dupe(u8, "/zei/conflict");
    first.value = try std.testing.allocator.dupe(u8, "seq:7:alpha");
    try std.testing.expectEqual(PutRecordResult.inserted, try store.putRecord("/zei/conflict", &first, 1_000, .remote));

    var conflicting = kad.Record.init();
    defer conflicting.deinit(std.testing.allocator);
    conflicting.key = try std.testing.allocator.dupe(u8, "/zei/conflict");
    conflicting.value = try std.testing.allocator.dupe(u8, "seq:7:beta");
    try std.testing.expectError(error.ConflictingKadRecordVersion, store.putRecord("/zei/conflict", &conflicting, 2_000, .remote));
}

test "kad store tracks provider expiry and local republish eligibility" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    var provider = kad.Peer.init(std.testing.allocator);
    defer provider.deinit(std.testing.allocator);
    provider.id = try std.testing.allocator.dupe(u8, "provider-1");
    provider.connection = .CONNECTED;
    try provider.addrs.append(try std.testing.allocator.dupe(u8, "/ip4/127.0.0.1/tcp/24001"));

    try store.addProvider("content-key", &provider, 10_000, .local);

    var due_now = try store.dueLocalProviderRepublishes(std.testing.allocator, 10_000 + republish_interval_ms - 1);
    defer {
        for (due_now.items) |*item| item.deinit(std.testing.allocator);
        due_now.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), due_now.items.len);

    var due_later = try store.dueLocalProviderRepublishes(std.testing.allocator, 10_000 + republish_interval_ms);
    defer {
        for (due_later.items) |*item| item.deinit(std.testing.allocator);
        due_later.deinit();
    }
    try std.testing.expectEqual(@as(usize, 1), due_later.items.len);
    try std.testing.expectEqualStrings("content-key", due_later.items[0].key);
    try std.testing.expectEqualStrings("provider-1", due_later.items[0].provider.id);

    var providers = try store.getProviders(std.testing.allocator, "content-key", 10_000);
    defer {
        for (providers.items) |*peer| peer.deinit(std.testing.allocator);
        providers.deinit();
    }
    try std.testing.expectEqual(@as(usize, 1), providers.items.len);

    var expired = try store.getProviders(std.testing.allocator, "content-key", 10_000 + provider_validity_ms + 1);
    defer {
        for (expired.items) |*peer| peer.deinit(std.testing.allocator);
        expired.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), expired.items.len);
}
