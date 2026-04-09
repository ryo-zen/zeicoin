// address_book.zig - Thread-safe peerbook with per-address scoring, backoff,
// source tracking, and self-observation.

const std = @import("std");
const Multiaddr = @import("../multiaddr/multiaddr.zig").Multiaddr;
const IdentityKey = @import("peer_id.zig").IdentityKey;

const min_redial_ms: u64 = 30_000;
const max_backoff_ms: u64 = 300_000;
const peer_ttl_ms: u64 = 24 * 60 * 60 * 1000;

pub const HostComponent = struct {
    protocol: []const u8,
    value: []const u8,
};

pub const AddressSource = struct {
    identify: bool = false,
    peer_exchange: bool = false,
    bootstrap: bool = false,
    kad: bool = false,

    pub fn merge(self: *AddressSource, other: AddressSource) void {
        self.identify = self.identify or other.identify;
        self.peer_exchange = self.peer_exchange or other.peer_exchange;
        self.bootstrap = self.bootstrap or other.bootstrap;
        self.kad = self.kad or other.kad;
    }
};

pub const PeerAddrEntry = struct {
    addr: []u8,
    source: AddressSource,
    score: i32,
    fail_count: u32,
    next_dial_ms: u64,
    last_seen_ms: u64,
    last_success_ms: u64,
    last_failure_ms: u64,
};

pub const PeerEntry = struct {
    peer_id: ?[]u8,
    addresses: std.array_list.Managed(PeerAddrEntry),

    pub fn init(allocator: std.mem.Allocator, peer_id: ?[]const u8) !PeerEntry {
        return .{
            .peer_id = if (peer_id) |id| try allocator.dupe(u8, id) else null,
            .addresses = std.array_list.Managed(PeerAddrEntry).init(allocator),
        };
    }

    pub fn deinit(self: *PeerEntry, allocator: std.mem.Allocator) void {
        if (self.peer_id) |peer_id| allocator.free(peer_id);
        for (self.addresses.items) |addr| allocator.free(addr.addr);
        self.addresses.deinit();
    }
};

pub const PeerSnapshot = struct {
    addr: []u8,
    peer_id: ?[]u8,
    source: AddressSource,
    score: i32,
    fail_count: u32,
    next_dial_ms: u64,
    last_seen_ms: u64,
};

pub const SelfObservedAddr = struct {
    addr: []u8,
    source_peers: std.array_list.Managed([]u8),
    via_identify: bool,
    via_peer_exchange: bool,
    last_seen_ms: u64,
};

pub const SelfObservedSnapshot = struct {
    addr: []u8,
    source_count: usize,
    via_identify: bool,
    via_peer_exchange: bool,
    promoted: bool,
};

pub const AddressBook = struct {
    allocator: std.mem.Allocator,
    self_peer_id: []u8,
    mutex: std.Thread.Mutex = .{},
    peers: std.array_list.Managed(PeerEntry),
    self_observed: std.array_list.Managed(SelfObservedAddr),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, self_peer_id: []const u8) !Self {
        return .{
            .allocator = allocator,
            .self_peer_id = try allocator.dupe(u8, self_peer_id),
            .peers = std.array_list.Managed(PeerEntry).init(allocator),
            .self_observed = std.array_list.Managed(SelfObservedAddr).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.allocator.free(self.self_peer_id);
        for (self.peers.items) |entry| {
            var owned = entry;
            owned.deinit(self.allocator);
        }
        self.peers.deinit();
        for (self.self_observed.items) |*entry| {
            self.allocator.free(entry.addr);
            for (entry.source_peers.items) |peer_id| self.allocator.free(peer_id);
            entry.source_peers.deinit();
        }
        self.self_observed.deinit();
    }

    pub fn learn(self: *Self, addr: []const u8, now_ms: u64) !void {
        try self.learnPeer(null, &[_][]const u8{addr}, .{}, now_ms);
    }

    pub fn learnBootstrap(self: *Self, addr: []const u8, now_ms: u64) !void {
        try self.learnPeer(null, &[_][]const u8{addr}, .{ .bootstrap = true }, now_ms);
    }

    pub fn learnWithPeer(self: *Self, addr: []const u8, peer_id_text: ?[]const u8, now_ms: u64) !void {
        try self.learnPeer(peer_id_text, &[_][]const u8{addr}, .{}, now_ms);
    }

    pub fn learnAdvertised(self: *Self, addr: []const u8, source_peer_id: ?[]const u8, now_ms: u64) !void {
        try self.learnPeer(source_peer_id, &[_][]const u8{addr}, .{ .peer_exchange = true }, now_ms);
    }

    pub fn learnIdentifyAddr(self: *Self, addr: []const u8, peer_id_text: ?[]const u8, now_ms: u64) !void {
        try self.learnPeer(peer_id_text, &[_][]const u8{addr}, .{ .identify = true }, now_ms);
    }

    pub fn learnKadPeer(self: *Self, peer_id_text: ?[]const u8, addrs: []const []const u8, now_ms: u64) !void {
        try self.learnPeer(peer_id_text, addrs, .{ .kad = true }, now_ms);
    }

    pub fn learnPeer(
        self: *Self,
        peer_id_text: ?[]const u8,
        addrs: []const []const u8,
        source: AddressSource,
        now_ms: u64,
    ) !void {
        var canonical_addrs = std.array_list.Managed([]u8).init(self.allocator);
        defer freeOwnedSlices(self.allocator, &canonical_addrs);

        for (addrs) |addr| {
            const canonical_addr = try canonicalPeerAddr(self.allocator, addr, peer_id_text);
            errdefer self.allocator.free(canonical_addr);
            if (!isLikelyDialable(canonical_addr)) {
                self.allocator.free(canonical_addr);
                continue;
            }

            const canonical_peer_id = peerIdSlice(canonical_addr);
            if (canonical_peer_id) |peer_id| {
                if (std.mem.eql(u8, peer_id, self.self_peer_id)) {
                    if (source.identify or source.peer_exchange) {
                        try self.recordSelfObservation(canonical_addr, peer_id_text, source.identify, source.peer_exchange, now_ms);
                    }
                    self.allocator.free(canonical_addr);
                    continue;
                }
            }

            if (containsAddr(canonical_addrs.items, canonical_addr)) {
                self.allocator.free(canonical_addr);
                continue;
            }

            try canonical_addrs.append(canonical_addr);
        }

        if (canonical_addrs.items.len == 0) return;

        const resolved_peer_id = peerIdSlice(canonical_addrs.items[0]);

        self.mutex.lock();
        defer self.mutex.unlock();

        for (canonical_addrs.items) |canonical_addr| {
            const carried = if (resolved_peer_id != null) self.takeAnonymousStateLocked(canonical_addr) else null;
            const peer_idx = if (resolved_peer_id) |_|
                try self.ensurePeerEntryLocked(resolved_peer_id)
            else
                try self.ensureAnonymousPeerLocked(canonical_addr);
            try self.upsertPeerAddrLocked(&self.peers.items[peer_idx], canonical_addr, source, now_ms, carried);
        }
    }

    pub fn observeSelfFromIdentify(
        self: *Self,
        observed_addr: []const u8,
        source_peer_id: []const u8,
        listen_port: u16,
        now_ms: u64,
    ) !void {
        const host = extractHost(observed_addr) orelse return;
        const candidate = try std.fmt.allocPrint(
            self.allocator,
            "/{s}/{s}/tcp/{}/p2p/{s}",
            .{ host.protocol, host.value, listen_port, self.self_peer_id },
        );
        defer self.allocator.free(candidate);
        try self.recordSelfObservation(candidate, source_peer_id, true, false, now_ms);
    }

    pub fn markDialSuccess(self: *Self, addr: []const u8, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |*peer| {
            for (peer.addresses.items) |*entry| {
                if (!samePeerAddress(entry.addr, addr, peer.peer_id, peerIdSlice(addr))) continue;
                entry.score += 10;
                entry.fail_count = 0;
                entry.last_success_ms = now_ms;
                entry.next_dial_ms = now_ms + min_redial_ms;
                return;
            }
        }
    }

    pub fn markDialFailure(self: *Self, addr: []const u8, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |*peer| {
            for (peer.addresses.items) |*entry| {
                if (!samePeerAddress(entry.addr, addr, peer.peer_id, peerIdSlice(addr))) continue;
                applyDialFailure(entry, now_ms);
                return;
            }
        }
    }

    pub fn markPeerFailure(self: *Self, peer_id_text: []const u8, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |*peer| {
            if (peer.peer_id == null or !std.mem.eql(u8, peer.peer_id.?, peer_id_text)) continue;
            for (peer.addresses.items) |*entry| {
                applyDialFailure(entry, now_ms);
            }
            return;
        }
    }

    fn applyDialFailure(entry: *PeerAddrEntry, now_ms: u64) void {
        entry.score -= 20;
        entry.fail_count +|= 1;
        entry.last_failure_ms = now_ms;
        const exp = @min(entry.fail_count, 8);
        var backoff_ms: u64 = (@as(u64, 1) << @intCast(exp)) * 1000;
        if (backoff_ms > max_backoff_ms) backoff_ms = max_backoff_ms;
        entry.next_dial_ms = now_ms + backoff_ms;
    }

    pub fn chooseDialCandidate(
        self: *Self,
        allocator: std.mem.Allocator,
        now_ms: u64,
        local_listen_ma: []const u8,
    ) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const local_transport = transportSlice(local_listen_ma);
        var best: ?struct {
            peer_idx: usize,
            addr_idx: usize,
            score: i32,
            source_rank: u8,
        } = null;

        for (self.peers.items, 0..) |peer, peer_idx| {
            for (peer.addresses.items, 0..) |entry, addr_idx| {
                if (entry.next_dial_ms > now_ms) continue;
                if (std.mem.eql(u8, transportSlice(entry.addr), local_transport)) continue;
                if (peer.peer_id) |peer_id| {
                    if (std.mem.eql(u8, peer_id, self.self_peer_id)) continue;
                }
                if (!isLikelyDialable(entry.addr)) continue;
                const source_rank = dialSourceRank(entry.source);
                if (best == null or
                    source_rank > best.?.source_rank or
                    (source_rank == best.?.source_rank and entry.score > best.?.score))
                {
                    best = .{
                        .peer_idx = peer_idx,
                        .addr_idx = addr_idx,
                        .score = entry.score,
                        .source_rank = source_rank,
                    };
                }
            }
        }
        if (best == null) return null;

        self.peers.items[best.?.peer_idx].addresses.items[best.?.addr_idx].next_dial_ms = now_ms + min_redial_ms;
        return try allocator.dupe(u8, self.peers.items[best.?.peer_idx].addresses.items[best.?.addr_idx].addr);
    }

    pub fn pruneStale(self: *Self, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var peer_idx: usize = 0;
        while (peer_idx < self.peers.items.len) {
            var addr_idx: usize = 0;
            while (addr_idx < self.peers.items[peer_idx].addresses.items.len) {
                const entry = self.peers.items[peer_idx].addresses.items[addr_idx];
                if (now_ms -| entry.last_seen_ms <= peer_ttl_ms) {
                    addr_idx += 1;
                    continue;
                }
                self.freePeerAddrEntry(self.peers.items[peer_idx].addresses.swapRemove(addr_idx));
            }

            if (self.peers.items[peer_idx].addresses.items.len == 0) {
                var removed = self.peers.swapRemove(peer_idx);
                removed.deinit(self.allocator);
                continue;
            }
            peer_idx += 1;
        }
    }

    pub fn snapshot(self: *Self, allocator: std.mem.Allocator) !std.array_list.Managed(PeerSnapshot) {
        var out = std.array_list.Managed(PeerSnapshot).init(allocator);
        errdefer {
            for (out.items) |entry| {
                allocator.free(entry.addr);
                if (entry.peer_id) |peer_id| allocator.free(peer_id);
            }
            out.deinit();
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |peer| {
            for (peer.addresses.items) |entry| {
                try out.append(.{
                    .addr = try allocator.dupe(u8, entry.addr),
                    .peer_id = if (peer.peer_id) |peer_id| try allocator.dupe(u8, peer_id) else null,
                    .source = entry.source,
                    .score = entry.score,
                    .fail_count = entry.fail_count,
                    .next_dial_ms = entry.next_dial_ms,
                    .last_seen_ms = entry.last_seen_ms,
                });
            }
        }
        return out;
    }

    pub fn snapshotSelfObservations(self: *Self, allocator: std.mem.Allocator) !std.array_list.Managed(SelfObservedSnapshot) {
        var out = std.array_list.Managed(SelfObservedSnapshot).init(allocator);
        errdefer {
            for (out.items) |entry| allocator.free(entry.addr);
            out.deinit();
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.self_observed.items) |entry| {
            try out.append(.{
                .addr = try allocator.dupe(u8, entry.addr),
                .source_count = entry.source_peers.items.len,
                .via_identify = entry.via_identify,
                .via_peer_exchange = entry.via_peer_exchange,
                .promoted = entry.via_peer_exchange or entry.source_peers.items.len >= 2,
            });
        }
        return out;
    }

    pub fn snapshotPromotedSelfAddrs(self: *Self, allocator: std.mem.Allocator) !std.array_list.Managed([]u8) {
        var out = std.array_list.Managed([]u8).init(allocator);
        errdefer freeOwnedSlices(allocator, &out);

        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.self_observed.items) |entry| {
            if (!entry.via_peer_exchange and entry.source_peers.items.len < 2) continue;
            try out.append(try allocator.dupe(u8, entry.addr));
        }
        return out;
    }

    fn ensurePeerEntryLocked(self: *Self, peer_id: ?[]const u8) !usize {
        if (peer_id) |resolved| {
            for (self.peers.items, 0..) |peer, idx| {
                if (peer.peer_id == null) continue;
                if (std.mem.eql(u8, peer.peer_id.?, resolved)) return idx;
            }
        }

        try self.peers.append(try PeerEntry.init(self.allocator, peer_id));
        return self.peers.items.len - 1;
    }

    fn ensureAnonymousPeerLocked(self: *Self, canonical_addr: []const u8) !usize {
        for (self.peers.items, 0..) |peer, idx| {
            if (peer.peer_id != null) continue;
            for (peer.addresses.items) |entry| {
                if (std.mem.eql(u8, entry.addr, canonical_addr)) return idx;
            }
        }

        try self.peers.append(try PeerEntry.init(self.allocator, null));
        return self.peers.items.len - 1;
    }

    fn upsertPeerAddrLocked(
        self: *Self,
        peer: *PeerEntry,
        canonical_addr: []const u8,
        source: AddressSource,
        now_ms: u64,
        carried: ?PeerAddrEntry,
    ) !void {
        for (peer.addresses.items) |*existing| {
            if (!std.mem.eql(u8, existing.addr, canonical_addr)) continue;
            existing.last_seen_ms = @max(existing.last_seen_ms, now_ms);
            existing.source.merge(source);
            if (carried) |moved| self.mergePeerAddrState(existing, moved, now_ms);
            return;
        }

        var entry = PeerAddrEntry{
            .addr = try self.allocator.dupe(u8, canonical_addr),
            .source = source,
            .score = 0,
            .fail_count = 0,
            .next_dial_ms = 0,
            .last_seen_ms = now_ms,
            .last_success_ms = 0,
            .last_failure_ms = 0,
        };
        if (carried) |moved| self.mergePeerAddrState(&entry, moved, now_ms);
        try peer.addresses.append(entry);
    }

    fn recordSelfObservation(
        self: *Self,
        canonical_addr: []const u8,
        source_peer_id: ?[]const u8,
        via_identify: bool,
        via_peer_exchange: bool,
        now_ms: u64,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.self_observed.items) |*existing| {
            if (!std.mem.eql(u8, existing.addr, canonical_addr)) continue;
            existing.last_seen_ms = now_ms;
            existing.via_identify = existing.via_identify or via_identify;
            existing.via_peer_exchange = existing.via_peer_exchange or via_peer_exchange;
            try self.addObservationSource(existing, source_peer_id);
            return;
        }

        var sources = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (sources.items) |peer_id| self.allocator.free(peer_id);
            sources.deinit();
        }
        if (source_peer_id) |peer_id| {
            try sources.append(try self.allocator.dupe(u8, peer_id));
        }

        try self.self_observed.append(.{
            .addr = try self.allocator.dupe(u8, canonical_addr),
            .source_peers = sources,
            .via_identify = via_identify,
            .via_peer_exchange = via_peer_exchange,
            .last_seen_ms = now_ms,
        });
    }

    fn addObservationSource(self: *Self, entry: *SelfObservedAddr, source_peer_id: ?[]const u8) !void {
        const peer_id = source_peer_id orelse return;
        for (entry.source_peers.items) |existing| {
            if (std.mem.eql(u8, existing, peer_id)) return;
        }
        try entry.source_peers.append(try self.allocator.dupe(u8, peer_id));
    }

    fn takeAnonymousStateLocked(self: *Self, canonical_addr: []const u8) ?PeerAddrEntry {
        var peer_idx: usize = 0;
        while (peer_idx < self.peers.items.len) {
            if (self.peers.items[peer_idx].peer_id != null) {
                peer_idx += 1;
                continue;
            }

            var addr_idx: usize = 0;
            while (addr_idx < self.peers.items[peer_idx].addresses.items.len) {
                if (!std.mem.eql(u8, transportSlice(self.peers.items[peer_idx].addresses.items[addr_idx].addr), transportSlice(canonical_addr))) {
                    addr_idx += 1;
                    continue;
                }

                const carried = self.peers.items[peer_idx].addresses.swapRemove(addr_idx);
                if (self.peers.items[peer_idx].addresses.items.len == 0) {
                    var removed = self.peers.swapRemove(peer_idx);
                    removed.deinit(self.allocator);
                }
                return carried;
            }
            peer_idx += 1;
        }
        return null;
    }

    fn mergePeerAddrState(self: *Self, dst: *PeerAddrEntry, src: PeerAddrEntry, now_ms: u64) void {
        dst.source.merge(src.source);
        if (dst.score == 0 and src.score != 0) {
            dst.score = src.score;
        } else {
            dst.score = @max(dst.score, src.score);
        }
        dst.fail_count = @max(dst.fail_count, src.fail_count);
        dst.next_dial_ms = @max(dst.next_dial_ms, src.next_dial_ms);
        dst.last_seen_ms = @max(@max(dst.last_seen_ms, src.last_seen_ms), now_ms);
        dst.last_success_ms = @max(dst.last_success_ms, src.last_success_ms);
        dst.last_failure_ms = @max(dst.last_failure_ms, src.last_failure_ms);
        self.allocator.free(src.addr);
    }

    fn freePeerAddrEntry(self: *Self, entry: PeerAddrEntry) void {
        self.allocator.free(entry.addr);
    }
};

// --- Helper functions ---

pub fn canonicalPeerAddr(allocator: std.mem.Allocator, addr: []const u8, peer_id_text: ?[]const u8) ![]u8 {
    var multiaddr = try Multiaddr.create(allocator, addr);
    defer multiaddr.deinit();

    if (multiaddr.getPeerId() == null) {
        if (peer_id_text) |peer_id| {
            const peer_component = try std.fmt.allocPrint(allocator, "/p2p/{s}", .{peer_id});
            defer allocator.free(peer_component);

            var peer_multiaddr = try Multiaddr.create(allocator, peer_component);
            defer peer_multiaddr.deinit();
            try multiaddr.encapsulate(&peer_multiaddr);
        }
    }

    return allocator.dupe(u8, multiaddr.toString());
}

pub fn isLikelyDialable(addr: []const u8) bool {
    if (addr.len == 0) return false;
    const host = extractHost(addr) orelse return false;
    if (isWildcardHost(host)) return false;
    return std.mem.indexOf(u8, addr, "/tcp/") != null;
}

fn containsAddr(addrs: []const []const u8, candidate: []const u8) bool {
    for (addrs) |addr| {
        if (std.mem.eql(u8, addr, candidate)) return true;
    }
    return false;
}

pub fn transportSlice(addr: []const u8) []const u8 {
    const idx = std.mem.indexOf(u8, addr, "/p2p/") orelse return addr;
    return addr[0..idx];
}

pub fn peerIdSlice(addr: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, addr, "/p2p/") orelse return null;
    return addr[idx + "/p2p/".len ..];
}

pub fn samePeerAddress(a: []const u8, b: []const u8, a_peer: ?[]const u8, b_peer: ?[]const u8) bool {
    if (!std.mem.eql(u8, transportSlice(a), transportSlice(b))) return false;
    if (a_peer == null or b_peer == null) return true;
    return std.mem.eql(u8, a_peer.?, b_peer.?);
}

pub fn extractIp(multiaddr: []const u8) ?[]const u8 {
    const host = extractHost(multiaddr) orelse return null;
    if (!std.mem.eql(u8, host.protocol, "ip4")) return null;
    return host.value;
}

pub fn extractHost(multiaddr: []const u8) ?HostComponent {
    var it = std.mem.tokenizeScalar(u8, multiaddr, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, "ip4") or
            std.mem.eql(u8, part, "ip6") or
            std.mem.eql(u8, part, "dns") or
            std.mem.eql(u8, part, "dns4") or
            std.mem.eql(u8, part, "dns6") or
            std.mem.eql(u8, part, "dnsaddr"))
        {
            return .{
                .protocol = part,
                .value = it.next() orelse return null,
            };
        }
    }
    return null;
}

pub fn isWildcardListenAddr(multiaddr: []const u8) bool {
    const host = extractHost(multiaddr) orelse return false;
    return isWildcardHost(host);
}

fn isWildcardHost(host: HostComponent) bool {
    if (std.mem.eql(u8, host.protocol, "ip4")) {
        return std.mem.eql(u8, host.value, "0.0.0.0");
    }
    if (std.mem.eql(u8, host.protocol, "ip6")) {
        const parsed = std.Io.net.Ip6Address.parse(host.value, 0) catch return false;
        return std.mem.eql(u8, &parsed.bytes, &[_]u8{0} ** 16);
    }
    return false;
}

fn dialSourceRank(source: AddressSource) u8 {
    if (source.identify) return 4;
    if (source.kad) return 3;
    if (source.peer_exchange) return 2;
    if (source.bootstrap) return 1;
    return 0;
}

pub fn extractListenPort(multiaddr: []const u8) ?u16 {
    var it = std.mem.tokenizeScalar(u8, multiaddr, '/');
    while (it.next()) |part| {
        if (!std.mem.eql(u8, part, "tcp")) continue;
        const port_text = it.next() orelse return null;
        return std.fmt.parseInt(u16, port_text, 10) catch null;
    }
    return null;
}

pub fn freeOwnedSlices(allocator: std.mem.Allocator, list: *std.array_list.Managed([]u8)) void {
    for (list.items) |item| allocator.free(item);
    list.deinit();
}

// --- Tests ---

fn makeTestPeerId(allocator: std.mem.Allocator) ![]u8 {
    var identity = try IdentityKey.generate(allocator, std.testing.io);
    defer identity.deinit();
    return allocator.dupe(u8, identity.peer_id.toString());
}

test "address book learn and snapshot" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addr = try std.fmt.allocPrint(allocator, "/ip4/192.168.1.1/tcp/10801/p2p/{s}", .{remote_peer_id});
    defer allocator.free(addr);
    try book.learnWithPeer(addr, null, 1000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), snap.items.len);
    try std.testing.expect(std.mem.indexOf(u8, snap.items[0].addr, "192.168.1.1") != null);
    try std.testing.expectEqual(false, snap.items[0].source.bootstrap);
}

test "address book deduplicates same peer" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addr = try std.fmt.allocPrint(allocator, "/ip4/10.0.0.1/tcp/10801/p2p/{s}", .{remote_peer_id});
    defer allocator.free(addr);
    try book.learnWithPeer(addr, null, 1000);
    try book.learnWithPeer(addr, null, 2000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), snap.items.len);
}

test "address book aggregates multiple addresses under one peer" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addrs = [_][]const u8{
        "/ip4/10.0.0.1/tcp/10801",
        "/ip4/10.0.0.2/tcp/10801",
    };
    try book.learnPeer(remote_peer_id, &addrs, .{ .identify = true }, 1000);
    try book.learnPeer(remote_peer_id, &[_][]const u8{"/ip4/10.0.0.2/tcp/10801"}, .{ .kad = true }, 2000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), snap.items.len);
    for (snap.items) |entry| {
        try std.testing.expectEqualStrings(remote_peer_id, entry.peer_id.?);
    }

    var saw_identify = false;
    var saw_kad = false;
    for (snap.items) |entry| {
        saw_identify = saw_identify or entry.source.identify;
        if (std.mem.indexOf(u8, entry.addr, "10.0.0.2") != null) {
            try std.testing.expect(entry.source.kad);
            saw_kad = true;
        }
    }
    try std.testing.expect(saw_identify);
    try std.testing.expect(saw_kad);
}

test "address book migrates anonymous address state when peer id becomes known" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addr = "/ip4/10.0.0.1/tcp/10801";
    try book.learnBootstrap(addr, 1000);
    book.markDialFailure(addr, 2000);
    try book.learnWithPeer(addr, remote_peer_id, 3000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), snap.items.len);
    try std.testing.expectEqualStrings(remote_peer_id, snap.items[0].peer_id.?);
    try std.testing.expect(snap.items[0].source.bootstrap);
    try std.testing.expectEqual(@as(i32, -20), snap.items[0].score);
    try std.testing.expectEqual(@as(u32, 1), snap.items[0].fail_count);
}

test "address book scoring on success and failure" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addr = try std.fmt.allocPrint(allocator, "/ip4/10.0.0.1/tcp/10801/p2p/{s}", .{remote_peer_id});
    defer allocator.free(addr);
    try book.learnWithPeer(addr, null, 1000);

    book.markDialSuccess(addr, 2000);
    {
        var snap = try book.snapshot(allocator);
        defer {
            for (snap.items) |entry| {
                allocator.free(entry.addr);
                if (entry.peer_id) |peer_id| allocator.free(peer_id);
            }
            snap.deinit();
        }
        try std.testing.expectEqual(@as(i32, 10), snap.items[0].score);
    }

    book.markDialFailure(addr, 3000);
    {
        var snap = try book.snapshot(allocator);
        defer {
            for (snap.items) |entry| {
                allocator.free(entry.addr);
                if (entry.peer_id) |peer_id| allocator.free(peer_id);
            }
            snap.deinit();
        }
        try std.testing.expectEqual(@as(i32, -10), snap.items[0].score);
    }
}

test "address book can penalize stable addresses by peer id" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    try book.learnIdentifyAddr("/ip4/10.0.0.1/tcp/10801", remote_peer_id, 1000);
    book.markPeerFailure(remote_peer_id, 2000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), snap.items.len);
    try std.testing.expectEqualStrings(remote_peer_id, snap.items[0].peer_id.?);
    try std.testing.expectEqual(@as(i32, -20), snap.items[0].score);
    try std.testing.expectEqual(@as(u32, 1), snap.items[0].fail_count);
    try std.testing.expect(snap.items[0].source.identify);
}

test "address book tags bootstrap and peer exchange sources" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    try book.learnBootstrap("/ip4/10.0.0.1/tcp/10801", 1000);
    try book.learnAdvertised("/ip4/10.0.0.1/tcp/10801", remote_peer_id, 2000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), snap.items.len);
    try std.testing.expect(snap.items[0].source.bootstrap);
    try std.testing.expect(snap.items[0].source.peer_exchange);
}

test "address book prefers stable advertised addresses over observed session addresses" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    try book.learnWithPeer("/ip4/172.33.0.11/tcp/48708", remote_peer_id, 1000);
    try book.learnIdentifyAddr("/ip4/172.33.0.11/tcp/10801", remote_peer_id, 2000);

    const candidate = (try book.chooseDialCandidate(
        allocator,
        3000,
        "/ip4/172.33.0.12/tcp/10801",
    )).?;
    defer allocator.free(candidate);

    try std.testing.expect(std.mem.indexOf(u8, candidate, "/tcp/10801") != null);
    try std.testing.expect(std.mem.indexOf(u8, candidate, "/tcp/48708") == null);
}

test "address book prunes stale peers" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addr = try std.fmt.allocPrint(allocator, "/ip4/10.0.0.1/tcp/10801/p2p/{s}", .{remote_peer_id});
    defer allocator.free(addr);
    try book.learnWithPeer(addr, null, 1000);
    book.pruneStale(1000 + peer_ttl_ms + 1);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), snap.items.len);
}

test "address book skips self addresses" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    const addr = try std.fmt.allocPrint(allocator, "/ip4/10.0.0.1/tcp/10801/p2p/{s}", .{local_peer_id});
    defer allocator.free(addr);
    try book.learnWithPeer(addr, null, 1000);

    var snap = try book.snapshot(allocator);
    defer {
        for (snap.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snap.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), snap.items.len);
}

test "helper: isLikelyDialable" {
    try std.testing.expect(isLikelyDialable("/ip4/10.0.0.1/tcp/10801"));
    try std.testing.expect(isLikelyDialable("/ip6/2001:db8::1/tcp/10801"));
    try std.testing.expect(isLikelyDialable("/dns/bootstrap.example.com/tcp/10801"));
    try std.testing.expect(isLikelyDialable("/dns6/bootstrap.example.com/tcp/10801"));
    try std.testing.expect(!isLikelyDialable("/ip4/0.0.0.0/tcp/10801"));
    try std.testing.expect(!isLikelyDialable("/ip6/::/tcp/10801"));
    try std.testing.expect(!isLikelyDialable(""));
    try std.testing.expect(!isLikelyDialable("/dns/bootstrap.example.com/udp/10801"));
}

test "helper: peerIdSlice and transportSlice" {
    const addr = "/ip4/10.0.0.1/tcp/10801/p2p/12D3KooWPeerA";
    try std.testing.expectEqualStrings("12D3KooWPeerA", peerIdSlice(addr).?);
    try std.testing.expectEqualStrings("/ip4/10.0.0.1/tcp/10801", transportSlice(addr));

    try std.testing.expectEqual(@as(?[]const u8, null), peerIdSlice("/ip4/10.0.0.1/tcp/10801"));
    try std.testing.expectEqualStrings("/ip4/10.0.0.1/tcp/10801", transportSlice("/ip4/10.0.0.1/tcp/10801"));
}

test "helper: extractIp and extractListenPort" {
    try std.testing.expectEqualStrings("172.31.0.11", extractIp("/ip4/172.31.0.11/tcp/42001").?);
    try std.testing.expectEqual(@as(?u16, 10811), extractListenPort("/ip4/0.0.0.0/tcp/10811"));
}

test "helper: extractHost supports ip6 and dns" {
    const ip6 = extractHost("/ip6/2001:db8::1/tcp/42001").?;
    try std.testing.expectEqualStrings("ip6", ip6.protocol);
    try std.testing.expectEqualStrings("2001:db8::1", ip6.value);

    const dns = extractHost("/dns4/bootstrap.example.com/tcp/42001").?;
    try std.testing.expectEqualStrings("dns4", dns.protocol);
    try std.testing.expectEqualStrings("bootstrap.example.com", dns.value);
}

test "observeSelfFromIdentify preserves ipv6 observations" {
    const allocator = std.testing.allocator;
    const local_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(local_peer_id);
    const remote_peer_id = try makeTestPeerId(allocator);
    defer allocator.free(remote_peer_id);

    var book = try AddressBook.init(allocator, local_peer_id);
    defer book.deinit();

    try book.observeSelfFromIdentify("/ip6/2001:db8::99/tcp/55000", remote_peer_id, 10811, 1000);

    var promoted = try book.snapshotSelfObservations(allocator);
    defer {
        for (promoted.items) |entry| allocator.free(entry.addr);
        promoted.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), promoted.items.len);
    try std.testing.expect(std.mem.startsWith(u8, promoted.items[0].addr, "/ip6/2001:db8::99/tcp/10811/"));
}
