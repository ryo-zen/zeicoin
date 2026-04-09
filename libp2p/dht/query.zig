const std = @import("std");
const libp2p = @import("../api.zig");
const routing_table_mod = @import("routing_table.zig");
const kad = @import("message.zig");
const store_mod = @import("store.zig");
const address_book_mod = @import("../peer/address_book.zig");

const Multiaddr = libp2p.Multiaddr;
const Host = libp2p.Host;
const PeerId = libp2p.PeerId;
const AddressBook = libp2p.AddressBook;
const ConnInfo = libp2p.ConnInfo;
const yamux = libp2p.yamux;

pub const alpha_default: usize = 10;
pub const bucket_size: usize = routing_table_mod.bucket_size;
pub const refresh_interval_default_ms: u64 = 10 * 60 * 1000;
pub const query_timeout_default_ms: u64 = 10 * 1000;
pub const max_inbound_streams_per_peer_default: usize = 4;
pub const max_inbound_streams_global_default: usize = 32;
const provider_key_max_len: usize = 80;

pub const BootstrapRunResult = struct {
    lookups_started: usize = 0,
    timed_out: bool = false,
};

pub const PeerInfo = struct {
    peer_id: []u8,
    addrs: std.array_list.Managed([]u8),
    connection: routing_table_mod.ConnectionType,

    pub fn init(allocator: std.mem.Allocator) PeerInfo {
        return .{
            .peer_id = &.{},
            .addrs = std.array_list.Managed([]u8).init(allocator),
            .connection = .not_connected,
        };
    }

    pub fn deinit(self: *PeerInfo, allocator: std.mem.Allocator) void {
        if (self.peer_id.len > 0) allocator.free(self.peer_id);
        address_book_mod.freeOwnedSlices(allocator, &self.addrs);
    }

    pub fn clone(self: *const PeerInfo, allocator: std.mem.Allocator) !PeerInfo {
        var out = PeerInfo.init(allocator);
        errdefer out.deinit(allocator);
        out.peer_id = try allocator.dupe(u8, self.peer_id);
        out.connection = self.connection;
        for (self.addrs.items) |addr| try out.addrs.append(try allocator.dupe(u8, addr));
        return out;
    }
};

pub const LookupResult = struct {
    peers: std.array_list.Managed(PeerInfo),

    pub fn deinit(self: *LookupResult, allocator: std.mem.Allocator) void {
        for (self.peers.items) |*peer| peer.deinit(allocator);
        self.peers.deinit();
    }
};

const Candidate = struct {
    peer: PeerInfo,
    distance: [32]u8,
    queried: bool,
    responded: bool,

    fn deinit(self: *Candidate, allocator: std.mem.Allocator) void {
        self.peer.deinit(allocator);
    }
};

const CandidateDistance = struct {
    fn lessThan(_: void, lhs: Candidate, rhs: Candidate) bool {
        return std.mem.order(u8, &lhs.distance, &rhs.distance) == .lt;
    }
};

pub const QueryService = struct {
    allocator: std.mem.Allocator,
    host: *Host,
    routing_table: *routing_table_mod.RoutingTable,
    address_book: *AddressBook,
    store: store_mod.Store,
    mode: routing_table_mod.KadMode,
    alpha: usize,
    refresh_interval_ms: u64,
    query_timeout_ms: u64,
    lookup_override: ?*const fn (service: *Self, io: std.Io, target_peer_id: []const u8, userdata: ?*anyopaque) anyerror!LookupResult,
    lookup_override_userdata: ?*anyopaque,
    clock_ms_fn: *const fn (userdata: ?*anyopaque) u64,
    clock_userdata: ?*anyopaque,
    inbound_limits_mutex: std.Thread.Mutex,
    inbound_streams_global: usize,
    inbound_streams_per_peer: std.StringHashMap(usize),
    max_inbound_streams_per_peer: usize,
    max_inbound_streams_global: usize,

    const Self = @This();
    const RequestContext = struct {
        remote_peer_id: ?[]const u8 = null,
        remote_addr: ?std.Io.net.IpAddress = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        host: *Host,
        routing_table: *routing_table_mod.RoutingTable,
        address_book: *AddressBook,
        mode: routing_table_mod.KadMode,
    ) Self {
        return .{
            .allocator = allocator,
            .host = host,
            .routing_table = routing_table,
            .address_book = address_book,
            .store = store_mod.Store.init(allocator),
            .mode = mode,
            .alpha = alpha_default,
            .refresh_interval_ms = refresh_interval_default_ms,
            .query_timeout_ms = query_timeout_default_ms,
            .lookup_override = null,
            .lookup_override_userdata = null,
            .clock_ms_fn = defaultClockMs,
            .clock_userdata = null,
            .inbound_limits_mutex = .{},
            .inbound_streams_global = 0,
            .inbound_streams_per_peer = std.StringHashMap(usize).init(allocator),
            .max_inbound_streams_per_peer = max_inbound_streams_per_peer_default,
            .max_inbound_streams_global = max_inbound_streams_global_default,
        };
    }

    pub fn deinit(self: *Self) void {
        var inbound_it = self.inbound_streams_per_peer.iterator();
        while (inbound_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.inbound_streams_per_peer.deinit();
        self.store.deinit();
    }

    pub fn register(self: *Self) !void {
        if (self.mode != .server) return;
        if (self.host.registry.has(kad.PROTOCOL_ID)) return;
        try self.host.setStreamHandler(kad.PROTOCOL_ID, .{
            .func = inboundHandler,
            .userdata = self,
        });
    }

    pub fn sendFindNode(
        self: *Self,
        io: std.Io,
        peer: *const PeerInfo,
        target_peer_id: []const u8,
    ) !kad.Message {
        const session = try self.dialPeer(io, peer);
        var stream = try self.host.newStream(io, session, kad.PROTOCOL_ID);
        defer stream.deinit();

        var request = kad.Message.init(self.allocator);
        defer request.deinit(self.allocator);
        request.type = .FIND_NODE;
        request.key = try self.allocator.dupe(u8, target_peer_id);

        try kad.sendRequest(self.allocator, io, &stream, &request);
        const response = kad.readResponse(self.allocator, io, &stream) catch |err| {
            stream.close() catch {};
            return err;
        };
        try stream.close();
        return response;
    }

    pub fn putValue(self: *Self, io: std.Io, key: []const u8, value: []const u8) !void {
        var record = kad.Record.init();
        defer record.deinit(self.allocator);
        record.key = try self.allocator.dupe(u8, key);
        record.value = try self.allocator.dupe(u8, value);

        _ = try self.store.putRecord(key, &record, nowMs(), .local);
        _ = try self.publishValueRecord(io, key, &record);
    }

    pub fn addSelfAsProvider(self: *Self, io: std.Io, key: []const u8) !void {
        var provider = try self.makeSelfProviderPeer();
        defer provider.deinit(self.allocator);

        try self.store.addProvider(key, &provider, nowMs(), .local);
        _ = try self.publishProviderRecord(io, key, &provider);
    }

    pub fn iterativeFindNode(
        self: *Self,
        io: std.Io,
        target_peer_id: []const u8,
    ) !LookupResult {
        var candidates = std.array_list.Managed(Candidate).init(self.allocator);
        defer {
            for (candidates.items) |*candidate| candidate.deinit(self.allocator);
            candidates.deinit();
        }

        var seeds = try self.routing_table.closestPeers(self.allocator, target_peer_id, bucket_size);
        defer {
            for (seeds.items) |*snapshot| snapshot.deinit(self.allocator);
            seeds.deinit();
        }
        for (seeds.items) |*snapshot| {
            var info = try peerInfoFromSnapshot(self.allocator, snapshot);
            errdefer info.deinit(self.allocator);
            try insertOrMergeCandidate(self.allocator, &candidates, target_peer_id, info);
        }

        while (true) {
            if (candidates.items.len == 0) break;
            if (topClosestResponded(candidates.items)) break;

            var batch = std.array_list.Managed(usize).init(self.allocator);
            defer batch.deinit();

            for (candidates.items, 0..) |*candidate, index| {
                if (candidate.queried) continue;
                candidate.queried = true;
                try batch.append(index);
                if (batch.items.len == self.alpha) break;
            }

            if (batch.items.len == 0) break;

            const Task = struct {
                service: *Self,
                peer: PeerInfo,
                target_peer_id: []u8,
                io: std.Io,

                fn run(task: *@This()) anyerror!kad.Message {
                    defer task.peer.deinit(task.service.allocator);
                    defer task.service.allocator.free(task.target_peer_id);
                    return try task.service.sendFindNode(task.io, &task.peer, task.target_peer_id);
                }
            };

            var tasks = try self.allocator.alloc(Task, batch.items.len);
            defer self.allocator.free(tasks);
            var futures = try self.allocator.alloc(@TypeOf(try io.concurrent(Task.run, .{&tasks[0]})), batch.items.len);
            defer self.allocator.free(futures);

            for (batch.items, 0..) |candidate_index, batch_index| {
                tasks[batch_index] = .{
                    .service = self,
                    .peer = try candidates.items[candidate_index].peer.clone(self.allocator),
                    .target_peer_id = try self.allocator.dupe(u8, target_peer_id),
                    .io = io,
                };
                futures[batch_index] = try io.concurrent(Task.run, .{&tasks[batch_index]});
            }

            for (batch.items, 0..) |candidate_index, batch_index| {
                var response = futures[batch_index].await(io) catch continue;
                defer response.deinit(self.allocator);

                candidates.items[candidate_index].responded = true;
                try self.upsertRoutingPeer(
                    candidates.items[candidate_index].peer.peer_id,
                    candidates.items[candidate_index].peer.addrs.items,
                    candidates.items[candidate_index].peer.connection,
                );

                for (response.closer_peers.items) |*wire_peer| {
                    var peer = try peerInfoFromWire(self.allocator, wire_peer);
                    errdefer peer.deinit(self.allocator);
                    if (std.mem.eql(u8, peer.peer_id, self.host.identity.peer_id.toString())) {
                        peer.deinit(self.allocator);
                        continue;
                    }
                    try self.learnDiscoveredPeer(&peer);
                    try insertOrMergeCandidate(self.allocator, &candidates, target_peer_id, peer);
                }
            }
        }

        var out = LookupResult{
            .peers = std.array_list.Managed(PeerInfo).init(self.allocator),
        };
        errdefer out.deinit(self.allocator);

        const limit = @min(bucket_size, candidates.items.len);
        for (candidates.items[0..limit]) |*candidate| {
            try out.peers.append(try candidate.peer.clone(self.allocator));
        }

        return out;
    }

    pub fn bootstrapOnce(self: *Self, io: std.Io) !BootstrapRunResult {
        const start_ms = self.clock_ms_fn(self.clock_userdata);
        var result = BootstrapRunResult{};
        self.store.pruneExpired(start_ms);

        try self.performBootstrapLookup(io, self.host.identity.peer_id.getBytes(), &result);
        if (self.clock_ms_fn(self.clock_userdata) - start_ms >= self.query_timeout_ms) {
            result.timed_out = true;
            return result;
        }

        var buckets = try self.routing_table.nonEmptyBucketIndices(self.allocator);
        defer buckets.deinit();

        for (buckets.items, 0..) |bucket_index, ordinal| {
            if (self.clock_ms_fn(self.clock_userdata) - start_ms >= self.query_timeout_ms) {
                result.timed_out = true;
                break;
            }

            const prefix = try std.fmt.allocPrint(self.allocator, "kad-refresh-{x}-{d}", .{
                start_ms,
                bucket_index,
            });
            defer self.allocator.free(prefix);

            const refresh_peer_id = try self.routing_table.allocRefreshPeerIdForBucket(
                self.allocator,
                prefix,
                bucket_index,
                ordinal,
            );
            defer self.allocator.free(refresh_peer_id);

            try self.performBootstrapLookup(io, refresh_peer_id, &result);

            if (self.clock_ms_fn(self.clock_userdata) - start_ms >= self.query_timeout_ms) {
                result.timed_out = true;
                break;
            }
        }

        try self.republishDue(io, self.clock_ms_fn(self.clock_userdata));
        return result;
    }

    pub fn refreshLoop(self: *Self, io: std.Io, stop: *const std.atomic.Value(bool)) !void {
        _ = try self.bootstrapOnce(io);

        while (!stop.load(.acquire)) {
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(self.refresh_interval_ms)), .awake) catch |err| switch (err) {
                error.Canceled => return,
                else => return err,
            };
            if (stop.load(.acquire)) break;
            _ = self.bootstrapOnce(io) catch {};
        }
    }

    fn inboundHandler(stream: *yamux.Stream, conn_info: ConnInfo, userdata: ?*anyopaque) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(userdata.?));
        if (self.mode != .server) return error.NotServerMode;

        defer stream.close() catch {};

        const remote_peer_id = if (conn_info.remote_peer_id) |peer_id| peer_id.toString() else null;
        if (!try self.tryAcquireInboundStream(remote_peer_id)) {
            self.penalizeInboundPeer(conn_info);
            return error.KadInboundStreamLimitExceeded;
        }
        defer self.releaseInboundStream(remote_peer_id);

        while (true) {
            var request = kad.readMessageFrame(self.allocator, stream.session.session_io, stream) catch |err| switch (err) {
                error.EndOfStream => return,
                error.MessageTooLarge,
                error.InvalidWireType,
                error.InvalidFieldLength,
                error.TruncatedFrame,
                => {
                    self.penalizeInboundPeer(conn_info);
                    return err;
                },
                else => return err,
            };
            defer request.deinit(self.allocator);

            var response = try self.handleRequest(&request, .{
                .remote_peer_id = if (conn_info.remote_peer_id) |peer_id| peer_id.toString() else null,
                .remote_addr = conn_info.remote_addr,
            });
            defer if (response) |*msg| msg.deinit(self.allocator);

            if (response) |*msg| {
                kad.writeMessageFrame(self.allocator, stream.session.session_io, stream, msg) catch |err| switch (err) {
                    error.MessageTooLarge => {
                        self.penalizeInboundPeer(conn_info);
                        return err;
                    },
                    else => return err,
                };
            }
        }
    }

    fn tryAcquireInboundStream(self: *Self, remote_peer_id: ?[]const u8) !bool {
        self.inbound_limits_mutex.lock();
        defer self.inbound_limits_mutex.unlock();

        if (self.inbound_streams_global >= self.max_inbound_streams_global) return false;
        if (remote_peer_id) |peer_id| {
            if (self.inbound_streams_per_peer.getPtr(peer_id)) |current| {
                if (current.* >= self.max_inbound_streams_per_peer) return false;
                current.* += 1;
            } else {
                const owned_key = try self.allocator.dupe(u8, peer_id);
                errdefer self.allocator.free(owned_key);
                try self.inbound_streams_per_peer.putNoClobber(owned_key, 1);
            }
        }
        self.inbound_streams_global += 1;
        return true;
    }

    fn releaseInboundStream(self: *Self, remote_peer_id: ?[]const u8) void {
        self.inbound_limits_mutex.lock();
        defer self.inbound_limits_mutex.unlock();

        if (self.inbound_streams_global > 0) self.inbound_streams_global -= 1;
        if (remote_peer_id) |peer_id| {
            if (self.inbound_streams_per_peer.getPtr(peer_id)) |current| {
                if (current.* <= 1) {
                    if (self.inbound_streams_per_peer.fetchRemove(peer_id)) |removed| {
                        self.allocator.free(removed.key);
                    }
                } else {
                    current.* -= 1;
                }
            }
        }
    }

    fn penalizeInboundPeer(self: *Self, conn_info: ConnInfo) void {
        const remote_peer_id = conn_info.remote_peer_id orelse return;
        self.address_book.markPeerFailure(remote_peer_id.toString(), nowMs());
    }

    fn handleRequest(self: *Self, request: *const kad.Message, ctx: RequestContext) !?kad.Message {
        self.store.pruneExpired(nowMs());
        switch (request.type) {
            .FIND_NODE => return try self.handleFindNode(request),
            .GET_VALUE => return try self.handleGetValue(request),
            .PUT_VALUE => return try self.handlePutValue(request),
            .ADD_PROVIDER => return try self.handleAddProvider(request, ctx),
            .GET_PROVIDERS => return try self.handleGetProviders(request),
            .PING => {
                var response = kad.Message.init(self.allocator);
                response.type = .PING;
                if (request.key.len > 0) response.key = try self.allocator.dupe(u8, request.key);
                return response;
            },
        }
    }

    fn handleFindNode(self: *Self, request: *const kad.Message) !kad.Message {
        var response = kad.Message.init(self.allocator);
        errdefer response.deinit(self.allocator);

        response.type = .FIND_NODE;
        response.key = try self.allocator.dupe(u8, request.key);
        try self.appendCloserPeers(&response, request.key);

        return response;
    }

    fn republishDue(self: *Self, io: std.Io, now_ms: u64) !void {
        var values = try self.store.dueLocalValueRepublishes(self.allocator, now_ms);
        defer {
            for (values.items) |*item| item.deinit(self.allocator);
            values.deinit();
        }
        for (values.items) |*item| {
            if (try self.publishValueRecord(io, item.key, &item.record)) {
                self.store.markValueRepublished(item.key, now_ms);
            }
        }

        var providers = try self.store.dueLocalProviderRepublishes(self.allocator, now_ms);
        defer {
            for (providers.items) |*item| item.deinit(self.allocator);
            providers.deinit();
        }
        for (providers.items) |*item| {
            if (try self.publishProviderRecord(io, item.key, &item.provider)) {
                self.store.markProviderRepublished(item.key, item.provider.id, now_ms);
            }
        }
    }

    fn publishValueRecord(self: *Self, io: std.Io, key: []const u8, record: *const kad.Record) !bool {
        var lookup = try self.runLookup(io, key);
        defer lookup.deinit(self.allocator);
        if (lookup.peers.items.len == 0) return false;

        var any_success = false;
        for (lookup.peers.items) |*peer| {
            self.sendPutValue(io, peer, key, record) catch continue;
            any_success = true;
        }
        return any_success;
    }

    fn publishProviderRecord(self: *Self, io: std.Io, key: []const u8, provider: *const kad.Peer) !bool {
        var lookup = try self.runLookup(io, key);
        defer lookup.deinit(self.allocator);
        if (lookup.peers.items.len == 0) return false;

        var any_success = false;
        for (lookup.peers.items) |*peer| {
            self.sendAddProvider(io, peer, key, provider) catch continue;
            any_success = true;
        }
        return any_success;
    }

    fn sendPutValue(
        self: *Self,
        io: std.Io,
        peer: *const PeerInfo,
        key: []const u8,
        record: *const kad.Record,
    ) !void {
        const session = try self.dialPeer(io, peer);
        var stream = try self.host.newStream(io, session, kad.PROTOCOL_ID);
        defer stream.deinit();

        var request = kad.Message.init(self.allocator);
        defer request.deinit(self.allocator);
        request.type = .PUT_VALUE;
        request.key = try self.allocator.dupe(u8, key);
        request.record = try cloneKadRecord(self.allocator, record);

        try kad.sendRequest(self.allocator, io, &stream, &request);
        var response = kad.readResponse(self.allocator, io, &stream) catch |err| {
            stream.close() catch {};
            return err;
        };
        defer response.deinit(self.allocator);
        try stream.close();

        if (response.type != .PUT_VALUE) return error.InvalidKadResponseType;
    }

    fn sendAddProvider(
        self: *Self,
        io: std.Io,
        peer: *const PeerInfo,
        key: []const u8,
        provider: *const kad.Peer,
    ) !void {
        const session = try self.dialPeer(io, peer);
        var stream = try self.host.newStream(io, session, kad.PROTOCOL_ID);
        defer stream.deinit();

        var request = kad.Message.init(self.allocator);
        defer request.deinit(self.allocator);
        request.type = .ADD_PROVIDER;
        request.key = try self.allocator.dupe(u8, key);
        try request.provider_peers.append(try cloneKadPeer(self.allocator, provider));

        try kad.sendRequest(self.allocator, io, &stream, &request);
        stream.close() catch {};
    }

    fn makeSelfProviderPeer(self: *Self) !kad.Peer {
        var provider = kad.Peer.init(self.allocator);
        errdefer provider.deinit(self.allocator);
        provider.id = try self.allocator.dupe(u8, self.host.identity.peer_id.toString());
        provider.connection = .CONNECTED;

        if (self.host.listen_addr) |*listen_addr| {
            try provider.addrs.append(try self.allocator.dupe(u8, listen_addr.getBytesAddress()));
        } else {
            return error.NoListenAddress;
        }
        return provider;
    }

    fn handleGetValue(self: *Self, request: *const kad.Message) !kad.Message {
        if (request.key.len == 0) return error.EmptyKadRecordKey;

        var response = kad.Message.init(self.allocator);
        errdefer response.deinit(self.allocator);
        response.type = .GET_VALUE;
        response.key = try self.allocator.dupe(u8, request.key);

        response.record = try self.store.getRecord(self.allocator, request.key, nowMs());
        try self.appendCloserPeers(&response, request.key);
        return response;
    }

    fn handlePutValue(self: *Self, request: *const kad.Message) !kad.Message {
        if (request.record == null) return error.MissingKadRecord;
        const record = &request.record.?;

        const put_result = try self.store.putRecord(request.key, record, nowMs(), .remote);
        if (put_result == .rejected_older) return error.StaleKadRecord;

        var response = kad.Message.init(self.allocator);
        errdefer response.deinit(self.allocator);
        response.type = .PUT_VALUE;
        response.key = try self.allocator.dupe(u8, request.key);
        response.record = try self.store.getRecord(self.allocator, request.key, nowMs());
        return response;
    }

    fn handleAddProvider(self: *Self, request: *const kad.Message, ctx: RequestContext) !?kad.Message {
        if (request.key.len == 0) return error.EmptyKadProviderKey;
        if (request.key.len > provider_key_max_len) return error.KadProviderKeyTooLarge;
        const remote_peer_id = ctx.remote_peer_id orelse return error.UnknownKadProviderSender;

        var accepted: usize = 0;
        for (request.provider_peers.items) |*provider| {
            const normalized_provider_id = normalizeProviderPeerId(self.allocator, provider.id) catch continue;
            defer self.allocator.free(normalized_provider_id);
            if (!std.mem.eql(u8, normalized_provider_id, remote_peer_id)) continue;
            if (provider.addrs.items.len == 0) continue;

            var normalized_provider = try cloneKadPeer(self.allocator, provider);
            defer normalized_provider.deinit(self.allocator);
            self.allocator.free(normalized_provider.id);
            normalized_provider.id = try self.allocator.dupe(u8, normalized_provider_id);

            try self.store.addProvider(request.key, &normalized_provider, nowMs(), .remote);
            accepted += 1;
        }
        if (accepted == 0) return error.NoValidKadProvider;
        return null;
    }

    fn handleGetProviders(self: *Self, request: *const kad.Message) !kad.Message {
        if (request.key.len == 0) return error.EmptyKadProviderKey;
        if (request.key.len > provider_key_max_len) return error.KadProviderKeyTooLarge;

        var response = kad.Message.init(self.allocator);
        errdefer response.deinit(self.allocator);
        response.type = .GET_PROVIDERS;
        response.key = try self.allocator.dupe(u8, request.key);
        response.provider_peers = try self.store.getProviders(self.allocator, request.key, nowMs());
        try self.appendCloserPeers(&response, request.key);
        return response;
    }

    fn appendCloserPeers(self: *Self, response: *kad.Message, key: []const u8) !void {
        var closest = try self.routing_table.closestPeers(self.allocator, key, bucket_size);
        defer {
            for (closest.items) |*snapshot| snapshot.deinit(self.allocator);
            closest.deinit();
        }

        for (closest.items) |*snapshot| {
            var peer = try wirePeerFromSnapshot(self.allocator, snapshot);
            errdefer peer.deinit(self.allocator);
            try response.closer_peers.append(peer);
        }
    }

    fn dialPeer(self: *Self, io: std.Io, peer: *const PeerInfo) !*yamux.Session {
        var last_err: ?anyerror = null;
        for (peer.addrs.items) |addr_text| {
            var multiaddr = Multiaddr.create(self.allocator, addr_text) catch |err| {
                last_err = err;
                continue;
            };
            defer multiaddr.deinit();

            const session = self.host.dial(io, &multiaddr) catch |err| {
                last_err = err;
                continue;
            };
            return session;
        }
        return last_err orelse error.NoDialableAddress;
    }

    fn learnDiscoveredPeer(self: *Self, peer: *const PeerInfo) !void {
        try self.address_book.learnKadPeer(peer.peer_id, peer.addrs.items, nowMs());
        try self.upsertRoutingPeer(peer.peer_id, peer.addrs.items, peer.connection);
    }

    fn performBootstrapLookup(self: *Self, io: std.Io, target_peer_id: []const u8, result: *BootstrapRunResult) !void {
        result.lookups_started += 1;
        var lookup = try self.runLookup(io, target_peer_id);
        defer lookup.deinit(self.allocator);
    }

    fn runLookup(self: *Self, io: std.Io, target_peer_id: []const u8) !LookupResult {
        if (self.lookup_override) |override| {
            return try override(self, io, target_peer_id, self.lookup_override_userdata);
        }
        return try self.iterativeFindNode(io, target_peer_id);
    }

    fn upsertRoutingPeer(
        self: *Self,
        peer_id: []const u8,
        addrs: []const []const u8,
        connection: routing_table_mod.ConnectionType,
    ) !void {
        const result = try self.routing_table.insertOrUpdate(
            peer_id,
            addrs,
            .server,
            connection,
            nowMs(),
        );
        switch (result) {
            .pending_eviction => |pending| try self.routing_table.keepIncumbent(pending.bucket_index, pending.incumbent_peer_id),
            else => {},
        }
    }
};

fn defaultClockMs(_: ?*anyopaque) u64 {
    return nowMs();
}

fn topClosestResponded(candidates: []const Candidate) bool {
    const limit = @min(bucket_size, candidates.len);
    if (limit == 0) return false;
    for (candidates[0..limit]) |candidate| {
        if (!candidate.responded) return false;
    }
    return true;
}

fn insertOrMergeCandidate(
    allocator: std.mem.Allocator,
    candidates: *std.array_list.Managed(Candidate),
    target_peer_id: []const u8,
    peer_in: PeerInfo,
) !void {
    var peer = peer_in;
    errdefer peer.deinit(allocator);

    for (candidates.items) |*candidate| {
        if (!std.mem.eql(u8, candidate.peer.peer_id, peer.peer_id)) continue;
        try mergePeerAddrs(allocator, &candidate.peer.addrs, peer.addrs.items);
        if (@intFromEnum(peer.connection) > @intFromEnum(candidate.peer.connection)) {
            candidate.peer.connection = peer.connection;
        }
        var owned = peer;
        owned.deinit(allocator);
        return;
    }

    try candidates.append(.{
        .peer = peer,
        .distance = routing_table_mod.xorDistance(
            routing_table_mod.hashKey(target_peer_id),
            routing_table_mod.hashKey(peer.peer_id),
        ),
        .queried = false,
        .responded = false,
    });
    std.sort.block(Candidate, candidates.items, {}, CandidateDistance.lessThan);
}

fn mergePeerAddrs(
    allocator: std.mem.Allocator,
    owned: *std.array_list.Managed([]u8),
    addrs: []const []const u8,
) !void {
    for (addrs) |addr| {
        for (owned.items) |existing| {
            if (std.mem.eql(u8, existing, addr)) break;
        } else {
            try owned.append(try allocator.dupe(u8, addr));
        }
    }
}

fn peerInfoFromSnapshot(allocator: std.mem.Allocator, snapshot: *const routing_table_mod.PeerSnapshot) !PeerInfo {
    var out = PeerInfo.init(allocator);
    errdefer out.deinit(allocator);
    out.peer_id = try allocator.dupe(u8, snapshot.peer_id);
    out.connection = snapshot.connection;
    for (snapshot.addrs.items) |addr| {
        try out.addrs.append(try allocator.dupe(u8, address_book_mod.transportSlice(addr)));
    }
    return out;
}

fn peerInfoFromWire(allocator: std.mem.Allocator, peer: *const kad.Peer) !PeerInfo {
    var out = PeerInfo.init(allocator);
    errdefer out.deinit(allocator);

    out.peer_id = try allocator.dupe(u8, peer.id);
    out.connection = connectionFromWire(peer.connection);
    for (peer.addrs.items) |addr_bytes| {
        var multiaddr = try Multiaddr.createFromBytes(allocator, addr_bytes);
        defer multiaddr.deinit();
        try out.addrs.append(try allocator.dupe(u8, multiaddr.getStringAddress()));
    }
    return out;
}

fn wirePeerFromSnapshot(allocator: std.mem.Allocator, snapshot: *const routing_table_mod.PeerSnapshot) !kad.Peer {
    var out = kad.Peer.init(allocator);
    errdefer out.deinit(allocator);

    out.id = try allocator.dupe(u8, snapshot.peer_id);
    out.connection = connectionToWire(snapshot.connection);

    for (snapshot.addrs.items) |addr_text| {
        var multiaddr = try Multiaddr.create(allocator, address_book_mod.transportSlice(addr_text));
        defer multiaddr.deinit();
        try out.addrs.append(try allocator.dupe(u8, multiaddr.getBytesAddress()));
    }

    return out;
}

fn cloneKadRecord(allocator: std.mem.Allocator, record: *const kad.Record) !kad.Record {
    var out = kad.Record.init();
    errdefer out.deinit(allocator);
    out.key = try allocator.dupe(u8, record.key);
    out.value = try allocator.dupe(u8, record.value);
    if (record.time_received.len > 0) {
        out.time_received = try allocator.dupe(u8, record.time_received);
    }
    return out;
}

fn cloneKadPeer(allocator: std.mem.Allocator, peer: *const kad.Peer) !kad.Peer {
    var out = kad.Peer.init(allocator);
    errdefer out.deinit(allocator);
    out.id = try allocator.dupe(u8, peer.id);
    out.connection = peer.connection;
    for (peer.addrs.items) |addr| {
        try out.addrs.append(try allocator.dupe(u8, addr));
    }
    return out;
}

fn normalizeProviderPeerId(allocator: std.mem.Allocator, peer_id: []const u8) ![]u8 {
    if (peer_id.len == 0) return error.EmptyKadProviderPeerId;

    if (PeerId.fromString(allocator, peer_id)) |parsed_text| {
        var parsed = parsed_text;
        defer parsed.deinit();
        return allocator.dupe(u8, parsed.toString());
    } else |_| {}

    if (PeerId.fromBytes(allocator, peer_id)) |parsed_bytes| {
        var parsed = parsed_bytes;
        defer parsed.deinit();
        return allocator.dupe(u8, parsed.toString());
    } else |_| {}

    return error.InvalidKadProviderPeerId;
}

fn connectionToWire(connection: routing_table_mod.ConnectionType) kad.ConnectionType {
    return switch (connection) {
        .not_connected => .NOT_CONNECTED,
        .connected => .CONNECTED,
        .can_connect => .CAN_CONNECT,
        .cannot_connect => .CANNOT_CONNECT,
    };
}

fn connectionFromWire(connection: kad.ConnectionType) routing_table_mod.ConnectionType {
    return switch (connection) {
        .NOT_CONNECTED => .not_connected,
        .CONNECTED => .connected,
        .CAN_CONNECT => .can_connect,
        .CANNOT_CONNECT => .cannot_connect,
    };
}

fn formatIpAddressAsMultiaddr(allocator: std.mem.Allocator, addr: std.Io.net.IpAddress) ![]u8 {
    return switch (addr) {
        .ip4 => |a| std.fmt.allocPrint(
            allocator,
            "/ip4/{}.{}.{}.{}/tcp/{}",
            .{ a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.port },
        ),
        .ip6 => |a| blk: {
            const unresolved: std.Io.net.Ip6Address.Unresolved = .{
                .bytes = a.bytes,
                .interface_name = null,
            };
            break :blk try std.fmt.allocPrint(allocator, "/ip6/{f}/tcp/{}", .{ unresolved, a.port });
        },
    };
}

fn nowMs() u64 {
    const io = std.Io.Threaded.global_single_threaded.ioBasic();
    const now_result = std.Io.Clock.real.now(io);
    const ts = switch (@typeInfo(@TypeOf(now_result))) {
        .error_union => now_result catch return 0,
        else => now_result,
    };
    const seconds = ts.toSeconds();
    if (seconds <= 0) return 0;
    return @as(u64, @intCast(seconds)) * 1000;
}

fn freeLookupResult(allocator: std.mem.Allocator, result: *LookupResult) void {
    result.deinit(allocator);
}

fn freeBookSnapshot(allocator: std.mem.Allocator, snap: *std.array_list.Managed(address_book_mod.PeerSnapshot)) void {
    for (snap.items) |entry| {
        allocator.free(entry.addr);
        if (entry.peer_id) |peer_id| allocator.free(peer_id);
    }
    snap.deinit();
}

const BootstrapTraceCtx = struct {
    allocator: std.mem.Allocator,
    calls: std.array_list.Managed([]u8),
    clock_ms: u64 = 1_000,
    advance_per_lookup_ms: u64 = 0,
    run_count: usize = 0,
    stop_after_runs: ?usize = null,
    stop_flag: ?*std.atomic.Value(bool) = null,

    fn init(allocator: std.mem.Allocator) BootstrapTraceCtx {
        return .{
            .allocator = allocator,
            .calls = std.array_list.Managed([]u8).init(allocator),
        };
    }

    fn deinit(self: *BootstrapTraceCtx) void {
        address_book_mod.freeOwnedSlices(self.allocator, &self.calls);
    }
};

fn traceClockMs(userdata: ?*anyopaque) u64 {
    const ctx: *BootstrapTraceCtx = @ptrCast(@alignCast(userdata.?));
    return ctx.clock_ms;
}

fn traceLookupOverride(
    service: *QueryService,
    _: std.Io,
    target_peer_id: []const u8,
    userdata: ?*anyopaque,
) !LookupResult {
    const ctx: *BootstrapTraceCtx = @ptrCast(@alignCast(userdata.?));
    try ctx.calls.append(try ctx.allocator.dupe(u8, target_peer_id));

    if (std.mem.eql(u8, target_peer_id, service.host.identity.peer_id.getBytes())) {
        ctx.run_count += 1;
        if (ctx.stop_after_runs) |limit| {
            if (ctx.run_count >= limit) {
                if (ctx.stop_flag) |stop| {
                    stop.store(true, .release);
                }
            }
        }
    }

    ctx.clock_ms += ctx.advance_per_lookup_ms;
    return .{ .peers = std.array_list.Managed(PeerInfo).init(ctx.allocator) };
}

test "kad bootstrap once runs self lookup then one lookup per non-empty bucket" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    _ = try table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/23011"}, .server, .connected, 1000);
    _ = try table.insertOrUpdate("peer-b", &[_][]const u8{"/ip4/127.0.0.1/tcp/23012"}, .server, .connected, 1000);
    _ = try table.insertOrUpdate("peer-c", &[_][]const u8{"/ip4/127.0.0.1/tcp/23013"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();
    var trace = BootstrapTraceCtx.init(allocator);
    defer trace.deinit();
    service.lookup_override = traceLookupOverride;
    service.lookup_override_userdata = &trace;
    service.clock_ms_fn = traceClockMs;
    service.clock_userdata = &trace;

    var non_empty = try table.nonEmptyBucketIndices(allocator);
    defer non_empty.deinit();

    const run = try service.bootstrapOnce(io);
    try std.testing.expectEqual(@as(usize, 1 + non_empty.items.len), run.lookups_started);
    try std.testing.expect(!run.timed_out);
    try std.testing.expectEqual(@as(usize, 1 + non_empty.items.len), trace.calls.items.len);
    try std.testing.expectEqualSlices(u8, host.identity.peer_id.getBytes(), trace.calls.items[0]);

    for (trace.calls.items[1..], non_empty.items) |target_peer_id, bucket_index| {
        try std.testing.expectEqual(bucket_index, try table.bucketIndexForPeer(target_peer_id));
    }
}

test "kad refresh loop runs bootstrap on startup then periodically" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();
    _ = try table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/23111"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();
    service.refresh_interval_ms = 1;

    var trace = BootstrapTraceCtx.init(allocator);
    defer trace.deinit();
    var stop = std.atomic.Value(bool).init(false);
    trace.stop_after_runs = 2;
    trace.stop_flag = &stop;
    service.lookup_override = traceLookupOverride;
    service.lookup_override_userdata = &trace;
    service.clock_ms_fn = traceClockMs;
    service.clock_userdata = &trace;

    try service.refreshLoop(io, &stop);
    try std.testing.expectEqual(@as(usize, 2), trace.run_count);
}

test "kad bootstrap once aborts when query timeout is exhausted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    _ = try table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/23211"}, .server, .connected, 1000);
    _ = try table.insertOrUpdate("peer-b", &[_][]const u8{"/ip4/127.0.0.1/tcp/23212"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();
    service.query_timeout_ms = 10;

    var trace = BootstrapTraceCtx.init(allocator);
    defer trace.deinit();
    trace.advance_per_lookup_ms = 11;
    service.lookup_override = traceLookupOverride;
    service.lookup_override_userdata = &trace;
    service.clock_ms_fn = traceClockMs;
    service.clock_userdata = &trace;

    const run = try service.bootstrapOnce(io);
    try std.testing.expect(run.timed_out);
    try std.testing.expectEqual(@as(usize, 1), run.lookups_started);
    try std.testing.expectEqual(@as(usize, 1), trace.calls.items.len);
    try std.testing.expectEqualSlices(u8, host.identity.peer_id.getBytes(), trace.calls.items[0]);
}

test "kad query service handles repeated find node requests on one stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer server.deinit();
    var server_book = try AddressBook.init(allocator, server.identity.peer_id.toString());
    defer server_book.deinit();
    var server_table = try routing_table_mod.RoutingTable.init(allocator, server.identity.peer_id.toString());
    defer server_table.deinit();

    _ = try server_table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/22011"}, .server, .connected, 1000);
    _ = try server_table.insertOrUpdate("peer-b", &[_][]const u8{"/ip4/127.0.0.1/tcp/22012"}, .server, .connected, 1000);
    _ = try server_table.insertOrUpdate("peer-c", &[_][]const u8{"/ip4/127.0.0.1/tcp/22013"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &server, &server_table, &server_book, .server);
    defer service.deinit();
    try service.register();

    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22010");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client.deinit();
    var client_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22010");
    defer client_addr.deinit();

    const session = try client.dial(io, &client_addr);
    var stream = try client.newStream(io, session, kad.PROTOCOL_ID);
    defer stream.deinit();

    var req_one = kad.Message.init(allocator);
    defer req_one.deinit(allocator);
    req_one.type = .FIND_NODE;
    req_one.key = try allocator.dupe(u8, "target-one");

    var req_two = kad.Message.init(allocator);
    defer req_two.deinit(allocator);
    req_two.type = .FIND_NODE;
    req_two.key = try allocator.dupe(u8, "target-two");

    try kad.writeMessageFrame(allocator, io, &stream, &req_one);
    try kad.writeMessageFrame(allocator, io, &stream, &req_two);

    var resp_one = try kad.readMessageFrame(allocator, io, &stream);
    defer resp_one.deinit(allocator);
    var resp_two = try kad.readMessageFrame(allocator, io, &stream);
    defer resp_two.deinit(allocator);

    try std.testing.expectEqual(kad.MessageType.FIND_NODE, resp_one.type);
    try std.testing.expectEqual(kad.MessageType.FIND_NODE, resp_two.type);
    try std.testing.expectEqualStrings("target-one", resp_one.key);
    try std.testing.expectEqualStrings("target-two", resp_two.key);
    try std.testing.expect(resp_one.closer_peers.items.len > 0);
    try std.testing.expect(resp_two.closer_peers.items.len > 0);
    try stream.close();
}

test "kad inbound requests do not learn remote observed socket addresses" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer server.deinit();
    var server_book = try AddressBook.init(allocator, server.identity.peer_id.toString());
    defer server_book.deinit();
    var server_table = try routing_table_mod.RoutingTable.init(allocator, server.identity.peer_id.toString());
    defer server_table.deinit();

    _ = try server_table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/22016"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &server, &server_table, &server_book, .server);
    defer service.deinit();
    try service.register();

    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22015");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client.deinit();
    var client_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22015");
    defer client_addr.deinit();

    const session = try client.dial(io, &client_addr);
    var stream = try client.newStream(io, session, kad.PROTOCOL_ID);
    defer stream.deinit();

    var request = kad.Message.init(allocator);
    defer request.deinit(allocator);
    request.type = .FIND_NODE;
    request.key = try allocator.dupe(u8, "no-observed-learning");

    try kad.writeMessageFrame(allocator, io, &stream, &request);
    var response = try kad.readMessageFrame(allocator, io, &stream);
    defer response.deinit(allocator);

    try std.testing.expectEqual(kad.MessageType.FIND_NODE, response.type);
    try std.testing.expect(response.closer_peers.items.len > 0);

    var snapshot = try server_book.snapshot(allocator);
    defer {
        for (snapshot.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        snapshot.deinit();
    }
    try std.testing.expectEqual(@as(usize, 0), snapshot.items.len);

    try stream.close();
}

test "kad inbound stream limits enforce per-peer and global budgets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer server.deinit();
    var server_book = try AddressBook.init(allocator, server.identity.peer_id.toString());
    defer server_book.deinit();
    var server_table = try routing_table_mod.RoutingTable.init(allocator, server.identity.peer_id.toString());
    defer server_table.deinit();

    _ = try server_table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/22021"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &server, &server_table, &server_book, .server);
    defer service.deinit();
    service.max_inbound_streams_per_peer = 1;
    service.max_inbound_streams_global = 2;
    try service.register();

    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22020");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client_a = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client_a.deinit();
    var client_b = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client_b.deinit();
    var client_c = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client_c.deinit();

    var dial_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22020");
    defer dial_addr.deinit();

    const session_a = try client_a.dial(io, &dial_addr);
    const session_b = try client_b.dial(io, &dial_addr);
    const session_c = try client_c.dial(io, &dial_addr);

    var stream_a = try client_a.newStream(io, session_a, kad.PROTOCOL_ID);
    defer stream_a.deinit();
    var req_a = kad.Message.init(allocator);
    defer req_a.deinit(allocator);
    req_a.type = .FIND_NODE;
    req_a.key = try allocator.dupe(u8, "limit-a");
    try kad.writeMessageFrame(allocator, io, &stream_a, &req_a);
    var resp_a = try kad.readMessageFrame(allocator, io, &stream_a);
    defer resp_a.deinit(allocator);

    var stream_b = try client_b.newStream(io, session_b, kad.PROTOCOL_ID);
    defer stream_b.deinit();
    var req_b = kad.Message.init(allocator);
    defer req_b.deinit(allocator);
    req_b.type = .FIND_NODE;
    req_b.key = try allocator.dupe(u8, "limit-b");
    try kad.writeMessageFrame(allocator, io, &stream_b, &req_b);
    var resp_b = try kad.readMessageFrame(allocator, io, &stream_b);
    defer resp_b.deinit(allocator);

    var extra_peer_stream = try client_a.newStream(io, session_a, kad.PROTOCOL_ID);
    defer extra_peer_stream.deinit();
    var extra_peer_req = kad.Message.init(allocator);
    defer extra_peer_req.deinit(allocator);
    extra_peer_req.type = .FIND_NODE;
    extra_peer_req.key = try allocator.dupe(u8, "limit-peer");
    try kad.writeMessageFrame(allocator, io, &extra_peer_stream, &extra_peer_req);
    try std.testing.expectError(error.EndOfStream, kad.readMessageFrame(allocator, io, &extra_peer_stream));

    var extra_global_stream = try client_c.newStream(io, session_c, kad.PROTOCOL_ID);
    defer extra_global_stream.deinit();
    var extra_global_req = kad.Message.init(allocator);
    defer extra_global_req.deinit(allocator);
    extra_global_req.type = .FIND_NODE;
    extra_global_req.key = try allocator.dupe(u8, "limit-global");
    try kad.writeMessageFrame(allocator, io, &extra_global_stream, &extra_global_req);
    try std.testing.expectError(error.EndOfStream, kad.readMessageFrame(allocator, io, &extra_global_stream));

    try stream_a.close();
    try stream_b.close();
}

test "kad inbound stream counters own copied peer-id keys" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();

    var peer_id_buf = [_]u8{ 'p', 'e', 'e', 'r', '-', '1' };
    try std.testing.expect(try service.tryAcquireInboundStream(peer_id_buf[0..]));
    try std.testing.expectEqual(@as(usize, 1), service.inbound_streams_per_peer.count());

    peer_id_buf[0] = 'x';
    try std.testing.expect(service.inbound_streams_per_peer.get("peer-1") != null);

    service.releaseInboundStream("peer-1");
    try std.testing.expectEqual(@as(usize, 0), service.inbound_streams_global);
    try std.testing.expectEqual(@as(usize, 0), service.inbound_streams_per_peer.count());
}

test "kad inbound penalties target stable peer addresses by peer id" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();

    var remote_identity = try libp2p.IdentityKey.generate(allocator, io);
    defer remote_identity.deinit();

    const remote_addr = try std.fmt.allocPrint(
        allocator,
        "/ip4/127.0.0.1/tcp/24001/p2p/{s}",
        .{remote_identity.peer_id.toString()},
    );
    defer allocator.free(remote_addr);
    try book.learnIdentifyAddr(remote_addr, remote_identity.peer_id.toString(), 1000);

    service.penalizeInboundPeer(.{
        .remote_peer_id = &remote_identity.peer_id,
        .remote_addr = std.Io.net.IpAddress{
            .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 48708 },
        },
    });

    var snap = try book.snapshot(allocator);
    defer freeBookSnapshot(allocator, &snap);

    try std.testing.expectEqual(@as(usize, 1), snap.items.len);
    try std.testing.expectEqualStrings(remote_identity.peer_id.toString(), snap.items[0].peer_id.?);
    try std.testing.expectEqual(@as(i32, -20), snap.items[0].score);
    try std.testing.expectEqual(@as(u32, 1), snap.items[0].fail_count);
    try std.testing.expect(std.mem.indexOf(u8, snap.items[0].addr, "/tcp/24001") != null);
}

test "kad malformed inbound frame closes only the bad stream" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer server.deinit();
    var server_book = try AddressBook.init(allocator, server.identity.peer_id.toString());
    defer server_book.deinit();
    var server_table = try routing_table_mod.RoutingTable.init(allocator, server.identity.peer_id.toString());
    defer server_table.deinit();

    _ = try server_table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/22031"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &server, &server_table, &server_book, .server);
    defer service.deinit();
    try service.register();

    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22030");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client.deinit();
    var client_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22030");
    defer client_addr.deinit();

    const session = try client.dial(io, &client_addr);

    var bad_stream = try client.newStream(io, session, kad.PROTOCOL_ID);
    defer bad_stream.deinit();
    try bad_stream.writeByte(0x01); // frame length
    try bad_stream.writeByte(0x0B); // field 1 with invalid wire type 3
    try std.testing.expectError(error.EndOfStream, kad.readMessageFrame(allocator, io, &bad_stream));

    var good_stream = try client.newStream(io, session, kad.PROTOCOL_ID);
    defer good_stream.deinit();
    var good_req = kad.Message.init(allocator);
    defer good_req.deinit(allocator);
    good_req.type = .FIND_NODE;
    good_req.key = try allocator.dupe(u8, "after-malformed");
    try kad.writeMessageFrame(allocator, io, &good_stream, &good_req);

    var good_resp = try kad.readMessageFrame(allocator, io, &good_stream);
    defer good_resp.deinit(allocator);
    try std.testing.expectEqual(kad.MessageType.FIND_NODE, good_resp.type);
    try std.testing.expect(good_resp.closer_peers.items.len > 0);
}

test "kad iterative find node converges and learns discovered peers" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var b = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer b.deinit();
    var b_book = try AddressBook.init(allocator, b.identity.peer_id.toString());
    defer b_book.deinit();
    var b_table = try routing_table_mod.RoutingTable.init(allocator, b.identity.peer_id.toString());
    defer b_table.deinit();
    var b_service = QueryService.init(allocator, &b, &b_table, &b_book, .server);
    defer b_service.deinit();
    try b_service.register();
    var b_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22111");
    defer b_addr.deinit();
    try b.listen(io, &b_addr);
    var b_future = try io.concurrent(Host.serve, .{ &b, io });
    defer {
        _ = b_future.cancel(io) catch {};
        b_future.await(io) catch {};
    }

    var c = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer c.deinit();
    var c_book = try AddressBook.init(allocator, c.identity.peer_id.toString());
    defer c_book.deinit();
    var c_table = try routing_table_mod.RoutingTable.init(allocator, c.identity.peer_id.toString());
    defer c_table.deinit();
    var c_service = QueryService.init(allocator, &c, &c_table, &c_book, .server);
    defer c_service.deinit();
    try c_service.register();
    var c_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22112");
    defer c_addr.deinit();
    try c.listen(io, &c_addr);
    var c_future = try io.concurrent(Host.serve, .{ &c, io });
    defer {
        _ = c_future.cancel(io) catch {};
        c_future.await(io) catch {};
    }

    var d = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer d.deinit();
    var d_book = try AddressBook.init(allocator, d.identity.peer_id.toString());
    defer d_book.deinit();
    var d_table = try routing_table_mod.RoutingTable.init(allocator, d.identity.peer_id.toString());
    defer d_table.deinit();
    var d_service = QueryService.init(allocator, &d, &d_table, &d_book, .server);
    defer d_service.deinit();
    try d_service.register();
    var d_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22113");
    defer d_addr.deinit();
    try d.listen(io, &d_addr);
    var d_future = try io.concurrent(Host.serve, .{ &d, io });
    defer {
        _ = d_future.cancel(io) catch {};
        d_future.await(io) catch {};
    }

    var e = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer e.deinit();
    var e_book = try AddressBook.init(allocator, e.identity.peer_id.toString());
    defer e_book.deinit();
    var e_table = try routing_table_mod.RoutingTable.init(allocator, e.identity.peer_id.toString());
    defer e_table.deinit();
    var e_service = QueryService.init(allocator, &e, &e_table, &e_book, .server);
    defer e_service.deinit();
    try e_service.register();
    var e_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22114");
    defer e_addr.deinit();
    try e.listen(io, &e_addr);
    var e_future = try io.concurrent(Host.serve, .{ &e, io });
    defer {
        _ = e_future.cancel(io) catch {};
        e_future.await(io) catch {};
    }

    _ = try b_table.insertOrUpdate(c.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22112"}, .server, .can_connect, 1000);
    _ = try b_table.insertOrUpdate(d.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22113"}, .server, .connected, 1000);

    _ = try c_table.insertOrUpdate(d.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22113"}, .server, .connected, 1000);
    _ = try c_table.insertOrUpdate(e.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22114"}, .server, .connected, 1000);

    _ = try d_table.insertOrUpdate(e.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22114"}, .server, .connected, 1000);

    var client = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client.deinit();
    var client_book = try AddressBook.init(allocator, client.identity.peer_id.toString());
    defer client_book.deinit();
    var client_table = try routing_table_mod.RoutingTable.init(allocator, client.identity.peer_id.toString());
    defer client_table.deinit();

    _ = try client_table.insertOrUpdate(b.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22111"}, .server, .can_connect, 1000);
    _ = try client_table.insertOrUpdate(c.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22112"}, .server, .can_connect, 1000);

    var client_service = QueryService.init(allocator, &client, &client_table, &client_book, .client);
    defer client_service.deinit();
    var result = try client_service.iterativeFindNode(io, e.identity.peer_id.getBytes());
    defer freeLookupResult(allocator, &result);

    var saw_target = false;
    for (result.peers.items) |peer| {
        if (std.mem.eql(u8, peer.peer_id, e.identity.peer_id.toString())) saw_target = true;
    }
    try std.testing.expect(saw_target);

    var discovered = try client_table.getPeerSnapshot(allocator, e.identity.peer_id.toString());
    defer if (discovered) |*snapshot| snapshot.deinit(allocator);
    try std.testing.expect(discovered != null);

    var snap = try client_book.snapshot(allocator);
    defer freeBookSnapshot(allocator, &snap);
    var saw_kad = false;
    for (snap.items) |entry| {
        if (entry.peer_id) |peer_id| {
            if (std.mem.eql(u8, peer_id, e.identity.peer_id.toString()) and entry.source.kad) {
                saw_kad = true;
            }
        }
    }
    try std.testing.expect(saw_kad);
}

test "kad iterative find node terminates when known peers are exhausted" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var server = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer server.deinit();
    var server_book = try AddressBook.init(allocator, server.identity.peer_id.toString());
    defer server_book.deinit();
    var server_table = try routing_table_mod.RoutingTable.init(allocator, server.identity.peer_id.toString());
    defer server_table.deinit();
    var server_service = QueryService.init(allocator, &server, &server_table, &server_book, .server);
    defer server_service.deinit();
    try server_service.register();

    var listen_addr = try Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/22210");
    defer listen_addr.deinit();
    try server.listen(io, &listen_addr);

    var serve_future = try io.concurrent(Host.serve, .{ &server, io });
    defer {
        _ = serve_future.cancel(io) catch {};
        serve_future.await(io) catch {};
    }

    var client = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer client.deinit();
    var client_book = try AddressBook.init(allocator, client.identity.peer_id.toString());
    defer client_book.deinit();
    var client_table = try routing_table_mod.RoutingTable.init(allocator, client.identity.peer_id.toString());
    defer client_table.deinit();

    _ = try client_table.insertOrUpdate(server.identity.peer_id.toString(), &[_][]const u8{"/ip4/127.0.0.1/tcp/22210"}, .server, .can_connect, 1000);

    var client_service = QueryService.init(allocator, &client, &client_table, &client_book, .client);
    defer client_service.deinit();
    var result = try client_service.iterativeFindNode(io, "unreachable-target");
    defer freeLookupResult(allocator, &result);

    try std.testing.expectEqual(@as(usize, 1), result.peers.items.len);
    try std.testing.expectEqualStrings(server.identity.peer_id.toString(), result.peers.items[0].peer_id);
}

test "kad query service stores and returns local value records" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    _ = try table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/24111"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();

    var put_request = kad.Message.init(allocator);
    defer put_request.deinit(allocator);
    put_request.type = .PUT_VALUE;
    put_request.key = try allocator.dupe(u8, "/zei/value-key");
    put_request.record = kad.Record.init();
    put_request.record.?.key = try allocator.dupe(u8, "/zei/value-key");
    put_request.record.?.value = try allocator.dupe(u8, "seq:1:value-1");

    var put_response = (try service.handleRequest(&put_request, .{})).?;
    defer put_response.deinit(allocator);
    try std.testing.expectEqual(kad.MessageType.PUT_VALUE, put_response.type);
    try std.testing.expect(put_response.record != null);
    try std.testing.expectEqualStrings("seq:1:value-1", put_response.record.?.value);

    var get_request = kad.Message.init(allocator);
    defer get_request.deinit(allocator);
    get_request.type = .GET_VALUE;
    get_request.key = try allocator.dupe(u8, "/zei/value-key");

    var get_response = (try service.handleRequest(&get_request, .{})).?;
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(kad.MessageType.GET_VALUE, get_response.type);
    try std.testing.expect(get_response.record != null);
    try std.testing.expectEqualStrings("seq:1:value-1", get_response.record.?.value);
    try std.testing.expectEqual(@as(usize, 1), get_response.closer_peers.items.len);
}

test "kad add provider accepts only the sender peer id" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    _ = try table.insertOrUpdate("peer-a", &[_][]const u8{"/ip4/127.0.0.1/tcp/24211"}, .server, .connected, 1000);

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();

    var sender_identity = try libp2p.IdentityKey.generate(allocator, io);
    defer sender_identity.deinit();

    var invalid = kad.Message.init(allocator);
    defer invalid.deinit(allocator);
    invalid.type = .ADD_PROVIDER;
    invalid.key = try allocator.dupe(u8, "provider-key");
    var wrong_peer = kad.Peer.init(allocator);
    wrong_peer.id = try allocator.dupe(u8, "different-peer");
    wrong_peer.connection = .CONNECTED;
    try wrong_peer.addrs.append(try allocator.dupe(u8, "/ip4/127.0.0.1/tcp/24212"));
    try invalid.provider_peers.append(wrong_peer);

    try std.testing.expectError(error.NoValidKadProvider, service.handleRequest(&invalid, .{
        .remote_peer_id = sender_identity.peer_id.toString(),
    }));

    var valid = kad.Message.init(allocator);
    defer valid.deinit(allocator);
    valid.type = .ADD_PROVIDER;
    valid.key = try allocator.dupe(u8, "provider-key");
    var good_peer = kad.Peer.init(allocator);
    good_peer.id = try allocator.dupe(u8, sender_identity.peer_id.toString());
    good_peer.connection = .CONNECTED;
    try good_peer.addrs.append(try allocator.dupe(u8, "/ip4/127.0.0.1/tcp/24213"));
    try valid.provider_peers.append(good_peer);

    try std.testing.expect((try service.handleRequest(&valid, .{
        .remote_peer_id = sender_identity.peer_id.toString(),
    })) == null);

    var get_request = kad.Message.init(allocator);
    defer get_request.deinit(allocator);
    get_request.type = .GET_PROVIDERS;
    get_request.key = try allocator.dupe(u8, "provider-key");

    var response = (try service.handleRequest(&get_request, .{})).?;
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), response.provider_peers.items.len);
    try std.testing.expectEqualStrings(sender_identity.peer_id.toString(), response.provider_peers.items[0].id);
    try std.testing.expectEqual(@as(usize, 1), response.closer_peers.items.len);
}

test "kad add provider accepts raw peer id bytes from remote provider record" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var host = Host.init(allocator, try libp2p.IdentityKey.generate(allocator, io));
    defer host.deinit();
    var book = try AddressBook.init(allocator, host.identity.peer_id.toString());
    defer book.deinit();
    var table = try routing_table_mod.RoutingTable.init(allocator, host.identity.peer_id.toString());
    defer table.deinit();

    var sender_identity = try libp2p.IdentityKey.generate(allocator, io);
    defer sender_identity.deinit();

    var service = QueryService.init(allocator, &host, &table, &book, .server);
    defer service.deinit();

    var request = kad.Message.init(allocator);
    defer request.deinit(allocator);
    request.type = .ADD_PROVIDER;
    request.key = try allocator.dupe(u8, "provider-key-raw");

    var raw_peer = kad.Peer.init(allocator);
    raw_peer.id = try allocator.dupe(u8, sender_identity.peer_id.getBytes());
    raw_peer.connection = .CONNECTED;
    try raw_peer.addrs.append(try allocator.dupe(u8, "/ip4/127.0.0.1/tcp/24214"));
    try request.provider_peers.append(raw_peer);

    try std.testing.expect((try service.handleRequest(&request, .{
        .remote_peer_id = sender_identity.peer_id.toString(),
    })) == null);

    var get_request = kad.Message.init(allocator);
    defer get_request.deinit(allocator);
    get_request.type = .GET_PROVIDERS;
    get_request.key = try allocator.dupe(u8, "provider-key-raw");

    var response = (try service.handleRequest(&get_request, .{})).?;
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), response.provider_peers.items.len);
    try std.testing.expectEqualStrings(sender_identity.peer_id.toString(), response.provider_peers.items[0].id);
}
