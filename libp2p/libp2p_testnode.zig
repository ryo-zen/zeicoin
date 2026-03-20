const std = @import("std");
const build_options = @import("build_options");
const libp2p = @import("libp2p");
const Multiaddr = libp2p.Multiaddr;
const TcpTransport = libp2p.TcpTransport;
const TcpConnection = libp2p.TcpConnection;
const IdentityKey = libp2p.IdentityKey;
const noise = libp2p.noise;
const yamux = libp2p.yamux;
const identify = libp2p.identify;
const ms = libp2p.ms;

const print = std.debug.print;
const test_protocol = "/zeicoin/peers/1.0.0";
const max_line_len: usize = 512;
const max_peers_response: usize = 1024;
const dial_loop_seconds: u64 = 5;
const min_redial_ms: u64 = 30_000;
const max_backoff_ms: u64 = 300_000;
const peer_ttl_ms: u64 = 24 * 60 * 60 * 1000;

const SharedAddressBook = struct {
    allocator: std.mem.Allocator,
    self_peer_id: []u8,
    mutex: std.Thread.Mutex = .{},
    peers: std.array_list.Managed(PeerEntry),
    self_observed: std.array_list.Managed(SelfObservedAddr),

    const Self = @This();
    const PeerEntry = struct {
        addr: []u8,
        peer_id: ?[]u8,
        score: i32,
        fail_count: u32,
        next_dial_ms: u64,
        last_seen_ms: u64,
        last_success_ms: u64,
        last_failure_ms: u64,
    };

    const PeerSnapshot = struct {
        addr: []u8,
        peer_id: ?[]u8,
        score: i32,
        fail_count: u32,
        next_dial_ms: u64,
    };

    const SelfObservedAddr = struct {
        addr: []u8,
        source_peers: std.array_list.Managed([]u8),
        via_identify: bool,
        via_peer_exchange: bool,
        last_seen_ms: u64,
    };

    const SelfObservedSnapshot = struct {
        addr: []u8,
        source_count: usize,
        via_identify: bool,
        via_peer_exchange: bool,
        promoted: bool,
    };

    fn init(allocator: std.mem.Allocator, self_peer_id: []const u8) !Self {
        return .{
            .allocator = allocator,
            .self_peer_id = try allocator.dupe(u8, self_peer_id),
            .peers = std.array_list.Managed(PeerEntry).init(allocator),
            .self_observed = std.array_list.Managed(SelfObservedAddr).init(allocator),
        };
    }

    fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.allocator.free(self.self_peer_id);
        for (self.peers.items) |entry| {
            self.allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| self.allocator.free(peer_id);
        }
        self.peers.deinit();
        for (self.self_observed.items) |*entry| {
            self.allocator.free(entry.addr);
            for (entry.source_peers.items) |peer_id| self.allocator.free(peer_id);
            entry.source_peers.deinit();
        }
        self.self_observed.deinit();
    }

    fn learn(self: *Self, addr: []const u8, now_ms: u64) !void {
        try self.learnWithPeer(addr, null, now_ms);
    }

    fn learnWithPeer(self: *Self, addr: []const u8, peer_id_text: ?[]const u8, now_ms: u64) !void {
        const canonical_addr = try canonicalPeerAddr(self.allocator, addr, peer_id_text);
        defer self.allocator.free(canonical_addr);
        if (!isLikelyDialable(canonical_addr)) return;

        const canonical_peer_id = peerIdSlice(canonical_addr);
        if (canonical_peer_id) |peer_id| {
            if (std.mem.eql(u8, peer_id, self.self_peer_id)) {
                try self.recordSelfObservation(canonical_addr, peer_id_text, false, true, now_ms);
                return;
            }
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |*existing| {
            if (!samePeerAddress(existing.addr, canonical_addr, existing.peer_id, canonical_peer_id)) continue;

            existing.last_seen_ms = now_ms;
            if (!std.mem.eql(u8, existing.addr, canonical_addr)) {
                self.allocator.free(existing.addr);
                existing.addr = try self.allocator.dupe(u8, canonical_addr);
            }
            if (canonical_peer_id) |peer_id| {
                if (existing.peer_id) |current| {
                    if (!std.mem.eql(u8, current, peer_id)) {
                        self.allocator.free(current);
                        existing.peer_id = try self.allocator.dupe(u8, peer_id);
                    }
                } else {
                    existing.peer_id = try self.allocator.dupe(u8, peer_id);
                }
            }
            return;
        }

        try self.peers.append(.{
            .addr = try self.allocator.dupe(u8, canonical_addr),
            .peer_id = if (canonical_peer_id) |peer_id| try self.allocator.dupe(u8, peer_id) else null,
            .score = 0,
            .fail_count = 0,
            .next_dial_ms = 0,
            .last_seen_ms = now_ms,
            .last_success_ms = 0,
            .last_failure_ms = 0,
        });
    }

    fn learnAdvertised(self: *Self, addr: []const u8, source_peer_id: ?[]const u8, now_ms: u64) !void {
        try self.learnWithPeer(addr, source_peer_id, now_ms);
    }

    fn observeSelfFromIdentify(
        self: *Self,
        observed_addr: []const u8,
        source_peer_id: []const u8,
        listen_port: u16,
        now_ms: u64,
    ) !void {
        const ip = extractIp(observed_addr) orelse return;
        const candidate = try std.fmt.allocPrint(
            self.allocator,
            "/ip4/{s}/tcp/{}/p2p/{s}",
            .{ ip, listen_port, self.self_peer_id },
        );
        defer self.allocator.free(candidate);
        try self.recordSelfObservation(candidate, source_peer_id, true, false, now_ms);
    }

    fn markDialSuccess(self: *Self, addr: []const u8, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |*entry| {
            if (!samePeerAddress(entry.addr, addr, entry.peer_id, peerIdSlice(addr))) continue;
            entry.score += 10;
            entry.fail_count = 0;
            entry.last_success_ms = now_ms;
            entry.next_dial_ms = now_ms + min_redial_ms;
            return;
        }
    }

    fn markDialFailure(self: *Self, addr: []const u8, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.peers.items) |*entry| {
            if (!samePeerAddress(entry.addr, addr, entry.peer_id, peerIdSlice(addr))) continue;
            entry.score -= 20;
            entry.fail_count +|= 1;
            entry.last_failure_ms = now_ms;
            const exp = @min(entry.fail_count, 8);
            var backoff_ms: u64 = (@as(u64, 1) << @intCast(exp)) * 1000;
            if (backoff_ms > max_backoff_ms) backoff_ms = max_backoff_ms;
            entry.next_dial_ms = now_ms + backoff_ms;
            return;
        }
    }

    fn chooseDialCandidate(
        self: *Self,
        allocator: std.mem.Allocator,
        now_ms: u64,
        local_listen_ma: []const u8,
    ) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var best_idx: ?usize = null;
        const local_transport = transportSlice(local_listen_ma);
        for (self.peers.items, 0..) |entry, idx| {
            if (entry.next_dial_ms > now_ms) continue;
            if (std.mem.eql(u8, transportSlice(entry.addr), local_transport)) continue;
            if (entry.peer_id) |peer_id| {
                if (std.mem.eql(u8, peer_id, self.self_peer_id)) continue;
            }
            if (!isLikelyDialable(entry.addr)) continue;
            if (best_idx == null or entry.score > self.peers.items[best_idx.?].score) {
                best_idx = idx;
            }
        }
        if (best_idx == null) return null;

        self.peers.items[best_idx.?].next_dial_ms = now_ms + min_redial_ms;
        return try allocator.dupe(u8, self.peers.items[best_idx.?].addr);
    }

    fn pruneStale(self: *Self, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var i: usize = 0;
        while (i < self.peers.items.len) {
            const entry = self.peers.items[i];
            if (now_ms -| entry.last_seen_ms <= peer_ttl_ms) {
                i += 1;
                continue;
            }
            self.allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| self.allocator.free(peer_id);
            _ = self.peers.swapRemove(i);
        }
    }

    fn snapshot(self: *Self, allocator: std.mem.Allocator) !std.array_list.Managed(PeerSnapshot) {
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
        for (self.peers.items) |entry| {
            try out.append(.{
                .addr = try allocator.dupe(u8, entry.addr),
                .peer_id = if (entry.peer_id) |peer_id| try allocator.dupe(u8, peer_id) else null,
                .score = entry.score,
                .fail_count = entry.fail_count,
                .next_dial_ms = entry.next_dial_ms,
            });
        }
        return out;
    }

    fn snapshotSelfObservations(self: *Self, allocator: std.mem.Allocator) !std.array_list.Managed(SelfObservedSnapshot) {
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

    fn snapshotPromotedSelfAddrs(self: *Self, allocator: std.mem.Allocator) !std.array_list.Managed([]u8) {
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
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var evented_io: if (build_options.use_evented) std.Io.Evented else void = undefined;
    const io: std.Io = if (comptime build_options.use_evented) blk: {
        if (!@hasDecl(std.Io, "Evented"))
            @compileError("std.Io.Evented not available in this Zig build");
        evented_io = try std.Io.Evented.init(init.gpa, .{});
        break :blk evented_io.io();
    } else init.io;
    defer if (comptime build_options.use_evented) evented_io.deinit();

    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_it.deinit();
    _ = args_it.next(); // executable name

    const listen_ma = if (args_it.next()) |arg| arg else "/ip4/0.0.0.0/tcp/10811";
    const bootstrap_ma = args_it.next();
    const identity_path_arg = args_it.next();

    var transport = TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_addr = try Multiaddr.create(allocator, listen_ma);
    defer listen_addr.deinit();

    const listener = try transport.listen(io, &listen_addr);
    const identity_path = if (identity_path_arg) |path| path else blk: {
        const actual_port = extractListenPort(listener.multiaddr.toString()) orelse return error.InvalidListenMultiaddr;
        break :blk try std.fmt.allocPrint(allocator, ".libp2p_identity_{}.key", .{actual_port});
    };
    defer if (identity_path_arg == null) allocator.free(identity_path);

    var identity = try IdentityKey.loadOrCreate(allocator, io, identity_path);
    defer identity.deinit();

    var address_book = try SharedAddressBook.init(allocator, identity.peer_id.toString());
    defer address_book.deinit();

    print("libp2p_testnode listening on {s}\n", .{listener.multiaddr.toString()});
    print("libp2p identity peer_id={s} key_file={s}\n", .{ identity.peer_id.toString(), identity_path });

    var conn_group: std.Io.Group = .init;
    defer conn_group.cancel(io);

    var accept_future = try io.concurrent(acceptLoop, .{ listener, io, allocator, &identity, &address_book, &conn_group });
    defer _ = accept_future.cancel(io) catch {};

    if (bootstrap_ma) |addr_text| {
        try address_book.learn(addr_text, nowMs());
        var dial_addr = try Multiaddr.create(allocator, addr_text);
        defer dial_addr.deinit();

        var conn = transport.dial(io, &dial_addr) catch |err| {
            print("bootstrap dial failed: {s} ({s})\n", .{ addr_text, @errorName(err) });
            while (true) {
                io.sleep(std.Io.Duration.fromSeconds(5), std.Io.Clock.awake) catch {};
                print("status: listener active, bootstrap unreachable\n", .{});
            }
        };
        defer conn.deinit();

        print("connected to bootstrap {s}\n", .{addr_text});
        const discovered = try runInitiatorHandshake(allocator, io, &conn, &identity, &address_book, listen_ma, addr_text);
        defer {
            for (discovered.items) |addr| allocator.free(addr);
            discovered.deinit();
        }
        address_book.markDialSuccess(addr_text, nowMs());
        for (discovered.items) |addr| {
            print("discovered peer: {s}\n", .{addr});
        }
    }

    while (true) {
        io.sleep(std.Io.Duration.fromSeconds(dial_loop_seconds), std.Io.Clock.awake) catch {};
        const now_ms = nowMs();
        address_book.pruneStale(now_ms);

        const maybe_candidate = try address_book.chooseDialCandidate(allocator, now_ms, listener.multiaddr.toString());
        if (maybe_candidate) |candidate| {
            defer allocator.free(candidate);
            tryDialCandidate(allocator, io, &transport, &identity, &address_book, listen_ma, candidate, now_ms);
        }

        var peers = try address_book.snapshot(allocator);
        defer {
            for (peers.items) |entry| {
                allocator.free(entry.addr);
                if (entry.peer_id) |peer_id| allocator.free(peer_id);
            }
            peers.deinit();
        }
        var self_observed = try address_book.snapshotSelfObservations(allocator);
        defer {
            for (self_observed.items) |entry| allocator.free(entry.addr);
            self_observed.deinit();
        }
        print("status: listening={s} active_listeners={d} known_peers={d}\n", .{
            listener.multiaddr.toString(),
            transport.listeners.items.len,
            peers.items.len,
        });
        for (peers.items) |entry| {
            print("  peer {s} peer_id={s} score={} fails={} next_dial_ms={}\n", .{
                entry.addr,
                entry.peer_id orelse "-",
                entry.score,
                entry.fail_count,
                entry.next_dial_ms,
            });
        }
        for (self_observed.items) |entry| {
            print("  self_addr {s} sources={} identify={} peer_exchange={} promoted={}\n", .{
                entry.addr,
                entry.source_count,
                entry.via_identify,
                entry.via_peer_exchange,
                entry.promoted,
            });
        }
    }
}

fn acceptLoop(
    listener: *TcpTransport.Listener,
    io: std.Io,
    allocator: std.mem.Allocator,
    identity: *const IdentityKey,
    address_book: *SharedAddressBook,
    conn_group: *std.Io.Group,
) std.Io.Cancelable!void {
    while (true) {
        try std.Io.checkCancel(io);
        var conn = listener.accept(io) catch |err| {
            switch (err) {
                error.Canceled, error.SocketNotListening => return,
                else => {
                    print("accept failed: {s}\n", .{@errorName(err)});
                    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
                    continue;
                },
            }
        };

        const remote = if (conn.remoteMultiaddr()) |ma| ma.toString() else "unknown";
        print("incoming connection from {s}\n", .{remote});

        conn_group.concurrent(io, handleInboundConn, .{
            conn,
            io,
            allocator,
            identity,
            address_book,
            listener.multiaddr.toString(),
        }) catch |err| {
            print("spawn handler failed: {s}\n", .{@errorName(err)});
            conn.deinit();
        };
    }
}

fn handleInboundConn(
    conn: TcpConnection,
    io: std.Io,
    allocator: std.mem.Allocator,
    identity: *const IdentityKey,
    address_book: *SharedAddressBook,
    listen_addr: []const u8,
) void {
    var owned_conn = conn;
    defer owned_conn.deinit();

    runResponderHandshake(allocator, io, &owned_conn, identity, listen_addr, address_book) catch |err| {
        print("handshake failed: {s}\n", .{@errorName(err)});
    };
}

const ConnReader = struct {
    conn: *TcpConnection,
    io: std.Io,

    pub fn readByte(self: *ConnReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.conn.readSome(self.io, &one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *ConnReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.conn.readSome(self.io, dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const ConnWriter = struct {
    conn: *TcpConnection,
    io: std.Io,

    pub fn writeAll(self: *ConnWriter, data: []const u8) !void {
        try self.conn.writeAll(self.io, data);
    }

    pub fn writeByte(self: *ConnWriter, b: u8) !void {
        const one = [_]u8{b};
        try self.conn.writeAll(self.io, &one);
    }
};

const SecureConnReader = struct {
    conn: *noise.SecureTransport,
    io: std.Io,

    pub fn readByte(self: *SecureConnReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.conn.readSome(self.io, &one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *SecureConnReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.conn.readSome(self.io, dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const SecureConnWriter = struct {
    conn: *noise.SecureTransport,
    io: std.Io,

    pub fn writeAll(self: *SecureConnWriter, data: []const u8) !void {
        try self.conn.writeAll(self.io, data);
    }

    pub fn writeByte(self: *SecureConnWriter, b: u8) !void {
        try self.conn.writeByte(self.io, b);
    }
};

const YamuxReader = struct {
    stream: *yamux.Stream,

    pub fn readByte(self: *YamuxReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.stream.readSome(&one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *YamuxReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.stream.readSome(dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const YamuxWriter = struct {
    stream: *yamux.Stream,

    pub fn writeAll(self: *YamuxWriter, data: []const u8) !void {
        try self.stream.writeAll(data);
    }

    pub fn writeByte(self: *YamuxWriter, b: u8) !void {
        try self.stream.writeByte(b);
    }
};

fn runInitiatorHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *TcpConnection,
    identity: *const IdentityKey,
    address_book: *SharedAddressBook,
    listen_ma: []const u8,
    dialed_addr: []const u8,
) !std.array_list.Managed([]u8) {
    var reader: ConnReader = .{ .conn = conn, .io = io };
    var writer: ConnWriter = .{ .conn = conn, .io = io };

    try ms.writeMessage(io, &writer, ms.PROTOCOL_ID);
    const version_ack = try ms.readMessage(io, &reader, allocator);
    defer allocator.free(version_ack);
    if (!std.mem.eql(u8, version_ack, ms.PROTOCOL_ID)) return error.ProtocolMismatch;

    try ms.writeMessage(io, &writer, noise.PROTOCOL_ID);
    const noise_ack = try ms.readMessage(io, &reader, allocator);
    defer allocator.free(noise_ack);
    if (!std.mem.eql(u8, noise_ack, noise.PROTOCOL_ID)) return error.ProtocolMismatch;

    var noise_result = try noise.performInitiator(allocator, io, conn.connection(), identity, peerIdSlice(dialed_addr));
    defer noise_result.deinit();
    print("noise handshake complete with peer_id={s}\n", .{noise_result.remote_peer_id.toString()});
    try address_book.learnWithPeer(dialed_addr, noise_result.remote_peer_id.toString(), nowMs());

    var secure = noise.SecureTransport.init(allocator, conn.connection(), noise_result.tx_key, noise_result.rx_key);
    defer secure.deinit();
    var secure_reader: SecureConnReader = .{ .conn = &secure, .io = io };
    var secure_writer: SecureConnWriter = .{ .conn = &secure, .io = io };

    try ms.writeMessage(io, &secure_writer, yamux.PROTOCOL_ID);
    const yamux_ack = try ms.readMessage(io, &secure_reader, allocator);
    defer allocator.free(yamux_ack);
    if (!std.mem.eql(u8, yamux_ack, yamux.PROTOCOL_ID)) return error.ProtocolMismatch;

    var mux_session = yamux.Session.init(allocator, &secure, true);
    try mux_session.start();
    defer mux_session.deinit();
    var id_stream = try mux_session.openStream();
    defer id_stream.deinit();
    var id_reader: YamuxReader = .{ .stream = &id_stream };
    var id_writer: YamuxWriter = .{ .stream = &id_stream };

    try ms.writeMessage(io, &id_writer, identify.PROTOCOL_ID);
    const identify_ack = try ms.readMessage(io, &id_reader, allocator);
    defer allocator.free(identify_ack);
    if (!std.mem.eql(u8, identify_ack, identify.PROTOCOL_ID)) return error.ProtocolMismatch;

    const identify_bytes = try readAllFromStream(allocator, &id_stream);
    defer allocator.free(identify_bytes);
    var identify_info = try identify.decodeIdentify(allocator, identify_bytes);
    defer identify_info.deinit(allocator);
    print("identify received: agent={s} protocols={d}\n", .{
        identify_info.agent_version,
        identify_info.protocols.items.len,
    });
    const listen_port = extractListenPort(listen_ma) orelse return error.InvalidListenMultiaddr;
    if (identify_info.observed_addr.len > 0) {
        try address_book.observeSelfFromIdentify(
            identify_info.observed_addr,
            noise_result.remote_peer_id.toString(),
            listen_port,
            nowMs(),
        );
    }
    for (identify_info.listen_addrs.items) |addr| {
        try address_book.learnAdvertised(addr, noise_result.remote_peer_id.toString(), nowMs());
    }

    var mux_stream = try mux_session.openStream();
    defer mux_stream.deinit();
    var mux_reader: YamuxReader = .{ .stream = &mux_stream };
    var mux_writer: YamuxWriter = .{ .stream = &mux_stream };

    try ms.writeMessage(io, &mux_writer, test_protocol);
    const proto_ack = try ms.readMessage(io, &mux_reader, allocator);
    defer allocator.free(proto_ack);
    if (!std.mem.eql(u8, proto_ack, test_protocol)) return error.ProtocolMismatch;

    print("multistream negotiated protocol: {s}\n", .{proto_ack});

    const request = try std.fmt.allocPrint(allocator, "GET_PEERS {}\n", .{listen_port});
    defer allocator.free(request);
    try mux_writer.writeAll(request);

    const first_line = try readLine(allocator, &mux_reader);
    defer allocator.free(first_line);
    if (!std.mem.startsWith(u8, first_line, "PEERS ")) return error.InvalidPeerResponse;
    const count_text = first_line["PEERS ".len..];
    const count = try std.fmt.parseInt(usize, count_text, 10);
    if (count > max_peers_response) return error.InvalidPeerResponse;

    var discovered = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (discovered.items) |addr| allocator.free(addr);
        discovered.deinit();
    }

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const peer_addr = try readPeerExchangeAddr(allocator, &mux_reader);
        errdefer allocator.free(peer_addr);
        try address_book.learnAdvertised(peer_addr, noise_result.remote_peer_id.toString(), nowMs());
        try discovered.append(peer_addr);
    }

    return discovered;
}

fn runResponderHandshake(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *TcpConnection,
    identity: *const IdentityKey,
    local_listen_ma: []const u8,
    address_book: *SharedAddressBook,
) !void {
    var reader: ConnReader = .{ .conn = conn, .io = io };
    var writer: ConnWriter = .{ .conn = conn, .io = io };

    const init_msg = try ms.readMessage(io, &reader, allocator);
    defer allocator.free(init_msg);
    if (!std.mem.eql(u8, init_msg, ms.PROTOCOL_ID)) return error.ProtocolMismatch;
    try ms.writeMessage(io, &writer, ms.PROTOCOL_ID);

    const proposal = try ms.readMessage(io, &reader, allocator);
    defer allocator.free(proposal);

    if (std.mem.eql(u8, proposal, noise.PROTOCOL_ID)) {
        try ms.writeMessage(io, &writer, noise.PROTOCOL_ID);
        var noise_result = try noise.performResponder(allocator, io, conn.connection(), identity, null);
        defer noise_result.deinit();
        print("noise handshake complete with peer_id={s}\n", .{noise_result.remote_peer_id.toString()});

        var secure = noise.SecureTransport.init(allocator, conn.connection(), noise_result.tx_key, noise_result.rx_key);
        defer secure.deinit();
        var secure_reader: SecureConnReader = .{ .conn = &secure, .io = io };
        var secure_writer: SecureConnWriter = .{ .conn = &secure, .io = io };

        const mux_proposal = try ms.readMessage(io, &secure_reader, allocator);
        defer allocator.free(mux_proposal);
        if (!std.mem.eql(u8, mux_proposal, yamux.PROTOCOL_ID)) {
            try ms.writeMessage(io, &secure_writer, ms.NA);
            return error.UnsupportedProtocol;
        }
        try ms.writeMessage(io, &secure_writer, yamux.PROTOCOL_ID);

        var mux_session = yamux.Session.init(allocator, &secure, false);
        try mux_session.start();
        defer mux_session.deinit();

        var stream_group: std.Io.Group = .init;
        defer stream_group.cancel(io);
        while (true) {
            var mux_stream = mux_session.acceptStream() catch |err| switch (err) {
                yamux.YamuxError.GoAway,
                yamux.YamuxError.SessionClosed,
                => break,
                else => return err,
            };

            stream_group.concurrent(io, handleResponderMuxStream, .{
                mux_stream,
                io,
                allocator,
                identity,
                local_listen_ma,
                address_book,
                conn,
                noise_result.remote_peer_id.toString(),
            }) catch |err| {
                mux_stream.deinit();
                return err;
            };
        }

        try stream_group.await(io);
    } else {
        try ms.writeMessage(io, &writer, ms.NA);
        return error.UnsupportedProtocol;
    }
}

fn handleResponderMuxStream(
    mux_stream: yamux.Stream,
    io: std.Io,
    allocator: std.mem.Allocator,
    identity: *const IdentityKey,
    local_listen_ma: []const u8,
    address_book: *SharedAddressBook,
    conn: *TcpConnection,
    remote_peer_id: []const u8,
) std.Io.Cancelable!void {
    try std.Io.checkCancel(io);

    handleResponderMuxStreamInner(
        mux_stream,
        io,
        allocator,
        identity,
        local_listen_ma,
        address_book,
        conn,
        remote_peer_id,
    ) catch |err| {
        print("mux stream handler failed: {s}\n", .{@errorName(err)});
    };
}

fn handleResponderMuxStreamInner(
    mux_stream: yamux.Stream,
    io: std.Io,
    allocator: std.mem.Allocator,
    identity: *const IdentityKey,
    local_listen_ma: []const u8,
    address_book: *SharedAddressBook,
    conn: *TcpConnection,
    remote_peer_id: []const u8,
) !void {
    var owned_stream = mux_stream;
    defer owned_stream.deinit();
    var mux_reader: YamuxReader = .{ .stream = &owned_stream };
    var mux_writer: YamuxWriter = .{ .stream = &owned_stream };

    const proposal_on_stream = try ms.readMessage(io, &mux_reader, allocator);
    defer allocator.free(proposal_on_stream);

    if (std.mem.eql(u8, proposal_on_stream, identify.PROTOCOL_ID)) {
        try ms.writeMessage(io, &mux_writer, identify.PROTOCOL_ID);
        const supported = [_][]const u8{
            identify.PROTOCOL_ID,
            test_protocol,
        };
        const encoded_pubkey = encodeIdentityPublicKey(identity.public_key);
        var listen_addrs = try buildAdvertisedListenAddrs(
            allocator,
            address_book,
            local_listen_ma,
            identity.peer_id.toString(),
        );
        defer freeOwnedSlices(allocator, &listen_addrs);
        const observed_addr = try observedMaBytesFromConn(allocator, conn);
        defer allocator.free(observed_addr);
        const identify_payload = try identify.encodeIdentify(
            allocator,
            "/zeicoin/testnet/1.0.0",
            "zeicoin/libp2p-testnode/1.0.0",
            &encoded_pubkey,
            listen_addrs.items,
            observed_addr,
            &supported,
        );
        defer allocator.free(identify_payload);
        try mux_writer.writeAll(identify_payload);
        try owned_stream.close();
        return;
    }

    if (!std.mem.eql(u8, proposal_on_stream, test_protocol)) {
        try ms.writeMessage(io, &mux_writer, ms.NA);
        try owned_stream.close();
        return error.UnsupportedProtocol;
    }
    try ms.writeMessage(io, &mux_writer, test_protocol);
    print("accepted protocol: {s}\n", .{proposal_on_stream});

    const req_line = try readLine(allocator, &mux_reader);
    defer allocator.free(req_line);
    const listen_port = parseGetPeersRequest(req_line) orelse return error.InvalidPeerRequest;

    if (conn.remoteMultiaddr()) |remote_ma| {
        if (extractIp(remote_ma.toString())) |ip| {
            const observed = try std.fmt.allocPrint(allocator, "/ip4/{s}/tcp/{}", .{ ip, listen_port });
            defer allocator.free(observed);
            try address_book.learnWithPeer(observed, remote_peer_id, nowMs());
        }
    }

    var peers = try address_book.snapshot(allocator);
    defer {
        for (peers.items) |entry| {
            allocator.free(entry.addr);
            if (entry.peer_id) |peer_id| allocator.free(peer_id);
        }
        peers.deinit();
    }

    const header = try std.fmt.allocPrint(allocator, "PEERS {}\n", .{peers.items.len});
    defer allocator.free(header);
    try mux_writer.writeAll(header);
    for (peers.items) |entry| {
        try writePeerExchangeAddr(allocator, &mux_writer, entry.addr);
    }
    try owned_stream.close();
}

fn readLine(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();

    while (true) {
        const b = try reader.readByte();
        if (b == '\n') break;
        if (buf.items.len >= max_line_len) return error.LineTooLong;
        try buf.append(b);
    }

    return buf.toOwnedSlice();
}

fn readAllFromStream(allocator: std.mem.Allocator, stream: *yamux.Stream) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var buf: [1024]u8 = undefined;
    while (true) {
        const n = try stream.readSome(&buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
    }
    return out.toOwnedSlice();
}

fn encodeIdentityPublicKey(public_key: [32]u8) [36]u8 {
    var out: [36]u8 = undefined;
    out[0] = 0x08;
    out[1] = 0x01;
    out[2] = 0x12;
    out[3] = 0x20;
    @memcpy(out[4..], &public_key);
    return out;
}

fn observedMaBytesFromConn(allocator: std.mem.Allocator, conn: *const TcpConnection) ![]u8 {
    if (conn.remoteMultiaddr()) |ma| return allocator.dupe(u8, ma.getBytesAddress());
    return allocator.dupe(u8, "");
}

fn tryDialCandidate(
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: *TcpTransport,
    identity: *const IdentityKey,
    address_book: *SharedAddressBook,
    listen_ma: []const u8,
    candidate: []const u8,
    now_ms: u64,
) void {
    var dial_addr = Multiaddr.create(allocator, candidate) catch |err| {
        print("discovery dial parse failed: {s} ({s})\n", .{ candidate, @errorName(err) });
        address_book.markDialFailure(candidate, now_ms);
        return;
    };
    defer dial_addr.deinit();

    var conn = transport.dial(io, &dial_addr) catch |err| {
        print("discovery dial failed: {s} ({s})\n", .{ candidate, @errorName(err) });
        address_book.markDialFailure(candidate, now_ms);
        return;
    };
    defer conn.deinit();

    const discovered = runInitiatorHandshake(allocator, io, &conn, identity, address_book, listen_ma, candidate) catch |err| {
        print("discovery handshake failed: {s} ({s})\n", .{ candidate, @errorName(err) });
        address_book.markDialFailure(candidate, now_ms);
        return;
    };
    defer {
        for (discovered.items) |addr| allocator.free(addr);
        discovered.deinit();
    }

    address_book.markDialSuccess(candidate, now_ms);
    for (discovered.items) |addr| {
        print("discovered via {s}: {s}\n", .{ candidate, addr });
    }
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

fn isLikelyDialable(addr: []const u8) bool {
    if (addr.len == 0) return false;
    if (!std.mem.startsWith(u8, addr, "/ip4/")) return false;
    if (std.mem.startsWith(u8, addr, "/ip4/0.0.0.0/")) return false;
    return std.mem.indexOf(u8, addr, "/tcp/") != null;
}

fn transportSlice(addr: []const u8) []const u8 {
    const idx = std.mem.indexOf(u8, addr, "/p2p/") orelse return addr;
    return addr[0..idx];
}

fn peerIdSlice(addr: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, addr, "/p2p/") orelse return null;
    return addr[idx + "/p2p/".len ..];
}

fn samePeerAddress(a: []const u8, b: []const u8, a_peer: ?[]const u8, b_peer: ?[]const u8) bool {
    if (!std.mem.eql(u8, transportSlice(a), transportSlice(b))) return false;
    if (a_peer == null or b_peer == null) return true;
    return std.mem.eql(u8, a_peer.?, b_peer.?);
}

fn canonicalPeerAddr(allocator: std.mem.Allocator, addr: []const u8, peer_id_text: ?[]const u8) ![]u8 {
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

fn buildAdvertisedListenAddrs(
    allocator: std.mem.Allocator,
    address_book: *SharedAddressBook,
    local_listen_ma: []const u8,
    peer_id_text: []const u8,
) !std.array_list.Managed([]u8) {
    var out = std.array_list.Managed([]u8).init(allocator);
    errdefer freeOwnedSlices(allocator, &out);

    var promoted = try address_book.snapshotPromotedSelfAddrs(allocator);
    defer freeOwnedSlices(allocator, &promoted);
    if (promoted.items.len > 0) {
        for (promoted.items) |addr| {
            var ma = try Multiaddr.create(allocator, addr);
            defer ma.deinit();
            try out.append(try allocator.dupe(u8, ma.getBytesAddress()));
        }
        return out;
    }

    if (std.mem.startsWith(u8, local_listen_ma, "/ip4/0.0.0.0/")) return out;

    const full_addr = try canonicalPeerAddr(allocator, local_listen_ma, peer_id_text);
    defer allocator.free(full_addr);

    var ma = try Multiaddr.create(allocator, full_addr);
    defer ma.deinit();
    try out.append(try allocator.dupe(u8, ma.getBytesAddress()));
    return out;
}

fn freeOwnedSlices(allocator: std.mem.Allocator, list: *std.array_list.Managed([]u8)) void {
    for (list.items) |item| allocator.free(item);
    list.deinit();
}

fn writePeerExchangeAddr(allocator: std.mem.Allocator, writer: *YamuxWriter, addr: []const u8) !void {
    var ma = try Multiaddr.create(allocator, addr);
    defer ma.deinit();
    try writeVarintWriter(writer, ma.getBytesAddress().len);
    try writer.writeAll(ma.getBytesAddress());
}

fn readPeerExchangeAddr(allocator: std.mem.Allocator, reader: *YamuxReader) ![]u8 {
    const addr_len = try readVarintReader(reader);
    const addr_bytes = try allocator.alloc(u8, addr_len);
    defer allocator.free(addr_bytes);
    try reader.readNoEof(addr_bytes);

    var ma = try Multiaddr.createFromBytes(allocator, addr_bytes);
    defer ma.deinit();
    return allocator.dupe(u8, ma.toString());
}

fn writeVarintWriter(writer: anytype, value: usize) !void {
    var buf: [10]u8 = undefined;
    const len = writeVarint(&buf, value);
    try writer.writeAll(buf[0..len]);
}

fn readVarintReader(reader: anytype) !usize {
    var result: usize = 0;
    var shift: u6 = 0;
    while (true) {
        const b = try reader.readByte();
        result |= @as(usize, b & 0x7F) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift >= @bitSizeOf(usize)) return error.InvalidVarint;
    }
}

fn writeVarint(out: []u8, value: usize) usize {
    var v = value;
    var i: usize = 0;
    while (v >= 0x80) : (v >>= 7) {
        out[i] = @as(u8, @intCast(v & 0x7F)) | 0x80;
        i += 1;
    }
    out[i] = @as(u8, @intCast(v));
    return i + 1;
}

fn parseGetPeersRequest(line: []const u8) ?u16 {
    if (!std.mem.startsWith(u8, line, "GET_PEERS ")) return null;
    const port_text = line["GET_PEERS ".len..];
    return std.fmt.parseInt(u16, port_text, 10) catch null;
}

fn extractIp(multiaddr: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, multiaddr, '/');
    while (it.next()) |part| {
        if (!std.mem.eql(u8, part, "ip4")) continue;
        return it.next();
    }
    return null;
}

fn extractListenPort(multiaddr: []const u8) ?u16 {
    var it = std.mem.tokenizeScalar(u8, multiaddr, '/');
    while (it.next()) |part| {
        if (!std.mem.eql(u8, part, "tcp")) continue;
        const port_text = it.next() orelse return null;
        return std.fmt.parseInt(u16, port_text, 10) catch null;
    }
    return null;
}

test "parse GET_PEERS request" {
    try std.testing.expectEqual(@as(?u16, 10811), parseGetPeersRequest("GET_PEERS 10811"));
    try std.testing.expectEqual(@as(?u16, null), parseGetPeersRequest("GET_PEERS abc"));
    try std.testing.expectEqual(@as(?u16, null), parseGetPeersRequest("INVALID 10811"));
}

test "extract IP and listen port from multiaddr" {
    try std.testing.expectEqualStrings("172.31.0.11", extractIp("/ip4/172.31.0.11/tcp/42001").?);
    try std.testing.expectEqual(@as(?u16, 10811), extractListenPort("/ip4/0.0.0.0/tcp/10811"));
    try std.testing.expectEqual(@as(?u16, null), extractListenPort("/ip4/0.0.0.0/udp/10811"));
}
