const std = @import("std");
const noise = @import("../security/noise.zig");
const tcp = @import("../transport/tcp.zig");
const multiaddr_mod = @import("../multiaddr/multiaddr.zig");
const ms = @import("../protocol/multistream.zig");
const SyncMutex = std.Io.Mutex;
const SyncCondition = std.Io.Condition;
const DemuxFuture = std.Io.Future(anyerror!void);
const KeepaliveFuture = std.Io.Future(anyerror!void);
const OpenStreamFuture = std.Io.Future(anyerror!Stream);
const AcceptStreamFuture = std.Io.Future(anyerror!Stream);

pub const PROTOCOL_ID = "/yamux/1.0.0";
const MAX_FRAME_PAYLOAD: u32 = 4 * 1024 * 1024; // 4 MiB reduces per-frame overhead on bulk transfers
const INITIAL_STREAM_WINDOW: u32 = 8 * 1024 * 1024;
const WINDOW_UPDATE_THRESHOLD: u32 = 4 * 1024 * 1024;
const MAX_ACK_BACKLOG: u16 = 256;
const MAX_PENDING_ACCEPT: usize = 64;

pub const SessionOptions = struct {
    keepalive_interval_ms: i64 = 15_000,
    keepalive_timeout_ms: i64 = 45_000,
};

pub const YamuxError = error{
    InvalidFrame,
    UnsupportedVersion,
    UnsupportedFrameType,
    UnexpectedFrame,
    StreamClosed,
    SessionClosed,
    AckBacklogFull,
    GoAway,
    ProtocolError,
};

const FrameType = enum(u8) {
    data = 0x0,
    window_update = 0x1,
    ping = 0x2,
    go_away = 0x3,
};

const SessionState = enum {
    open,
    go_away_sent,
    go_away_received,
    closing,
    closed,
};

const StreamState = enum {
    syn_sent,
    syn_received,
    open,
    local_half_closed,
    remote_half_closed,
    closed,
    reset,
};

const GoAwayCode = enum(u32) {
    normal = 0,
    protocol_error = 1,
    internal_error = 2,
};

const FLAG_SYN: u16 = 0x1;
const FLAG_ACK: u16 = 0x2;
const FLAG_FIN: u16 = 0x4;
const FLAG_RST: u16 = 0x8;

const FrameHeader = struct {
    version: u8,
    typ: FrameType,
    flags: u16,
    stream_id: u32,
    length: u32,
};

const Frame = struct {
    header: FrameHeader,
    payload: []const u8,

    fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

const StreamCore = struct {
    allocator: std.mem.Allocator,
    stream_id: u32,
    state: StreamState,
    send_window: u32 = INITIAL_STREAM_WINDOW,
    recv_window: u32 = INITIAL_STREAM_WINDOW,
    pending_window_credit: u32 = 0,
    inbound_data: std.array_list.Managed(u8),
    inbound_offset: usize = 0,
    mutex: SyncMutex = .init,
    cond: SyncCondition = .init,

    fn init(allocator: std.mem.Allocator, stream_id: u32, state: StreamState) StreamCore {
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .state = state,
            .inbound_data = std.array_list.Managed(u8).init(allocator),
            .inbound_offset = 0,
        };
    }

    fn deinit(self: *StreamCore) void {
        self.inbound_data.deinit();
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    transport: *noise.SecureTransport,
    is_initiator: bool,
    next_stream_id: u32,
    state: SessionState = .open,
    state_mu: SyncMutex = .init,
    write_mu: SyncMutex = .init,
    streams_mu: SyncMutex = .init,
    streams: std.AutoHashMap(u32, *StreamCore),
    pending_accept_mu: SyncMutex = .init,
    pending_accept_cv: SyncCondition = .init,
    pending_accept: std.array_list.Managed(u32),
    outbound_ack_backlog: u16 = 0,
    pending_ping: ?u32 = null,
    pending_ping_elapsed_ms: i64 = 0,
    keepalive_nonce: u32 = 1,
    options: SessionOptions,
    frame_payload: std.array_list.Managed(u8),
    demux_future: ?DemuxFuture = null,
    keepalive_future: ?KeepaliveFuture = null,
    demux_started: bool = false,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        transport: *noise.SecureTransport,
        is_initiator: bool,
    ) Self {
        return initWithOptions(allocator, transport, is_initiator, .{});
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        transport: *noise.SecureTransport,
        is_initiator: bool,
        options: SessionOptions,
    ) Self {
        return .{
            .allocator = allocator,
            .transport = transport,
            .is_initiator = is_initiator,
            .next_stream_id = if (is_initiator) 1 else 2,
            .streams = std.AutoHashMap(u32, *StreamCore).init(allocator),
            .pending_accept = std.array_list.Managed(u32).init(allocator),
            .options = options,
            .frame_payload = std.array_list.Managed(u8).init(allocator),
        };
    }

    pub fn start(self: *Self) !void {
        if (self.demux_started) return;
        self.demux_future = try self.transport.conn.io.concurrent(demuxTaskMain, .{self});
        self.keepalive_future = try self.transport.conn.io.concurrent(keepaliveTaskMain, .{self});
        self.demux_started = true;
    }

    pub fn deinit(self: *Self) void {
        self.beginClosing(.closing);
        self.transport.conn.close(self.transport.conn.io) catch {};

        if (self.demux_future) |*future| {
            _ = future.cancel(self.transport.conn.io) catch {};
        }
        if (self.keepalive_future) |*future| {
            _ = future.cancel(self.transport.conn.io) catch {};
        }

        mutexLock(&self.streams_mu);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        mutexUnlock(&self.streams_mu);
        self.streams.deinit();
        self.pending_accept.deinit();
        self.frame_payload.deinit();
    }

    pub fn openStream(self: *Self, io: std.Io) !Stream {
        if (!self.canOpenNewStreams()) {
            return YamuxError.GoAway;
        }

        mutexLock(&self.state_mu);
        if (self.outbound_ack_backlog >= MAX_ACK_BACKLOG) {
            mutexUnlock(&self.state_mu);
            return YamuxError.AckBacklogFull;
        }
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        self.outbound_ack_backlog += 1;
        mutexUnlock(&self.state_mu);

        const core = try self.createStreamCore(stream_id, .syn_sent);
        errdefer self.destroyStreamCore(stream_id);

        try self.writeFrame(.data, FLAG_SYN, stream_id, 0, "");

        mutexLock(&core.mutex);
        defer mutexUnlock(&core.mutex);
        while (true) {
            switch (core.state) {
                .open, .remote_half_closed, .local_half_closed => break,
                .reset => return YamuxError.StreamClosed,
                .closed => return YamuxError.SessionClosed,
                else => {
                    if (self.sessionIsClosed()) return YamuxError.SessionClosed;
                    try condWait(&core.cond, io, &core.mutex);
                },
            }
        }

        return Stream.init(self.allocator, self, core);
    }

    pub fn openStreamConcurrent(self: *Self, io: std.Io) std.Io.ConcurrentError!OpenStreamFuture {
        return io.concurrent(openStreamTaskMain, .{ self, io });
    }

    pub fn acceptStream(self: *Self, io: std.Io) !Stream {
        while (true) {
            mutexLock(&self.pending_accept_mu);
            while (self.pending_accept.items.len == 0) {
                if (self.state != .open) {
                    mutexUnlock(&self.pending_accept_mu);
                    return YamuxError.GoAway;
                }
                try condWait(&self.pending_accept_cv, io, &self.pending_accept_mu);
            }
            const stream_id = self.pending_accept.orderedRemove(0);
            mutexUnlock(&self.pending_accept_mu);

            mutexLock(&self.streams_mu);
            const core = self.streams.get(stream_id);
            mutexUnlock(&self.streams_mu);
            if (core) |stream_core| {
                return Stream.init(self.allocator, self, stream_core);
            }
        }
    }

    pub fn acceptStreamConcurrent(self: *Self, io: std.Io) std.Io.ConcurrentError!AcceptStreamFuture {
        return io.concurrent(acceptStreamTaskMain, .{ self, io });
    }

    pub fn ping(self: *Self, nonce_value: u32) !void {
        mutexLock(&self.state_mu);
        if (self.state != .open) {
            mutexUnlock(&self.state_mu);
            return YamuxError.GoAway;
        }
        self.pending_ping = nonce_value;
        self.pending_ping_elapsed_ms = 0;
        mutexUnlock(&self.state_mu);
        try self.writeFrame(.ping, FLAG_SYN, 0, nonce_value, "");
    }

    fn keepaliveTask(self: *Self) !void {
        const interval_ms = if (self.options.keepalive_interval_ms > 0) self.options.keepalive_interval_ms else 15_000;
        const timeout_ms = if (self.options.keepalive_timeout_ms > interval_ms) self.options.keepalive_timeout_ms else interval_ms;

        while (true) {
            try std.Io.checkCancel(self.transport.conn.io);
            try self.transport.conn.io.sleep(std.Io.Duration.fromMilliseconds(interval_ms), .awake);

            var send_ping: ?u32 = null;
            var timed_out = false;

            mutexLock(&self.state_mu);
            if (self.state != .open) {
                mutexUnlock(&self.state_mu);
                return;
            }

            if (self.pending_ping) |pending_nonce| {
                _ = pending_nonce;
                self.pending_ping_elapsed_ms +|= interval_ms;
                if (self.pending_ping_elapsed_ms >= timeout_ms) {
                    timed_out = true;
                }
            } else {
                send_ping = self.keepalive_nonce;
                self.keepalive_nonce +%= 1;
                self.pending_ping = send_ping;
                self.pending_ping_elapsed_ms = 0;
            }
            mutexUnlock(&self.state_mu);

            if (timed_out) {
                self.sendGoAway(.protocol_error) catch {};
                self.beginClosing(.closed);
                self.transport.conn.close(self.transport.conn.io) catch {};
                return YamuxError.GoAway;
            }

            if (send_ping) |nonce_value| {
                self.writeFrame(.ping, FLAG_SYN, 0, nonce_value, "") catch |err| {
                    self.beginClosing(.closed);
                    self.transport.conn.close(self.transport.conn.io) catch {};
                    return err;
                };
            }
        }
    }

    fn demuxTask(self: *Self) !void {
        while (true) {
            try std.Io.checkCancel(self.transport.conn.io);
            const frame = self.readFrame() catch |err| {
                if (!self.sessionIsClosed()) {
                    self.beginClosing(.closed);
                }
                return err;
            };

            self.handleFrame(frame) catch |err| {
                if (err == YamuxError.ProtocolError) {
                    self.sendGoAway(.protocol_error) catch {};
                } else if (err != YamuxError.GoAway) {
                    self.sendGoAway(.internal_error) catch {};
                }
                self.beginClosing(.closed);
                self.transport.conn.close(self.transport.conn.io) catch {};
                return err;
            };
        }
    }

    fn handleFrame(self: *Self, frame: Frame) !void {
        switch (frame.header.typ) {
            .data => try self.handleStreamFrame(frame),
            .window_update => try self.handleWindowUpdate(frame),
            .ping => try self.handlePing(frame),
            .go_away => try self.handleGoAway(frame),
        }
    }

    fn handleStreamFrame(self: *Self, frame: Frame) !void {
        if (frame.header.stream_id == 0) return YamuxError.ProtocolError;

        var core = self.lookupStream(frame.header.stream_id);
        if (core == null) {
            if ((frame.header.flags & FLAG_SYN) == 0) {
                try self.writeFrame(.data, FLAG_RST, frame.header.stream_id, 0, "");
                return;
            }
            if ((frame.header.flags & FLAG_ACK) != 0) return YamuxError.ProtocolError;
            if (!self.isValidInboundStreamId(frame.header.stream_id)) {
                try self.writeFrame(.data, FLAG_RST, frame.header.stream_id, 0, "");
                return;
            }
            if (!self.canAcceptNewStreams()) {
                try self.writeFrame(.data, FLAG_RST, frame.header.stream_id, 0, "");
                return;
            }

            mutexLock(&self.pending_accept_mu);
            const backlog_full = self.pending_accept.items.len >= MAX_PENDING_ACCEPT;
            mutexUnlock(&self.pending_accept_mu);
            if (backlog_full) {
                try self.writeFrame(.data, FLAG_RST, frame.header.stream_id, 0, "");
                return;
            }

            core = try self.createStreamCore(frame.header.stream_id, .syn_received);
            try self.writeFrame(.data, FLAG_ACK, frame.header.stream_id, 0, "");

            mutexLock(&core.?.mutex);
            if ((frame.header.flags & FLAG_FIN) != 0) {
                core.?.state = .remote_half_closed;
            } else {
                core.?.state = .open;
            }
            mutexUnlock(&core.?.mutex);

            self.pendingAccept(frame.header.stream_id);
        }

        try self.applyDataFrame(core.?, frame);
    }

    fn handleWindowUpdate(self: *Self, frame: Frame) !void {
        if (frame.header.stream_id == 0) return YamuxError.ProtocolError;

        const core = self.lookupStream(frame.header.stream_id) orelse {
            try self.writeFrame(.window_update, FLAG_RST, frame.header.stream_id, 0, "");
            return;
        };

        var should_signal = false;
        mutexLock(&core.mutex);
        defer mutexUnlock(&core.mutex);

        if ((frame.header.flags & FLAG_ACK) != 0 and core.state == .syn_sent) {
            core.state = .open;
            self.decrementAckBacklog();
            should_signal = true;
        }
        if (frame.header.length > 0) {
            core.send_window +|= frame.header.length;
            should_signal = true;
        }
        if ((frame.header.flags & FLAG_RST) != 0) {
            core.state = .reset;
            should_signal = true;
        } else if ((frame.header.flags & FLAG_FIN) != 0) {
            core.state = switch (core.state) {
                .local_half_closed => .closed,
                .closed, .reset => core.state,
                else => .remote_half_closed,
            };
            should_signal = true;
        }

        if (should_signal) {
            core.cond.broadcast(syncIo());
        }
    }

    fn handlePing(self: *Self, frame: Frame) !void {
        if (frame.header.stream_id != 0) return YamuxError.ProtocolError;
        if (frame.header.flags == FLAG_SYN) {
            try self.writeFrame(.ping, FLAG_ACK, 0, frame.header.length, "");
            return;
        }
        if (frame.header.flags == FLAG_ACK) {
            mutexLock(&self.state_mu);
            if (self.pending_ping == frame.header.length) {
                self.pending_ping = null;
                self.pending_ping_elapsed_ms = 0;
            }
            mutexUnlock(&self.state_mu);
            return;
        }
        return YamuxError.ProtocolError;
    }

    fn handleGoAway(self: *Self, frame: Frame) !void {
        if (frame.header.stream_id != 0 or frame.header.flags != 0) return YamuxError.ProtocolError;

        const code: GoAwayCode = switch (frame.header.length) {
            0 => .normal,
            1 => .protocol_error,
            2 => .internal_error,
            else => return YamuxError.ProtocolError,
        };

        switch (code) {
            .normal => {
                self.beginClosing(.go_away_received);
                return;
            },
            else => {
                self.beginClosing(.closed);
                self.transport.conn.close(self.transport.conn.io) catch {};
                return YamuxError.GoAway;
            },
        }
    }

    fn applyDataFrame(self: *Self, core: *StreamCore, frame: Frame) !void {
        var should_signal = false;

        mutexLock(&core.mutex);
        defer mutexUnlock(&core.mutex);

        if ((frame.header.flags & FLAG_ACK) != 0 and core.state == .syn_sent) {
            core.state = .open;
            self.decrementAckBacklog();
            should_signal = true;
        }

        if (frame.payload.len > 0) {
            if (frame.payload.len > core.recv_window) {
                return YamuxError.ProtocolError;
            }
            if (core.inbound_offset == core.inbound_data.items.len) {
                core.inbound_data.clearRetainingCapacity();
                core.inbound_offset = 0;
            }
            try core.inbound_data.appendSlice(frame.payload);
            core.recv_window -= @intCast(frame.payload.len);
            should_signal = true;
        }

        if ((frame.header.flags & FLAG_RST) != 0) {
            core.state = .reset;
            should_signal = true;
        } else if ((frame.header.flags & FLAG_FIN) != 0) {
            core.state = switch (core.state) {
                .local_half_closed => .closed,
                .closed, .reset => core.state,
                else => .remote_half_closed,
            };
            should_signal = true;
        }

        if (should_signal) {
            core.cond.broadcast(syncIo());
        }
    }

    fn createStreamCore(self: *Self, stream_id: u32, state: StreamState) !*StreamCore {
        const core = try self.allocator.create(StreamCore);
        errdefer self.allocator.destroy(core);
        core.* = StreamCore.init(self.allocator, stream_id, state);
        mutexLock(&self.streams_mu);
        defer mutexUnlock(&self.streams_mu);
        try self.streams.put(stream_id, core);
        return core;
    }

    fn destroyStreamCore(self: *Self, stream_id: u32) void {
        mutexLock(&self.streams_mu);
        defer mutexUnlock(&self.streams_mu);
        if (self.streams.fetchRemove(stream_id)) |removed| {
            removed.value.deinit();
            self.allocator.destroy(removed.value);
        }
    }

    fn lookupStream(self: *Self, stream_id: u32) ?*StreamCore {
        mutexLock(&self.streams_mu);
        defer mutexUnlock(&self.streams_mu);
        return self.streams.get(stream_id);
    }

    fn pendingAccept(self: *Self, stream_id: u32) void {
        mutexLock(&self.pending_accept_mu);
        defer mutexUnlock(&self.pending_accept_mu);
        self.pending_accept.append(stream_id) catch return;
        self.pending_accept_cv.signal(syncIo());
    }

    fn decrementAckBacklog(self: *Self) void {
        mutexLock(&self.state_mu);
        defer mutexUnlock(&self.state_mu);
        if (self.outbound_ack_backlog > 0) self.outbound_ack_backlog -= 1;
    }

    fn beginClosing(self: *Self, next_state: SessionState) void {
        mutexLock(&self.state_mu);
        if (@intFromEnum(next_state) > @intFromEnum(self.state)) {
            self.state = next_state;
        } else if (self.state == .open) {
            self.state = next_state;
        }
        mutexUnlock(&self.state_mu);

        mutexLock(&self.pending_accept_mu);
        self.pending_accept_cv.broadcast(syncIo());
        mutexUnlock(&self.pending_accept_mu);

        if (next_state != .closing and next_state != .closed) return;

        mutexLock(&self.streams_mu);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.cond.broadcast(syncIo());
        }
        mutexUnlock(&self.streams_mu);
    }

    fn sendGoAway(self: *Self, code: GoAwayCode) !void {
        mutexLock(&self.state_mu);
        if (self.state != .open) {
            mutexUnlock(&self.state_mu);
            return;
        }
        self.state = .go_away_sent;
        mutexUnlock(&self.state_mu);
        try self.writeFrame(.go_away, 0, 0, @intFromEnum(code), "");

        if (code != .normal) {
            self.beginClosing(.closed);
            self.transport.conn.close(self.transport.conn.io) catch {};
        }
    }

    fn sessionIsClosed(self: *Self) bool {
        mutexLock(&self.state_mu);
        defer mutexUnlock(&self.state_mu);
        return self.state == .closing or self.state == .closed;
    }

    fn canOpenNewStreams(self: *Self) bool {
        mutexLock(&self.state_mu);
        defer mutexUnlock(&self.state_mu);
        return self.state == .open;
    }

    fn canAcceptNewStreams(self: *Self) bool {
        mutexLock(&self.state_mu);
        defer mutexUnlock(&self.state_mu);
        return self.state == .open;
    }

    fn writeFrame(
        self: *Self,
        typ: FrameType,
        flags: u16,
        stream_id: u32,
        length: u32,
        payload: []const u8,
    ) !void {
        mutexLock(&self.write_mu);
        defer mutexUnlock(&self.write_mu);

        var header: [12]u8 = undefined;
        header[0] = 0;
        header[1] = @intFromEnum(typ);
        std.mem.writeInt(u16, header[2..4], flags, .big);
        std.mem.writeInt(u32, header[4..8], stream_id, .big);
        std.mem.writeInt(u32, header[8..12], length, .big);
        const io = self.transport.conn.io;
        var fragments = [_][]const u8{ &header, payload };
        try self.transport.writeVecAll(io, &fragments);
    }

    fn readFrame(self: *Self) !Frame {
        var header_bytes: [12]u8 = undefined;
        const io = self.transport.conn.io;
        try readNoEof(self.transport, io, &header_bytes);

        const version = header_bytes[0];
        if (version != 0) return YamuxError.UnsupportedVersion;

        const typ: FrameType = switch (header_bytes[1]) {
            0 => .data,
            1 => .window_update,
            2 => .ping,
            3 => .go_away,
            else => return YamuxError.UnsupportedFrameType,
        };

        const flags = std.mem.readInt(u16, header_bytes[2..4], .big);
        const stream_id = std.mem.readInt(u32, header_bytes[4..8], .big);
        const length = std.mem.readInt(u32, header_bytes[8..12], .big);

        if (typ == .data and length > MAX_FRAME_PAYLOAD) return YamuxError.InvalidFrame;
        if (typ != .data and length > MAX_FRAME_PAYLOAD and typ != .ping and typ != .go_away) return YamuxError.InvalidFrame;

        const payload_len: usize = if (typ == .data) length else 0;
        try self.frame_payload.resize(payload_len);
        if (payload_len > 0) try readNoEof(self.transport, io, self.frame_payload.items);

        return .{
            .header = .{
                .version = version,
                .typ = typ,
                .flags = flags,
                .stream_id = stream_id,
                .length = length,
            },
            .payload = self.frame_payload.items[0..payload_len],
        };
    }

    fn isValidInboundStreamId(self: *const Self, stream_id: u32) bool {
        if (stream_id == 0) return false;
        const is_odd = (stream_id & 1) == 1;
        return if (self.is_initiator) !is_odd else is_odd;
    }
};

pub const Stream = struct {
    session: *Session,
    core: *StreamCore,

    const Self = @This();

    fn init(allocator: std.mem.Allocator, session: *Session, core: *StreamCore) Self {
        _ = allocator;
        return .{
            .session = session,
            .core = core,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn writeAll(self: *Self, io: std.Io, data: []const u8) !void {
        var off: usize = 0;
        while (off < data.len) {
            mutexLock(&self.core.mutex);
            while (self.core.send_window == 0) {
                if (self.core.state == .reset or self.core.state == .closed or self.core.state == .local_half_closed) {
                    mutexUnlock(&self.core.mutex);
                    return YamuxError.StreamClosed;
                }
                if (self.session.sessionIsClosed()) {
                    mutexUnlock(&self.core.mutex);
                    return YamuxError.SessionClosed;
                }
                try condWait(&self.core.cond, io, &self.core.mutex);
            }

            if (self.core.state == .reset or self.core.state == .closed or self.core.state == .local_half_closed) {
                mutexUnlock(&self.core.mutex);
                return YamuxError.StreamClosed;
            }
            if (self.session.sessionIsClosed()) {
                mutexUnlock(&self.core.mutex);
                return YamuxError.SessionClosed;
            }

            const chunk_len: usize = @intCast(@min(@as(u32, @intCast(data.len - off)), @min(self.core.send_window, MAX_FRAME_PAYLOAD)));
            self.core.send_window -= @intCast(chunk_len);
            mutexUnlock(&self.core.mutex);

            try self.session.writeFrame(.data, 0, self.core.stream_id, @intCast(chunk_len), data[off .. off + chunk_len]);
            off += chunk_len;
        }
    }

    pub fn writeByte(self: *Self, io: std.Io, b: u8) !void {
        const one = [_]u8{b};
        try self.writeAll(io, &one);
    }

    pub fn close(self: *Self, io: std.Io) !void {
        mutexLock(&self.core.mutex);
        if (self.core.state == .local_half_closed or self.core.state == .closed or self.core.state == .reset) {
            mutexUnlock(&self.core.mutex);
            return;
        }
        self.core.state = switch (self.core.state) {
            .remote_half_closed => .closed,
            else => .local_half_closed,
        };
        mutexUnlock(&self.core.mutex);
        _ = io;
        try self.session.writeFrame(.data, FLAG_FIN, self.core.stream_id, 0, "");
    }

    pub fn readSome(self: *Self, io: std.Io, dest: []u8) !usize {
        if (dest.len == 0) return 0;

        while (true) {
            mutexLock(&self.core.mutex);

            if (self.core.inbound_offset < self.core.inbound_data.items.len) {
                const remaining = self.core.inbound_data.items.len - self.core.inbound_offset;
                const n = @min(remaining, dest.len);
                @memcpy(dest[0..n], self.core.inbound_data.items[self.core.inbound_offset .. self.core.inbound_offset + n]);
                self.core.inbound_offset += n;

                if (self.core.inbound_offset == self.core.inbound_data.items.len) {
                    self.core.inbound_data.clearRetainingCapacity();
                    self.core.inbound_offset = 0;
                }

                mutexUnlock(&self.core.mutex);
                try self.restoreReceiveWindow(@intCast(n));
                return n;
            }

            if (self.core.state == .reset) {
                mutexUnlock(&self.core.mutex);
                return YamuxError.StreamClosed;
            }
            if (self.core.state == .remote_half_closed or self.core.state == .closed) {
                mutexUnlock(&self.core.mutex);
                return 0;
            }
            if (self.session.sessionIsClosed()) {
                mutexUnlock(&self.core.mutex);
                return YamuxError.SessionClosed;
            }
            try condWait(&self.core.cond, io, &self.core.mutex);
            mutexUnlock(&self.core.mutex);
        }
    }

    fn restoreReceiveWindow(self: *Self, consumed: u32) !void {
        if (consumed == 0) return;

        var send_delta: u32 = 0;
        mutexLock(&self.core.mutex);
        self.core.pending_window_credit +|= consumed;
        if (self.core.pending_window_credit >= WINDOW_UPDATE_THRESHOLD or self.core.recv_window == 0) {
            send_delta = self.core.pending_window_credit;
            self.core.recv_window +|= send_delta;
            self.core.pending_window_credit = 0;
        }
        mutexUnlock(&self.core.mutex);

        if (send_delta > 0) {
            try self.session.writeFrame(.window_update, 0, self.core.stream_id, send_delta, "");
        }
    }
};

fn demuxTaskMain(session: *Session) anyerror!void {
    return session.demuxTask();
}

fn keepaliveTaskMain(session: *Session) anyerror!void {
    return session.keepaliveTask();
}

fn openStreamTaskMain(session: *Session, io: std.Io) anyerror!Stream {
    return session.openStream(io);
}

fn acceptStreamTaskMain(session: *Session, io: std.Io) anyerror!Stream {
    return session.acceptStream(io);
}

fn syncIo() std.Io {
    return std.Io.Threaded.global_single_threaded.ioBasic();
}

fn mutexLock(mutex: *SyncMutex) void {
    mutex.lockUncancelable(syncIo());
}

fn mutexUnlock(mutex: *SyncMutex) void {
    mutex.unlock(syncIo());
}

fn condWait(cond: *SyncCondition, io: std.Io, mutex: *SyncMutex) !void {
    try cond.wait(io, mutex);
}

fn readNoEof(transport: *noise.SecureTransport, io: std.Io, dest: []u8) !void {
    var off: usize = 0;
    while (off < dest.len) {
        const n = try transport.readSome(io, dest[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

fn readAllFromStream(allocator: std.mem.Allocator, io: std.Io, stream: *Stream) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try stream.readSome(io, &buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
    }
    return out.toOwnedSlice();
}

const TestReader = struct {
    stream: *Stream,
    io: std.Io,

    pub fn readByte(self: *TestReader) !u8 {
        var one: [1]u8 = undefined;
        const n = try self.stream.readSome(self.io, &one);
        if (n == 0) return error.EndOfStream;
        return one[0];
    }

    pub fn readNoEof(self: *TestReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            const n = try self.stream.readSome(self.io, dest[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

const TestWriter = struct {
    stream: *Stream,
    io: std.Io,

    pub fn writeAll(self: *TestWriter, data: []const u8) !void {
        try self.stream.writeAll(self.io, data);
    }

    pub fn writeByte(self: *TestWriter, b: u8) !void {
        try self.stream.writeByte(self.io, b);
    }
};

fn readLineFromTestStream(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();

    while (true) {
        const b = try reader.readByte();
        if (b == '\n') break;
        try buf.append(b);
    }

    return buf.toOwnedSlice();
}

test "yamux header parse primitives" {
    var header: [12]u8 = undefined;
    header[0] = 0;
    header[1] = @intFromEnum(FrameType.data);
    std.mem.writeInt(u16, header[2..4], FLAG_SYN | FLAG_ACK, .big);
    std.mem.writeInt(u32, header[4..8], 5, .big);
    std.mem.writeInt(u32, header[8..12], 123, .big);

    try std.testing.expectEqual(@as(u8, 0), header[0]);
    try std.testing.expectEqual(@as(u8, 0), header[1]);
    try std.testing.expectEqual(@as(u16, FLAG_SYN | FLAG_ACK), std.mem.readInt(u16, header[2..4], .big));
    try std.testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, header[4..8], .big));
    try std.testing.expectEqual(@as(u32, 123), std.mem.readInt(u32, header[8..12], .big));
}

test "yamux supports two concurrent streams" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x11} ** 32;
            const rx_key = [_]u8{0x22} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var first_accept = try session.acceptStreamConcurrent(ctx.io);
            var second_accept = try session.acceptStreamConcurrent(ctx.io);
            var first = try first_accept.await(ctx.io);
            defer first.deinit();
            var second = try second_accept.await(ctx.io);
            defer second.deinit();

            const second_msg = try readAllFromStream(ctx.allocator, ctx.io, &second);
            defer ctx.allocator.free(second_msg);
            const first_msg = try readAllFromStream(ctx.allocator, ctx.io, &first);
            defer ctx.allocator.free(first_msg);

            if (!std.mem.eql(u8, first_msg, "one")) return error.TestExpectedEqual;
            if (!std.mem.eql(u8, second_msg, "two")) return error.TestExpectedEqual;

            try second.writeAll(ctx.io, "dos");
            try second.close(ctx.io);

            try first.writeAll(ctx.io, "uno");
            try first.close(ctx.io);
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .allocator = allocator, .io = io };

    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0x11} ** 32, [_]u8{0x22} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var first_open = try session.openStreamConcurrent(io);
    var second_open = try session.openStreamConcurrent(io);
    var first = try first_open.await(io);
    defer first.deinit();
    var second = try second_open.await(io);
    defer second.deinit();

    try first.writeAll(io, "one");
    try first.close(io);
    try second.writeAll(io, "two");
    try second.close(io);

    const second_reply = try readAllFromStream(allocator, io, &second);
    defer allocator.free(second_reply);
    const first_reply = try readAllFromStream(allocator, io, &first);
    defer allocator.free(first_reply);

    try std.testing.expectEqualStrings("uno", first_reply);
    try std.testing.expectEqualStrings("dos", second_reply);
    try responder_future.await(io);
}

test "yamux supports three simultaneous streams from both sides" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x13} ** 32;
            const rx_key = [_]u8{0x24} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_1_future = try session.acceptStreamConcurrent(ctx.io);
            var accept_2_future = try session.acceptStreamConcurrent(ctx.io);
            var accept_3_future = try session.acceptStreamConcurrent(ctx.io);
            var open_1_future = try session.openStreamConcurrent(ctx.io);
            var open_2_future = try session.openStreamConcurrent(ctx.io);
            var open_3_future = try session.openStreamConcurrent(ctx.io);

            var out_1 = try open_1_future.await(ctx.io);
            defer out_1.deinit();
            var out_2 = try open_2_future.await(ctx.io);
            defer out_2.deinit();
            var out_3 = try open_3_future.await(ctx.io);
            defer out_3.deinit();

            try out_1.writeAll(ctx.io, "resp-1");
            try out_1.close(ctx.io);
            try out_2.writeAll(ctx.io, "resp-2");
            try out_2.close(ctx.io);
            try out_3.writeAll(ctx.io, "resp-3");
            try out_3.close(ctx.io);

            var in_1 = try accept_1_future.await(ctx.io);
            defer in_1.deinit();
            var in_2 = try accept_2_future.await(ctx.io);
            defer in_2.deinit();
            var in_3 = try accept_3_future.await(ctx.io);
            defer in_3.deinit();

            const msg_1 = try readAllFromStream(ctx.allocator, ctx.io, &in_1);
            defer ctx.allocator.free(msg_1);
            const msg_2 = try readAllFromStream(ctx.allocator, ctx.io, &in_2);
            defer ctx.allocator.free(msg_2);
            const msg_3 = try readAllFromStream(ctx.allocator, ctx.io, &in_3);
            defer ctx.allocator.free(msg_3);

            var saw_1 = false;
            var saw_2 = false;
            var saw_3 = false;
            for ([_][]const u8{ msg_1, msg_2, msg_3 }) |msg| {
                if (std.mem.eql(u8, msg, "init-1")) {
                    saw_1 = true;
                } else if (std.mem.eql(u8, msg, "init-2")) {
                    saw_2 = true;
                } else if (std.mem.eql(u8, msg, "init-3")) {
                    saw_3 = true;
                } else {
                    return error.TestExpectedEqual;
                }
            }
            if (!saw_1 or !saw_2 or !saw_3) return error.TestExpectedEqual;
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0x13} ** 32, [_]u8{0x24} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var accept_1_future = try session.acceptStreamConcurrent(io);
    var accept_2_future = try session.acceptStreamConcurrent(io);
    var accept_3_future = try session.acceptStreamConcurrent(io);
    var open_1_future = try session.openStreamConcurrent(io);
    var open_2_future = try session.openStreamConcurrent(io);
    var open_3_future = try session.openStreamConcurrent(io);

    var out_1 = try open_1_future.await(io);
    defer out_1.deinit();
    var out_2 = try open_2_future.await(io);
    defer out_2.deinit();
    var out_3 = try open_3_future.await(io);
    defer out_3.deinit();

    try out_1.writeAll(io, "init-1");
    try out_1.close(io);
    try out_2.writeAll(io, "init-2");
    try out_2.close(io);
    try out_3.writeAll(io, "init-3");
    try out_3.close(io);

    var in_1 = try accept_1_future.await(io);
    defer in_1.deinit();
    var in_2 = try accept_2_future.await(io);
    defer in_2.deinit();
    var in_3 = try accept_3_future.await(io);
    defer in_3.deinit();

    const msg_1 = try readAllFromStream(allocator, io, &in_1);
    defer allocator.free(msg_1);
    const msg_2 = try readAllFromStream(allocator, io, &in_2);
    defer allocator.free(msg_2);
    const msg_3 = try readAllFromStream(allocator, io, &in_3);
    defer allocator.free(msg_3);

    var saw_1 = false;
    var saw_2 = false;
    var saw_3 = false;
    for ([_][]const u8{ msg_1, msg_2, msg_3 }) |msg| {
        if (std.mem.eql(u8, msg, "resp-1")) {
            saw_1 = true;
        } else if (std.mem.eql(u8, msg, "resp-2")) {
            saw_2 = true;
        } else if (std.mem.eql(u8, msg, "resp-3")) {
            saw_3 = true;
        } else {
            return error.TestExpectedEqual;
        }
    }
    try std.testing.expect(saw_1 and saw_2 and saw_3);
    try responder_future.await(io);
}

test "yamux blocks on exhausted window then resumes after window update" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const payload = try allocator.alloc(u8, INITIAL_STREAM_WINDOW + 64 * 1024);
    defer allocator.free(payload);
    @memset(payload, 0x5A);

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x31} ** 32;
            const rx_key = [_]u8{0x42} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_future = try session.acceptStreamConcurrent(ctx.io);
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            // Delay reads so the remote writer exhausts send_window and blocks.
            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(180), .awake);

            const received = try readAllFromStream(ctx.allocator, ctx.io, &stream);
            defer ctx.allocator.free(received);

            if (received.len != INITIAL_STREAM_WINDOW + 64 * 1024) return error.TestExpectedEqual;
            for (received) |byte| {
                if (byte != 0x5A) return error.TestExpectedEqual;
            }
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .allocator = allocator, .io = io };

    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0x31} ** 32, [_]u8{0x42} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    const WriterCtx = struct {
        stream: *Stream,
        io: std.Io,
        payload: []const u8,
        elapsed_ns: u64 = 0,

        fn run(ctx: *@This()) anyerror!void {
            var timer = try std.time.Timer.start();
            try ctx.stream.writeAll(ctx.io, ctx.payload);
            try ctx.stream.close(ctx.io);
            ctx.elapsed_ns = timer.read();
        }
    };

    var open_future = try session.openStreamConcurrent(io);
    var stream = try open_future.await(io);
    defer stream.deinit();

    var writer_ctx = WriterCtx{
        .stream = &stream,
        .io = io,
        .payload = payload,
    };
    var writer_future = try io.concurrent(WriterCtx.run, .{&writer_ctx});
    defer _ = writer_future.cancel(io) catch {};

    try writer_future.await(io);
    try std.testing.expect(writer_ctx.elapsed_ns >= 120 * std.time.ns_per_ms);
    try responder_future.await(io);
}

test "yamux handles identify then peer exchange across sequential streams" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x61} ** 32;
            const rx_key = [_]u8{0x72} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var identify_accept = try session.acceptStreamConcurrent(ctx.io);
            var identify_stream = try identify_accept.await(ctx.io);
            defer identify_stream.deinit();

            var identify_reader = TestReader{ .stream = &identify_stream, .io = ctx.io };
            var identify_writer = TestWriter{ .stream = &identify_stream, .io = ctx.io };

            const identify_proto = try ms.readMessage(ctx.io, &identify_reader, ctx.allocator);
            defer ctx.allocator.free(identify_proto);
            if (!std.mem.eql(u8, identify_proto, "/ipfs/id/1.0.0")) return error.TestExpectedEqual;

            try ms.writeMessage(ctx.io, &identify_writer, "/ipfs/id/1.0.0");
            try identify_writer.writeAll("identify-payload");
            try identify_stream.close(ctx.io);

            var peer_accept = try session.acceptStreamConcurrent(ctx.io);
            var peer_stream = try peer_accept.await(ctx.io);
            defer peer_stream.deinit();

            var peer_reader = TestReader{ .stream = &peer_stream, .io = ctx.io };
            var peer_writer = TestWriter{ .stream = &peer_stream, .io = ctx.io };

            const proto = try ms.readMessage(ctx.io, &peer_reader, ctx.allocator);
            defer ctx.allocator.free(proto);
            if (!std.mem.eql(u8, proto, "/zeicoin/peers/1.0.0")) return error.TestExpectedEqual;

            try ms.writeMessage(ctx.io, &peer_writer, "/zeicoin/peers/1.0.0");

            const req_line = try readLineFromTestStream(ctx.allocator, &peer_reader);
            defer ctx.allocator.free(req_line);
            if (!std.mem.eql(u8, req_line, "GET_PEERS 12011")) return error.TestExpectedEqual;

            try peer_writer.writeAll("PEERS 1\n");
            try peer_stream.close(ctx.io);
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0x61} ** 32, [_]u8{0x72} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var identify_open = try session.openStreamConcurrent(io);
    var identify_stream = try identify_open.await(io);
    defer identify_stream.deinit();

    var identify_reader = TestReader{ .stream = &identify_stream, .io = io };
    var identify_writer = TestWriter{ .stream = &identify_stream, .io = io };

    try ms.writeMessage(io, &identify_writer, "/ipfs/id/1.0.0");
    const identify_ack = try ms.readMessage(io, &identify_reader, allocator);
    defer allocator.free(identify_ack);
    try std.testing.expectEqualStrings("/ipfs/id/1.0.0", identify_ack);

    const identify_payload = try readAllFromStream(allocator, io, &identify_stream);
    defer allocator.free(identify_payload);
    try std.testing.expectEqualStrings("identify-payload", identify_payload);

    var peer_open = try session.openStreamConcurrent(io);
    var peer_stream = try peer_open.await(io);
    defer peer_stream.deinit();

    var peer_reader = TestReader{ .stream = &peer_stream, .io = io };
    var peer_writer = TestWriter{ .stream = &peer_stream, .io = io };

    try ms.writeMessage(io, &peer_writer, "/zeicoin/peers/1.0.0");
    const peer_ack = try ms.readMessage(io, &peer_reader, allocator);
    defer allocator.free(peer_ack);
    try std.testing.expectEqualStrings("/zeicoin/peers/1.0.0", peer_ack);

    try peer_writer.writeAll("GET_PEERS 12011\n");
    const peer_header = try readLineFromTestStream(allocator, &peer_reader);
    defer allocator.free(peer_header);
    try std.testing.expectEqualStrings("PEERS 1", peer_header);
    try responder_future.await(io);
}

test "yamux normal go away drains existing streams and rejects new ones" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0x81} ** 32;
            const rx_key = [_]u8{0x92} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_future = try session.acceptStreamConcurrent(ctx.io);
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            try session.sendGoAway(.normal);

            const req = try readAllFromStream(ctx.allocator, ctx.io, &stream);
            defer ctx.allocator.free(req);
            if (!std.mem.eql(u8, req, "still-open")) return error.TestExpectedEqual;

            try stream.writeAll(ctx.io, "reply");
            try stream.close(ctx.io);

            _ = session.acceptStream(ctx.io) catch |err| {
                if (err != YamuxError.GoAway) return err;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0x81} ** 32, [_]u8{0x92} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var open_future = try session.openStreamConcurrent(io);
    var stream = try open_future.await(io);
    defer stream.deinit();
    try stream.writeAll(io, "still-open");
    try stream.close(io);

    const reply = try readAllFromStream(allocator, io, &stream);
    defer allocator.free(reply);
    try std.testing.expectEqualStrings("reply", reply);

    try std.testing.expectError(YamuxError.GoAway, session.openStream(io));
    try responder_future.await(io);
}

test "yamux keepalive ping pong keeps session alive" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const opts = SessionOptions{
        .keepalive_interval_ms = 30,
        .keepalive_timeout_ms = 150,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: SessionOptions,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0xA1} ** 32;
            const rx_key = [_]u8{0xB2} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.initWithOptions(ctx.allocator, &secure, false, ctx.options);
            defer session.deinit();
            try session.start();

            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(220), .awake);

            var accept_future = try session.acceptStreamConcurrent(ctx.io);
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            const req = try readAllFromStream(ctx.allocator, ctx.io, &stream);
            defer ctx.allocator.free(req);
            if (!std.mem.eql(u8, req, "alive")) return error.TestExpectedEqual;

            try stream.writeAll(ctx.io, "ok");
            try stream.close(ctx.io);
        }
    };

    var responder_ctx = ResponderCtx{
        .listener = listener,
        .allocator = allocator,
        .io = io,
        .options = opts,
    };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0xA1} ** 32, [_]u8{0xB2} ** 32);
    defer secure.deinit();

    var session = Session.initWithOptions(allocator, &secure, true, opts);
    defer session.deinit();
    try session.start();

    try io.sleep(std.Io.Duration.fromMilliseconds(220), .awake);

    var open_future = try session.openStreamConcurrent(io);
    var stream = try open_future.await(io);
    defer stream.deinit();
    try stream.writeAll(io, "alive");
    try stream.close(io);

    const reply = try readAllFromStream(allocator, io, &stream);
    defer allocator.free(reply);
    try std.testing.expectEqualStrings("ok", reply);
    try responder_future.await(io);
}

test "yamux keepalive timeout closes unresponsive session" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();
            try ctx.io.sleep(std.Io.Duration.fromMilliseconds(300), .awake);
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0xC1} ** 32, [_]u8{0xD2} ** 32);
    defer secure.deinit();

    var session = Session.initWithOptions(allocator, &secure, true, .{
        .keepalive_interval_ms = 20,
        .keepalive_timeout_ms = 60,
    });
    defer session.deinit();
    try session.start();

    try io.sleep(std.Io.Duration.fromMilliseconds(220), .awake);

    _ = session.openStream(io) catch |err| switch (err) {
        YamuxError.GoAway, YamuxError.SessionClosed => {},
        else => return err,
    };
    if (!session.sessionIsClosed()) return error.TestUnexpectedResult;
    try responder_future.await(io);
}

test "yamux error go away closes streams and rejects new ones" {
    const allocator = std.testing.allocator;
    const io = std.Io.Threaded.global_single_threaded.ioBasic();

    var transport = tcp.TcpTransport.init(allocator);
    defer transport.deinit();

    var listen_ma = try multiaddr_mod.Multiaddr.create(allocator, "/ip4/127.0.0.1/tcp/0");
    defer listen_ma.deinit();
    const listener = transport.listen(io, &listen_ma) catch |err| switch (err) {
        error.NetworkDown => return error.SkipZigTest,
        else => return err,
    };

    const ResponderCtx = struct {
        listener: *tcp.TcpTransport.Listener,
        allocator: std.mem.Allocator,
        io: std.Io,

        fn run(ctx: *@This()) anyerror!void {
            const tx_key = [_]u8{0xE1} ** 32;
            const rx_key = [_]u8{0xF2} ** 32;

            var conn = try ctx.listener.accept(ctx.io);
            defer conn.deinit();

            var secure = noise.SecureTransport.init(ctx.allocator, &conn, rx_key, tx_key);
            defer secure.deinit();

            var session = Session.init(ctx.allocator, &secure, false);
            defer session.deinit();
            try session.start();

            var accept_future = try session.acceptStreamConcurrent(ctx.io);
            var stream = try accept_future.await(ctx.io);
            defer stream.deinit();

            const req = try readAllFromStream(ctx.allocator, ctx.io, &stream);
            defer ctx.allocator.free(req);
            if (!std.mem.eql(u8, req, "boom")) return error.TestExpectedEqual;

            try session.sendGoAway(.internal_error);
        }
    };

    var responder_ctx = ResponderCtx{ .listener = listener, .allocator = allocator, .io = io };
    var responder_future = try io.concurrent(ResponderCtx.run, .{&responder_ctx});
    defer _ = responder_future.cancel(io) catch {};

    var dial_ma = try multiaddr_mod.Multiaddr.create(allocator, listener.multiaddr.toString());
    defer dial_ma.deinit();
    var dial_future = try transport.dialConcurrent(io, &dial_ma);
    var conn = try dial_future.await(io);
    defer conn.deinit();

    var secure = noise.SecureTransport.init(allocator, &conn, [_]u8{0xE1} ** 32, [_]u8{0xF2} ** 32);
    defer secure.deinit();

    var session = Session.init(allocator, &secure, true);
    defer session.deinit();
    try session.start();

    var open_future = try session.openStreamConcurrent(io);
    var stream = try open_future.await(io);
    defer stream.deinit();
    try stream.writeAll(io, "boom");
    try stream.close(io);

    var one: [1]u8 = undefined;
    _ = stream.readSome(io, &one) catch |err| switch (err) {
        YamuxError.StreamClosed, YamuxError.SessionClosed => 0,
        else => return err,
    };
    _ = session.openStream(io) catch |err| switch (err) {
        YamuxError.GoAway, YamuxError.SessionClosed => {},
        else => return err,
    };
    if (!session.sessionIsClosed()) return error.TestUnexpectedResult;
    try responder_future.await(io);
}
