const std = @import("std");
const noise = @import("../security/noise.zig");
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
    session_io: std.Io,
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
            .session_io = transport.conn.io,
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
        self.transport.conn.close() catch {};

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

    pub fn openStream(self: *Self) !Stream {
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
                    try condWait(&core.cond, self.session_io, &core.mutex);
                },
            }
        }

        return Stream.init(self.allocator, self, core);
    }

    pub fn openStreamConcurrent(self: *Self) std.Io.ConcurrentError!OpenStreamFuture {
        return self.session_io.concurrent(openStreamTaskMain, .{self});
    }

    pub fn acceptStream(self: *Self) !Stream {
        while (true) {
            mutexLock(&self.pending_accept_mu);
            while (self.pending_accept.items.len == 0) {
                if (self.state != .open) {
                    mutexUnlock(&self.pending_accept_mu);
                    return YamuxError.GoAway;
                }
                try condWait(&self.pending_accept_cv, self.session_io, &self.pending_accept_mu);
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

    pub fn acceptStreamConcurrent(self: *Self) std.Io.ConcurrentError!AcceptStreamFuture {
        return self.session_io.concurrent(acceptStreamTaskMain, .{self});
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

    // Test-only helper: emit an explicit RST for a target stream.
    pub fn testSendRst(self: *Self, stream_id: u32) !void {
        try self.writeFrame(.data, FLAG_RST, stream_id, 0, "");
    }

    // Test-only helper: emit GO_AWAY for lifecycle coverage.
    pub fn testSendGoAway(self: *Self, code: u32) !void {
        const go_away_code: GoAwayCode = switch (code) {
            0 => .normal,
            1 => .protocol_error,
            2 => .internal_error,
            else => return YamuxError.ProtocolError,
        };
        try self.sendGoAway(go_away_code);
    }

    // Test-only helper: expose closed-state check.
    pub fn testSessionIsClosed(self: *Self) bool {
        return self.sessionIsClosed();
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
                self.transport.conn.close() catch {};
                return YamuxError.GoAway;
            }

            if (send_ping) |nonce_value| {
                self.writeFrame(.ping, FLAG_SYN, 0, nonce_value, "") catch |err| {
                    self.beginClosing(.closed);
                    self.transport.conn.close() catch {};
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
                self.transport.conn.close() catch {};
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
            core.cond.broadcast(self.transport.conn.io);
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
                self.transport.conn.close() catch {};
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
            core.cond.broadcast(self.transport.conn.io);
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
        self.pending_accept_cv.signal(self.transport.conn.io);
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
        self.pending_accept_cv.broadcast(self.transport.conn.io);
        mutexUnlock(&self.pending_accept_mu);

        if (next_state != .closing and next_state != .closed) return;

        mutexLock(&self.streams_mu);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.cond.broadcast(self.transport.conn.io);
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
            self.transport.conn.close() catch {};
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

    // Test-only helper: expose stream id for targeted control-frame tests.
    pub fn testStreamId(self: *const Self) u32 {
        return self.core.stream_id;
    }

    pub fn writeAll(self: *Self, data: []const u8) !void {
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
                try condWait(&self.core.cond, self.session.session_io, &self.core.mutex);
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

    pub fn writeByte(self: *Self, b: u8) !void {
        const one = [_]u8{b};
        try self.writeAll(&one);
    }

    pub fn close(self: *Self) !void {
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
        try self.session.writeFrame(.data, FLAG_FIN, self.core.stream_id, 0, "");
    }

    pub fn readSome(self: *Self, dest: []u8) !usize {
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
            try condWait(&self.core.cond, self.session.session_io, &self.core.mutex);
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

fn openStreamTaskMain(session: *Session) anyerror!Stream {
    return session.openStream();
}

fn acceptStreamTaskMain(session: *Session) anyerror!Stream {
    return session.acceptStream();
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
