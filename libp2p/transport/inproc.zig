// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");
const connection_mod = @import("connection.zig");

const Role = enum {
    initiator,
    responder,
};

const InProcShared = struct {
    allocator: std.mem.Allocator,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    initiator_to_responder: std.array_list.Managed(u8),
    initiator_to_responder_off: usize = 0,
    responder_to_initiator: std.array_list.Managed(u8),
    responder_to_initiator_off: usize = 0,
    initiator_closed: bool = false,
    responder_closed: bool = false,
    refs: u8 = 2,

    fn init(allocator: std.mem.Allocator) InProcShared {
        return .{
            .allocator = allocator,
            .initiator_to_responder = std.array_list.Managed(u8).init(allocator),
            .responder_to_initiator = std.array_list.Managed(u8).init(allocator),
        };
    }

    fn deinit(self: *InProcShared) void {
        self.initiator_to_responder.deinit();
        self.responder_to_initiator.deinit();
    }
};

pub const InProcConnection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    shared: *InProcShared,
    role: Role,
    is_closed: bool = false,
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,

    const Self = @This();

    pub const Pair = struct {
        initiator: InProcConnection,
        responder: InProcConnection,
    };

    pub fn initPair(allocator: std.mem.Allocator, io: std.Io) !Pair {
        const shared = try allocator.create(InProcShared);
        shared.* = InProcShared.init(allocator);

        return .{
            .initiator = .{
                .allocator = allocator,
                .io = io,
                .shared = shared,
                .role = .initiator,
            },
            .responder = .{
                .allocator = allocator,
                .io = io,
                .shared = shared,
                .role = .responder,
            },
        };
    }

    pub fn deinit(self: *Self) void {
        if (!self.is_closed) {
            self.close(self.io) catch {};
        }

        const destroy = blk: {
            self.shared.mutex.lockUncancelable(self.io);
            defer self.shared.mutex.unlock(self.io);
            if (self.shared.refs > 0) self.shared.refs -= 1;
            break :blk self.shared.refs == 0;
        };

        if (destroy) {
            self.shared.deinit();
            self.allocator.destroy(self.shared);
        }
    }

    pub fn readSome(self: *Self, io: std.Io, buffer: []u8) !usize {
        if (self.is_closed) return error.ConnectionClosed;

        self.shared.mutex.lockUncancelable(io);
        defer self.shared.mutex.unlock(io);

        while (true) {
            const src = if (self.role == .initiator) &self.shared.responder_to_initiator else &self.shared.initiator_to_responder;
            const src_off = if (self.role == .initiator) &self.shared.responder_to_initiator_off else &self.shared.initiator_to_responder_off;
            const peer_closed = if (self.role == .initiator) self.shared.responder_closed else self.shared.initiator_closed;

            if (src_off.* < src.items.len) {
                const remaining = src.items.len - src_off.*;
                const n = @min(remaining, buffer.len);
                @memcpy(buffer[0..n], src.items[src_off.* .. src_off.* + n]);
                src_off.* += n;
                if (src_off.* == src.items.len) {
                    src.clearRetainingCapacity();
                    src_off.* = 0;
                }
                self.bytes_read += n;
                return n;
            }
            if (peer_closed) return 0;
            try self.shared.cond.wait(io, &self.shared.mutex);
        }
    }

    pub fn writeAll(self: *Self, io: std.Io, data: []const u8) !void {
        if (self.is_closed) return error.ConnectionClosed;

        self.shared.mutex.lockUncancelable(io);
        defer self.shared.mutex.unlock(io);

        const dst = if (self.role == .initiator) &self.shared.initiator_to_responder else &self.shared.responder_to_initiator;
        const dst_off = if (self.role == .initiator) &self.shared.initiator_to_responder_off else &self.shared.responder_to_initiator_off;
        const peer_closed = if (self.role == .initiator) self.shared.responder_closed else self.shared.initiator_closed;
        if (peer_closed) return error.ConnectionClosed;

        compactBuffer(dst, dst_off);
        try dst.appendSlice(data);
        self.bytes_written += data.len;
        self.shared.cond.broadcast(io);
    }

    pub fn writeVecAll(self: *Self, io: std.Io, fragments: anytype) !void {
        const Fragments = @TypeOf(fragments.*);
        switch (@typeInfo(Fragments)) {
            .array => |array_info| {
                self.shared.mutex.lockUncancelable(io);
                defer self.shared.mutex.unlock(io);

                const dst = if (self.role == .initiator) &self.shared.initiator_to_responder else &self.shared.responder_to_initiator;
                const dst_off = if (self.role == .initiator) &self.shared.initiator_to_responder_off else &self.shared.responder_to_initiator_off;
                const peer_closed = if (self.role == .initiator) self.shared.responder_closed else self.shared.initiator_closed;
                if (peer_closed) return error.ConnectionClosed;

                compactBuffer(dst, dst_off);

                var total: usize = 0;
                const vecs: [array_info.len][]const u8 = fragments.*;
                inline for (vecs) |part| total += part.len;
                try dst.ensureUnusedCapacity(total);
                inline for (vecs) |part| dst.appendSliceAssumeCapacity(part);
                self.bytes_written += total;
                self.shared.cond.broadcast(io);
            },
            else => @compileError("writeVecAll expects a pointer to an array of byte slices"),
        }
    }

    pub fn close(self: *Self, io: std.Io) !void {
        if (!self.is_closed) {
            self.is_closed = true;
            self.shared.mutex.lockUncancelable(io);
            defer self.shared.mutex.unlock(io);
            if (self.role == .initiator) {
                self.shared.initiator_closed = true;
            } else {
                self.shared.responder_closed = true;
            }
            self.shared.cond.broadcast(io);
        }
    }

    pub fn isInitiator(self: *const Self) bool {
        return self.role == .initiator;
    }

    pub fn connection(self: *Self) connection_mod.Connection {
        return .{ .io = self.io, .ctx = self, .vtable = &connection_vtable };
    }

    fn connectionReadSome(ctx: *anyopaque, dest: []u8) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.readSome(self.io, dest);
    }

    fn connectionWriteVecAll(ctx: *anyopaque, fragments: []const []const u8) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        if (self.is_closed) return error.ConnectionClosed;

        self.shared.mutex.lockUncancelable(self.io);
        defer self.shared.mutex.unlock(self.io);

        const dst = if (self.role == .initiator) &self.shared.initiator_to_responder else &self.shared.responder_to_initiator;
        const dst_off = if (self.role == .initiator) &self.shared.initiator_to_responder_off else &self.shared.responder_to_initiator_off;
        const peer_closed = if (self.role == .initiator) self.shared.responder_closed else self.shared.initiator_closed;
        if (peer_closed) return error.ConnectionClosed;

        compactBuffer(dst, dst_off);

        var total: usize = 0;
        for (fragments) |part| total += part.len;
        try dst.ensureUnusedCapacity(total);
        for (fragments) |part| dst.appendSliceAssumeCapacity(part);
        self.bytes_written += total;
        self.shared.cond.broadcast(self.io);
    }

    fn connectionClose(ctx: *anyopaque) anyerror!void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        return self.close(self.io);
    }

    const connection_vtable = connection_mod.Connection.VTable{
        .readSome = connectionReadSome,
        .writeVecAll = connectionWriteVecAll,
        .close = connectionClose,
    };

    fn compactBuffer(buf: *std.array_list.Managed(u8), off: *usize) void {
        if (off.* == 0) return;
        if (off.* >= buf.items.len) {
            buf.clearRetainingCapacity();
            off.* = 0;
            return;
        }

        const remaining = buf.items.len - off.*;
        std.mem.copyForwards(u8, buf.items[0..remaining], buf.items[off.*..]);
        buf.items.len = remaining;
        off.* = 0;
    }
};

test "inproc pair round-trip and close" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var pair = try InProcConnection.initPair(allocator, io);
    var initiator = pair.initiator;
    defer initiator.deinit();
    var responder = pair.responder;
    defer responder.deinit();

    try initiator.writeAll(io, "ping");
    var buf: [16]u8 = undefined;
    const n = try responder.readSome(io, &buf);
    try std.testing.expectEqualStrings("ping", buf[0..n]);

    try responder.writeAll(io, "pong");
    const m = try initiator.readSome(io, &buf);
    try std.testing.expectEqualStrings("pong", buf[0..m]);

    try initiator.close(io);
    const eof_n = try responder.readSome(io, &buf);
    try std.testing.expectEqual(@as(usize, 0), eof_n);
}
