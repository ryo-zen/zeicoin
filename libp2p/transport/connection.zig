const std = @import("std");

pub const Connection = struct {
    io: std.Io,
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        readSome: *const fn (ctx: *anyopaque, dest: []u8) anyerror!usize,
        writeVecAll: *const fn (ctx: *anyopaque, fragments: []const []const u8) anyerror!void,
        close: *const fn (ctx: *anyopaque) anyerror!void,
    };

    pub fn readSome(self: Connection, dest: []u8) !usize {
        return self.vtable.readSome(self.ctx, dest);
    }

    pub fn writeVecAll(self: Connection, fragments: anytype) !void {
        const Fragments = @TypeOf(fragments.*);
        switch (@typeInfo(Fragments)) {
            .array => {},
            else => @compileError("writeVecAll expects a pointer to an array of byte slices"),
        }
        const vecs: []const []const u8 = fragments[0..];
        return self.vtable.writeVecAll(self.ctx, vecs);
    }

    pub fn writeAll(self: Connection, data: []const u8) !void {
        const parts = [_][]const u8{data};
        try self.vtable.writeVecAll(self.ctx, &parts);
    }

    pub fn close(self: Connection) !void {
        return self.vtable.close(self.ctx);
    }
};
