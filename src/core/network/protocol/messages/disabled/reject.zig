// reject.zig - Rejection message for invalid data
// Provides feedback about why something was rejected

const std = @import("std");
const protocol = @import("../protocol.zig");

pub const RejectMessage = struct {
    /// Message type that was rejected
    rejected_message: protocol.MessageType,
    /// Rejection reason code
    code: protocol.RejectCode,
    /// Human-readable reason
    reason: []const u8,
    /// Additional data (e.g., block/tx hash)
    data: []const u8,
    
    pub fn init(
        allocator: std.mem.Allocator,
        rejected: protocol.MessageType,
        code: protocol.RejectCode,
        reason: []const u8,
        data: []const u8,
    ) !RejectMessage {
        return .{
            .rejected_message = rejected,
            .code = code,
            .reason = try allocator.dupe(u8, reason[0..@min(reason.len, 256)]),
            .data = try allocator.dupe(u8, data[0..@min(data.len, 64)]),
        };
    }
    
    pub fn deinit(self: *RejectMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
        allocator.free(self.data);
    }
    
    pub fn encode(self: RejectMessage, writer: anytype) !void {
        try writer.writeByte(@intFromEnum(self.rejected_message));
        try writer.writeByte(@intFromEnum(self.code));
        
        try writer.writeInt(u16, @intCast(self.reason.len), .little);
        try writer.writeAll(self.reason);
        
        try writer.writeInt(u16, @intCast(self.data.len), .little);
        try writer.writeAll(self.data);
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !RejectMessage {
        const rejected = try reader.readEnum(protocol.MessageType, .little);
        const code = try reader.readEnum(protocol.RejectCode, .little);
        
        const reason_len = try reader.readInt(u16, .little);
        const reason = try allocator.alloc(u8, reason_len);
        errdefer allocator.free(reason);
        try reader.readNoEof(reason);
        
        const data_len = try reader.readInt(u16, .little);
        const data = try allocator.alloc(u8, data_len);
        errdefer allocator.free(data);
        try reader.readNoEof(data);
        
        return .{
            .rejected_message = rejected,
            .code = code,
            .reason = reason,
            .data = data,
        };
    }
    
    pub fn estimateSize(self: RejectMessage) usize {
        return 1 + 1 + 2 + self.reason.len + 2 + self.data.len;
    }
};