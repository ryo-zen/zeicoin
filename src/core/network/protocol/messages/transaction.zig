// transaction.zig - Transaction message for broadcasting

const std = @import("std");
const types = @import("../../../types/types.zig");
const serialize = @import("../../../storage/serialize.zig");

pub const TransactionMessage = struct {
    transaction: types.Transaction,
    
    pub fn encode(self: TransactionMessage, writer: anytype) !void {
        try serialize.serialize(writer, self.transaction);
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !TransactionMessage {
        return .{ .transaction = try serialize.deserialize(reader, types.Transaction, allocator) };
    }
    
    pub fn deinit(self: *TransactionMessage, allocator: std.mem.Allocator) void {
        self.transaction.deinit(allocator);
    }
    
    pub fn estimateSize(self: TransactionMessage) usize {
        _ = self;
        return 4096; // 4KB estimate
    }
};