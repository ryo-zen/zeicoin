// serialize.zig - Zeicoin Minimal Serializer
// Clean, simple, Zig-native serialization for ZeiCoin data structures

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const types = @import("../types/types.zig");

const log = std.log.scoped(.storage);

// Debug logging helper - only logs in Debug builds
fn debugLog(comptime fmt: []const u8, args: anytype) void {
    if (builtin.mode == .Debug) {
        log.debug(fmt, args);
    }
}

// Error types for serialization
pub const SerializeError = error{
    EndOfStream,
    InvalidData,
    UnsupportedType,
} || std.mem.Allocator.Error || std.Io.Writer.Error || std.Io.Reader.Error;

/// Serialize any value to a writer
pub fn serialize(writer: anytype, value: anytype) SerializeError!void {
    var w = writer;
    const T = @TypeOf(value);
    const type_info = @typeInfo(T);

    switch (type_info) {
        // Basic integer types
        .int => |int_info| {
            if (int_info.bits <= 64) {
                try serializeInt(writer, value);
            } else if (int_info.bits == 256) {
                // Special handling for u256 (used for chain work)
                try serializeU256(writer, value);
            } else {
                return SerializeError.UnsupportedType;
            }
        },

        // Boolean
        .bool => try serializeBool(writer, value),

        // Float types
        .float => |float_info| {
            if (float_info.bits == 32 or float_info.bits == 64) {
                try serializeFloat(writer, value);
            } else {
                return SerializeError.UnsupportedType;
            }
        },

        // Arrays and slices
        .array => |array_info| {
            if (array_info.child == u8) {
                // Byte arrays - serialize length then data
                try serialize(w, @as(u32, array_info.len));
                try w.writeAll(&value);
            } else {
                // Generic arrays - serialize each element
                try serialize(w, @as(u32, array_info.len));
                for (value) |item| {
                    try serialize(w, item);
                }
            }
        },

        .pointer => |ptr_info| {
            switch (ptr_info.size) {
                .slice => {
                    if (ptr_info.child == u8) {
                        // String/byte slice - serialize length then data
                        try serialize(w, @as(u32, @intCast(value.len)));
                        try w.writeAll(value);
                    } else {
                        // Generic slice - serialize each element
                        try serialize(w, @as(u32, @intCast(value.len)));
                        for (value) |item| {
                            try serialize(w, item);
                        }
                    }
                },
                .one => {
                    // Handle string literals (pointer to array)
                    const child_info = @typeInfo(ptr_info.child);
                    if (child_info == .array and child_info.array.child == u8) {
                        // String literal - serialize length then data
                        try serialize(w, @as(u32, @intCast(value.len)));
                        try w.writeAll(value);
                    } else {
                        return SerializeError.UnsupportedType;
                    }
                },
                else => return SerializeError.UnsupportedType,
            }
        },

        // Structs - serialize each field
        .@"struct" => |struct_info| {
            // For extern structs with fixed layout, write raw bytes
            if (struct_info.layout == .@"extern") {
                const bytes = std.mem.asBytes(&value);
                try w.writeAll(bytes);
            } else {
                // For regular structs, serialize each field
                inline for (struct_info.fields) |field| {
                    try serialize(w, @field(value, field.name));
                }
            }
        },

        // Optional types
        .optional => {
            if (value) |val| {
                try serialize(w, @as(u8, 1)); // Present
                try serialize(w, val);
            } else {
                try serialize(w, @as(u8, 0)); // Null
            }
        },

        else => return SerializeError.UnsupportedType,
    }
}

/// Deserialize a value of type T from a reader
pub fn deserialize(reader: anytype, comptime T: type, allocator: std.mem.Allocator) SerializeError!T {
    const type_info = @typeInfo(T);

    switch (type_info) {
        // Basic integer types
        .int => |int_info| {
            if (int_info.bits <= 64) {
                return deserializeInt(reader, T);
            } else if (int_info.bits == 256) {
                // Special handling for u256 (used for chain work)
                return deserializeU256(reader);
            } else {
                return SerializeError.UnsupportedType;
            }
        },

        // Boolean
        .bool => return deserializeBool(reader),

        // Float types
        .float => |float_info| {
            if (float_info.bits == 32 or float_info.bits == 64) {
                return deserializeFloat(reader, T);
            } else {
                return SerializeError.UnsupportedType;
            }
        },

        // Arrays
        .array => |array_info| {
            var result: T = undefined;
            const len = try deserialize(reader, u32, allocator);
            if (len != array_info.len) {
                return SerializeError.InvalidData;
            }

            if (array_info.child == u8) {
                // Byte array
                try reader.readSliceAll(&result);
            } else {
                // Generic array
                for (&result) |*item| {
                    item.* = try deserialize(reader, array_info.child, allocator);
                }
            }
            return result;
        },

        .pointer => |ptr_info| {
            switch (ptr_info.size) {
                .slice => {
                    const len = try deserialize(reader, u32, allocator);

                    // Return empty slice without allocation for zero-length slices
                    if (len == 0) {
                        return &[_]ptr_info.child{};
                    }

                    if (ptr_info.child == u8) {
                        // String/byte slice
                        const data = try allocator.alloc(u8, len);
                        try reader.readSliceAll(data);
                        return data;
                    } else {
                        // Generic slice
                        const data = try allocator.alloc(ptr_info.child, len);
                        var initialized_count: usize = 0;
                        errdefer {
                            // Clean up any items that were successfully deserialized
                            for (data[0..initialized_count]) |*item| {
                                if (@hasDecl(ptr_info.child, "deinit")) {
                                    item.deinit(allocator);
                                }
                            }
                            allocator.free(data);
                        }
                        
                        for (data) |*item| {
                            item.* = try deserialize(reader, ptr_info.child, allocator);
                            initialized_count += 1;
                        }
                        return data;
                    }
                },
                else => return SerializeError.UnsupportedType,
            }
        },

        // Structs - deserialize each field
        .@"struct" => |struct_info| {
            // For extern structs with fixed layout, read raw bytes
            if (struct_info.layout == .@"extern") {
                var result: T = undefined;
                const bytes = std.mem.asBytes(&result);
                try reader.readSliceAll(bytes);
                return result;
            } else {
                // For regular structs, deserialize each field
                var result: T = undefined;
                inline for (struct_info.fields) |field| {
                    @field(result, field.name) = try deserialize(reader, field.type, allocator);
                }
                return result;
            }
        },

        // Optional types
        .optional => |opt_info| {
            const present = try deserialize(reader, u8, allocator);
            if (present == 1) {
                return try deserialize(reader, opt_info.child, allocator);
            } else {
                return null;
            }
        },

        else => return SerializeError.UnsupportedType,
    }
}

// Helper functions for basic types
fn serializeInt(writer: anytype, value: anytype) !void {
    var w = writer;
    const bytes = std.mem.toBytes(value);
    try w.writeAll(&bytes);
}

fn deserializeInt(reader: anytype, comptime T: type) !T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    try reader.readSliceAll(&bytes);
    return std.mem.bytesToValue(T, &bytes);
}

fn serializeBool(writer: anytype, value: bool) !void {
    var w = writer;
    try w.writeByte(if (value) 1 else 0);
}

fn deserializeBool(reader: anytype) !bool {
    const byte = try reader.takeByte();
    return byte != 0;
}

fn serializeU256(writer: anytype, value: u256) !void {
    var w = writer;
    const bytes = std.mem.toBytes(value);
    try w.writeAll(&bytes);
}

fn deserializeU256(reader: anytype) !u256 {
    var bytes: [32]u8 = undefined;
    try reader.readSliceAll(&bytes);
    return std.mem.bytesToValue(u256, &bytes);
}

fn serializeFloat(writer: anytype, value: anytype) !void {
    var w = writer;
    const bytes = std.mem.toBytes(value);
    try w.writeAll(&bytes);
}

fn deserializeFloat(reader: anytype, comptime T: type) !T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    try reader.readSliceAll(&bytes);
    return std.mem.bytesToValue(T, &bytes);
}

// Convenience functions for common use cases
pub fn serializeToBytes(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var collecting = std.Io.Writer.Allocating.init(allocator);
    defer collecting.deinit();

    try serialize(collecting.writer, value);
    return try collecting.toOwnedSlice();
}

pub fn deserializeFromBytes(data: []const u8, comptime T: type, allocator: std.mem.Allocator) !T {
    var reader = std.Io.Reader.fixed(data);
    return deserialize(&reader, T, allocator);
}

/// Serialize a BlockHeader to a writer
pub fn writeBlockHeader(writer: anytype, header: types.BlockHeader) !void {
    try header.serialize(writer);
}

/// Deserialize a BlockHeader from a reader
pub fn readBlockHeader(reader: anytype) !types.BlockHeader {
    return try types.BlockHeader.deserialize(reader);
}

/// Serialize a Block to a writer
pub fn writeBlock(writer: anytype, block: types.Block) !void {
    debugLog("writeBlock() starting - height: {}, txs: {}", .{ block.height, block.transactions.len });

    // Serialize header
    try block.header.serialize(writer);

    // Serialize height
    try std.Io.Writer.writeInt(writer, u32, block.height, .little);

    // Serialize transaction count
    try std.Io.Writer.writeInt(writer, u32, @intCast(block.transactions.len), .little);

    // Serialize each transaction
    for (block.transactions) |tx| {
        try writeTransaction(writer, tx);
    }

    debugLog("writeBlock() completed - height: {}", .{block.height});
}

/// Deserialize a Block from a reader
pub fn readBlock(reader: anytype, allocator: std.mem.Allocator) !types.Block {
    debugLog("readBlock() starting", .{});

    // Deserialize header
    const header = try types.BlockHeader.deserialize(reader);

    // Deserialize height
    const height = try reader.takeInt(u32, .little);

    // Deserialize transaction count
    const tx_count = try reader.takeInt(u32, .little);

    if (tx_count > 100000) {
        log.warn("Suspicious transaction count: {}", .{tx_count});
    }

    // Deserialize transactions
    const transactions = try allocator.alloc(types.Transaction, tx_count);
    errdefer allocator.free(transactions);

    var i: usize = 0;
    while (i < tx_count) : (i += 1) {
        transactions[i] = readTransaction(reader, allocator) catch |err| {
            log.err("Error deserializing transaction {}: {}", .{ i, err });
            // Free previously read transactions to prevent leaks
            for (transactions[0..i]) |*tx| {
                tx.deinit(allocator);
            }
            return err;
        };
    }

    debugLog("readBlock() completed - height: {}, txs: {}", .{ height, tx_count });
    return types.Block{
        .header = header,
        .transactions = transactions,
        .height = height,
    };
}

/// Serialize a Transaction to a writer
pub fn writeTransaction(writer: anytype, tx: types.Transaction) !void {
    try std.Io.Writer.writeInt(writer, u16, tx.version, .little);
    try std.Io.Writer.writeInt(writer, u16, @bitCast(tx.flags), .little);
    try writer.writeAll(std.mem.asBytes(&tx.sender));
    try writer.writeAll(std.mem.asBytes(&tx.recipient));
    try std.Io.Writer.writeInt(writer, u64, tx.amount, .little);
    try std.Io.Writer.writeInt(writer, u64, tx.fee, .little);
    try std.Io.Writer.writeInt(writer, u64, tx.nonce, .little);
    try std.Io.Writer.writeInt(writer, u64, tx.timestamp, .little);
    try std.Io.Writer.writeInt(writer, u64, tx.expiry_height, .little);
    try writer.writeAll(&tx.sender_public_key);
    try writer.writeAll(std.mem.asBytes(&tx.signature));
    try std.Io.Writer.writeInt(writer, u16, tx.script_version, .little);
    
    // Variable length fields with length prefixes
    try std.Io.Writer.writeInt(writer, u32, @intCast(tx.witness_data.len), .little);
    try writer.writeAll(tx.witness_data);
    try std.Io.Writer.writeInt(writer, u32, @intCast(tx.extra_data.len), .little);
    try writer.writeAll(tx.extra_data);
}

/// Deserialize a Transaction from a reader
pub fn readTransaction(reader: anytype, allocator: std.mem.Allocator) !types.Transaction {
    // Initialize with zeroes to ensure slice lengths are 0. This makes the errdefer safe.
    var tx: types.Transaction = std.mem.zeroes(types.Transaction);
    // This errdefer will clean up any partially allocated data if an error occurs below
    errdefer tx.deinit(allocator);

    tx.version = try reader.takeInt(u16, .little);
    tx.flags = @bitCast(try reader.takeInt(u16, .little));
    try reader.readSliceAll(std.mem.asBytes(&tx.sender));
    try reader.readSliceAll(std.mem.asBytes(&tx.recipient));
    tx.amount = try reader.takeInt(u64, .little);
    tx.fee = try reader.takeInt(u64, .little);
    tx.nonce = try reader.takeInt(u64, .little);
    tx.timestamp = try reader.takeInt(u64, .little);
    tx.expiry_height = try reader.takeInt(u64, .little);
    try reader.readSliceAll(&tx.sender_public_key);
    try reader.readSliceAll(std.mem.asBytes(&tx.signature));
    tx.script_version = try reader.takeInt(u16, .little);

    const witness_len = try reader.takeInt(u32, .little);
    if (witness_len > 0) {
        const witness_buf = try allocator.alloc(u8, witness_len);
        try reader.readSliceAll(witness_buf);
        tx.witness_data = witness_buf;
    }

    const extra_len = try reader.takeInt(u32, .little);
    if (extra_len > 0) {
        const extra_buf = try allocator.alloc(u8, extra_len);
        try reader.readSliceAll(extra_buf);
        tx.extra_data = extra_buf;
    }

    return tx;
}

// Tests
test "serialize basic types" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    // Test integers
    try serialize(aw.writer, @as(u32, 42));
    try serialize(aw.writer, @as(i64, -123));

    // Test boolean
    try serialize(aw.writer, true);
    try serialize(aw.writer, false);

    // Test float
    try serialize(aw.writer, @as(f32, 3.14));
    // Verify we have data
    try testing.expect(aw.written().len > 0);
}

test "deserialize basic types" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    // Serialize test data
    try serialize(aw.writer, @as(u32, 42));
    try serialize(aw.writer, true);
    try serialize(aw.writer, @as(f32, 3.14));

    // Deserialize
    var reader = std.Io.Reader.fixed(aw.written());

    const val1 = try deserialize(&reader, u32, testing.allocator);
    const val2 = try deserialize(&reader, bool, testing.allocator);
    const val3 = try deserialize(&reader, f32, testing.allocator);

    try testing.expectEqual(@as(u32, 42), val1);
    try testing.expectEqual(true, val2);
    try testing.expectApproxEqAbs(@as(f32, 3.14), val3, 0.001);
}

test "serialize strings" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const test_string = "Hello ZeiCoin!";
    try serialize(aw.writer, test_string);
    // Deserialize
    var reader = std.Io.Reader.fixed(aw.written());
    const result = try deserialize(&reader, []const u8, testing.allocator);
    defer testing.allocator.free(result);

    try testing.expectEqualStrings(test_string, result);
}

test "serialize structs" {
    const TestStruct = struct {
        id: u32,
        name: []const u8,
        active: bool,
    };

    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const test_data = TestStruct{
        .id = 123,
        .name = "test",
        .active = true,
    };

    try serialize(aw.writer, test_data);
    // Deserialize
    var reader = std.Io.Reader.fixed(aw.written());
    const result = try deserialize(&reader, TestStruct, testing.allocator);
    defer testing.allocator.free(result.name);

    try testing.expectEqual(@as(u32, 123), result.id);
    try testing.expectEqualStrings("test", result.name);
    try testing.expectEqual(true, result.active);
}

test "serialize optionals" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();

    const some_value: ?u32 = 42;
    const null_value: ?u32 = null;

    try serialize(aw.writer, some_value);
    try serialize(aw.writer, null_value);
    // Deserialize
    var reader = std.Io.Reader.fixed(aw.written());

    const result1 = try deserialize(&reader, ?u32, testing.allocator);
    const result2 = try deserialize(&reader, ?u32, testing.allocator);

    try testing.expectEqual(@as(?u32, 42), result1);
    try testing.expectEqual(@as(?u32, null), result2);
}
