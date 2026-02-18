const std = @import("std");
const types = @import("types.zig");

/// Format a successful JSON-RPC 2.0 response
pub fn formatSuccess(allocator: std.mem.Allocator, result: []const u8, id: ?std.json.Value) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try aw.writer.writeAll("{\"jsonrpc\":\"2.0\",\"result\":");
    try aw.writer.writeAll(result);
    try aw.writer.writeAll(",\"id\":");

    // Handle optional id
    if (id) |id_value| {
        switch (id_value) {
            .integer => |i| try aw.writer.print("{d}", .{i}),
            .string => |s| try aw.writer.print("\"{s}\"", .{s}),
            .null => try aw.writer.writeAll("null"),
            else => try aw.writer.writeAll("null"),
        }
    } else {
        try aw.writer.writeAll("null");
    }

    try aw.writer.writeAll("}");
    return try aw.toOwnedSlice();
}

/// Format a JSON-RPC 2.0 error response
pub fn formatError(allocator: std.mem.Allocator, code: types.ErrorCode, data: ?[]const u8, id: ?std.json.Value) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try aw.writer.writeAll("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":");
    try aw.writer.print("{d}", .{@intFromEnum(code)});
    try aw.writer.writeAll(",\"message\":\"");
    try aw.writer.writeAll(code.message());
    try aw.writer.writeAll("\"");

    if (data) |d| {
        try aw.writer.writeAll(",\"data\":");
        try std.json.Stringify.value(d, .{}, &aw.writer);
    }

    try aw.writer.writeAll("},\"id\":");

    if (id) |i| {
        switch (i) {
            .integer => |int| try aw.writer.print("{d}", .{int}),
            .string => |s| try aw.writer.print("\"{s}\"", .{s}),
            .null => try aw.writer.writeAll("null"),
            else => try aw.writer.writeAll("null"),
        }
    } else {
        try aw.writer.writeAll("null");
    }

    try aw.writer.writeAll("}");
    return try aw.toOwnedSlice();
}

/// Format result object as JSON
pub fn formatResult(allocator: std.mem.Allocator, comptime T: type, value: T) ![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    try std.json.Stringify.value(value, .{}, &aw.writer);
    return try aw.toOwnedSlice();
}

// ========== Tests ==========

test "format success response with integer id" {
    const allocator = std.testing.allocator;

    const result = "{\"height\":100}";
    const id = std.json.Value{ .integer = 1 };

    const response = try formatSuccess(allocator, result, id);
    defer allocator.free(response);

    const expected = "{\"jsonrpc\":\"2.0\",\"result\":{\"height\":100},\"id\":1}";
    try std.testing.expectEqualStrings(expected, response);
}

test "format success response with string id" {
    const allocator = std.testing.allocator;

    const result = "{\"height\":100}";
    const id = std.json.Value{ .string = "test-id" };

    const response = try formatSuccess(allocator, result, id);
    defer allocator.free(response);

    const expected = "{\"jsonrpc\":\"2.0\",\"result\":{\"height\":100},\"id\":\"test-id\"}";
    try std.testing.expectEqualStrings(expected, response);
}

test "format error response" {
    const allocator = std.testing.allocator;

    const id = std.json.Value{ .integer = 1 };
    const response = try formatError(allocator, types.ErrorCode.mempool_full, null, id);
    defer allocator.free(response);

    const expected = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"Mempool full\"},\"id\":1}";
    try std.testing.expectEqualStrings(expected, response);
}

test "format error response with data" {
    const allocator = std.testing.allocator;

    const id = std.json.Value{ .integer = 1 };
    const data = "InvalidTransaction";
    const response = try formatError(allocator, types.ErrorCode.mempool_full, data, id);
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"data\":\"InvalidTransaction\"") != null);
}

test "format result object" {
    const allocator = std.testing.allocator;

    const value = types.GetHeightResponse{ .height = 42 };
    const result = try formatResult(allocator, types.GetHeightResponse, value);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"height\":42") != null);
}
