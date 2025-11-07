const std = @import("std");
const types = @import("types.zig");

/// Format a successful JSON-RPC 2.0 response
pub fn formatSuccess(allocator: std.mem.Allocator, result: []const u8, id: ?std.json.Value) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    const writer = buf.writer();
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"result\":");
    try writer.writeAll(result);
    try writer.writeAll(",\"id\":");

    // Handle optional id
    if (id) |id_value| {
        switch (id_value) {
            .integer => |i| try writer.print("{d}", .{i}),
            .string => |s| try writer.print("\"{s}\"", .{s}),
            .null => try writer.writeAll("null"),
            else => try writer.writeAll("null"),
        }
    } else {
        try writer.writeAll("null");
    }

    try writer.writeAll("}");
    return buf.toOwnedSlice();
}

/// Format a JSON-RPC 2.0 error response
pub fn formatError(allocator: std.mem.Allocator, code: types.ErrorCode, data: ?[]const u8, id: ?std.json.Value) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    const writer = buf.writer();
    try writer.writeAll("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":");
    try writer.print("{d}", .{@intFromEnum(code)});
    try writer.writeAll(",\"message\":\"");
    try writer.writeAll(code.message());
    try writer.writeAll("\"");

    if (data) |d| {
        try writer.writeAll(",\"data\":");
        try writer.writeAll(d);
    }

    try writer.writeAll("},\"id\":");

    if (id) |i| {
        switch (i) {
            .integer => |int| try writer.print("{d}", .{int}),
            .string => |s| try writer.print("\"{s}\"", .{s}),
            .null => try writer.writeAll("null"),
            else => try writer.writeAll("null"),
        }
    } else {
        try writer.writeAll("null");
    }

    try writer.writeAll("}");
    return buf.toOwnedSlice();
}

/// Format result object as JSON
pub fn formatResult(allocator: std.mem.Allocator, comptime T: type, value: T) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try std.json.stringify(value, .{}, buf.writer());
    return buf.toOwnedSlice();
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
    const data = "{\"size\":10000}";
    const response = try formatError(allocator, types.ErrorCode.mempool_full, data, id);
    defer allocator.free(response);

    try std.testing.expect(std.mem.indexOf(u8, response, "\"data\":{\"size\":10000}") != null);
}

test "format result object" {
    const allocator = std.testing.allocator;

    const value = types.GetHeightResponse{ .height = 42 };
    const result = try formatResult(allocator, types.GetHeightResponse, value);
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "\"height\":42") != null);
}
