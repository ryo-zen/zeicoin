// test_multistream_async.zig - Tests for async multistream protocol

const std = @import("std");
const multistream_async = @import("multistream_async.zig");
const tcp_async = @import("../transport/tcp_async.zig");
const libp2p = @import("../libp2p_internal.zig");

test "async multistream session creation" {
    const allocator = std.testing.allocator;
    
    // Create mock connection
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_async.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    // Test session creation
    const protocols = [_][]const u8{"/yamux/1.0.0", "/mplex/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: multistream_async.AsyncResult) void {
            _ = result;
            // Test callback - just verify it can be called
        }
    };
    
    var session = try multistream_async.AsyncSession.init(
        allocator,
        &connection,
        &protocols,
        true,
        TestCallback.callback,
    );
    defer session.deinit();
    
    // Verify session initialization
    try std.testing.expect(session.is_initiator);
    try std.testing.expectEqual(@as(usize, 0), session.current_protocol_index);
    try std.testing.expect(session.selected_protocol == null);
    try std.testing.expectEqual(@as(usize, 2), session.protocols.len);
}

test "async multistream message writing" {
    const allocator = std.testing.allocator;
    
    // Create mock connection
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_async.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    const protocols = [_][]const u8{"/test/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: multistream_async.AsyncResult) void {
            _ = result;
        }
    };
    
    var session = try multistream_async.AsyncSession.init(
        allocator,
        &connection,
        &protocols,
        true,
        TestCallback.callback,
    );
    defer session.deinit();
    
    // Test message writing
    try session.writeMessage(multistream_async.PROTOCOL_ID);
    
    // Verify write buffer contains expected data
    try std.testing.expect(session.write_buffer.items.len > 0);
    
    // Should contain length prefix + message + newline
    const expected_len = multistream_async.PROTOCOL_ID.len + 1; // +1 for newline
    try std.testing.expect(session.write_buffer.items.len >= expected_len);
    
    // Should end with newline
    try std.testing.expectEqual(multistream_async.NEWLINE, session.write_buffer.items[session.write_buffer.items.len - 1]);
}

test "async multistream protocol constants" {
    // Verify constants are correctly imported
    try std.testing.expectEqualStrings("/multistream/1.0.0", multistream_async.PROTOCOL_ID);
    try std.testing.expectEqual(@as(usize, 65535), multistream_async.MAX_MESSAGE_SIZE);
    try std.testing.expectEqual(@as(u8, 0x0A), multistream_async.NEWLINE);
    try std.testing.expectEqualStrings("na", multistream_async.NA);
}

test "async multistream message parsing" {
    // Test message parsing functionality
    const version_msg = multistream_async.parseMessage(multistream_async.PROTOCOL_ID);
    try std.testing.expectEqual(multistream_async.MessageType.RightProtocolVersion, version_msg.type);
    
    const na_msg = multistream_async.parseMessage(multistream_async.NA);
    try std.testing.expectEqual(multistream_async.MessageType.NAMessage, na_msg.type);
    
    const ls_msg = multistream_async.parseMessage("ls");
    try std.testing.expectEqual(multistream_async.MessageType.LSMessage, ls_msg.type);
    
    const protocol_msg = multistream_async.parseMessage("/yamux/1.0.0");
    try std.testing.expectEqual(multistream_async.MessageType.ProtocolName, protocol_msg.type);
    
    const invalid_msg = multistream_async.parseMessage("invalid");
    try std.testing.expectEqual(multistream_async.MessageType.InvalidMessage, invalid_msg.type);
}

test "async multistream negotiation callback structure" {
    // Test that we can create different callback types
    const SuccessCallback = struct {
        var result_received: bool = false;
        var protocol_received: ?[]const u8 = null;
        
        fn callback(result: multistream_async.AsyncResult) void {
            result_received = true;
            switch (result) {
                .success => |protocol| {
                    protocol_received = protocol;
                },
                .failure => {},
            }
        }
    };
    
    const ErrorCallback = struct {
        var error_received: bool = false;
        var error_value: ?anyerror = null;
        
        fn callback(result: multistream_async.AsyncResult) void {
            error_received = true;
            switch (result) {
                .success => {},
                .failure => |err| {
                    error_value = err;
                },
            }
        }
    };
    
    // Test success callback
    SuccessCallback.callback(.{ .success = "/test/1.0.0" });
    try std.testing.expect(SuccessCallback.result_received);
    try std.testing.expectEqualStrings("/test/1.0.0", SuccessCallback.protocol_received.?);
    
    // Test error callback
    ErrorCallback.callback(.{ .failure = error.TestError });
    try std.testing.expect(ErrorCallback.error_received);
    try std.testing.expectEqual(@as(anyerror, error.TestError), ErrorCallback.error_value.?);
}