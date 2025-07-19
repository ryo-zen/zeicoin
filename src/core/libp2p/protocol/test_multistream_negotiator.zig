// test_multistream_negotiator.zig - Tests for async multistream negotiation

const std = @import("std");
const negotiator = @import("multistream_negotiator.zig");
const tcp_context = @import("../transport/tcp_async_context.zig");
const multistream = @import("multistream.zig");

test "negotiator initialization" {
    const allocator = std.testing.allocator;
    
    // Create mock connection
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    // Test negotiator creation
    const protocols = [_][]const u8{"/yamux/1.0.0", "/mplex/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: negotiator.NegotiationResult) void {
            _ = result;
        }
    };
    
    var neg = try negotiator.MultistreamNegotiator.init(
        allocator,
        &connection,
        &protocols,
        true, // is_initiator
        TestCallback.callback,
    );
    defer neg.deinit();
    
    // Verify initialization
    try std.testing.expect(neg.is_initiator);
    try std.testing.expectEqual(@as(usize, 0), neg.current_protocol_index);
    try std.testing.expect(neg.selected_protocol == null);
    try std.testing.expect(!neg.multistream_negotiated);
    try std.testing.expect(!neg.is_writing);
}

test "negotiation result types" {
    // Test success result
    const success_result = negotiator.NegotiationResult{ .success = "/yamux/1.0.0" };
    switch (success_result) {
        .success => |protocol| {
            try std.testing.expectEqualStrings("/yamux/1.0.0", protocol);
        },
        else => unreachable,
    }
    
    // Test failure result
    const failure_result = negotiator.NegotiationResult{ .failure = error.TestError };
    switch (failure_result) {
        .failure => |err| {
            try std.testing.expectEqual(@as(anyerror, error.TestError), err);
        },
        else => unreachable,
    }
    
    // Test timeout result
    const timeout_result = negotiator.NegotiationResult{ .timeout = {} };
    switch (timeout_result) {
        .timeout => {},
        else => unreachable,
    }
}

test "write buffer message formatting" {
    const allocator = std.testing.allocator;
    
    // Create minimal negotiator to test message formatting
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    const protocols = [_][]const u8{"/test/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: negotiator.NegotiationResult) void {
            _ = result;
        }
    };
    
    var neg = try negotiator.MultistreamNegotiator.init(
        allocator,
        &connection,
        &protocols,
        true,
        TestCallback.callback,
    );
    defer neg.deinit();
    
    // Test message formatting by preparing a message
    neg.write_buffer.clearRetainingCapacity();
    try multistream.writeMessage(neg.write_buffer.writer(), multistream.PROTOCOL_ID);
    
    // Verify the buffer contains expected data
    try std.testing.expect(neg.write_buffer.items.len > 0);
    
    // Should contain varint length prefix + message + newline
    const expected_len = multistream.PROTOCOL_ID.len + 1; // +1 for newline
    try std.testing.expect(neg.write_buffer.items.len >= expected_len);
    
    // Should end with newline
    try std.testing.expectEqual(
        multistream.NEWLINE,
        neg.write_buffer.items[neg.write_buffer.items.len - 1],
    );
}

test "protocol matching logic" {
    // Test protocol matching scenarios
    const protocols = [_][]const u8{ "/yamux/1.0.0", "/mplex/1.0.0", "/secio/1.0.0" };
    
    // Test exact match
    for (protocols, 0..) |protocol, i| {
        const match_found = blk: {
            for (protocols) |supported| {
                if (std.mem.eql(u8, protocol, supported)) {
                    break :blk true;
                }
            }
            break :blk false;
        };
        
        try std.testing.expect(match_found);
        _ = i;
    }
    
    // Test no match
    const unsupported = "/unknown/1.0.0";
    const no_match = blk: {
        for (protocols) |supported| {
            if (std.mem.eql(u8, unsupported, supported)) {
                break :blk false;
            }
        }
        break :blk true;
    };
    
    try std.testing.expect(no_match);
}

test "callback context handling" {
    const allocator = std.testing.allocator;
    
    // Test that callback context properly stores and retrieves negotiator pointer
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    const protocols = [_][]const u8{"/test/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: negotiator.NegotiationResult) void {
            _ = result;
        }
    };
    
    var neg = try negotiator.MultistreamNegotiator.init(
        allocator,
        &connection,
        &protocols,
        true,
        TestCallback.callback,
    );
    defer neg.deinit();
    
    // Test context creation and retrieval
    const context = tcp_context.createContext(&neg);
    const retrieved = context.getUserData(*negotiator.MultistreamNegotiator);
    
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqual(&neg, retrieved.?);
}

test "state transitions" {
    // Test valid state transitions for initiator
    const initiator_states = [_]negotiator.SessionState{
        .WaitingForVersionResponse,
        .WaitingForProtocolResponse,
        .Completed,
    };
    
    // Test valid state transitions for responder  
    const responder_states = [_]negotiator.SessionState{
        .WaitingForProposal,
        .SendingVersionAck,
        .SendingProtocolAck,
        .Completed,
    };
    
    // Just verify the states exist and can be compared
    try std.testing.expectEqual(negotiator.SessionState.WaitingForVersionResponse, initiator_states[0]);
    try std.testing.expectEqual(negotiator.SessionState.WaitingForProposal, responder_states[0]);
}

test "write queue management" {
    const allocator = std.testing.allocator;
    
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    const protocols = [_][]const u8{"/test/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: negotiator.NegotiationResult) void {
            _ = result;
        }
    };
    
    var neg = try negotiator.MultistreamNegotiator.init(
        allocator,
        &connection,
        &protocols,
        true,
        TestCallback.callback,
    );
    defer neg.deinit();
    
    // Verify initial write queue state
    try std.testing.expectEqual(@as(usize, 0), neg.write_queue.items.len);
    try std.testing.expect(!neg.is_writing);
    
    // Test that queue can be modified (structure test)
    const test_data = try allocator.dupe(u8, "test message");
    defer allocator.free(test_data);
    
    try neg.write_queue.append(test_data);
    try std.testing.expectEqual(@as(usize, 1), neg.write_queue.items.len);
    
    _ = neg.write_queue.orderedRemove(0);
    try std.testing.expectEqual(@as(usize, 0), neg.write_queue.items.len);
}

test "error handling scenarios" {
    // Test various error types that can occur during negotiation
    const error_cases = [_]anyerror{
        error.ConnectionClosed,
        error.MessageTooLarge,
        error.ParseError,
        error.ProtocolVersionMismatch,
        error.ProtocolMismatch,
        error.NoProtocolMatch,
        error.UnexpectedMessage,
        error.UnexpectedState,
        error.InternalError,
    };
    
    for (error_cases) |err| {
        const result = negotiator.NegotiationResult{ .failure = err };
        switch (result) {
            .failure => |received_err| {
                try std.testing.expectEqual(err, received_err);
            },
            else => unreachable,
        }
    }
}

test "protocol index management" {
    const allocator = std.testing.allocator;
    
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    const protocols = [_][]const u8{ "/first/1.0.0", "/second/1.0.0", "/third/1.0.0" };
    
    const TestCallback = struct {
        fn callback(result: negotiator.NegotiationResult) void {
            _ = result;
        }
    };
    
    var neg = try negotiator.MultistreamNegotiator.init(
        allocator,
        &connection,
        &protocols,
        true,
        TestCallback.callback,
    );
    defer neg.deinit();
    
    // Test initial state
    try std.testing.expectEqual(@as(usize, 0), neg.current_protocol_index);
    try std.testing.expectEqual(@as(usize, 3), neg.protocols.len);
    
    // Test index bounds checking logic
    try std.testing.expect(neg.current_protocol_index < neg.protocols.len);
    
    // Simulate advancing through protocols
    neg.current_protocol_index += 1;
    try std.testing.expectEqual(@as(usize, 1), neg.current_protocol_index);
    try std.testing.expect(neg.current_protocol_index < neg.protocols.len);
    
    neg.current_protocol_index += 1;
    try std.testing.expectEqual(@as(usize, 2), neg.current_protocol_index);
    try std.testing.expect(neg.current_protocol_index < neg.protocols.len);
    
    neg.current_protocol_index += 1;
    try std.testing.expectEqual(@as(usize, 3), neg.current_protocol_index);
    try std.testing.expect(neg.current_protocol_index >= neg.protocols.len); // Out of protocols
}