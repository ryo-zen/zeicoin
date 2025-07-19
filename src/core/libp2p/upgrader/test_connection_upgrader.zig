// test_connection_upgrader.zig - Tests for connection upgrader

const std = @import("std");
const upgrader = @import("connection_upgrader.zig");
const tcp_context = @import("../transport/tcp_async_context.zig");

test "connection types and transitions" {
    const allocator = std.testing.allocator;
    
    // Create mock TCP connection
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var tcp_conn = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer tcp_conn.deinit();
    
    // Test connection progression: Raw -> Layer -> Secure -> Muxed
    
    // 1. Raw connection
    var raw_conn = upgrader.RawConnection.init(&tcp_conn, allocator);
    defer raw_conn.deinit();
    
    // 2. Layer connection
    var layer_conn = upgrader.LayerConnection.init(raw_conn, allocator);
    defer layer_conn.deinit();
    
    try layer_conn.addLayer("/yamux/1.0.0");
    try layer_conn.addLayer("/secio/1.0.0");
    try std.testing.expectEqual(@as(usize, 2), layer_conn.layers.items.len);
    
    // 3. Secure connection
    var secure_conn = upgrader.SecureConnection.init(layer_conn, "/plaintext/1.0.0");
    defer secure_conn.deinit();
    
    try std.testing.expectEqualStrings("/plaintext/1.0.0", secure_conn.security_protocol);
    
    // 4. Muxed connection
    var muxed_conn = upgrader.MuxedConnection.init(secure_conn, "/yamux/1.0.0");
    defer muxed_conn.deinit();
    
    try std.testing.expectEqualStrings("/yamux/1.0.0", muxed_conn.muxer_protocol);
}

test "protocol adaptor interface" {
    // Test protocol adaptor structure
    const test_upgrade_fn = struct {
        fn upgrade(connection: *anyopaque, alloc: std.mem.Allocator) anyerror!*anyopaque {
            _ = connection;
            _ = alloc;
            var dummy: u8 = 0;
            return @ptrCast(&dummy);
        }
    }.upgrade;
    
    const adaptor = upgrader.ProtocolAdaptor{
        .protocol_id = "/test/1.0.0",
        .upgrade_fn = test_upgrade_fn,
    };
    
    try std.testing.expectEqualStrings("/test/1.0.0", adaptor.getProtocolId());
}

test "upgrader initialization and adaptor management" {
    const allocator = std.testing.allocator;
    
    var upgrader_impl = upgrader.Upgrader.init(allocator);
    defer upgrader_impl.deinit();
    
    // Test initial state
    try std.testing.expectEqual(@as(usize, 0), upgrader_impl.layer_adaptors.items.len);
    try std.testing.expectEqual(@as(usize, 0), upgrader_impl.security_adaptors.items.len);
    try std.testing.expectEqual(@as(usize, 0), upgrader_impl.muxer_adaptors.items.len);
    
    // Test adding adaptors
    const dummy_fn = struct {
        fn upgrade(connection: *anyopaque, alloc: std.mem.Allocator) anyerror!*anyopaque {
            _ = connection;
            _ = alloc;
            var dummy: u8 = 0;
            return @ptrCast(&dummy);
        }
    }.upgrade;
    
    const layer_adaptor = upgrader.ProtocolAdaptor{
        .protocol_id = "/layer/1.0.0",
        .upgrade_fn = dummy_fn,
    };
    
    const security_adaptor = upgrader.ProtocolAdaptor{
        .protocol_id = "/plaintext/1.0.0",
        .upgrade_fn = dummy_fn,
    };
    
    const muxer_adaptor = upgrader.ProtocolAdaptor{
        .protocol_id = "/yamux/1.0.0",
        .upgrade_fn = dummy_fn,
    };
    
    try upgrader_impl.addLayerAdaptor(layer_adaptor);
    try upgrader_impl.addSecurityAdaptor(security_adaptor);
    try upgrader_impl.addMuxerAdaptor(muxer_adaptor);
    
    try std.testing.expectEqual(@as(usize, 1), upgrader_impl.layer_adaptors.items.len);
    try std.testing.expectEqual(@as(usize, 1), upgrader_impl.security_adaptors.items.len);
    try std.testing.expectEqual(@as(usize, 1), upgrader_impl.muxer_adaptors.items.len);
}

test "upgrade result types" {
    const allocator = std.testing.allocator;
    
    // Create mock connections for each result type
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var tcp_conn = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer tcp_conn.deinit();
    
    const raw_conn = upgrader.RawConnection.init(&tcp_conn, allocator);
    
    // Test layer connection result
    const layer_conn = upgrader.LayerConnection.init(raw_conn, allocator);
    const layer_result = upgrader.UpgradeResult{ .layer_connection = layer_conn };
    
    switch (layer_result) {
        .layer_connection => {},
        else => unreachable,
    }
    
    // Test secure connection result
    const secure_conn = upgrader.SecureConnection.init(layer_conn, "/plaintext/1.0.0");
    const secure_result = upgrader.UpgradeResult{ .secure_connection = secure_conn };
    
    switch (secure_result) {
        .secure_connection => {},
        else => unreachable,
    }
    
    // Test muxed connection result
    const muxed_conn = upgrader.MuxedConnection.init(secure_conn, "/yamux/1.0.0");
    const muxed_result = upgrader.UpgradeResult{ .muxed_connection = muxed_conn };
    
    switch (muxed_result) {
        .muxed_connection => {},
        else => unreachable,
    }
    
    // Test failure result
    const failure_result = upgrader.UpgradeResult{ .failure = error.TestError };
    
    switch (failure_result) {
        .failure => |err| {
            try std.testing.expectEqual(@as(anyerror, error.TestError), err);
        },
        else => unreachable,
    }
}

test "callback function types" {
    // Test that callback types can be created and called
    const TestCallbacks = struct {
        var layer_called: bool = false;
        var secure_called: bool = false;
        var muxed_called: bool = false;
        
        fn onLayer(result: upgrader.UpgradeResult) void {
            _ = result;
            layer_called = true;
        }
        
        fn onSecured(result: upgrader.UpgradeResult) void {
            _ = result;
            secure_called = true;
        }
        
        fn onMuxed(result: upgrader.UpgradeResult) void {
            _ = result;
            muxed_called = true;
        }
    };
    
    // Test callbacks
    const layer_callback: upgrader.OnLayerCallback = TestCallbacks.onLayer;
    const secure_callback: upgrader.OnSecuredCallback = TestCallbacks.onSecured;
    const muxed_callback: upgrader.OnMuxedCallback = TestCallbacks.onMuxed;
    
    const dummy_result = upgrader.UpgradeResult{ .failure = error.TestError };
    
    layer_callback(dummy_result);
    secure_callback(dummy_result);
    muxed_callback(dummy_result);
    
    try std.testing.expect(TestCallbacks.layer_called);
    try std.testing.expect(TestCallbacks.secure_called);
    try std.testing.expect(TestCallbacks.muxed_called);
}

test "layer upgrade session structure" {
    const allocator = std.testing.allocator;
    
    // Test that we can create the upgrade session components
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    defer client_stream.close();
    
    var tcp_conn = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer tcp_conn.deinit();
    
    var upgrader_impl = upgrader.Upgrader.init(allocator);
    defer upgrader_impl.deinit();
    
    const raw_conn = upgrader.RawConnection.init(&tcp_conn, allocator);
    const layer_protocols = [_][]const u8{"/test/1.0.0"};
    
    const TestCallback = struct {
        fn callback(result: upgrader.UpgradeResult) void {
            _ = result;
        }
    };
    
    // Test that callback and session setup works
    const callback: upgrader.OnLayerCallback = TestCallback.callback;
    _ = callback;
    _ = raw_conn;
    _ = layer_protocols;
    
    // Note: Full session test would require implementing the internal
    // session structures, which we've demonstrated the interface for
}

test "error handling in upgrade results" {
    // Test various error scenarios
    const error_cases = [_]anyerror{
        error.NoAdaptorFound,
        error.ProtocolMismatch,
        error.ConnectionFailed,
        error.SecurityNegotiationFailed,
        error.MuxerNegotiationFailed,
        error.InternalError,
    };
    
    for (error_cases) |err| {
        const result = upgrader.UpgradeResult{ .failure = err };
        
        switch (result) {
            .failure => |received_err| {
                try std.testing.expectEqual(err, received_err);
            },
            else => unreachable,
        }
    }
}

test "connection type enum values" {
    // Test connection type enum
    try std.testing.expectEqual(upgrader.ConnectionType.Raw, .Raw);
    try std.testing.expectEqual(upgrader.ConnectionType.Layer, .Layer);
    try std.testing.expectEqual(upgrader.ConnectionType.Secure, .Secure);
    try std.testing.expectEqual(upgrader.ConnectionType.Muxed, .Muxed);
    
    // Test that they can be compared
    const raw_type = upgrader.ConnectionType.Raw;
    try std.testing.expect(raw_type != .Muxed);
    try std.testing.expect(raw_type == .Raw);
}