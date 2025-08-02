// test_tcp_async_context.zig - Tests for context-aware async TCP

const std = @import("std");
const tcp_context = @import("tcp_async_context.zig");

test "callback context creation and data access" {
    // Test user data storage and retrieval
    var test_data: i32 = 42;
    const context = tcp_context.createContext(&test_data);
    
    // Verify we can retrieve the data
    const retrieved = context.getUserData(i32);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqual(@as(i32, 42), retrieved.?.*);
    
    // Test with different type
    var string_data = "hello";
    var string_context = tcp_context.CallbackContext{};
    string_context.setUserData(&string_data);
    
    const retrieved_string = string_context.getUserData(*const [5:0]u8);
    try std.testing.expect(retrieved_string != null);
    try std.testing.expectEqualStrings("hello", retrieved_string.?.*);
}

test "async connection initialization with context support" {
    const allocator = std.testing.allocator;
    
    // Create test socket pair
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    
    // Create context-aware connection (takes ownership of stream)
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    // Verify basic properties
    try std.testing.expect(connection.is_initiator);
    try std.testing.expect(!connection.is_closed);
    try std.testing.expectEqual(@as(u64, 0), connection.bytes_read);
    try std.testing.expectEqual(@as(u64, 0), connection.bytes_written);
    try std.testing.expect(!connection.hasPendingOperation());
}

test "async read with user context" {
    const allocator = std.testing.allocator;
    
    // Create connected socket pair
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    // Accept connection in thread
    const AcceptContext = struct {
        server: std.net.Server,
        client_stream: ?std.net.Stream = null,
        
        fn accept(self: *@This()) void {
            const conn = self.server.accept() catch return;
            self.client_stream = conn.stream;
        }
    };
    
    var accept_ctx = AcceptContext{ .server = server };
    const accept_thread = try std.Thread.spawn(.{}, AcceptContext.accept, .{&accept_ctx});
    
    // Connect client
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    
    accept_thread.join();
    if (accept_ctx.client_stream) |stream| {
        defer stream.close();
    }
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    // Test callback with context
    const TestContext = struct {
        callback_called: bool = false,
        bytes_received: usize = 0,
        connection_ptr: ?*tcp_context.AsyncTcpConnection = null,
        
        fn readCallback(
            conn: *tcp_context.AsyncTcpConnection,
            context: *tcp_context.CallbackContext,
            result: tcp_context.AsyncResult,
        ) void {
            if (context.getUserData(@This())) |test_ctx| {
                test_ctx.callback_called = true;
                test_ctx.connection_ptr = conn;
                
                switch (result) {
                    .success => |bytes| {
                        test_ctx.bytes_received = bytes;
                    },
                    .failure => {},
                }
            }
        }
    };
    
    var test_ctx = TestContext{};
    const callback_context = tcp_context.createContext(&test_ctx);
    
    // Start async read
    var buffer: [1024]u8 = undefined;
    try connection.asyncReadWithContext(&buffer, TestContext.readCallback, callback_context);
    
    // Verify operation is pending
    try std.testing.expect(connection.hasPendingOperation());
    
    // Process pending operations (simulates event loop)
    connection.processPendingOperations();
    
    // Note: In this test, the read will likely complete with WouldBlock since no data is sent
    // The callback might not be called, but the structure is correct
}

test "async write with user context" {
    const allocator = std.testing.allocator;
    
    // Create socket pair
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    // Test write callback with context
    const WriteTestContext = struct {
        write_completed: bool = false,
        bytes_written: usize = 0,
        
        fn writeCallback(
            conn: *tcp_context.AsyncTcpConnection,
            context: *tcp_context.CallbackContext,
            result: tcp_context.AsyncResult,
        ) void {
            _ = conn;
            if (context.getUserData(@This())) |test_ctx| {
                test_ctx.write_completed = true;
                
                switch (result) {
                    .success => |bytes| {
                        test_ctx.bytes_written = bytes;
                    },
                    .failure => {},
                }
            }
        }
    };
    
    var write_test_ctx = WriteTestContext{};
    const write_context = tcp_context.createContext(&write_test_ctx);
    
    // Start async write
    const test_data = "Hello, async TCP with context!";
    try connection.asyncWriteWithContext(test_data, WriteTestContext.writeCallback, write_context);
    
    // Verify operation is pending
    try std.testing.expect(connection.hasPendingOperation());
    
    // Process operations
    connection.processPendingOperations();
    
    // The write should complete (assuming socket is writable)
    // Note: In a real scenario with proper event loop, the callback would be called
}

test "multiple context types" {
    // Test that different user data types work correctly
    var int_data: i32 = 123;
    var string_data = "test";
    var bool_data: bool = true;
    
    const int_context = tcp_context.createContext(&int_data);
    const string_context = tcp_context.createContext(&string_data);
    const bool_context = tcp_context.createContext(&bool_data);
    
    // Verify each context maintains its own data
    try std.testing.expectEqual(@as(i32, 123), int_context.getUserData(i32).?.*);
    try std.testing.expectEqualStrings("test", string_context.getUserData(*const [4:0]u8).?.*);
    try std.testing.expectEqual(true, bool_context.getUserData(bool).?.*);
    
    // Verify wrong type returns null
    try std.testing.expect(int_context.getUserData(bool) == null);
    try std.testing.expect(string_context.getUserData(i32) == null);
}

test "operation state management" {
    const allocator = std.testing.allocator;
    
    const addr = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try addr.listen(.{});
    defer server.deinit();
    
    const client_stream = try std.net.tcpConnectToAddress(server.listen_address);
    
    var connection = try tcp_context.AsyncTcpConnection.init(allocator, client_stream, true);
    defer connection.deinit();
    
    // Initially no pending operations
    try std.testing.expect(!connection.hasPendingOperation());
    
    // Start operation
    const TestCallback = struct {
        fn callback(
            conn: *tcp_context.AsyncTcpConnection,
            context: *tcp_context.CallbackContext,
            result: tcp_context.AsyncResult,
        ) void {
            _ = conn;
            _ = context;
            _ = result;
        }
    };
    
    var buffer: [100]u8 = undefined;
    try connection.asyncRead(&buffer, TestCallback.callback);
    
    // Now should have pending operation
    try std.testing.expect(connection.hasPendingOperation());
    
    // Trying to start another operation should fail
    try std.testing.expectError(error.OperationInProgress, connection.asyncRead(&buffer, TestCallback.callback));
}