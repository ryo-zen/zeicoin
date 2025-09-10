// Client connection module for ZeiCoin CLI
// Handles server discovery, connection establishment, and basic communication

const std = @import("std");
const log = std.log.scoped(.cli);
const print = std.debug.print;
const net = std.net;

const zeicoin = @import("zeicoin");
const types = zeicoin.types;

pub const ConnectionError = error{
    NetworkError,
    ConnectionTimeout,
    ConnectionFailed,
    InvalidServerAddress,
};

pub const ClientConnection = struct {
    stream: net.Stream,
    server_ip: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ClientConnection) void {
        self.stream.close();
        self.allocator.free(self.server_ip);
    }

    pub fn writeRequest(self: *ClientConnection, request: []const u8) !void {
        try self.stream.writeAll(request);
    }

    pub fn readResponse(self: *ClientConnection, buffer: []u8) ![]const u8 {
        const bytes_read = readWithTimeout(self.stream, buffer) catch {
            log.info("❌ Server response timeout (5s)", .{});
            return ConnectionError.ConnectionTimeout;
        };
        return buffer[0..bytes_read];
    }
};

// Auto-detect server IP by checking common interfaces
fn autoDetectServerIP(allocator: std.mem.Allocator) ?[]const u8 {
    // Try to get local IP from hostname command
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "hostname", "-I" },
    }) catch return null;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited == 0 and result.stdout.len > 0) {
        // Parse first IP from output
        var it = std.mem.splitScalar(u8, result.stdout, ' ');
        if (it.next()) |first_ip| {
            const trimmed = std.mem.trim(u8, first_ip, " \t\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
        }
    }

    return null;
}

fn testServerConnection(ip: []const u8) bool {
    const address = net.Address.parseIp4(ip, 10802) catch return false;
    
    var stream = connectWithTimeout(address) catch return false;
    defer stream.close();
    
    // Server is healthy if it responds with any data
    const test_msg = "STATUS";
    stream.writeAll(test_msg) catch return false;
    
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(stream, &buffer) catch return false;
    
    return bytes_read > 0;
}

pub fn getServerIP(allocator: std.mem.Allocator) ![]const u8 {
    // 1. Try environment variable first
    if (std.process.getEnvVarOwned(allocator, "ZEICOIN_SERVER")) |server_ip| {
        return server_ip;
    } else |_| {}

    // 2. Try auto-detection with connection test
    if (autoDetectServerIP(allocator)) |detected_ip| {
        defer allocator.free(detected_ip);

        // Test if detected IP actually has a ZeiCoin server
        if (testServerConnection(detected_ip)) {
            return allocator.dupe(u8, detected_ip);
        }
    }

    // 3. Try bootstrap servers from JSON config
    const bootstrap_nodes = types.loadBootstrapNodes(allocator) catch |err| {
        log.info("⚠️  Failed to load bootstrap nodes: {}", .{err});
        return ConnectionError.NetworkError;
    };
    defer types.freeBootstrapNodes(allocator, bootstrap_nodes);

    log.info("🔍 Testing bootstrap nodes for health...", .{});
    for (bootstrap_nodes) |bootstrap_addr| {
        // Parse IP from "ip:port" format
        var it = std.mem.splitScalar(u8, bootstrap_addr, ':');
        if (it.next()) |ip_str| {
            log.info("  Testing {s}... ", .{ip_str});
            if (testServerConnection(ip_str)) {
                log.info("✅ Healthy!", .{});
                log.info("🌐 Using healthy bootstrap node: {s}", .{ip_str});
                return allocator.dupe(u8, ip_str);
            } else {
                log.info("❌ Unhealthy or offline", .{});
            }
        }
    }

    log.info("⚠️  No healthy bootstrap nodes found", .{});

    // 4. Final fallback to localhost
    print("💡 Using localhost fallback (set ZEICOIN_SERVER to override)\n", .{});
    return allocator.dupe(u8, "127.0.0.1");
}

fn connectWithTimeout(address: net.Address) !net.Stream {
    const ConnectResult = struct {
        result: ?net.Stream = null,
        error_occurred: bool = false,
        completed: bool = false,
    };

    var connect_result = ConnectResult{};

    // Spawn thread for connection attempt
    const connect_thread = std.Thread.spawn(.{}, struct {
        fn connectWorker(addr: net.Address, result: *ConnectResult) void {
            result.result = net.tcpConnectToAddress(addr) catch {
                result.error_occurred = true;
                result.completed = true;
                return;
            };
            result.completed = true;
        }
    }.connectWorker, .{ address, &connect_result }) catch {
        return ConnectionError.ConnectionFailed;
    };

    // Wait for completion or timeout (5 seconds)
    const timeout_ns = 5 * std.time.ns_per_s;
    const start_time = std.time.nanoTimestamp();

    while (!connect_result.completed) {
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) {
            // Timeout - the thread will continue but we abandon it
            return ConnectionError.ConnectionTimeout;
        }
        std.time.sleep(10 * std.time.ns_per_ms); // Check every 10ms
    }

    connect_thread.join();

    if (connect_result.error_occurred) {
        return ConnectionError.ConnectionFailed;
    }

    return connect_result.result orelse ConnectionError.ConnectionFailed;
}

fn readWithTimeout(stream: net.Stream, buffer: []u8) !usize {
    const ReadResult = struct {
        bytes_read: usize = 0,
        error_occurred: bool = false,
        completed: bool = false,
    };

    var read_result = ReadResult{};

    // Spawn thread for read attempt
    const read_thread = std.Thread.spawn(.{}, struct {
        fn readWorker(s: net.Stream, buf: []u8, result: *ReadResult) void {
            result.bytes_read = s.read(buf) catch {
                result.error_occurred = true;
                result.completed = true;
                return;
            };
            result.completed = true;
        }
    }.readWorker, .{ stream, buffer, &read_result }) catch {
        return error.ReadTimeout;
    };

    // Wait for completion or timeout (5 seconds)
    const timeout_ns = 5 * std.time.ns_per_s;
    const start_time = std.time.nanoTimestamp();

    while (!read_result.completed) {
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) {
            // Timeout - the thread will continue but we abandon it
            return error.ReadTimeout;
        }
        std.time.sleep(10 * std.time.ns_per_ms); // Check every 10ms
    }

    read_thread.join();

    if (read_result.error_occurred) {
        return error.ReadTimeout;
    }

    return read_result.bytes_read;
}

/// Connect to ZeiCoin server with automatic server discovery
pub fn connect(allocator: std.mem.Allocator) !ClientConnection {
    const server_ip = try getServerIP(allocator);
    errdefer allocator.free(server_ip);

    const server_address = net.Address.parseIp4(server_ip, 10802) catch {
        log.info("❌ Invalid server address: {s}", .{server_ip});
        return ConnectionError.InvalidServerAddress;
    };

    const stream = connectWithTimeout(server_address) catch |err| {
        switch (err) {
            ConnectionError.ConnectionTimeout => {
                print("❌ Connection timeout to ZeiCoin server at {s}:10802 (5s)\n", .{server_ip});
                return ConnectionError.ConnectionTimeout;
            },
            ConnectionError.ConnectionFailed => {
                print("❌ Cannot connect to ZeiCoin server at {s}:10802\n", .{server_ip});
                print("💡 Make sure the server is running\n", .{});
                return ConnectionError.ConnectionFailed;
            },
            else => return err,
        }
    };

    return ClientConnection{
        .stream = stream,
        .server_ip = server_ip,
        .allocator = allocator,
    };
}

/// Send a request and get response in one call
pub fn sendRequest(allocator: std.mem.Allocator, request: []const u8, response_buffer: []u8) ![]const u8 {
    var connection = try connect(allocator);
    defer connection.deinit();
    
    try connection.writeRequest(request);
    return try connection.readResponse(response_buffer);
}