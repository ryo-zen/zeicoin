// Client connection module for ZeiCoin CLI
// Handles server discovery, connection establishment, and basic communication

const std = @import("std");
const log = std.log.scoped(.cli);
const print = std.debug.print;
const net = std.Io.net;

const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const util = zeicoin.util;

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
    io: std.Io,

    pub fn deinit(self: *ClientConnection) void {
        self.stream.close(self.io);
        self.allocator.free(self.server_ip);
    }

    pub fn writeRequest(self: *ClientConnection, request: []const u8) !void {
        var write_buf: [4096]u8 = undefined;
        var writer = self.stream.writer(self.io, &write_buf);
        try writer.interface.writeAll(request);
    }

    pub fn readResponse(self: *ClientConnection, buffer: []u8) ![]const u8 {
        const msg = self.stream.socket.receive(self.io, buffer) catch |err| {
            log.info("❌ Server response error: {}", .{err});
            return ConnectionError.ConnectionTimeout;
        };
        return msg.data;
    }
};

// Auto-detect server IP by checking common interfaces
fn autoDetectServerIP(allocator: std.mem.Allocator, io: std.Io) ?[]const u8 {
    // Try to get local IP from hostname command
    var child = std.process.spawn(io, .{
        .argv = &[_][]const u8{ "hostname", "-I" },
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch return null;
    
    var stdout_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &stdout_buf);
    const stdout = stdout_reader.interface.readAlloc(allocator, 4096) catch return null;
    defer allocator.free(stdout);
    
    var stderr_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &stderr_buf);
    _ = stderr_reader.interface.readAlloc(allocator, 4096) catch {};
    
    const term = child.wait(io) catch return null;

    if (term == .exited and term.exited == 0 and stdout.len > 0) {
        // Parse first IP from output
        var it = std.mem.splitScalar(u8, stdout, ' ');
        if (it.next()) |first_ip| {
            const trimmed = std.mem.trim(u8, first_ip, " \t\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
        }
    }

    return null;
}

fn testServerConnection(io: std.Io, ip: []const u8) bool {
    const address = net.IpAddress.parse(ip, 10802) catch return false;
    
    var stream = address.connect(io, .{ .mode = .stream }) catch return false;
    defer stream.close(io);
    
    // Server is healthy if it responds with any data
    const test_msg = "STATUS";
    var write_buf: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    writer.interface.writeAll(test_msg) catch return false;
    
    var buffer: [1024]u8 = undefined;
    const msg = stream.socket.receive(io, &buffer) catch return false;
    
    return msg.data.len > 0;
}

pub fn getServerIP(allocator: std.mem.Allocator, io: std.Io) ![]const u8 {
    // 1. Try environment variable first
    if (util.getEnvVarOwned(allocator, "ZEICOIN_SERVER")) |server_ip| {
        return server_ip;
    } else |_| {}

    // 2. Try auto-detection with connection test
    if (autoDetectServerIP(allocator, io)) |detected_ip| {
        defer allocator.free(detected_ip);

        // Test if detected IP actually has a ZeiCoin server
        if (testServerConnection(io, detected_ip)) {
            return allocator.dupe(u8, detected_ip);
        }
    }

    // 3. Try bootstrap servers from JSON config
    const bootstrap_nodes = types.loadBootstrapNodes(allocator, io) catch |err| {
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
            if (testServerConnection(io, ip_str)) {
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

/// Connect to ZeiCoin server with automatic server discovery
pub fn connect(allocator: std.mem.Allocator, io: std.Io) !ClientConnection {
    const server_ip = try getServerIP(allocator, io);
    errdefer allocator.free(server_ip);

    const server_address = net.IpAddress.parse(server_ip, 10802) catch {
        log.info("❌ Invalid server address: {s}", .{server_ip});
        return ConnectionError.InvalidServerAddress;
    };

    const stream = server_address.connect(io, .{ .mode = .stream }) catch |err| {
        log.info("❌ Cannot connect to ZeiCoin server at {s}:10802: {}", .{server_ip, err});
        print("💡 Make sure the server is running\n", .{});
        return ConnectionError.ConnectionFailed;
    };

    return ClientConnection{
        .stream = stream,
        .server_ip = server_ip,
        .allocator = allocator,
        .io = io,
    };
}

/// Send a request and get response in one call
pub fn sendRequest(allocator: std.mem.Allocator, io: std.Io, request: []const u8, response_buffer: []u8) ![]const u8 {
    var connection_inst = try connect(allocator, io);
    defer connection_inst.deinit();
    
    try connection_inst.writeRequest(request);
    return try connection_inst.readResponse(response_buffer);
}
