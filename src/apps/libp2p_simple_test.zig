// libp2p_simple_test.zig - Simple test for libp2p protocol communication
// Simplified version to test basic connectivity without complex formatting

const std = @import("std");
const print = std.debug.print;
const zeicoin = @import("zeicoin");

const tcp_context = zeicoin.libp2p.tcp_context;
const negotiator = zeicoin.libp2p.negotiator;

const TEST_PORT = 9999;
const PROTOCOL_ID = "/test/echo/1.0.0";

/// Simple test server
const SimpleServer = struct {
    allocator: std.mem.Allocator,
    server: std.net.Server,
    running: bool,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, port: u16) !Self {
        const addr = try std.net.Address.parseIp("0.0.0.0", port);
        const server = try addr.listen(.{ .reuse_address = true });
        
        print("Server listening on port {}\n", .{port});
        
        return Self{
            .allocator = allocator,
            .server = server,
            .running = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.server.deinit();
    }
    
    pub fn start(self: *Self) !void {
        self.running = true;
        print("Server starting...\n", .{});
        
        while (self.running) {
            const connection = self.server.accept() catch |err| {
                if (err == error.SocketNotListening) break;
                print("Accept error: {}\n", .{err});
                continue;
            };
            
            print("Incoming connection\n", .{});
            
            // Handle connection (simplified)
            self.handleConnection(connection) catch |err| {
                print("Connection handling error: {}\n", .{err});
            };
        }
    }
    
    fn handleConnection(self: *Self, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();
        
        // Create async TCP connection wrapper
        var tcp_conn = try tcp_context.AsyncTcpConnection.init(
            self.allocator, 
            connection.stream, 
            false // not initiator
        );
        defer tcp_conn.deinit();
        
        print("Created async TCP connection wrapper\n", .{});
        
        // Simple echo: read some data and write it back
        var buffer: [1024]u8 = undefined;
        const bytes_read = try connection.stream.read(&buffer);
        if (bytes_read > 0) {
            _ = try connection.stream.write(buffer[0..bytes_read]);
            print("Echoed {} bytes\n", .{bytes_read});
        }
        
        // Keep connection alive briefly
        std.time.sleep(2 * std.time.ns_per_s);
    }
    
    pub fn stop(self: *Self) void {
        self.running = false;
    }
};

/// Simple test client
const SimpleClient = struct {
    allocator: std.mem.Allocator,
    target_address: std.net.Address,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Self {
        const addr = try std.net.Address.parseIp(host, port);
        
        return Self{
            .allocator = allocator,
            .target_address = addr,
        };
    }
    
    pub fn connect(self: *Self) !void {
        print("Client connecting...\n", .{});
        
        const stream = try std.net.tcpConnectToAddress(self.target_address);
        defer stream.close();
        
        print("TCP connection established\n", .{});
        
        // Create async TCP connection wrapper
        var tcp_conn = try tcp_context.AsyncTcpConnection.init(
            self.allocator,
            stream,
            true // is initiator
        );
        defer tcp_conn.deinit();
        
        print("Created async TCP connection wrapper\n", .{});
        
        // Send test message
        const test_message = "Hello libp2p!";
        _ = try stream.write(test_message);
        print("Sent test message\n", .{});
        
        // Read response
        var buffer: [1024]u8 = undefined;
        const bytes_read = try stream.read(&buffer);
        if (bytes_read > 0) {
            print("Received echo response: {s}\n", .{buffer[0..bytes_read]});
        }
        
        print("Client test complete\n", .{});
    }
};

fn printUsage(program_name: []const u8) void {
    print("Usage: {s} <mode> [options]\n", .{program_name});
    print("Modes:\n", .{});
    print("  server [port]     - Start test server (default port: {})\n", .{TEST_PORT});
    print("  client <host> [port] - Connect to test server (default port: {})\n", .{TEST_PORT});
    print("\nExamples:\n", .{});
    print("  {s} server\n", .{program_name});
    print("  {s} server 8080\n", .{program_name});
    print("  {s} client localhost\n", .{program_name});
    print("  {s} client 127.0.0.1 8080\n", .{program_name});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    if (args.len < 2) {
        printUsage(args[0]);
        return;
    }
    
    const mode = args[1];
    
    if (std.mem.eql(u8, mode, "server")) {
        const port = if (args.len >= 3) 
            try std.fmt.parseInt(u16, args[2], 10) 
        else 
            TEST_PORT;
            
        print("Starting libp2p simple test server on port {}\n", .{port});
        
        var server = try SimpleServer.init(allocator, port);
        defer server.deinit();
        
        try server.start();
        
    } else if (std.mem.eql(u8, mode, "client")) {
        if (args.len < 3) {
            print("Client mode requires host argument\n", .{});
            printUsage(args[0]);
            return;
        }
        
        const host = args[2];
        const port = if (args.len >= 4) 
            try std.fmt.parseInt(u16, args[3], 10) 
        else 
            TEST_PORT;
            
        print("Starting libp2p simple test client connecting to {s}:{}\n", .{ host, port });
        
        var client = try SimpleClient.init(allocator, host, port);
        
        try client.connect();
        
    } else {
        print("Unknown mode: {s}\n", .{mode});
        printUsage(args[0]);
    }
}