// libp2p_test.zig - Test application for libp2p protocol communication
// Tests multistream negotiation and connection upgrading between two nodes

const std = @import("std");
const print = std.debug.print;
const zeicoin = @import("zeicoin");

const tcp_context = zeicoin.libp2p.tcp_context;
const negotiator = zeicoin.libp2p.negotiator;
const upgrader = zeicoin.libp2p.upgrader;
const session = zeicoin.libp2p.session;

const TEST_PORT = 9999;
const PROTOCOL_ID = "/test/echo/1.0.0";

/// Test server that listens for connections and responds to echo protocol
const TestServer = struct {
    allocator: std.mem.Allocator,
    listen_address: std.net.Address,
    server: std.net.Server,
    upgrader_impl: upgrader.Upgrader,
    running: bool,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, port: u16) !Self {
        const addr = try std.net.Address.parseIp("0.0.0.0", port);
        const server = try addr.listen(.{ .reuse_address = true });
        
        print("🖥️  Server listening on port {}\n", .{port});
        
        var upgrader_impl = upgrader.Upgrader.init(allocator);
        
        // Add test protocol adaptor
        const test_adaptor = upgrader.ProtocolAdaptor{
            .protocol_id = PROTOCOL_ID,
            .upgrade_fn = testProtocolUpgrade,
        };
        try upgrader_impl.addLayerAdaptor(test_adaptor);
        
        return Self{
            .allocator = allocator,
            .listen_address = addr,
            .server = server,
            .upgrader_impl = upgrader_impl,
            .running = false,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.server.deinit();
        self.upgrader_impl.deinit();
    }
    
    fn testProtocolUpgrade(connection: *anyopaque, alloc: std.mem.Allocator) anyerror!*anyopaque {
        _ = connection;
        print("📜 Test protocol upgrade successful\n", .{});
        // In real implementation, would wrap connection with protocol handler
        const dummy: u8 = 1;
        const result = try alloc.create(u8);
        result.* = dummy;
        return @ptrCast(result);
    }
    
    pub fn start(self: *Self) !void {
        self.running = true;
        print("🚀 Test server starting...\n", .{});
        
        while (self.running) {
            const connection = self.server.accept() catch |err| {
                if (err == error.SocketNotListening) break;
                print("❌ Accept error: {}\n", .{err});
                continue;
            };
            
            print("📥 Incoming connection from {}\n", .{connection.address});
            
            // Handle connection in background (simplified for test)
            self.handleConnection(connection) catch |err| {
                print("❌ Connection handling error: {}\n", .{err});
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
        
        print("🔧 Created async TCP connection wrapper\n", .{});
        
        // Create raw connection for upgrader
        const raw_conn = upgrader.RawConnection.init(&tcp_conn, self.allocator);
        
        // Start upgrade session
        const layer_protocols = [_][]const u8{PROTOCOL_ID};
        
        const upgrade_callback = struct {
            fn callback(result: session.SessionResult) void {
                switch (result) {
                    .success => |muxed_conn| {
                        print("✅ Server: Connection upgrade successful! Protocol: {s}\n", .{muxed_conn.muxer_protocol});
                        // In real implementation, would start protocol handlers
                    },
                    .failure => |err| {
                        print("❌ Server: Connection upgrade failed: {}\n", .{err});
                    },
                }
            }
        }.callback;
        
        // Create and start upgrade session
        var upgrade_session = try session.createInboundSession(
            self.allocator,
            &self.upgrader_impl,
            &layer_protocols,
            raw_conn,
            upgrade_callback,
        );
        defer upgrade_session.deinit();
        
        print("🔄 Server: Started inbound upgrade session\n", .{});
        
        // Keep connection alive for testing
        std.time.sleep(5 * std.time.ns_per_s);
    }
    
    pub fn stop(self: *Self) void {
        self.running = false;
    }
};

/// Test client that connects to server and initiates protocol negotiation
const TestClient = struct {
    allocator: std.mem.Allocator,
    target_address: std.net.Address,
    upgrader_impl: upgrader.Upgrader,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Self {
        const addr = try std.net.Address.parseIp(host, port);
        
        var upgrader_impl = upgrader.Upgrader.init(allocator);
        
        // Add test protocol adaptor
        const test_adaptor = upgrader.ProtocolAdaptor{
            .protocol_id = PROTOCOL_ID,
            .upgrade_fn = TestServer.testProtocolUpgrade,
        };
        try upgrader_impl.addLayerAdaptor(test_adaptor);
        
        return Self{
            .allocator = allocator,
            .target_address = addr,
            .upgrader_impl = upgrader_impl,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.upgrader_impl.deinit();
    }
    
    pub fn connect(self: *Self) !void {
        print("🔗 Client connecting to {}...\n", .{self.target_address});
        
        const stream = try std.net.tcpConnectToAddress(self.target_address);
        defer stream.close();
        
        print("✅ TCP connection established\n", .{});
        
        // Create async TCP connection wrapper
        var tcp_conn = try tcp_context.AsyncTcpConnection.init(
            self.allocator,
            stream,
            true // is initiator
        );
        defer tcp_conn.deinit();
        
        // Create raw connection for upgrader
        const raw_conn = upgrader.RawConnection.init(&tcp_conn, self.allocator);
        
        // Start upgrade session
        const layer_protocols = [_][]const u8{PROTOCOL_ID};
        
        const upgrade_callback = struct {
            fn callback(result: session.SessionResult) void {
                switch (result) {
                    .success => |muxed_conn| {
                        print("✅ Client: Connection upgrade successful! Protocol: {s}\n", .{muxed_conn.muxer_protocol});
                        // Could send test messages here
                    },
                    .failure => |err| {
                        print("❌ Client: Connection upgrade failed: {}\n", .{err});
                    },
                }
            }
        }.callback;
        
        // Create multiaddr for outbound session (simplified)
        const addr_str = try std.fmt.allocPrint(self.allocator, "/ip4/127.0.0.1/tcp/{}", .{TEST_PORT});
        defer self.allocator.free(addr_str);
        
        // Import the libp2p internal types
        const libp2p_internal = @import("../core/libp2p/libp2p_internal.zig");
        const multiaddr = libp2p_internal.Multiaddr.init(addr_str);
        
        // Generate test peer ID
        var peer_id_bytes: [32]u8 = undefined;
        std.crypto.random.bytes(&peer_id_bytes);
        const peer_id = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(peer_id_bytes[0..8])});
        defer self.allocator.free(peer_id);
        
        // Create and start upgrade session
        var upgrade_session = try session.createOutboundSession(
            self.allocator,
            &self.upgrader_impl,
            &layer_protocols,
            raw_conn,
            &multiaddr,
            peer_id,
            upgrade_callback,
        );
        defer upgrade_session.deinit();
        
        print("🔄 Client: Started outbound upgrade session\n", .{});
        
        // Keep connection alive for testing
        std.time.sleep(3 * std.time.ns_per_s);
        
        print("✅ Client: Test complete\n", .{});
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
    print("  {s} client 192.168.1.100 8080\n", .{program_name});
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
            
        print("🌟 Starting libp2p test server on port {}\n", .{port});
        
        var server = try TestServer.init(allocator, port);
        defer server.deinit();
        
        try server.start();
        
    } else if (std.mem.eql(u8, mode, "client")) {
        if (args.len < 3) {
            print("❌ Client mode requires host argument\n", .{});
            printUsage(args[0]);
            return;
        }
        
        const host = args[2];
        const port = if (args.len >= 4) 
            try std.fmt.parseInt(u16, args[3], 10) 
        else 
            TEST_PORT;
            
        print("🌟 Starting libp2p test client connecting to {}:{}\n", .{ host, port });
        
        var client = try TestClient.init(allocator, host, port);
        defer client.deinit();
        
        try client.connect();
        
    } else {
        print("❌ Unknown mode: {s}\n", .{mode});
        printUsage(args[0]);
    }
}