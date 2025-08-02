// libp2p.zig - Core libp2p module for ZeiCoin
// Provides a minimal libp2p implementation focused on TCP transport
// Based on the C++ libp2p architecture

const std = @import("std");

// Re-export core components
pub const multiaddr = @import("multiaddr/multiaddr.zig");
pub const tcp = @import("transport/tcp.zig");
pub const peer_id = @import("peer/peer_id.zig");
const libp2p_internal = @import("libp2p_internal.zig");
// TODO: Implement protocol negotiation
// pub const protocol = @import("protocol/multistream.zig");

// Type aliases for convenience
pub const Multiaddr = multiaddr.Multiaddr;
pub const ProtocolCode = multiaddr.ProtocolCode;
pub const TcpTransport = tcp.TcpTransport;
pub const TcpConnection = tcp.TcpConnection;
pub const PeerId = peer_id.PeerId;

/// Core libp2p host implementation
pub const Host = struct {
    allocator: std.mem.Allocator,
    transport: TcpTransport,
    peer_id: ?PeerId,
    listeners: std.ArrayList(Multiaddr),
    connections: std.ArrayList(*Connection),
    
    const Self = @This();
    
    pub const Connection = struct {
        tcp_conn: TcpConnection,
        remote_peer: ?PeerId,
        protocols: std.ArrayList([]const u8),
        allocator: std.mem.Allocator,
        
        pub fn init(allocator: std.mem.Allocator, tcp_conn: TcpConnection) Connection {
            return .{
                .tcp_conn = tcp_conn,
                .remote_peer = null,
                .protocols = std.ArrayList([]const u8).init(allocator),
                .allocator = allocator,
            };
        }
        
        pub fn deinit(self: *Connection) void {
            for (self.protocols.items) |proto| {
                self.allocator.free(proto);
            }
            self.protocols.deinit();
            self.tcp_conn.deinit();
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .transport = TcpTransport.init(allocator),
            .peer_id = null,
            .listeners = std.ArrayList(Multiaddr).init(allocator),
            .connections = std.ArrayList(*Connection).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        for (self.connections.items) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }
        self.connections.deinit();
        
        for (self.listeners.items) |*listener| {
            listener.deinit();
        }
        self.listeners.deinit();
        
        self.transport.deinit();
        
        if (self.peer_id) |*pid| {
            pid.deinit();
        }
    }
    
    /// Set the host's peer ID
    pub fn setPeerId(self: *Self, id: PeerId) void {
        if (self.peer_id) |*old_id| {
            old_id.deinit();
        }
        self.peer_id = id;
    }
    
    /// Listen on a multiaddr
    pub fn listen(self: *Self, addr: []const u8) !void {
        var ma = try Multiaddr.create(self.allocator, addr);
        errdefer ma.deinit();
        
        // Convert to internal Multiaddr type for transport layer
        var internal_ma = try libp2p_internal.Multiaddr.create(self.allocator, addr);
        defer internal_ma.deinit();
        
        _ = try self.transport.listen(&internal_ma);
        // Store the actual listening address
        try self.listeners.append(ma);
        
        std.log.info("Listening on {s}", .{ma.getStringAddress()});
    }
    
    /// Connect to a peer
    pub fn connect(self: *Self, addr: []const u8) !*Connection {
        var ma = try Multiaddr.create(self.allocator, addr);
        defer ma.deinit();
        
        // Convert to internal Multiaddr type for transport layer
        var internal_ma = try libp2p_internal.Multiaddr.create(self.allocator, addr);
        defer internal_ma.deinit();
        
        const tcp_conn = try self.transport.dial(&internal_ma);
        
        const conn = try self.allocator.create(Connection);
        conn.* = Connection.init(self.allocator, tcp_conn);
        
        try self.connections.append(conn);
        
        std.log.info("Connected to {s}", .{addr});
        
        return conn;
    }
    
    /// Close a connection
    pub fn disconnect(self: *Self, conn: *Connection) void {
        // Find and remove from connections list
        for (self.connections.items, 0..) |c, i| {
            if (c == conn) {
                _ = self.connections.swapRemove(i);
                break;
            }
        }
        
        conn.deinit();
        self.allocator.destroy(conn);
    }
    
    /// Get listening addresses
    pub fn getListenAddrs(self: *const Self) []const Multiaddr {
        return self.listeners.items;
    }
    
    /// Get active connections
    pub fn getConnections(self: *const Self) []const *Connection {
        return self.connections.items;
    }
};

/// Create a new libp2p host with default configuration
pub fn createHost(allocator: std.mem.Allocator) !*Host {
    const host = try allocator.create(Host);
    host.* = Host.init(allocator);
    
    // Generate and set peer ID
    const id = try PeerId.random(allocator);
    host.setPeerId(id);
    
    return host;
}

// Tests
test "create and use libp2p host" {
    const allocator = std.testing.allocator;
    
    const host = try createHost(allocator);
    defer {
        host.deinit();
        allocator.destroy(host);
    }
    
    // Listen on a random port
    try host.listen("/ip4/127.0.0.1/tcp/0");
    
    const addrs = host.getListenAddrs();
    try std.testing.expectEqual(@as(usize, 1), addrs.len);
}

test "connect between hosts" {
    const allocator = std.testing.allocator;
    
    // Create two hosts
    const host1 = try createHost(allocator);
    defer {
        host1.deinit();
        allocator.destroy(host1);
    }
    
    const host2 = try createHost(allocator);
    defer {
        host2.deinit();
        allocator.destroy(host2);
    }
    
    // Host1 listens
    try host1.listen("/ip4/127.0.0.1/tcp/0");
    
    // Get actual listening address
    const listener = host1.transport.listeners.items[0];
    const port = listener.server.listen_address.getPort();
    
    const connect_addr = try std.fmt.allocPrint(allocator, "/ip4/127.0.0.1/tcp/{}", .{port});
    defer allocator.free(connect_addr);
    
    // Host2 connects to host1
    const conn = try host2.connect(connect_addr);
    defer host2.disconnect(conn);
    
    try std.testing.expectEqual(@as(usize, 1), host2.getConnections().len);
}