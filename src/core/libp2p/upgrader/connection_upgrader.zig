// connection_upgrader.zig - Connection upgrader for libp2p
// Handles connection lifecycle: Raw -> Layer -> Secure -> Muxed
// Based on C++ libp2p upgrader implementation

const std = @import("std");
const tcp_context = @import("../transport/tcp_async_context.zig");
const negotiator = @import("../protocol/multistream_negotiator.zig");
const libp2p = @import("../libp2p_internal.zig");

/// Connection upgrade stages following libp2p specification
pub const ConnectionType = enum {
    Raw,        // Basic TCP connection
    Layer,      // With protocol layers applied
    Secure,     // With security protocol applied  
    Muxed,      // With stream multiplexing applied
};

/// Protocol adaptor interface for different layers
pub const ProtocolAdaptor = struct {
    protocol_id: []const u8,
    upgrade_fn: *const fn (connection: *anyopaque, allocator: std.mem.Allocator) anyerror!*anyopaque,
    
    pub fn getProtocolId(self: *const ProtocolAdaptor) []const u8 {
        return self.protocol_id;
    }
};

/// Raw connection (basic TCP)
pub const RawConnection = struct {
    tcp_connection: *tcp_context.AsyncTcpConnection,
    allocator: std.mem.Allocator,
    
    pub fn init(tcp_connection: *tcp_context.AsyncTcpConnection, allocator: std.mem.Allocator) RawConnection {
        return .{
            .tcp_connection = tcp_connection,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *RawConnection) void {
        _ = self;
        // Note: tcp_connection is managed externally
    }
};

/// Layer connection (with protocol layers)
pub const LayerConnection = struct {
    raw: RawConnection,
    layers: std.ArrayList([]const u8), // Applied layer protocols
    
    pub fn init(raw: RawConnection, allocator: std.mem.Allocator) LayerConnection {
        return .{
            .raw = raw,
            .layers = std.ArrayList([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *LayerConnection) void {
        self.layers.deinit();
        self.raw.deinit();
    }
    
    pub fn addLayer(self: *LayerConnection, protocol: []const u8) !void {
        try self.layers.append(protocol);
    }
};

/// Secure connection (with security protocol)
pub const SecureConnection = struct {
    layer: LayerConnection,
    security_protocol: []const u8,
    
    pub fn init(layer: LayerConnection, security_protocol: []const u8) SecureConnection {
        return .{
            .layer = layer,
            .security_protocol = security_protocol,
        };
    }
    
    pub fn deinit(self: *SecureConnection) void {
        self.layer.deinit();
    }
};

/// Muxed connection (with stream multiplexing)
pub const MuxedConnection = struct {
    secure: SecureConnection,
    muxer_protocol: []const u8,
    
    pub fn init(secure: SecureConnection, muxer_protocol: []const u8) MuxedConnection {
        return .{
            .secure = secure,
            .muxer_protocol = muxer_protocol,
        };
    }
    
    pub fn deinit(self: *MuxedConnection) void {
        self.secure.deinit();
    }
};

/// Upgrade result types
pub const UpgradeResult = union(enum) {
    layer_connection: LayerConnection,
    secure_connection: SecureConnection,
    muxed_connection: MuxedConnection,
    failure: anyerror,
};

/// Callback function types (matching C++ interface)
pub const OnLayerCallback = *const fn (result: UpgradeResult) void;
pub const OnSecuredCallback = *const fn (result: UpgradeResult) void;
pub const OnMuxedCallback = *const fn (result: UpgradeResult) void;

/// Connection upgrader interface  
pub const Upgrader = struct {
    allocator: std.mem.Allocator,
    
    // Available protocol adaptors
    layer_adaptors: std.ArrayList(ProtocolAdaptor),
    security_adaptors: std.ArrayList(ProtocolAdaptor),
    muxer_adaptors: std.ArrayList(ProtocolAdaptor),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .layer_adaptors = std.ArrayList(ProtocolAdaptor).init(allocator),
            .security_adaptors = std.ArrayList(ProtocolAdaptor).init(allocator),
            .muxer_adaptors = std.ArrayList(ProtocolAdaptor).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.layer_adaptors.deinit();
        self.security_adaptors.deinit();
        self.muxer_adaptors.deinit();
    }
    
    /// Add layer protocol adaptor
    pub fn addLayerAdaptor(self: *Self, adaptor: ProtocolAdaptor) !void {
        try self.layer_adaptors.append(adaptor);
    }
    
    /// Add security protocol adaptor
    pub fn addSecurityAdaptor(self: *Self, adaptor: ProtocolAdaptor) !void {
        try self.security_adaptors.append(adaptor);
    }
    
    /// Add muxer protocol adaptor
    pub fn addMuxerAdaptor(self: *Self, adaptor: ProtocolAdaptor) !void {
        try self.muxer_adaptors.append(adaptor);
    }
    
    /// Upgrade outbound connection through layer protocols
    pub fn upgradeLayersOutbound(
        self: *Self,
        address: *const libp2p.Multiaddr,
        raw_conn: RawConnection,
        layer_protocols: []const []const u8,
        callback: OnLayerCallback,
    ) !void {
        _ = address; // For future use with address-specific protocols
        
        if (layer_protocols.len == 0) {
            // No layers to upgrade
            const layer_conn = LayerConnection.init(raw_conn, self.allocator);
            callback(.{ .layer_connection = layer_conn });
            return;
        }
        
        // Create upgrade session for layer processing
        var session = try LayerUpgradeSession.init(
            self.allocator,
            raw_conn,
            layer_protocols,
            &self.layer_adaptors,
            callback,
            true, // is_initiator
        );
        
        try session.start();
    }
    
    /// Upgrade inbound connection through layer protocols
    pub fn upgradeLayersInbound(
        self: *Self,
        raw_conn: RawConnection,
        layer_protocols: []const []const u8,
        callback: OnLayerCallback,
    ) !void {
        if (layer_protocols.len == 0) {
            // No layers to upgrade
            const layer_conn = LayerConnection.init(raw_conn, self.allocator);
            callback(.{ .layer_connection = layer_conn });
            return;
        }
        
        // Create upgrade session for layer processing
        var session = try LayerUpgradeSession.init(
            self.allocator,
            raw_conn,
            layer_protocols,
            &self.layer_adaptors,
            callback,
            false, // is_initiator
        );
        
        try session.start();
    }
    
    /// Upgrade to secure connection (outbound)
    pub fn upgradeToSecureOutbound(
        self: *Self,
        layer_conn: LayerConnection,
        remote_peer_id: []const u8,
        callback: OnSecuredCallback,
    ) !void {
        _ = remote_peer_id; // For future security protocol use
        
        // Create security upgrade session
        var session = try SecurityUpgradeSession.init(
            self.allocator,
            layer_conn,
            &self.security_adaptors,
            callback,
            true, // is_initiator
        );
        
        try session.start();
    }
    
    /// Upgrade to secure connection (inbound)
    pub fn upgradeToSecureInbound(
        self: *Self,
        layer_conn: LayerConnection,
        callback: OnSecuredCallback,
    ) !void {
        // Create security upgrade session
        var session = try SecurityUpgradeSession.init(
            self.allocator,
            layer_conn,
            &self.security_adaptors,
            callback,
            false, // is_initiator
        );
        
        try session.start();
    }
    
    /// Upgrade to muxed connection
    pub fn upgradeToMuxed(
        self: *Self,
        secure_conn: SecureConnection,
        callback: OnMuxedCallback,
    ) !void {
        // Create muxer upgrade session
        var session = try MuxerUpgradeSession.init(
            self.allocator,
            secure_conn,
            &self.muxer_adaptors,
            callback,
        );
        
        try session.start();
    }
    
    /// Find adaptor by protocol ID
    fn findAdaptor(adaptors: *const std.ArrayList(ProtocolAdaptor), protocol_id: []const u8) ?*const ProtocolAdaptor {
        for (adaptors.items) |*adaptor| {
            if (std.mem.eql(u8, adaptor.protocol_id, protocol_id)) {
                return adaptor;
            }
        }
        return null;
    }
};

/// Layer upgrade session
const LayerUpgradeSession = struct {
    allocator: std.mem.Allocator,
    raw_connection: RawConnection,
    layer_protocols: []const []const u8,
    available_adaptors: *const std.ArrayList(ProtocolAdaptor),
    callback: OnLayerCallback,
    is_initiator: bool,
    current_layer_index: usize,
    layer_connection: ?LayerConnection,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        raw_conn: RawConnection,
        layer_protocols: []const []const u8,
        adaptors: *const std.ArrayList(ProtocolAdaptor),
        callback: OnLayerCallback,
        is_initiator: bool,
    ) !*Self {
        const session = try allocator.create(Self);
        session.* = .{
            .allocator = allocator,
            .raw_connection = raw_conn,
            .layer_protocols = layer_protocols,
            .available_adaptors = adaptors,
            .callback = callback,
            .is_initiator = is_initiator,
            .current_layer_index = 0,
            .layer_connection = null,
        };
        return session;
    }
    
    pub fn deinit(self: *Self) void {
        if (self.layer_connection) |*conn| {
            conn.deinit();
        }
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *Self) !void {
        // Initialize layer connection
        self.layer_connection = LayerConnection.init(self.raw_connection, self.allocator);
        
        // Start upgrading through each layer
        try self.upgradeNextLayer();
    }
    
    fn upgradeNextLayer(self: *Self) anyerror!void {
        if (self.current_layer_index >= self.layer_protocols.len) {
            // All layers upgraded successfully
            if (self.layer_connection) |conn| {
                self.callback(.{ .layer_connection = conn });
            } else {
                self.callback(.{ .failure = error.InternalError });
            }
            return;
        }
        
        const protocol_id = self.layer_protocols[self.current_layer_index];
        
        // Find adaptor for this protocol
        if (Upgrader.findAdaptor(self.available_adaptors, protocol_id)) |adaptor| {
            // Negotiate and apply this layer protocol
            try self.negotiateLayer(adaptor);
        } else {
            // No adaptor found for this protocol
            self.callback(.{ .failure = error.NoAdaptorFound });
        }
    }
    
    fn negotiateLayer(self: *Self, adaptor: *const ProtocolAdaptor) !void {
        // For now, simplified - just add the layer without full negotiation
        // In complete implementation, would use multistream negotiation here
        if (self.layer_connection) |*conn| {
            try conn.addLayer(adaptor.protocol_id);
        }
        
        // Move to next layer
        self.current_layer_index += 1;
        self.upgradeNextLayer() catch |err| {
            self.callback(.{ .failure = err });
        };
    }
};

/// Security upgrade session  
const SecurityUpgradeSession = struct {
    allocator: std.mem.Allocator,
    layer_connection: LayerConnection,
    security_adaptors: *const std.ArrayList(ProtocolAdaptor),
    callback: OnSecuredCallback,
    is_initiator: bool,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        layer_conn: LayerConnection,
        adaptors: *const std.ArrayList(ProtocolAdaptor),
        callback: OnSecuredCallback,
        is_initiator: bool,
    ) !*Self {
        const session = try allocator.create(Self);
        session.* = .{
            .allocator = allocator,
            .layer_connection = layer_conn,
            .security_adaptors = adaptors,
            .callback = callback,
            .is_initiator = is_initiator,
        };
        return session;
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *Self) !void {
        // Collect available security protocols
        var protocols = std.ArrayList([]const u8).init(self.allocator);
        defer protocols.deinit();
        
        for (self.security_adaptors.items) |adaptor| {
            try protocols.append(adaptor.protocol_id);
        }
        
        if (protocols.items.len == 0) {
            // No security protocols available - use plaintext (for testing)
            const secure_conn = SecureConnection.init(self.layer_connection, "plaintext/1.0.0");
            self.callback(.{ .secure_connection = secure_conn });
            return;
        }
        
        // For now, use first available security protocol
        // In complete implementation, would negotiate via multistream
        const security_protocol = protocols.items[0];
        const secure_conn = SecureConnection.init(self.layer_connection, security_protocol);
        self.callback(.{ .secure_connection = secure_conn });
    }
};

/// Muxer upgrade session
const MuxerUpgradeSession = struct {
    allocator: std.mem.Allocator,
    secure_connection: SecureConnection,
    muxer_adaptors: *const std.ArrayList(ProtocolAdaptor),
    callback: OnMuxedCallback,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        secure_conn: SecureConnection,
        adaptors: *const std.ArrayList(ProtocolAdaptor),
        callback: OnMuxedCallback,
    ) !*Self {
        const session = try allocator.create(Self);
        session.* = .{
            .allocator = allocator,
            .secure_connection = secure_conn,
            .muxer_adaptors = adaptors,
            .callback = callback,
        };
        return session;
    }
    
    pub fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }
    
    pub fn start(self: *Self) !void {
        // Collect available muxer protocols
        var protocols = std.ArrayList([]const u8).init(self.allocator);
        defer protocols.deinit();
        
        for (self.muxer_adaptors.items) |adaptor| {
            try protocols.append(adaptor.protocol_id);
        }
        
        if (protocols.items.len == 0) {
            // No muxer protocols available - use simple connection
            const muxed_conn = MuxedConnection.init(self.secure_connection, "simple/1.0.0");
            self.callback(.{ .muxed_connection = muxed_conn });
            return;
        }
        
        // For now, use first available muxer protocol
        // In complete implementation, would negotiate via multistream
        const muxer_protocol = protocols.items[0];
        const muxed_conn = MuxedConnection.init(self.secure_connection, muxer_protocol);
        self.callback(.{ .muxed_connection = muxed_conn });
    }
};