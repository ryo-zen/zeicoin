// upgrade_session.zig - Complete connection upgrade session
// Orchestrates the full upgrade pipeline: Raw -> Layer -> Secure -> Muxed
// Based on C++ libp2p UpgraderSession implementation

const std = @import("std");
const upgrader = @import("connection_upgrader.zig");
const libp2p = @import("../libp2p_internal.zig");

/// Result of complete upgrade session
pub const SessionResult = union(enum) {
    success: upgrader.MuxedConnection,
    failure: anyerror,
};

/// Callback for complete session
pub const SessionCallback = *const fn (result: SessionResult) void;

/// Complete upgrade session that manages the full pipeline
pub const UpgradeSession = struct {
    allocator: std.mem.Allocator,
    upgrader_impl: *upgrader.Upgrader,
    layer_protocols: []const []const u8,
    raw_connection: upgrader.RawConnection,
    session_callback: SessionCallback,
    
    // Session state
    current_stage: upgrader.ConnectionType,
    layer_connection: ?upgrader.LayerConnection,
    secure_connection: ?upgrader.SecureConnection,
    muxed_connection: ?upgrader.MuxedConnection,
    
    // Remote peer info (for outbound)
    remote_peer_id: ?[]const u8,
    remote_address: ?*const libp2p.Multiaddr,
    is_initiator: bool,
    
    const Self = @This();
    
    pub fn init(
        allocator: std.mem.Allocator,
        upgrader_impl: *upgrader.Upgrader,
        layer_protocols: []const []const u8,
        raw_connection: upgrader.RawConnection,
        callback: SessionCallback,
    ) !*Self {
        const session = try allocator.create(Self);
        session.* = .{
            .allocator = allocator,
            .upgrader_impl = upgrader_impl,
            .layer_protocols = layer_protocols,
            .raw_connection = raw_connection,
            .session_callback = callback,
            .current_stage = .Raw,
            .layer_connection = null,
            .secure_connection = null,
            .muxed_connection = null,
            .remote_peer_id = null,
            .remote_address = null,
            .is_initiator = false,
        };
        return session;
    }
    
    pub fn deinit(self: *Self) void {
        // Clean up any intermediate connections
        if (self.muxed_connection) |*conn| {
            conn.deinit();
        } else if (self.secure_connection) |*conn| {
            conn.deinit();
        } else if (self.layer_connection) |*conn| {
            conn.deinit();
        }
        
        self.allocator.destroy(self);
    }
    
    /// Start inbound upgrade (responding to incoming connection)
    pub fn upgradeInbound(self: *Self) !void {
        self.is_initiator = false;
        
        if (self.layer_protocols.len == 0) {
            // No layer protocols - go directly to security
            try self.secureInbound(self.raw_connection);
        } else {
            // Upgrade through layer protocols first
            try self.upgrader_impl.upgradeLayersInbound(
                self.raw_connection,
                self.layer_protocols,
                onLayersUpgraded,
            );
        }
    }
    
    /// Start outbound upgrade (initiating connection)
    pub fn upgradeOutbound(
        self: *Self,
        address: *const libp2p.Multiaddr,
        remote_peer_id: []const u8,
    ) !void {
        self.is_initiator = true;
        self.remote_address = address;
        self.remote_peer_id = remote_peer_id;
        
        if (self.layer_protocols.len == 0) {
            // No layer protocols - go directly to security
            const layer_conn = upgrader.LayerConnection.init(self.raw_connection, self.allocator);
            try self.secureOutbound(layer_conn, remote_peer_id);
        } else {
            // Upgrade through layer protocols first
            try self.upgrader_impl.upgradeLayersOutbound(
                address,
                self.raw_connection,
                self.layer_protocols,
                onLayersUpgraded,
            );
        }
    }
    
    /// Called when layer upgrade completes
    fn onLayersUpgraded(result: upgrader.UpgradeResult) void {
        // Note: In real implementation, we'd need to properly pass session context
        // For now, this demonstrates the callback structure
        switch (result) {
            .layer_connection => |layer_conn| {
                // Move to security upgrade
                // self.secureInbound(layer_conn) or self.secureOutbound(layer_conn, peer_id)
                _ = layer_conn;
            },
            .failure => |err| {
                // Complete session with error
                std.log.err("Upgrade failed: {}", .{err});
            },
            else => {
                // Unexpected result type
            },
        }
    }
    
    /// Upgrade layer connection to secure (inbound)
    fn secureInbound(self: *Self, raw_conn: upgrader.RawConnection) !void {
        // Convert raw to layer connection
        const layer_conn = upgrader.LayerConnection.init(raw_conn, self.allocator);
        self.layer_connection = layer_conn;
        self.current_stage = .Layer;
        
        // Start security upgrade
        try self.upgrader_impl.upgradeToSecureInbound(
            layer_conn,
            onSecured,
        );
    }
    
    /// Upgrade layer connection to secure (outbound)
    fn secureOutbound(
        self: *Self,
        layer_conn: upgrader.LayerConnection,
        remote_peer_id: []const u8,
    ) !void {
        self.layer_connection = layer_conn;
        self.current_stage = .Layer;
        
        // Start security upgrade
        try self.upgrader_impl.upgradeToSecureOutbound(
            layer_conn,
            remote_peer_id,
            onSecured,
        );
    }
    
    /// Called when security upgrade completes
    fn onSecured(result: upgrader.UpgradeResult) void {
        switch (result) {
            .secure_connection => |secure_conn| {
                // Move to muxer upgrade
                // self.onSecuredComplete(secure_conn)
                _ = secure_conn;
            },
            .failure => |err| {
                // Complete session with error
                std.log.err("Upgrade failed: {}", .{err});
            },
            else => {
                // Unexpected result type
            },
        }
    }
    
    /// Complete the security stage and move to muxing
    fn onSecuredComplete(self: *Self, secure_conn: upgrader.SecureConnection) !void {
        self.secure_connection = secure_conn;
        self.current_stage = .Secure;
        
        // Start muxer upgrade
        try self.upgrader_impl.upgradeToMuxed(
            secure_conn,
            onMuxed,
        );
    }
    
    /// Called when muxer upgrade completes
    fn onMuxed(result: upgrader.UpgradeResult) void {
        switch (result) {
            .muxed_connection => |muxed_conn| {
                // Complete session successfully
                // self.completeSession(muxed_conn)
                _ = muxed_conn;
            },
            .failure => |err| {
                // Complete session with error
                std.log.err("Upgrade failed: {}", .{err});
            },
            else => {
                // Unexpected result type
            },
        }
    }
    
    /// Complete the session successfully
    fn completeSession(self: *Self, muxed_conn: upgrader.MuxedConnection) void {
        self.muxed_connection = muxed_conn;
        self.current_stage = .Muxed;
        
        // Call session callback
        self.session_callback(.{ .success = muxed_conn });
    }
    
    /// Complete the session with error
    fn completeWithError(self: *Self, err: anyerror) void {
        self.session_callback(.{ .failure = err });
    }
};

/// Factory function to create and start inbound upgrade session
pub fn createInboundSession(
    allocator: std.mem.Allocator,
    upgrader_impl: *upgrader.Upgrader,
    layer_protocols: []const []const u8,
    raw_connection: upgrader.RawConnection,
    callback: SessionCallback,
) !*UpgradeSession {
    const session = try UpgradeSession.init(
        allocator,
        upgrader_impl,
        layer_protocols,
        raw_connection,
        callback,
    );
    
    try session.upgradeInbound();
    return session;
}

/// Factory function to create and start outbound upgrade session  
pub fn createOutboundSession(
    allocator: std.mem.Allocator,
    upgrader_impl: *upgrader.Upgrader,
    layer_protocols: []const []const u8,
    raw_connection: upgrader.RawConnection,
    address: *const libp2p.Multiaddr,
    remote_peer_id: []const u8,
    callback: SessionCallback,
) !*UpgradeSession {
    const session = try UpgradeSession.init(
        allocator,
        upgrader_impl,
        layer_protocols,
        raw_connection,
        callback,
    );
    
    try session.upgradeOutbound(address, remote_peer_id);
    return session;
}