// handshake.zig - Initial handshake message
// Establishes protocol version and node capabilities

const std = @import("std");
const protocol = @import("../protocol.zig");
const types = @import("../../../types/types.zig");

pub const HandshakeMessage = struct {
    /// Protocol version
    version: u16,
    /// Services this node provides
    services: u64,
    /// Current time
    timestamp: i64,
    /// Our listening port (0 if not accepting connections)
    listen_port: u16,
    /// Random nonce to detect self-connections
    nonce: u64,
    /// User agent string
    user_agent: []const u8,
    /// Our current blockchain height
    start_height: u32,
    /// Network ID to prevent cross-network connections
    network_id: u32,
    
    const Self = @This();
    const MAX_USER_AGENT_LEN = 256;
    
    pub fn init(allocator: std.mem.Allocator, user_agent: []const u8) !Self {
        const agent_copy = try allocator.dupe(u8, user_agent[0..@min(user_agent.len, MAX_USER_AGENT_LEN)]);
        
        return Self{
            .version = protocol.PROTOCOL_VERSION,
            .services = protocol.ServiceFlags.NETWORK | protocol.ServiceFlags.HEADERS_FIRST,
            .timestamp = std.time.timestamp(),
            .listen_port = 0, // Set by caller if listening
            .nonce = std.crypto.random.int(u64),
            .user_agent = agent_copy,
            .start_height = 0, // Set by caller
            .network_id = types.CURRENT_NETWORK.getNetworkId(),
        };
    }
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.user_agent);
    }
    
    pub fn encode(self: Self, writer: anytype) !void {
        try writer.writeInt(u16, self.version, .little);
        try writer.writeInt(u64, self.services, .little);
        try writer.writeInt(i64, self.timestamp, .little);
        try writer.writeInt(u16, self.listen_port, .little);
        try writer.writeInt(u64, self.nonce, .little);
        
        // Write user agent with length prefix
        try writer.writeInt(u16, @intCast(self.user_agent.len), .little);
        try writer.writeAll(self.user_agent);
        
        try writer.writeInt(u32, self.start_height, .little);
        try writer.writeInt(u32, self.network_id, .little);
    }
    
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Self {
        const version = try reader.readInt(u16, .little);
        const services = try reader.readInt(u64, .little);
        const timestamp = try reader.readInt(i64, .little);
        const listen_port = try reader.readInt(u16, .little);
        const nonce = try reader.readInt(u64, .little);
        
        // Read user agent
        const agent_len = try reader.readInt(u16, .little);
        if (agent_len > MAX_USER_AGENT_LEN) {
            return error.UserAgentTooLong;
        }
        
        const user_agent = try allocator.alloc(u8, agent_len);
        errdefer allocator.free(user_agent);
        try reader.readNoEof(user_agent);
        
        const start_height = try reader.readInt(u32, .little);
        const network_id = try reader.readInt(u32, .little);
        
        return Self{
            .version = version,
            .services = services,
            .timestamp = timestamp,
            .listen_port = listen_port,
            .nonce = nonce,
            .user_agent = user_agent,
            .start_height = start_height,
            .network_id = network_id,
        };
    }
    
    pub fn estimateSize(self: Self) usize {
        return 2 + 8 + 8 + 2 + 8 + // Fixed fields
            2 + self.user_agent.len + // User agent
            4 + 4; // Height and network
    }
    
    /// Check if this node supports a specific service
    pub fn hasService(self: Self, service: u64) bool {
        return (self.services & service) != 0;
    }
    
    /// Validate handshake for compatibility
    pub fn validate(self: Self) !void {
        // Check protocol version
        if (self.version > protocol.PROTOCOL_VERSION) {
            return error.IncompatibleProtocolVersion;
        }
        
        // Check network ID
        if (self.network_id != types.CURRENT_NETWORK.getNetworkId()) {
            return error.WrongNetwork;
        }
        
        // Basic service validation
        if (self.services & protocol.ServiceFlags.NETWORK == 0) {
            return error.NotAFullNode;
        }
    }
};

// Tests
test "HandshakeMessage encode/decode" {
    const allocator = std.testing.allocator;
    
    var msg = try HandshakeMessage.init(allocator, "ZeiCoin/1.0.0");
    defer msg.deinit(allocator);
    
    msg.listen_port = 10801;
    msg.start_height = 12345;
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try msg.encode(buffer.writer());
    
    var stream = std.io.fixedBufferStream(buffer.items);
    var decoded = try HandshakeMessage.decode(allocator, stream.reader());
    defer decoded.deinit(allocator);
    
    try std.testing.expectEqual(msg.version, decoded.version);
    try std.testing.expectEqual(msg.services, decoded.services);
    try std.testing.expectEqual(msg.listen_port, decoded.listen_port);
    try std.testing.expectEqual(msg.start_height, decoded.start_height);
    try std.testing.expectEqualStrings(msg.user_agent, decoded.user_agent);
    
    // Validate the decoded message
    try decoded.validate();
}