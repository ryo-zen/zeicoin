// net_v2.zig - Clean networking implementation with headers-first sync
// Based on Bitcoin's headers-first protocol but simplified for ZeiCoin

const std = @import("std");
const net = std.net;
const types = @import("types.zig");
const util = @import("util.zig");
const serialize = @import("serialize.zig");

const ArrayList = std.ArrayList;
const Mutex = std.Thread.Mutex;
const Thread = std.Thread;

// Network constants
pub const DEFAULT_PORT: u16 = 10801;
pub const CLIENT_API_PORT: u16 = 10802;
pub const DISCOVERY_PORT: u16 = 10800;
pub const MAGIC_BYTES = [4]u8{ 0xF9, 0xBE, 0xB4, 0xD9 };
pub const DISCOVERY_MAGIC = [4]u8{ 0xDE, 0x11, 0xC0, 0x1E };
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024; // 32MB max
pub const MAX_PEERS: usize = 8;
pub const PROTOCOL_VERSION: u32 = 12; // v12: Headers-first sync

// Message types - simplified for headers-first
pub const MessageType = enum(u8) {
    version = 0,
    verack = 1,
    addr = 2,
    inv = 3,
    tx = 4,
    block = 5,
    getheaders = 6,
    headers = 7,
    getblock = 8,
    ping = 9,
    pong = 10,
    reject = 11,
};

// Message header (24 bytes)
pub const MessageHeader = struct {
    magic: [4]u8,
    command: [12]u8,
    length: u32,
    checksum: u32,
    
    pub fn create(msg_type: MessageType, payload_len: u32) MessageHeader {
        var command = std.mem.zeroes([12]u8);
        const type_name = @tagName(msg_type);
        @memcpy(command[0..type_name.len], type_name);
        
        return MessageHeader{
            .magic = MAGIC_BYTES,
            .command = command,
            .length = payload_len,
            .checksum = 0, // Will be set later
        };
    }
    
    pub fn setChecksum(self: *MessageHeader, payload: []const u8) void {
        self.checksum = calculateChecksum(payload);
    }
    
    pub fn calculateChecksum(payload: []const u8) u32 {
        var checksum: u32 = 0xFFFFFFFF;
        for (payload) |byte| {
            checksum = checksum ^ @as(u32, byte);
            for (0..8) |_| {
                if (checksum & 1 != 0) {
                    checksum = (checksum >> 1) ^ 0xEDB88320;
                } else {
                    checksum = checksum >> 1;
                }
            }
        }
        return checksum ^ 0xFFFFFFFF;
    }
};

// Network address
pub const NetworkAddress = struct {
    ip: []const u8,
    port: u16,
    
    pub fn format(self: NetworkAddress, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("{s}:{}", .{ self.ip, self.port });
    }
};

// Version message
pub const VersionMessage = struct {
    version: u32,
    services: u64,
    timestamp: i64,
    addr_recv: NetworkAddress,
    addr_from: NetworkAddress,
    nonce: u64,
    user_agent: []const u8,
    start_height: u32,
    relay: bool,
    
    pub fn serialize(self: VersionMessage, writer: anytype) !void {
        try writer.writeInt(u32, self.version, .little);
        try writer.writeInt(u64, self.services, .little);
        try writer.writeInt(i64, self.timestamp, .little);
        // Simplified - skip full address serialization
        try writer.writeInt(u32, self.start_height, .little);
    }
};

// Headers sync messages
pub const GetHeadersMessage = struct {
    start_height: u32,
    count: u32,
    
    pub fn serialize(self: GetHeadersMessage) [8]u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.start_height, .little);
        std.mem.writeInt(u32, buf[4..8], self.count, .little);
        return buf;
    }
    
    pub fn deserialize(data: []const u8) !GetHeadersMessage {
        if (data.len < 8) return error.InvalidMessage;
        return GetHeadersMessage{
            .start_height = std.mem.readInt(u32, data[0..4], .little),
            .count = std.mem.readInt(u32, data[4..8], .little),
        };
    }
};

pub const HeadersMessage = struct {
    start_height: u32,
    count: u32,
    
    pub fn serialize(self: HeadersMessage) [8]u8 {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.start_height, .little);
        std.mem.writeInt(u32, buf[4..8], self.count, .little);
        return buf;
    }
    
    pub fn deserialize(data: []const u8) !HeadersMessage {
        if (data.len < 8) return error.InvalidMessage;
        return HeadersMessage{
            .start_height = std.mem.readInt(u32, data[0..4], .little),
            .count = std.mem.readInt(u32, data[4..8], .little),
        };
    }
};

pub const GetBlockMessage = struct {
    height: u32,
    
    pub fn serialize(self: GetBlockMessage) [4]u8 {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.height, .little);
        return buf;
    }
    
    pub fn deserialize(data: []const u8) !GetBlockMessage {
        if (data.len < 4) return error.InvalidMessage;
        return GetBlockMessage{
            .height = std.mem.readInt(u32, data[0..4], .little),
        };
    }
};

// Peer state
pub const PeerState = enum {
    connecting,
    handshaking,
    connected,
    disconnected,
};

// Peer connection
pub const Peer = struct {
    allocator: std.mem.Allocator,
    address: NetworkAddress,
    socket: ?net.Stream,
    state: PeerState,
    version: u32,
    start_height: u32,
    last_seen: i64,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, address: NetworkAddress) Self {
        return .{
            .allocator = allocator,
            .address = address,
            .socket = null,
            .state = .disconnected,
            .version = 0,
            .start_height = 0,
            .last_seen = util.getTime(),
        };
    }
    
    pub fn connect(self: *Self) !void {
        const socket = try net.tcpConnectToHost(self.allocator, self.address.ip, self.address.port);
        self.socket = socket;
        self.state = .connecting;
        
        // Send version message
        try self.sendVersion();
        self.state = .handshaking;
    }
    
    pub fn disconnect(self: *Self) void {
        if (self.socket) |socket| {
            socket.close();
            self.socket = null;
        }
        self.state = .disconnected;
    }
    
    fn sendVersion(self: *Self) !void {
        const msg = VersionMessage{
            .version = PROTOCOL_VERSION,
            .services = 0,
            .timestamp = util.getTime(),
            .addr_recv = self.address,
            .addr_from = NetworkAddress{ .ip = "127.0.0.1", .port = DEFAULT_PORT },
            .nonce = std.crypto.random.int(u64),
            .user_agent = "ZeiCoin/0.1",
            .start_height = 0, // Will be set by blockchain
            .relay = true,
        };
        
        // Simplified sending - would need proper serialization
        const header = MessageHeader.create(.version, 100); // Approximate size
        try self.sendMessage(header, msg);
    }
    
    pub fn sendMessage(self: *Self, header: MessageHeader, payload: anytype) !void {
        if (self.socket == null) return error.NotConnected;
        
        // Send header
        try self.socket.?.writer().writeStruct(header);
        
        // Send payload (simplified)
        const T = @TypeOf(payload);
        if (std.meta.hasFn(T, "serialize")) {
            try payload.serialize(self.socket.?.writer());
        } else {
            try self.socket.?.writer().writeAll(payload);
        }
    }
    
    pub fn sendGetHeaders(self: *Self, start_height: u32, count: u32) !void {
        const msg = GetHeadersMessage{
            .start_height = start_height,
            .count = count,
        };
        
        const serialized = msg.serialize();
        var header = MessageHeader.create(.getheaders, serialized.len);
        header.setChecksum(&serialized);
        
        try self.sendMessage(header, serialized);
        std.debug.print("📤 Requested {} headers starting from height {}\n", .{ count, start_height });
    }
    
    pub fn sendGetBlock(self: *Self, height: u32) !void {
        const msg = GetBlockMessage{ .height = height };
        const serialized = msg.serialize();
        
        var header = MessageHeader.create(.getblock, serialized.len);
        header.setChecksum(&serialized);
        
        try self.sendMessage(header, serialized);
        std.debug.print("📤 Requested block at height {}\n", .{height});
    }
};

// Network manager
pub const NetworkManager = struct {
    allocator: std.mem.Allocator,
    peers: ArrayList(Peer),
    peers_mutex: Mutex,
    blockchain: ?*anyopaque, // Will be *ZeiCoin
    server_thread: ?Thread,
    discovery_thread: ?Thread,
    is_running: bool,
    port: u16,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .peers = ArrayList(Peer).init(allocator),
            .peers_mutex = Mutex{},
            .blockchain = null,
            .server_thread = null,
            .discovery_thread = null,
            .is_running = false,
            .port = DEFAULT_PORT,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.shutdown();
        
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        for (self.peers.items) |*peer| {
            peer.disconnect();
        }
        self.peers.deinit();
    }
    
    pub fn setBlockchain(self: *Self, blockchain: *anyopaque) void {
        self.blockchain = blockchain;
    }
    
    pub fn start(self: *Self, port: u16) !void {
        self.port = port;
        self.is_running = true;
        
        // Start server thread
        self.server_thread = try Thread.spawn(.{}, serverLoop, .{self});
        
        // Start discovery thread
        self.discovery_thread = try Thread.spawn(.{}, discoveryLoop, .{self});
        
        std.debug.print("🌐 Network started on port {}\n", .{port});
    }
    
    pub fn shutdown(self: *Self) void {
        self.is_running = false;
        
        if (self.server_thread) |thread| {
            thread.join();
            self.server_thread = null;
        }
        
        if (self.discovery_thread) |thread| {
            thread.join();
            self.discovery_thread = null;
        }
    }
    
    pub fn connectToPeer(self: *Self, address: NetworkAddress) !void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        // Check if already connected
        for (self.peers.items) |peer| {
            if (std.mem.eql(u8, peer.address.ip, address.ip) and 
                peer.address.port == address.port) {
                return;
            }
        }
        
        var peer = Peer.init(self.allocator, address);
        try peer.connect();
        try self.peers.append(peer);
        
        std.debug.print("✅ Connected to peer {}\n", .{address});
    }
    
    pub fn broadcastTransaction(self: *Self, tx: types.Transaction) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        for (self.peers.items) |*peer| {
            if (peer.state == .connected) {
                // Send transaction
                const header = MessageHeader.create(.tx, 0); // Size calculated later
                peer.sendMessage(header, tx) catch |err| {
                    std.debug.print("❌ Failed to send tx to peer: {}\n", .{err});
                };
            }
        }
    }
    
    pub fn broadcastBlock(self: *Self, block: types.Block) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        for (self.peers.items) |*peer| {
            if (peer.state == .connected) {
                // Send block
                const header = MessageHeader.create(.block, 0); // Size calculated later
                peer.sendMessage(header, block) catch |err| {
                    std.debug.print("❌ Failed to send block to peer: {}\n", .{err});
                };
            }
        }
    }
    
    pub fn getConnectedPeerCount(self: *Self) usize {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected) count += 1;
        }
        return count;
    }
    
    pub fn getRandomPeer(self: *Self) ?*Peer {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        
        var connected = ArrayList(*Peer).init(self.allocator);
        defer connected.deinit();
        
        for (self.peers.items) |*peer| {
            if (peer.state == .connected) {
                connected.append(peer) catch continue;
            }
        }
        
        if (connected.items.len == 0) return null;
        
        const index = std.crypto.random.int(usize) % connected.items.len;
        return connected.items[index];
    }
    
    // Server loop - accept incoming connections
    fn serverLoop(self: *Self) void {
        const address = net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, self.port);
        const server = net.Address.listen(address, .{
            .reuse_address = true,
        }) catch |err| {
            std.debug.print("❌ Failed to start server: {}\n", .{err});
            return;
        };
        defer server.deinit();
        
        std.debug.print("🎧 Listening on port {}\n", .{self.port});
        
        while (self.is_running) {
            const conn = server.accept() catch |err| {
                if (self.is_running) {
                    std.debug.print("❌ Accept error: {}\n", .{err});
                }
                continue;
            };
            
            // Handle connection in new thread
            Thread.spawn(.{}, handleConnection, .{ self, conn }) catch |err| {
                std.debug.print("❌ Failed to spawn handler thread: {}\n", .{err});
                conn.stream.close();
            };
        }
    }
    
    // Handle incoming connection
    fn handleConnection(self: *Self, conn: net.Server.Connection) void {
        defer conn.stream.close();
        
        const peer_address = conn.address;
        std.debug.print("📥 New connection from {}\n", .{peer_address});
        
        // Simple message loop
        var buffer: [MAX_MESSAGE_SIZE]u8 = undefined;
        while (self.is_running) {
            // Read header
            const header_bytes = conn.stream.reader().readBytesNoEof(@sizeOf(MessageHeader)) catch break;
            const header = std.mem.bytesToValue(MessageHeader, &header_bytes);
            
            // Validate magic
            if (!std.mem.eql(u8, &header.magic, &MAGIC_BYTES)) {
                std.debug.print("❌ Invalid magic bytes\n", .{});
                break;
            }
            
            // Read payload
            if (header.length > MAX_MESSAGE_SIZE) {
                std.debug.print("❌ Message too large: {}\n", .{header.length});
                break;
            }
            
            const payload = buffer[0..header.length];
            conn.stream.reader().readNoEof(payload) catch break;
            
            // Verify checksum
            if (header.checksum != MessageHeader.calculateChecksum(payload)) {
                std.debug.print("❌ Invalid checksum\n", .{});
                continue;
            }
            
            // Handle message
            self.handleMessage(conn.stream, header, payload);
        }
    }
    
    // Handle incoming message
    fn handleMessage(self: *Self, stream: net.Stream, header: MessageHeader, payload: []const u8) void {
        const command = std.mem.sliceTo(&header.command, 0);
        
        if (std.mem.eql(u8, command, "version")) {
            self.handleVersion(stream, payload);
        } else if (std.mem.eql(u8, command, "verack")) {
            self.handleVerack(stream);
        } else if (std.mem.eql(u8, command, "getheaders")) {
            self.handleGetHeaders(stream, payload);
        } else if (std.mem.eql(u8, command, "headers")) {
            self.handleHeaders(payload);
        } else if (std.mem.eql(u8, command, "getblock")) {
            self.handleGetBlock(stream, payload);
        } else if (std.mem.eql(u8, command, "block")) {
            self.handleBlock(payload);
        } else if (std.mem.eql(u8, command, "tx")) {
            self.handleTransaction(payload);
        } else if (std.mem.eql(u8, command, "ping")) {
            self.handlePing(stream);
        } else {
            std.debug.print("📥 Unknown command: {s}\n", .{command});
        }
    }
    
    // Message handlers
    fn handleVersion(self: *Self, stream: net.Stream, payload: []const u8) void {
        _ = self;
        _ = payload;
        // Send verack
        const header = MessageHeader.create(.verack, 0);
        stream.writer().writeStruct(header) catch return;
        
        std.debug.print("📤 Sent verack\n", .{});
    }
    
    fn handleVerack(self: *Self, stream: net.Stream) void {
        _ = self;
        _ = stream;
        std.debug.print("📥 Received verack - handshake complete\n", .{});
    }
    
    fn handleGetHeaders(self: *Self, stream: net.Stream, payload: []const u8) void {
        _ = stream; // TODO: Will be used to send response
        const msg = GetHeadersMessage.deserialize(payload) catch {
            std.debug.print("❌ Invalid getheaders message\n", .{});
            return;
        };
        
        // Limit check
        if (msg.count > types.HEADERS_SYNC.MAX_HEADERS_PER_MESSAGE) {
            std.debug.print("❌ Headers request too large: {}\n", .{msg.count});
            return;
        }
        
        // Get headers from blockchain
        if (self.blockchain) |bc| {
            // This will need to be implemented in main.zig
            _ = bc;
            std.debug.print("📥 GetHeaders request: {} headers from height {}\n", .{ msg.count, msg.start_height });
            
            // TODO: Get headers and send response
        }
    }
    
    fn handleHeaders(self: *Self, payload: []const u8) void {
        const msg = HeadersMessage.deserialize(payload[0..8]) catch {
            std.debug.print("❌ Invalid headers message\n", .{});
            return;
        };
        
        std.debug.print("📥 Received {} headers starting at height {}\n", .{ msg.count, msg.start_height });
        
        // Forward to blockchain
        if (self.blockchain) |bc| {
            // This will need to be implemented in main.zig
            _ = bc;
            const headers_data = payload[8..];
            _ = headers_data;
            // TODO: Process headers
        }
    }
    
    fn handleGetBlock(self: *Self, stream: net.Stream, payload: []const u8) void {
        const msg = GetBlockMessage.deserialize(payload) catch {
            std.debug.print("❌ Invalid getblock message\n", .{});
            return;
        };
        
        std.debug.print("📥 GetBlock request for height {}\n", .{msg.height});
        
        if (self.blockchain) |bc| {
            // TODO: Get block and send
            _ = bc;
            _ = stream;
        }
    }
    
    fn handleBlock(self: *Self, payload: []const u8) void {
        _ = self;
        _ = payload;
        std.debug.print("📥 Received block\n", .{});
        // TODO: Process block
    }
    
    fn handleTransaction(self: *Self, payload: []const u8) void {
        _ = self;
        _ = payload;
        std.debug.print("📥 Received transaction\n", .{});
        // TODO: Process transaction
    }
    
    fn handlePing(self: *Self, stream: net.Stream) void {
        _ = self;
        // Send pong
        const header = MessageHeader.create(.pong, 0);
        stream.writer().writeStruct(header) catch return;
    }
    
    // Discovery loop - find peers via UDP
    fn discoveryLoop(self: *Self) void {
        const socket = std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, DISCOVERY_PORT).listen(.{
            .reuse_address = true,
        }) catch return;
        defer socket.deinit();
        
        std.debug.print("🔍 Discovery listening on UDP port {}\n", .{DISCOVERY_PORT});
        
        // Simple discovery - would need proper implementation
        while (self.is_running) {
            std.time.sleep(30 * std.time.ns_per_s); // Check every 30 seconds
        }
    }
};

// Tests
test "Message header creation" {
    const header = MessageHeader.create(.version, 100);
    try std.testing.expectEqualSlices(u8, &header.magic, &MAGIC_BYTES);
    try std.testing.expectEqual(@as(u32, 100), header.length);
}

test "GetHeaders serialization" {
    const msg = GetHeadersMessage{
        .start_height = 1000,
        .count = 2000,
    };
    
    const serialized = msg.serialize();
    try std.testing.expectEqual(@as(usize, 8), serialized.len);
    
    const deserialized = try GetHeadersMessage.deserialize(&serialized);
    try std.testing.expectEqual(msg.start_height, deserialized.start_height);
    try std.testing.expectEqual(msg.count, deserialized.count);
}

test "Checksum calculation" {
    const data = "Hello, ZeiCoin!";
    const checksum1 = MessageHeader.calculateChecksum(data);
    const checksum2 = MessageHeader.calculateChecksum(data);
    try std.testing.expectEqual(checksum1, checksum2);
    
    const different = "Different data";
    const checksum3 = MessageHeader.calculateChecksum(different);
    try std.testing.expect(checksum1 != checksum3);
}