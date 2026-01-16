// peer_manager.zig - Modular peer management system
// Handles peer connections, discovery, and lifecycle

const std = @import("std");
const net = std.net;
const protocol = @import("protocol/protocol.zig");
const wire = @import("wire/wire.zig");
const message_types = @import("protocol/messages/message_types.zig");
const message_envelope = @import("protocol/message_envelope.zig");
const types = @import("../types/types.zig");

const ArrayList = std.ArrayList;
const Mutex = std.Thread.Mutex;

/// Peer connection state
pub const PeerState = enum {
    connecting,
    handshaking,
    connected,
    syncing,
    disconnecting,
    disconnected,

    /// Format peer state for cleaner logging
    pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        const state_str = switch (self) {
            .connecting => "connecting",
            .handshaking => "handshaking",
            .connected => "connected",
            .syncing => "syncing",
            .disconnecting => "disconnecting",
            .disconnected => "disconnected",
        };
        try writer.writeAll(state_str);
    }
};

/// Individual peer connection
pub const Peer = struct {
    allocator: std.mem.Allocator,
    id: u64,
    address: net.Address,
    state: PeerState,
    connection: wire.WireConnection,

    // Peer info from handshake
    version: u16,
    services: u64,
    height: u32,
    user_agent: []const u8,
    best_block_hash: [32]u8,

    // Connection management
    last_ping: i64,
    last_recv: i64,
    ping_nonce: ?u64,

    // Sync state
    syncing: bool,
    headers_requested: bool,

    // ZSP-001 Performance tracking
    ping_time_ms: u32,
    consecutive_successful_requests: u32,
    consecutive_failures: u32,

    // Failure metadata for reconnection logic
    last_failed_at: i64,
    failure_reason: ?[]const u8,
    retry_allowed_after: i64,

    // TCP send callback
    tcp_send_fn: ?*const fn (ctx: ?*anyopaque, data: []const u8) anyerror!void,
    tcp_send_ctx: ?*anyopaque,

    // Shutdown synchronization
    is_shutting_down: std.atomic.Value(bool),

    // Response queues for synchronous request/response patterns (fork detection)
    // These are used by fork_detector.zig to wait for specific responses
    block_hash_responses: std.AutoHashMap(u32, BlockHashResponse),  // height -> response
    chain_work_response: ?types.ChainWork,  // Latest chain work response
    
    // Block caches for synchronous requests (ZSP-001)
    received_blocks: std.AutoHashMap([32]u8, types.Block),          // hash -> block
    received_blocks_by_height: std.AutoHashMap(u32, types.Block),   // height -> block
    
    response_mutex: std.Thread.Mutex,  // Protects response queues and block caches
    
    // Reference counting for thread-safe peer lifecycle
    ref_count: std.atomic.Value(u32),

    const Self = @This();

    /// Block hash response for fork detection
    pub const BlockHashResponse = struct {
        hash: types.Hash,
        exists: bool,
        timestamp: i64,
    };

    pub fn init(allocator: std.mem.Allocator, id: u64, address: net.Address) Self {
        return .{
            .allocator = allocator,
            .id = id,
            .address = address,
            .state = .connecting,
            .connection = wire.WireConnection.init(allocator),
            .version = 0,
            .services = 0,
            .height = 0,
            .user_agent = &[_]u8{},
            .best_block_hash = [_]u8{0} ** 32,
            .last_ping = std.time.timestamp(),
            .last_recv = std.time.timestamp(),
            .ping_nonce = null,
            .syncing = false,
            .headers_requested = false,
            .ping_time_ms = 0,
            .consecutive_successful_requests = 0,
            .consecutive_failures = 0,
            .last_failed_at = 0,
            .failure_reason = null,
            .retry_allowed_after = 0,
            .tcp_send_fn = null,
            .tcp_send_ctx = null,
            .is_shutting_down = std.atomic.Value(bool).init(false),
            .block_hash_responses = std.AutoHashMap(u32, BlockHashResponse).init(allocator),
            .chain_work_response = null,
            .received_blocks = std.AutoHashMap([32]u8, types.Block).init(allocator),
            .received_blocks_by_height = std.AutoHashMap(u32, types.Block).init(allocator),
            .response_mutex = std.Thread.Mutex{},
            .ref_count = std.atomic.Value(u32).init(1),
        };
    }

    pub fn deinit(self: *Self) void {
        // Signal shutdown to connection threads
        self.is_shutting_down.store(true, .release);

        // Give threads a moment to notice the shutdown flag
        std.time.sleep(10 * std.time.ns_per_ms);

        if (self.user_agent.len > 0) {
            self.allocator.free(self.user_agent);
        }

        // Clean up response queues and block caches
        self.block_hash_responses.deinit();
        
        // Properly deinit all cached blocks
        var block_it = self.received_blocks.iterator();
        while (block_it.next()) |entry| {
            var mutable_block = entry.value_ptr.*;
            mutable_block.deinit(self.allocator);
        }
        self.received_blocks.deinit();
        self.received_blocks_by_height.deinit(); // Blocks are same as above, don't double-deinit

        self.connection.deinit();
    }

    /// Send a message to this peer
    pub fn sendMessage(self: *Self, msg_type: protocol.MessageType, msg: anytype) ![]const u8 {
        const result = try self.connection.sendMessage(msg_type, msg);

        // If we have a TCP send callback, use it to actually send the data
        self.response_mutex.lock();
        const send_fn = self.tcp_send_fn;
        const send_ctx = self.tcp_send_ctx;
        self.response_mutex.unlock();

        if (send_fn) |f| {
            try f(send_ctx, result);
        }

        return result;
    }

    /// Set TCP send callback
    pub fn setTcpSendCallback(self: *Self, send_fn: ?*const fn (ctx: ?*anyopaque, data: []const u8) anyerror!void, ctx: ?*anyopaque) void {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();
        self.tcp_send_fn = send_fn;
        self.tcp_send_ctx = ctx;
    }

    /// Process received data
    pub fn receiveData(self: *Self, data: []const u8) !void {
        // Check if we're shutting down before accessing connection
        if (self.is_shutting_down.load(.acquire)) {
            return error.PeerShuttingDown;
        }
        
        self.last_recv = std.time.timestamp();
        try self.connection.receiveData(data);
    }

    /// Try to read next message
    pub fn readMessage(self: *Self) !?message_envelope.MessageEnvelope {
        // Check if we're shutting down before accessing connection
        if (self.is_shutting_down.load(.acquire)) {
            return null; // Return null to stop message processing
        }
        
        const result = try self.connection.readMessage();
        if (result) |_| {
            self.last_recv = std.time.timestamp();
        }
        return result;
    }

    /// Check if peer needs ping
    pub fn needsPing(self: Self) bool {
        const now = std.time.timestamp();
        return (now - self.last_ping) > protocol.PING_INTERVAL_SECONDS;
    }

    /// Check if peer timed out
    pub fn isTimedOut(self: Self) bool {
        const now = std.time.timestamp();
        const timeout_result = (now - self.last_recv) > protocol.CONNECTION_TIMEOUT_SECONDS;
        return timeout_result;
    }

    /// Queue a block hash response (called by message handlers)
    pub fn queueBlockHashResponse(self: *Self, height: u32, hash: types.Hash, exists: bool) !void {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        try self.block_hash_responses.put(height, BlockHashResponse{
            .hash = hash,
            .exists = exists,
            .timestamp = std.time.timestamp(),
        });
    }

    /// Get a block hash response if available (non-blocking)
    pub fn getBlockHashResponse(self: *Self, height: u32) ?BlockHashResponse {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        return self.block_hash_responses.get(height);
    }

    /// Remove a block hash response after consuming it
    pub fn removeBlockHashResponse(self: *Self, height: u32) void {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        _ = self.block_hash_responses.remove(height);
    }

    /// Queue a chain work response (called by message handlers)
    pub fn queueChainWorkResponse(self: *Self, work: types.ChainWork) void {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        self.chain_work_response = work;
    }

    /// Get and consume the chain work response
    pub fn getChainWorkResponse(self: *Self) ?types.ChainWork {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        const work = self.chain_work_response;
        self.chain_work_response = null;  // Clear after reading
        return work;
    }

    /// Add a block to the received blocks cache
    pub fn addReceivedBlock(self: *Self, block: types.Block) !void {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        const hash = block.hash();
        
        // Deep copy block to ensure ownership in cache
        const block_copy = try block.clone(self.allocator);
        
        // Remove existing block if any to prevent leaks
        if (self.received_blocks.get(hash)) |old_block| {
            var mutable_old = old_block;
            mutable_old.deinit(self.allocator);
        }

        try self.received_blocks.put(hash, block_copy);
        try self.received_blocks_by_height.put(block.height, block_copy);
    }

    /// Get a received block by hash and remove it from cache
    pub fn getReceivedBlock(self: *Self, hash: [32]u8) ?types.Block {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        if (self.received_blocks.get(hash)) |block| {
            _ = self.received_blocks.remove(hash);
            _ = self.received_blocks_by_height.remove(block.height);
            return block;
        }
        return null;
    }

    /// Get a received block by height and remove it from cache
    pub fn getReceivedBlockByHeight(self: *Self, height: u32) ?types.Block {
        self.response_mutex.lock();
        defer self.response_mutex.unlock();

        if (self.received_blocks_by_height.get(height)) |block| {
            const hash = block.hash();
            _ = self.received_blocks.remove(hash);
            _ = self.received_blocks_by_height.remove(height);
            return block;
        }
        return null;
    }

    /// Increment reference count
    pub fn addRef(self: *Self) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    /// Decrement reference count and cleanup if zero
    pub fn release(self: *Self) void {
        const old_count = self.ref_count.fetchSub(1, .acq_rel);
        if (old_count == 1) {
            const allocator = self.allocator;
            self.deinit();
            allocator.destroy(self);
        }
    }

    /// Check if peer is connected and ready for requests
    pub fn isConnected(self: Self) bool {
        return self.state == .connected or self.state == .syncing;
    }

    /// Send request for specific block by hash
    pub fn sendGetBlockByHash(self: *Self, hash: [32]u8) !void {
        const hashes = [_][32]u8{hash};
        var msg = try message_types.GetBlocksMessage.init(self.allocator, &hashes);
        defer msg.deinit(self.allocator);

        _ = try self.sendMessage(.get_blocks, msg);
    }

    /// Send ZSP-001 compliant request for specific block by height
    /// Uses height encoding with 0xDEADBEEF magic marker for backward compatibility
    pub fn sendGetBlockByHeight(self: *Self, height: u32) !void {

        // ZSP-001 SPECIFICATION: Height-Encoded Block Requests
        // For height-based requests, we encode the height as a 32-byte hash using the
        // ZSP-001 specification format for backward compatibility with hash-based requests:
        //
        // Bytes 0-3:   Height (little-endian u32)
        // Bytes 4-7:   Magic marker 0xDEADBEEF (ZSP-001 identifier)
        // Bytes 8-31:  Zero padding
        //
        // This encoding allows peers to distinguish between real block hashes and
        // height-based requests while maintaining protocol compatibility.

        var height_hash: [32]u8 = [_]u8{0} ** 32;

        // Encode height in first 4 bytes (ZSP-001 format)
        std.mem.writeInt(u32, height_hash[0..4], height, .little);

        // Set ZSP-001 magic marker in bytes 4-8 to indicate height-encoded request
        const ZSP_001_HEIGHT_MAGIC: u32 = 0xDEADBEEF;
        std.mem.writeInt(u32, height_hash[4..8], ZSP_001_HEIGHT_MAGIC, .little);

        // Remaining bytes stay zero as per ZSP-001 specification

        // Send as single-item GetBlocksMessage
        var hashes = [_][32]u8{height_hash};
        var msg = try message_types.GetBlocksMessage.init(self.allocator, &hashes);
        defer msg.deinit(self.allocator);

        _ = try self.sendMessage(.get_blocks, msg);
    }

    /// Send ZSP-001 compliant request for multiple blocks (batch sync)
    /// Supports both hash-based and height-encoded requests in the same batch
    pub fn sendGetBlocks(self: *Self, hashes: []const [32]u8) !void {
        std.log.info("📤 [SEND GET_BLOCKS] ============================================", .{});
        std.log.info("📤 [SEND GET_BLOCKS] Peer {d} sending GetBlocks message", .{self.id});
        std.log.info("📤 [SEND GET_BLOCKS] Number of hashes: {d}", .{hashes.len});
        if (hashes.len > 0) {
            std.log.info("📤 [SEND GET_BLOCKS] First hash: {s}...{s}", .{
                std.fmt.fmtSliceHexLower(hashes[0][0..4]),
                std.fmt.fmtSliceHexLower(hashes[0][4..8]),
            });
        }

        // Create and send the batch message
        var msg = try message_types.GetBlocksMessage.init(self.allocator, hashes);
        defer msg.deinit(self.allocator);

        std.log.info("📤 [SEND GET_BLOCKS] Calling sendMessage with .get_blocks type", .{});
        const bytes_sent = try self.sendMessage(.get_blocks, msg);
        std.log.info("📤 [SEND GET_BLOCKS] ✅ Message sent successfully ({d} bytes)", .{bytes_sent});
        std.log.info("📤 [SEND GET_BLOCKS] ============================================", .{});
    }

    /// Request specific blocks by hash (Fix 3: Orphan block resolution)
    /// Used for targeted missing block requests during orphan processing
    pub fn requestMissingBlocks(self: *Self, block_hashes: []const [32]u8) !void {
        if (block_hashes.len == 0) return;

        const log = std.log.scoped(.network);
        log.info("📥 [REQUEST] Requesting {} missing block(s) from peer {}", .{
            block_hashes.len,
            self.id,
        });

        var msg = message_types.GetMissingBlocksMessage.init(self.allocator);
        defer msg.deinit(self.allocator);

        // Add each hash to request (up to MAX_MISSING_BLOCKS)
        for (block_hashes) |hash| {
            try msg.addHash(hash);
            log.debug("   Requesting: {s}", .{std.fmt.fmtSliceHexLower(&hash)});
        }

        // Send message
        _ = try self.sendMessage(.get_missing_blocks, msg);

        log.info("✅ [REQUEST] Missing blocks request sent", .{});
    }

    /// Send request for headers using block locator pattern
    pub fn sendGetHeaders(self: *Self, start_height: u32, count: u32) !void {
        _ = count; // For future use

        var locator = std.ArrayList([32]u8).init(self.allocator);
        defer locator.deinit();

        // Build a simple block locator
        // If we have a blockchain reference, use actual hashes; otherwise use genesis
        if (start_height > 0) {
            // For sync protocol, we want to start from our current height
            // Add a genesis hash as the locator - this tells the peer we need everything from genesis
            const genesis_hash = [_]u8{0} ** 32; // Genesis is always zero hash
            try locator.append(genesis_hash);
        } else {
            // Request from genesis
            const genesis_hash = [_]u8{0} ** 32;
            try locator.append(genesis_hash);
        }

        // Stop hash - zero means "send up to chain tip"
        const stop_hash = [_]u8{0} ** 32;

        var msg = try message_types.GetHeadersMessage.init(self.allocator, locator.items, stop_hash);
        defer msg.deinit(self.allocator);

        _ = try self.sendMessage(.get_headers, msg);
        std.log.info("Requested headers starting from height {} with {} locator hashes", .{ start_height, locator.items.len });
    }

    /// Send request for specific block (wrapper method)
    pub fn sendGetBlock(self: *Self, height: u32) !void {
        return self.sendGetBlockByHeight(height);
    }

    /// Check if peer supports ZSP-001 batch synchronization
    /// Based on advertised service flags during handshake
    pub fn supportsBatchSync(self: *const Self) bool {
        // Check for ZSP-001 batch sync capability flags
        const has_parallel_download = (self.services & protocol.ServiceFlags.PARALLEL_DOWNLOAD) != 0;
        const has_fast_sync = (self.services & protocol.ServiceFlags.FAST_SYNC) != 0;

        return has_parallel_download or has_fast_sync;
    }

    /// Get peer performance score for sync peer selection
    /// Used by sync manager to choose optimal peers for batch sync
    pub fn getSyncPerformanceScore(self: *const Self) f64 {
        // Base performance score
        var score: f64 = 100.0;

        // Penalize high ping times (prefer low-latency peers)
        if (self.ping_time_ms > 0) {
            const ping_penalty = @as(f64, @floatFromInt(self.ping_time_ms)) * 0.1;
            score -= ping_penalty;
        }

        // Bonus for stable connections
        if (self.consecutive_successful_requests > 10) {
            score += 20.0;
        }

        // Penalty for recent failures
        const failure_penalty = @as(f64, @floatFromInt(self.consecutive_failures)) * 5.0;
        score -= failure_penalty;

        // Bonus for batch sync capability
        if (self.supportsBatchSync()) {
            score += 50.0; // Significant bonus for ZSP-001 capability
        }

        return @max(1.0, score);
    }

    /// Update peer statistics after successful block request
    pub fn recordSuccessfulRequest(self: *Self) void {
        self.consecutive_successful_requests += 1;
        self.consecutive_failures = 0;
    }

    /// Update peer statistics after failed block request
    pub fn recordFailedRequest(self: *Self) void {
        self.consecutive_failures += 1;
        self.consecutive_successful_requests = 0;

        // Track failure timestamp and set cooldown
        self.last_failed_at = std.time.timestamp();
        self.retry_allowed_after = self.last_failed_at + 30; // 30-second cooldown
    }

    /// Check if peer can retry connection (cooldown expired)
    pub fn canRetryConnection(self: *const Self) bool {
        const now = std.time.timestamp();
        return now >= self.retry_allowed_after;
    }

    /// Check if peer should be considered for sync operations
    pub fn isEligibleForSync(self: *const Self) bool {
        // Must be connected
        if (!self.isConnected()) return false;

        // Too many recent failures
        if (self.consecutive_failures >= 5) return false;

        // High ping time threshold
        if (self.ping_time_ms > 2000) return false; // 2 second max

        return true;
    }

    /// Get human-readable peer status for debugging
    pub fn getStatusString(self: *const Self, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "Peer[{}] state:{} ping:{}ms batch:{} score:{d:.1}", .{
            self.id,
            self.state,
            self.ping_time_ms,
            self.supportsBatchSync(),
            self.getSyncPerformanceScore(),
        }) catch "status error";
    }

    /// Format peer for logging - safe version to prevent crashes
    pub fn format(self: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        
        // Safe address formatting to avoid std.net.Address crashes
        switch (self.address.any.family) {
            std.posix.AF.INET => {
                const addr = self.address.in.sa.addr;
                const port = std.mem.bigToNative(u16, self.address.in.sa.port);
                try writer.print("Peer[{}:{}.{}.{}.{}:{}:{}]", .{
                    self.id,
                    (addr >> 0) & 0xFF,
                    (addr >> 8) & 0xFF,
                    (addr >> 16) & 0xFF,
                    (addr >> 24) & 0xFF,
                    port,
                    self.state,
                });
            },
            std.posix.AF.INET6 => {
                try writer.print("Peer[{}:ipv6:{}]", .{ self.id, self.state });
            },
            else => {
                try writer.print("Peer[{}:unknown:{}]", .{ self.id, self.state });
            },
        }
    }
};

/// Peer manager handles all peer connections
pub const PeerManager = struct {
    allocator: std.mem.Allocator,
    peers: ArrayList(*Peer),
    mutex: Mutex,
    next_peer_id: u64,
    max_peers: usize,

    // Discovery
    known_addresses: ArrayList(net.Address),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_peers: usize) Self {
        return .{
            .allocator = allocator,
            .peers = ArrayList(*Peer).init(allocator),
            .mutex = .{},
            .next_peer_id = 1,
            .max_peers = max_peers,
            .known_addresses = ArrayList(net.Address).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.peers.items) |peer| {
            peer.release();
        }
        self.peers.deinit();
        self.known_addresses.deinit();
    }

    /// Stop all peer connections gracefully
    pub fn stop(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Mark all peers as disconnected
        for (self.peers.items) |peer| {
            peer.state = .disconnected;
        }
    }

    /// Add a new peer connection
    pub fn addPeer(self: *Self, address: net.Address) !*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();

        // SECURITY: Check if IP already has a connection (ignore port to prevent dual connections)
        for (self.peers.items) |peer| {
            // Compare IP addresses by converting to string representation
            const peer_ip = peer.address.getPort();
            const new_ip = address.getPort();
            _ = peer_ip;
            _ = new_ip;

            // For now, use simpler exact address matching until proper IP comparison is implemented
            if (peer.address.eql(address)) {
                return error.AlreadyConnected;
            }
        }

        // Check peer limit
        if (self.peers.items.len >= self.max_peers) {
            return error.TooManyPeers;
        }

        // Create new peer
        const peer = try self.allocator.create(Peer);
        const assigned_id = self.next_peer_id;
        peer.* = Peer.init(self.allocator, assigned_id, address);
        self.next_peer_id += 1;

        try self.peers.append(peer);

        return peer;
    }

    /// Remove a peer
    pub fn removePeer(self: *Self, peer_id: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var found = false;
        for (self.peers.items, 0..) |peer, i| {
            if (peer.id == peer_id) {
                found = true;

                // Release reference (might destroy if last reference)
                peer.release();

                _ = self.peers.orderedRemove(i);

                break;
            }
        }
    }

    /// Get peer by ID
    pub fn getPeer(self: *Self, peer_id: u64) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.peers.items) |peer| {
            if (peer.id == peer_id) {
                peer.addRef();
                return peer;
            }
        }
        return null;
    }

    /// Get all connected peers
    pub fn getConnectedPeers(self: *Self, list: *ArrayList(*Peer)) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                try list.append(peer);
            }
        }
    }

    /// Get best peer for sync (highest height)
    pub fn getBestPeerForSync(self: *Self) ?*Peer {
        self.mutex.lock();
        defer self.mutex.unlock();

        var best: ?*Peer = null;
        var best_height: u32 = 0;
        // Find best peer by height
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                if (peer.height > best_height) {
                    best = peer;
                    best_height = peer.height;
                }
            }
        }
        
        if (best) |p| p.addRef();
        return best;
    }

    /// Broadcast message to all connected peers
    pub fn broadcast(self: *Self, msg_type: protocol.MessageType, msg: anytype) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                _ = peer.sendMessage(msg_type, msg) catch {
                    continue;
                };
            }
        }
    }

    /// Add known address for discovery
    pub fn addKnownAddress(self: *Self, address: net.Address) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check if already known
        for (self.known_addresses.items) |known| {
            if (known.eql(address)) {
                return;
            }
        }

        try self.known_addresses.append(address);
    }

    /// Get random known address for connection
    pub fn getRandomAddress(self: *Self) ?net.Address {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.known_addresses.items.len == 0) {
            return null;
        }

        const index = std.crypto.random.uintLessThan(usize, self.known_addresses.items.len);
        return self.known_addresses.items[index];
    }

    /// Clean up timed out peers
    pub fn cleanupTimedOut(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        while (i < self.peers.items.len) {
            const peer = self.peers.items[i];
            if (peer.isTimedOut()) {
                peer.release();
                _ = self.peers.orderedRemove(i);
                // Don't increment i since we removed an item
            } else {
                i += 1;
            }
        }
    }

    /// Get connected peer count
    pub fn getConnectedCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected) {
                count += 1;
            }
        }
        return count;
    }

    /// Get highest peer height
    pub fn getHighestPeerHeight(self: *Self) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var highest: u32 = 0;
        for (self.peers.items) |peer| {
            if (peer.state == .connected and peer.height > highest) {
                highest = peer.height;
            }
        }
        return highest;
    }

    /// Get peer count by state
    pub fn getPeerCount(self: *Self) struct { total: usize, connected: usize, syncing: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();

        var connected: usize = 0;
        var syncing: usize = 0;

        for (self.peers.items) |peer| {
            if (peer.state == .connected) connected += 1;
            if (peer.syncing) syncing += 1;
        }

        return .{
            .total = self.peers.items.len,
            .connected = connected,
            .syncing = syncing,
        };
    }
};
