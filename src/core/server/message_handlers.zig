// message_handlers.zig - Network message handler implementations
// Handles all incoming network messages for the server

const std = @import("std");
const network = @import("../network/peer.zig");
const zen = @import("../node.zig");
const types = @import("../types/types.zig");

// Global handler for function pointer access
var global_handler: ?*MessageHandlerImpl = null;

// Clear global handler (call during cleanup)
pub fn clearGlobalHandler() void {
    global_handler = null;
}

/// Message handler implementation that holds blockchain reference
pub const MessageHandlerImpl = struct {
    blockchain: *zen.ZeiCoin,
    
    const Self = @This();
    
    pub fn init(blockchain: *zen.ZeiCoin) Self {
        return .{ .blockchain = blockchain };
    }
    
    pub fn createHandler(self: *Self) network.MessageHandler {
        // Store self globally for access by the function pointers
        global_handler = self;
        
        return network.MessageHandler{
            .getHeight = getHeightGlobal,
            .onPeerConnected = onPeerConnectedGlobal,
            .onGetHeaders = onGetHeadersGlobal,
            .onHeaders = onHeadersGlobal,
            .onAnnounce = onAnnounceGlobal,
            .onRequest = onRequestGlobal,
            .onBlock = onBlockGlobal,
            .onTransaction = onTransactionGlobal,
            .onGetBlocks = onGetBlocksGlobal,
            .onGetPeers = onGetPeersGlobal,
            .onPeers = onPeersGlobal,
            .onNotFound = onNotFoundGlobal,
            .onReject = onRejectGlobal,
        };
    }
    
    fn getHeight(self: *Self) !u32 {
        return self.blockchain.getHeight();
    }
    
    fn onPeerConnected(self: *Self, peer: *network.Peer) !void {
        const our_height = try self.blockchain.getHeight();
        std.log.info("👥 [PEER CONNECT] Peer {any} connected at height {} (our height: {})", .{
            peer.address, peer.height, our_height
        });
        std.log.info("🔍 [PEER CONNECT] Peer state: {}, services: 0x{x}", .{peer.state, peer.services});
        std.log.info("🔍 [PEER CONNECT] Sync manager status: {}", .{self.blockchain.sync_manager != null});
        
        // Check if we need to sync from peer (they have more blocks)
        if (peer.height > our_height) {
            const blocks_behind = peer.height - our_height;
            std.log.info("🚀 [PEER CONNECT] Peer has {} more blocks! Starting sync process...", .{blocks_behind});
            
            if (self.blockchain.sync_manager) |sync_manager| {
                std.log.info("🔄 [PEER CONNECT] Sync manager available, checking if already syncing: {}", .{sync_manager.isActive()});
                
                if (!sync_manager.isActive()) {
                    std.log.info("📥 [PEER CONNECT] Starting batch sync to download {} blocks", .{blocks_behind});
                    try sync_manager.startBatchSync(peer, peer.height);
                    std.log.info("✅ [PEER CONNECT] Batch sync started successfully", .{});
                } else {
                    std.log.info("⏳ [PEER CONNECT] Sync already active, skipping new sync request", .{});
                }
            } else {
                std.log.warn("❌ [PEER CONNECT] Sync manager is null, cannot start sync!", .{});
            }
        } else if (our_height > peer.height) {
            const blocks_ahead = our_height - peer.height;
            std.log.info("📤 [PEER CONNECT] We are {} blocks ahead of peer (they may sync from us)", .{blocks_ahead});
        } else {
            std.log.info("✅ [PEER CONNECT] Both nodes at same height {}, no sync needed", .{our_height});
        }
    }
    
    fn onGetHeaders(self: *Self, peer: *network.Peer, msg: network.messages.GetHeadersMessage) !void {
        std.log.debug("GetHeaders request received with {} locator hashes", .{msg.block_locator.len});
        
        // Find the best common block from the locator
        var start_height: u32 = 0; // Start from genesis (height 0)
        var found_common = false;
        
        for (msg.block_locator) |locator_hash| {
            // Check if this is genesis hash (all zeros)
            const is_genesis = std.mem.allEqual(u8, &locator_hash, 0);
            if (is_genesis) {
                start_height = 1; // Genesis found at 0, so start from height 1
                found_common = true;
                std.log.debug("Found genesis locator, starting from height 1", .{});
                break;
            }
            
            // Try to find this hash in our chain
            if (self.blockchain.chain_query.hasBlock(locator_hash)) {
                // Found a common block, we'll start from the next one
                // This is a simplified implementation - we should find the actual height
                start_height += 1; // Start from next block after common one
                found_common = true;
                std.log.debug("Found common block in locator, starting from height {}", .{start_height});
                break;
            }
        }
        
        if (!found_common) {
            std.log.debug("No common block found in locator, starting from genesis", .{});
            start_height = 0; // Start from genesis at height 0
        }
        
        const current_height = try self.blockchain.getHeight();
        const max_headers: u32 = 2000; // Standard limit
        
        var headers = std.ArrayList(types.BlockHeader).init(self.blockchain.allocator);
        defer headers.deinit();
        
        const end_height = @min(start_height + max_headers, current_height);
        std.log.debug("Sending headers from height {} to {} (current height: {})", .{ start_height, end_height, current_height });
        
        for (start_height..end_height + 1) |h| {
            var block = self.blockchain.chain_query.getBlock(@intCast(h)) catch |err| {
                std.log.debug("Failed to get block at height {}: {}", .{ h, err });
                continue;
            };
            defer block.deinit(self.blockchain.allocator);
            try headers.append(block.header);
        }
        
        if (headers.items.len > 0) {
            const headers_msg = try network.messages.HeadersMessage.init(self.blockchain.allocator, headers.items);
            _ = try peer.sendMessage(.headers, headers_msg);
            std.log.info("Sent {} headers to {any}", .{ headers.items.len, peer.address });
        }
    }
    
    fn onHeaders(self: *Self, peer: *network.Peer, msg: network.messages.HeadersMessage) !void {
        std.log.debug("Received {} headers from {any}", .{ msg.headers.len, peer.address });
        
        if (self.blockchain.sync_manager) |sync_manager| {
            // First check if we need to start sync based on received headers
            const current_height = try self.blockchain.getHeight();
            
            if (msg.headers.len > 0) {
                // Update peer height based on the latest header received
                const latest_header_height = current_height + msg.headers.len;
                if (latest_header_height > peer.height) {
                    std.log.info("🔄 [HEADERS] Updating peer height from {} to {}", .{ peer.height, latest_header_height });
                    peer.height = @intCast(latest_header_height);
                }
                
                // Check if we need to start a new sync operation
                if (latest_header_height > current_height and !sync_manager.isActive()) {
                    std.log.info("🚀 [HEADERS] Peer has {} blocks ahead, starting sync...", .{ latest_header_height - current_height });
                    try sync_manager.startBatchSync(peer, @intCast(latest_header_height));
                    std.log.info("✅ [HEADERS] Sync started successfully", .{});
                }
            }
            
            // Process headers with modern sync manager
            sync_manager.processIncomingHeaders(msg.headers, current_height + 1) catch |err| {
                std.log.warn("Failed to process headers: {}", .{err});
            };
        } else {
            std.log.info("Received {} headers but no sync manager available", .{msg.headers.len});
        }
    }
    
    fn onAnnounce(self: *Self, peer: *network.Peer, msg: network.messages.AnnounceMessage) !void {
        var need_sync_check = false;
        
        for (msg.items) |item| {
            switch (item.item_type) {
                .block => {
                    std.log.info("New block announced: {s}", .{
                        std.fmt.fmtSliceHexLower(&item.hash)
                    });
                    
                    if (!self.blockchain.chain_query.hasBlock(item.hash)) {
                        // We don't have this block - might need to sync
                        need_sync_check = true;
                        
                        var items = [_]network.messages.InventoryItem{item};
                        const request = try network.messages.RequestMessage.init(self.blockchain.allocator, &items);
                        _ = peer.sendMessage(.request, request) catch |err| {
                            std.log.debug("Failed to request block: {}", .{err});
                            continue;
                        };
                        std.log.debug("Requested block {s} from {any}", .{
                            std.fmt.fmtSliceHexLower(&item.hash), peer.address
                        });
                    }
                },
                .transaction => {
                    if (!self.blockchain.mempool_manager.hasTransaction(item.hash) and
                        !self.blockchain.chain_query.hasTransaction(item.hash)) {
                        var items = [_]network.messages.InventoryItem{item};
                        const request = try network.messages.RequestMessage.init(self.blockchain.allocator, &items);
                        _ = peer.sendMessage(.request, request) catch |err| {
                            std.log.debug("Failed to request tx: {}", .{err});
                            continue;
                        };
                        std.log.debug("Requested tx {s} from {any}", .{
                            std.fmt.fmtSliceHexLower(&item.hash), peer.address
                        });
                    }
                },
                else => {},
            }
        }
        
        // Check if we need to start a sync operation due to announced blocks
        if (need_sync_check) {
            const our_height = try self.blockchain.getHeight();
            std.log.info("🔍 [ANNOUNCE] Block announced we don't have, checking sync need (our height: {}, peer height: {})", .{ our_height, peer.height });
            
            // Request headers to get the peer's current height - the peer height from handshake may be stale
            std.log.info("📤 [ANNOUNCE] Requesting headers to get peer's current height...", .{});
            
            // Create a basic headers request to trigger height update
            var locator = std.ArrayList([32]u8).init(self.blockchain.allocator);
            defer locator.deinit();
            
            // Add our current best block hash as locator
            if (our_height > 0) {
                var current_block = self.blockchain.chain_query.getBlock(our_height - 1) catch {
                    std.log.warn("Failed to get current block for headers request", .{});
                    return;
                };
                defer current_block.deinit(self.blockchain.allocator);
                try locator.append(current_block.hash());
            } else {
                // Use zero hash for genesis
                try locator.append([_]u8{0} ** 32);
            }
            
            const stop_hash = [_]u8{0} ** 32; // No stop hash - get all headers to tip
            var get_headers = try network.messages.GetHeadersMessage.init(self.blockchain.allocator, locator.items, stop_hash);
            defer get_headers.deinit(self.blockchain.allocator);
            
            _ = peer.sendMessage(.get_headers, get_headers) catch |err| {
                std.log.warn("Failed to send headers request: {}", .{err});
                return;
            };
            
            std.log.info("✅ [ANNOUNCE] Headers request sent - will check for sync after response", .{});
        }
    }
    
    fn onRequest(self: *Self, peer: *network.Peer, msg: network.messages.RequestMessage) !void {
        std.log.debug("Data request from {any} for {} items", .{ peer.address, msg.items.len });
        
        for (msg.items) |item| {
            switch (item.item_type) {
                .block => {
                    var block = self.blockchain.chain_query.getBlockByHash(item.hash) catch {
                        var items = [_]network.messages.InventoryItem{item};
                        const not_found = try network.messages.NotFoundMessage.init(self.blockchain.allocator, &items);
                        _ = try peer.sendMessage(.not_found, not_found);
                        continue;
                    };
                    defer block.deinit(self.blockchain.allocator);
                    
                    const block_msg = network.messages.BlockMessage{ .block = block };
                    _ = try peer.sendMessage(.block, block_msg);
                    std.log.info("Sent block to {any}", .{peer.address});
                },
                .transaction => {
                    if (self.blockchain.mempool_manager.getTransaction(item.hash)) |tx| {
                        const tx_msg = network.messages.TransactionMessage{ .transaction = tx };
                        _ = try peer.sendMessage(.transaction, tx_msg);
                        std.log.debug("Sent tx from mempool to {any}", .{peer.address});
                    } else {
                        var tx = self.blockchain.chain_query.getTransactionByHash(item.hash) catch {
                            var items = [_]network.messages.InventoryItem{item};
                            const not_found = try network.messages.NotFoundMessage.init(self.blockchain.allocator, &items);
                            const data = try peer.sendMessage(.not_found, not_found);
                            defer self.blockchain.allocator.free(data);
                            continue;
                        };
                        defer tx.deinit(self.blockchain.allocator);
                        
                        const tx_msg = network.messages.TransactionMessage{ .transaction = tx };
                        _ = try peer.sendMessage(.transaction, tx_msg);
                        std.log.debug("Sent tx from blockchain to {any}", .{peer.address});
                    }
                },
                else => {},
            }
        }
    }
    
    fn onBlock(self: *Self, peer: *network.Peer, msg: network.messages.BlockMessage) !void {
        const block = msg.block;
        const block_hash = std.fmt.fmtSliceHexLower(&block.hash());
        std.log.info("📦 [BLOCK RECV] Received block from {any}", .{peer.address});
        std.log.info("🔍 [BLOCK RECV] Block hash: {s}", .{block_hash});
        std.log.info("🔍 [BLOCK RECV] Block transactions: {}, size: {} bytes", .{block.transactions.len, @sizeOf(@TypeOf(block))});
        
        // Check if we're in sync mode - if so, route to sync manager
        if (self.blockchain.sync_manager) |sync_manager| {
            std.log.info("🔍 [BLOCK RECV] Checking sync manager... Active: {}", .{sync_manager.isActive()});
            if (sync_manager.isActive()) {
                if (sync_manager.sync_peer == peer) {
                    std.log.info("🔄 [BLOCK RECV] This is our sync peer! Routing to sync manager...", .{});
                    // Route block to sync manager for headers-first sync
                    sync_manager.handleSyncBlock(&block) catch |err| {
                        std.log.warn("❌ [BLOCK RECV] Failed to process sync block from {any}: {}", .{ peer.address, err });
                    };
                    std.log.info("✅ [BLOCK RECV] Block routed to sync manager successfully", .{});
                    return;
                } else {
                    std.log.info("🔍 [BLOCK RECV] Block from different peer (not sync peer), processing normally", .{});
                }
            } else {
                std.log.info("🔍 [BLOCK RECV] Sync not active, processing block normally", .{});
            }
        } else {
            std.log.info("🔍 [BLOCK RECV] No sync manager available, processing block normally", .{});
        }
        
        // Normal block processing
        std.log.info("📝 [BLOCK RECV] Processing block through normal blockchain handler...", .{});
        self.blockchain.handleIncomingBlock(block, peer) catch |err| {
            std.log.warn("❌ [BLOCK RECV] Failed to process block from {any}: {}", .{ peer.address, err });
            
            // Send reject message back to peer
            const reject_info = self.mapErrorToReject(err);
            const reject_block_hash = block.hash();
            var reject_msg = network.messages.RejectMessage.init(
                self.blockchain.allocator,
                .block,
                reject_info.code,
                reject_info.reason,
                &reject_block_hash
            ) catch |reject_err| {
                std.log.debug("Failed to create reject message: {}", .{reject_err});
                return;
            };
            defer reject_msg.deinit(self.blockchain.allocator);
            
            _ = peer.sendMessage(.reject, reject_msg) catch |send_err| {
                std.log.debug("Failed to send block reject to {any}: {}", .{ peer.address, send_err });
                return;
            };
            
            std.log.info("📤 [BLOCK RECV] Sent block reject to {any}: {s}", .{ peer.address, reject_info.reason });
        };
    }
    
    fn onTransaction(self: *Self, peer: *network.Peer, msg: network.messages.TransactionMessage) !void {
        std.log.debug("Received transaction from {any}", .{peer.address});
        
        self.blockchain.handleIncomingTransaction(msg.transaction) catch |err| {
            std.log.debug("Failed to process transaction from {any}: {}", .{ peer.address, err });
            
            // Send reject message back to peer
            const reject_info = self.mapErrorToReject(err);
            const tx_hash = msg.transaction.hash();
            var reject_msg = network.messages.RejectMessage.init(
                self.blockchain.allocator,
                .transaction,
                reject_info.code,
                reject_info.reason,
                &tx_hash
            ) catch |reject_err| {
                std.log.debug("Failed to create reject message: {}", .{reject_err});
                return;
            };
            defer reject_msg.deinit(self.blockchain.allocator);
            
            _ = peer.sendMessage(.reject, reject_msg) catch |send_err| {
                std.log.debug("Failed to send transaction reject to {any}: {}", .{ peer.address, send_err });
                return;
            };
            
            std.log.debug("Sent transaction reject to {any}: {s}", .{ peer.address, reject_info.reason });
        };
    }
    
    fn onGetBlocks(self: *Self, peer: *network.Peer, msg: network.messages.GetBlocksMessage) !void {
        std.log.info("📥 [GET BLOCKS] Request from {any} for {} block hashes", .{
            peer.address, msg.hashes.len
        });
        
        var blocks_sent: u32 = 0;
        
        // Handle empty hash list (request for latest blocks)
        if (msg.hashes.len == 0) {
            std.log.info("📋 [GET BLOCKS] Empty hash list - sending latest blocks", .{});
            
            // Get current height and send the latest block
            const current_height = try self.blockchain.getHeight();
            std.log.info("📊 [GET BLOCKS] Current blockchain height: {}", .{current_height});
            
            if (current_height > 0) {
                // Height represents next block to create, so latest block is at height - 1
                const latest_block_height = current_height - 1;
                std.log.info("🔍 [GET BLOCKS] Attempting to get latest block at height {}", .{latest_block_height});
                
                var block = self.blockchain.chain_query.getBlock(latest_block_height) catch |err| {
                    std.log.warn("❌ [GET BLOCKS] Failed to get block at height {}: {}", .{latest_block_height, err});
                    
                    // Try height - 2 as additional fallback
                    if (latest_block_height > 0) {
                        const fallback_height = latest_block_height - 1;
                        std.log.info("🔄 [GET BLOCKS] Trying height {} instead", .{fallback_height});
                        var fallback_block = self.blockchain.chain_query.getBlock(fallback_height) catch |fallback_err| {
                            std.log.warn("❌ [GET BLOCKS] Fallback failed at height {}: {}", .{fallback_height, fallback_err});
                            return;
                        };
                        defer fallback_block.deinit(self.blockchain.allocator);
                        
                        std.log.info("📦 [GET BLOCKS] Sending fallback block at height {} to {any}", .{fallback_height, peer.address});
                        const block_msg = network.messages.BlockMessage{ .block = fallback_block };
                        _ = try peer.sendMessage(.block, block_msg);
                        blocks_sent += 1;
                        std.log.info("✅ [GET BLOCKS] Fallback block sent successfully", .{});
                        return;
                    } else {
                        return;
                    }
                };
                defer block.deinit(self.blockchain.allocator);
                
                std.log.info("📦 [GET BLOCKS] Sending block at height {} to {any}", .{latest_block_height, peer.address});
                const block_msg = network.messages.BlockMessage{ .block = block };
                _ = try peer.sendMessage(.block, block_msg);
                blocks_sent += 1;
                std.log.info("✅ [GET BLOCKS] Block sent successfully", .{});
            }
        } else {
            // Handle each requested block (by hash or by height)
            for (msg.hashes) |hash| {
                // Check if this is a height-based request (encoded as special hash)
                const HEIGHT_REQUEST_MAGIC: u32 = 0xDEADBEEF;
                const maybe_magic = std.mem.readInt(u32, hash[4..8], .little);
                
                if (maybe_magic == HEIGHT_REQUEST_MAGIC) {
                    // This is a height-based request
                    const requested_height = std.mem.readInt(u32, hash[0..4], .little);
                    std.log.info("🔍 [GET BLOCKS] Height-based request for block at height {}", .{requested_height});
                    
                    var block = self.blockchain.chain_query.getBlock(requested_height) catch |err| {
                        std.log.warn("❌ [GET BLOCKS] Block not found at height {}: {}", .{requested_height, err});
                        continue;
                    };
                    defer block.deinit(self.blockchain.allocator);
                    
                    std.log.info("📦 [GET BLOCKS] Found block at height {}, sending to {any}", .{requested_height, peer.address});
                    const block_msg = network.messages.BlockMessage{ .block = block };
                    _ = try peer.sendMessage(.block, block_msg);
                    blocks_sent += 1;
                    std.log.info("✅ [GET BLOCKS] Block sent successfully for height {}", .{requested_height});
                } else {
                    // Regular hash-based request
                    std.log.info("🔍 [GET BLOCKS] Looking for block with hash: {s}", .{std.fmt.fmtSliceHexLower(&hash)});
                    
                    if (self.blockchain.chain_query.getBlockByHash(hash)) |block_const| {
                        var block = block_const;
                        defer block.deinit(self.blockchain.allocator);
                        
                        std.log.info("📦 [GET BLOCKS] Found block, sending to {any}", .{peer.address});
                        const block_msg = network.messages.BlockMessage{ .block = block };
                        _ = try peer.sendMessage(.block, block_msg);
                        blocks_sent += 1;
                        std.log.info("✅ [GET BLOCKS] Block sent successfully", .{});
                    } else |err| {
                        std.log.warn("❌ [GET BLOCKS] Block not found: {} - {s}", .{err, std.fmt.fmtSliceHexLower(&hash)});
                        // Block not found - could send notfound message
                        continue;
                    }
                }
            }
        }
        
        std.log.info("📤 [GET BLOCKS] Sent {} blocks to {any}", .{ blocks_sent, peer.address });
    }
    
    fn onGetPeers(self: *Self, peer: *network.Peer, msg: network.messages.GetPeersMessage) !void {
        _ = msg;
        std.log.debug("GetPeers request from {any}", .{peer.address});
        
        var peer_list = std.ArrayList(network.messages.PeerAddress).init(self.blockchain.allocator);
        defer peer_list.deinit();
        
        if (self.blockchain.network_coordinator.getNetworkManager()) |net_manager| {
            net_manager.peer_manager.mutex.lock();
            defer net_manager.peer_manager.mutex.unlock();
            
            for (net_manager.peer_manager.peers.items) |known_peer| {
                if (known_peer.state == .connected and !std.net.Address.eql(known_peer.address, peer.address)) {
                    // Convert net.Address to PeerAddress format
                    var ip: [16]u8 = [_]u8{0} ** 16;
                    var port: u16 = 0;
                    
                    // Handle address type conversion without switch on union
                    if (known_peer.address.any.family == std.posix.AF.INET) {
                        // IPv4 - map to IPv6 format: ::ffff:a.b.c.d
                        const ipv4 = known_peer.address.in;
                        ip[10] = 0xff;
                        ip[11] = 0xff;
                        @memcpy(ip[12..16], std.mem.asBytes(&ipv4.sa.addr));
                        port = std.mem.bigToNative(u16, ipv4.sa.port);
                    } else if (known_peer.address.any.family == std.posix.AF.INET6) {
                        // IPv6
                        const ipv6 = known_peer.address.in6;
                        ip = ipv6.sa.addr;
                        port = std.mem.bigToNative(u16, ipv6.sa.port);
                    } else {
                        continue; // Skip unsupported address types
                    }
                    
                    try peer_list.append(.{
                        .ip = ip,
                        .port = port,
                        .services = known_peer.services,
                        .last_seen = @intCast(std.time.timestamp()),
                    });
                    
                    if (peer_list.items.len >= 10) break;
                }
            }
        }
        
        if (peer_list.items.len > 0) {
            const peers_msg = try network.messages.PeersMessage.init(self.blockchain.allocator, peer_list.items);
            _ = try peer.sendMessage(.peers, peers_msg);
            std.log.debug("Sent {} peer addresses to {any}", .{ peer_list.items.len, peer.address });
        }
    }
    
    fn onPeers(self: *Self, peer: *network.Peer, msg: network.messages.PeersMessage) !void {
        std.log.debug("Received {} peer addresses from {any}", .{ msg.addresses.len, peer.address });
        
        if (self.blockchain.network_coordinator.getNetworkManager()) |net_manager| {
            for (msg.addresses) |peer_addr| {
                // Convert PeerAddress back to net.Address
                const net_addr = if (std.mem.eql(u8, peer_addr.ip[0..10], &[_]u8{0} ** 10) and 
                                     std.mem.eql(u8, peer_addr.ip[10..12], &[_]u8{0xff, 0xff})) addr_blk: {
                    // IPv4-mapped IPv6
                    const ipv4_bytes = peer_addr.ip[12..16];
                    break :addr_blk std.net.Address.initIp4(ipv4_bytes.*, peer_addr.port);
                } else addr_blk: {
                    // IPv6
                    break :addr_blk std.net.Address.initIp6(peer_addr.ip, peer_addr.port, 0, 0);
                };
                
                if (net_manager.listen_address) |listen_addr| {
                    if (std.net.Address.eql(net_addr, listen_addr)) {
                        continue;
                    }
                }
                
                net_manager.connectToPeer(net_addr) catch |err| {
                    std.log.debug("Failed to connect to peer {any}: {}", .{ net_addr, err });
                };
            }
        }
    }
    
    fn onNotFound(self: *Self, peer: *network.Peer, msg: network.messages.NotFoundMessage) !void {
        _ = self;
        std.log.debug("NotFound from {any} for {} items", .{ peer.address, msg.items.len });
        
        for (msg.items) |item| {
            switch (item.item_type) {
                .block => std.log.debug("Peer {any} doesn't have block {s}", .{
                    peer.address, std.fmt.fmtSliceHexLower(&item.hash)
                }),
                .transaction => std.log.debug("Peer {any} doesn't have tx {s}", .{
                    peer.address, std.fmt.fmtSliceHexLower(&item.hash)
                }),
                else => {},
            }
        }
    }
    
    const RejectInfo = struct {
        code: network.protocol.RejectCode,
        reason: []const u8,
    };
    
    fn mapErrorToReject(self: *Self, err: anyerror) RejectInfo {
        _ = self;
        return switch (err) {
            error.InvalidBlock, error.InvalidTransaction => .{
                .code = .invalid,
                .reason = "Invalid data structure",
            },
            error.DuplicateBlock, error.DuplicateTransaction => .{
                .code = .duplicate,
                .reason = "Already exists",
            },
            error.InvalidSignature => .{
                .code = .invalid,
                .reason = "Invalid signature",
            },
            error.InsufficientBalance => .{
                .code = .invalid,
                .reason = "Insufficient balance",
            },
            error.InvalidNonce => .{
                .code = .invalid,
                .reason = "Invalid nonce",
            },
            error.BlockTooBig, error.TransactionTooBig => .{
                .code = .invalid,
                .reason = "Size limit exceeded",
            },
            error.OutOfMemory => .{
                .code = .invalid,
                .reason = "Resource exhaustion",
            },
            error.MovedToMempoolManager => .{
                .code = .obsolete,
                .reason = "Use mempool manager",
            },
            else => .{
                .code = .invalid,
                .reason = "Processing failed",
            },
        };
    }
    
    fn onReject(self: *Self, peer: *network.Peer, msg: network.messages.RejectMessage) !void {
        _ = self;
        std.log.warn("Reject from {}: {} - {s}", .{
            peer.address, msg.code, msg.reason
        });
        
        switch (msg.code) {
            .obsolete => {
                std.log.warn("Peer {any} reports our message is obsolete", .{
                    peer.address
                });
            },
            .invalid => {
                std.log.debug("Peer {any} rejected our message as invalid", .{
                    peer.address
                });
            },
            else => {},
        }
    }
};

// Global wrapper functions for function pointers
fn getHeightGlobal() anyerror!u32 {
    return global_handler.?.getHeight();
}

fn onPeerConnectedGlobal(peer: *network.Peer) anyerror!void {
    return global_handler.?.onPeerConnected(peer);
}

fn onGetHeadersGlobal(peer: *network.Peer, msg: network.messages.GetHeadersMessage) anyerror!void {
    return global_handler.?.onGetHeaders(peer, msg);
}

fn onHeadersGlobal(peer: *network.Peer, msg: network.messages.HeadersMessage) anyerror!void {
    return global_handler.?.onHeaders(peer, msg);
}

fn onAnnounceGlobal(peer: *network.Peer, msg: network.messages.AnnounceMessage) anyerror!void {
    return global_handler.?.onAnnounce(peer, msg);
}

fn onRequestGlobal(peer: *network.Peer, msg: network.messages.RequestMessage) anyerror!void {
    return global_handler.?.onRequest(peer, msg);
}

fn onBlockGlobal(peer: *network.Peer, msg: network.messages.BlockMessage) anyerror!void {
    return global_handler.?.onBlock(peer, msg);
}

fn onTransactionGlobal(peer: *network.Peer, msg: network.messages.TransactionMessage) anyerror!void {
    return global_handler.?.onTransaction(peer, msg);
}

fn onGetBlocksGlobal(peer: *network.Peer, msg: network.messages.GetBlocksMessage) anyerror!void {
    return global_handler.?.onGetBlocks(peer, msg);
}

fn onGetPeersGlobal(peer: *network.Peer, msg: network.messages.GetPeersMessage) anyerror!void {
    return global_handler.?.onGetPeers(peer, msg);
}

fn onPeersGlobal(peer: *network.Peer, msg: network.messages.PeersMessage) anyerror!void {
    return global_handler.?.onPeers(peer, msg);
}

fn onNotFoundGlobal(peer: *network.Peer, msg: network.messages.NotFoundMessage) anyerror!void {
    return global_handler.?.onNotFound(peer, msg);
}

fn onRejectGlobal(peer: *network.Peer, msg: network.messages.RejectMessage) anyerror!void {
    return global_handler.?.onReject(peer, msg);
}