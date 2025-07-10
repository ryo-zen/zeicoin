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
        std.log.info("Peer {any} connected at height {} (our height: {})", .{
            peer.address, peer.height, our_height
        });
        
        if (peer.height > our_height and self.blockchain.sync_manager != null) {
            try self.blockchain.sync_manager.?.startSync();
        }
    }
    
    fn onGetHeaders(self: *Self, peer: *network.Peer, msg: network.messages.GetHeadersMessage) !void {
        std.log.debug("GetHeaders request received", .{});
        
        // Find the best common block from the locator
        var start_height: u32 = 0;
        for (msg.block_locator) |locator_hash| {
            // Try to find this hash in our chain
            // For now, we'll implement a simple approach
            if (self.blockchain.chain_query.hasBlock(locator_hash)) {
                // Found a common block, we'll start from the next one
                // This is a simplified implementation - we should find the actual height
                start_height += 1; // Start from next block after common one
                break;
            }
        }
        
        const current_height = try self.blockchain.getHeight();
        const max_headers: u32 = 2000; // Standard limit
        
        var headers = std.ArrayList(types.BlockHeader).init(self.blockchain.allocator);
        defer headers.deinit();
        
        const end_height = @min(start_height + max_headers, current_height);
        for (start_height..end_height + 1) |h| {
            var block = self.blockchain.chain_query.getBlock(@intCast(h)) catch continue;
            defer block.deinit(self.blockchain.allocator);
            try headers.append(block.header);
        }
        
        if (headers.items.len > 0) {
            const headers_msg = try network.messages.HeadersMessage.init(self.blockchain.allocator, headers.items);
            const data = try peer.sendMessage(.headers, headers_msg);
            defer self.blockchain.allocator.free(data);
            std.log.info("Sent {} headers to {any}", .{ headers.items.len, peer.address });
        }
    }
    
    fn onHeaders(self: *Self, peer: *network.Peer, msg: network.messages.HeadersMessage) !void {
        std.log.debug("Received {} headers from {any}", .{ msg.headers.len, peer.address });
        
        if (self.blockchain.sync_manager) |sync_manager| {
            sync_manager.processIncomingHeaders(@constCast(msg.headers), 0) catch |err| {
                std.log.warn("Failed to process headers: {}", .{err});
            };
        }
    }
    
    fn onAnnounce(self: *Self, peer: *network.Peer, msg: network.messages.AnnounceMessage) !void {
        for (msg.items) |item| {
            switch (item.item_type) {
                .block => {
                    std.log.info("New block announced: {s}", .{
                        std.fmt.fmtSliceHexLower(&item.hash)
                    });
                    
                    if (!self.blockchain.chain_query.hasBlock(item.hash)) {
                        var items = [_]network.messages.InventoryItem{item};
                        const request = try network.messages.RequestMessage.init(self.blockchain.allocator, &items);
                        const data = peer.sendMessage(.request, request) catch |err| {
                            std.log.debug("Failed to request block: {}", .{err});
                            continue;
                        };
                        defer self.blockchain.allocator.free(data);
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
                        const data = peer.sendMessage(.request, request) catch |err| {
                            std.log.debug("Failed to request tx: {}", .{err});
                            continue;
                        };
                        defer self.blockchain.allocator.free(data);
                        std.log.debug("Requested tx {s} from {any}", .{
                            std.fmt.fmtSliceHexLower(&item.hash), peer.address
                        });
                    }
                },
                else => {},
            }
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
                        const data = try peer.sendMessage(.not_found, not_found);
                        defer self.blockchain.allocator.free(data);
                        continue;
                    };
                    defer block.deinit(self.blockchain.allocator);
                    
                    const block_msg = network.messages.BlockMessage{ .block = block };
                    const data = try peer.sendMessage(.block, block_msg);
                    defer self.blockchain.allocator.free(data);
                    std.log.info("Sent block to {any}", .{peer.address});
                },
                .transaction => {
                    if (self.blockchain.mempool_manager.getTransaction(item.hash)) |tx| {
                        const tx_msg = network.messages.TransactionMessage{ .transaction = tx };
                        const data = try peer.sendMessage(.transaction, tx_msg);
                        defer self.blockchain.allocator.free(data);
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
                        const data = try peer.sendMessage(.transaction, tx_msg);
                        defer self.blockchain.allocator.free(data);
                        std.log.debug("Sent tx from blockchain to {any}", .{peer.address});
                    }
                },
                else => {},
            }
        }
    }
    
    fn onBlock(self: *Self, peer: *network.Peer, msg: network.messages.BlockMessage) !void {
        std.log.info("Received block from {any}", .{peer.address});
        
        const block = msg.block;
        self.blockchain.handleIncomingBlock(block, peer) catch |err| {
            std.log.warn("Failed to process block from {any}: {}", .{ peer.address, err });
            // TODO: Send reject message back to peer
        };
    }
    
    fn onTransaction(self: *Self, peer: *network.Peer, msg: network.messages.TransactionMessage) !void {
        std.log.debug("Received transaction from {any}", .{peer.address});
        
        self.blockchain.handleIncomingTransaction(msg.transaction) catch |err| {
            std.log.debug("Failed to process transaction from {any}: {}", .{ peer.address, err });
            // TODO: Send reject message back to peer
        };
    }
    
    fn onGetBlocks(self: *Self, peer: *network.Peer, msg: network.messages.GetBlocksMessage) !void {
        std.log.debug("GetBlocks request from {} ({} hashes)", .{
            peer.address, msg.hashes.len
        });
        
        // Send each requested block
        for (msg.hashes) |hash| {
            if (self.blockchain.chain_query.getBlockByHash(hash)) |block_const| {
                var block = block_const;
                defer block.deinit(self.blockchain.allocator);
                
                const block_msg = network.messages.BlockMessage{ .block = block };
                const data = try peer.sendMessage(.block, block_msg);
                defer self.blockchain.allocator.free(data);
            } else |_| {
                // Block not found - could send notfound message
                continue;
            }
        }
        
        std.log.info("Sent {} blocks to {any}", .{ msg.hashes.len, peer.address });
    }
    
    fn onGetPeers(self: *Self, peer: *network.Peer, msg: network.messages.GetPeersMessage) !void {
        _ = msg;
        std.log.debug("GetPeers request from {any}", .{peer.address});
        
        var peer_list = std.ArrayList(network.messages.PeerAddress).init(self.blockchain.allocator);
        defer peer_list.deinit();
        
        if (self.blockchain.network) |net_manager| {
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
            const data = try peer.sendMessage(.peers, peers_msg);
            defer self.blockchain.allocator.free(data);
            std.log.debug("Sent {} peer addresses to {any}", .{ peer_list.items.len, peer.address });
        }
    }
    
    fn onPeers(self: *Self, peer: *network.Peer, msg: network.messages.PeersMessage) !void {
        std.log.debug("Received {} peer addresses from {any}", .{ msg.addresses.len, peer.address });
        
        if (self.blockchain.network) |net_manager| {
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