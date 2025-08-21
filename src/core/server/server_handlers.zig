// server_handlers.zig - Server-side network message handler implementations
// Handles all incoming network messages for the server

const std = @import("std");
const network = @import("../network/peer.zig");
const zen = @import("../node.zig");
const types = @import("../types/types.zig");

// Global handler for function pointer access
var global_handler: ?*ServerHandlers = null;

// Clear global handler (call during cleanup)
pub fn clearGlobalHandler() void {
    global_handler = null;
}

/// Server-side network handlers that implement blockchain callbacks
pub const ServerHandlers = struct {
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
            .onBlock = onBlockGlobal,
            .onTransaction = onTransactionGlobal,
            .onGetBlocks = onGetBlocksGlobal,
            .onGetPeers = onGetPeersGlobal,
            .onPeers = onPeersGlobal,
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
                std.log.info("🔄 [PEER CONNECT] Sync manager available, checking if sync can start: {}", .{sync_manager.getSyncState().canStart()});
                
                if (sync_manager.getSyncState().canStart()) {
                    std.log.info("📥 [PEER CONNECT] Starting batch sync to download {} blocks", .{blocks_behind});
                    try sync_manager.startSync(peer, peer.height);
                    std.log.info("✅ [PEER CONNECT] Batch sync started successfully", .{});
                } else {
                    std.log.info("⏳ [PEER CONNECT] Sync cannot start (state: {}), skipping new sync request", .{sync_manager.getSyncState()});
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

    fn onBlock(self: *Self, peer: *network.Peer, msg: network.message_types.BlockMessage) !void {
        std.log.info("📦 [BLOCK] Received block from {any}", .{peer.address});
        try self.blockchain.chain_processor.acceptBlock(msg.block);
    }

    fn onTransaction(self: *Self, peer: *network.Peer, msg: network.message_types.TransactionMessage) !void {
        std.log.info("💳 [TX] Received transaction from {any}", .{peer.address});
        _ = self.blockchain.mempool_manager.addTransaction(msg.transaction) catch |err| {
            std.log.debug("Failed to add transaction to mempool: {}", .{err});
        };
    }

    fn onGetBlocks(self: *Self, peer: *network.Peer, msg: network.message_types.GetBlocksMessage) !void {
        std.log.info("📋 [GET_BLOCKS] Request from {any}", .{peer.address});
        // Handle block requests - send blocks back to peer
        _ = self;
        _ = msg;
    }

    fn onGetPeers(self: *Self, peer: *network.Peer, msg: network.message_types.GetPeersMessage) !void {
        std.log.info("👥 [GET_PEERS] Request from {any}", .{peer.address});
        _ = self;
        _ = msg;
        // Handle peer list requests
    }

    fn onPeers(self: *Self, peer: *network.Peer, msg: network.message_types.PeersMessage) !void {
        std.log.info("📋 [PEERS] Received {} peer addresses from {any}", .{ msg.addresses.len, peer.address });
        _ = self;
        // Process received peer list
    }
};

// Global wrapper functions for function pointers
fn getHeightGlobal() anyerror!u32 {
    return global_handler.?.getHeight();
}

fn onPeerConnectedGlobal(peer: *network.Peer) anyerror!void {
    return global_handler.?.onPeerConnected(peer);
}

fn onBlockGlobal(peer: *network.Peer, msg: network.message_types.BlockMessage) anyerror!void {
    return global_handler.?.onBlock(peer, msg);
}

fn onTransactionGlobal(peer: *network.Peer, msg: network.message_types.TransactionMessage) anyerror!void {
    return global_handler.?.onTransaction(peer, msg);
}

fn onGetBlocksGlobal(peer: *network.Peer, msg: network.message_types.GetBlocksMessage) anyerror!void {
    return global_handler.?.onGetBlocks(peer, msg);
}

fn onGetPeersGlobal(peer: *network.Peer, msg: network.message_types.GetPeersMessage) anyerror!void {
    return global_handler.?.onGetPeers(peer, msg);
}

fn onPeersGlobal(peer: *network.Peer, msg: network.message_types.PeersMessage) anyerror!void {
    return global_handler.?.onPeers(peer, msg);
}