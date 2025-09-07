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
            .onGetBlockHash = onGetBlockHashGlobal,
            .onBlockHash = onBlockHashGlobal,
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
        std.log.info("📋 [GET_BLOCKS] Requested hashes: {}", .{msg.hashes.len});
        
        // Get current blockchain height
        const current_height = self.blockchain.getHeight() catch |err| {
            std.log.err("Failed to get blockchain height: {}", .{err});
            return;
        };
        
        std.log.info("📋 [GET_BLOCKS] Current height: {}, peer requesting blocks", .{current_height});
        
        // Send blocks starting from height 1 up to current height
        // This handles the common case where peer is at genesis (height 0) and needs all blocks
        var height: u32 = 1;
        while (height <= current_height) : (height += 1) {
            if (self.blockchain.database.getBlock(height)) |block| {
                std.log.info("📤 [GET_BLOCKS] Sending block {} to peer {any}", .{ height, peer.address });
                
                // Send block to peer
                const block_msg = network.message_types.BlockMessage{ .block = block };
                _ = peer.sendMessage(.block, block_msg) catch |err| {
                    std.log.err("Failed to send block {} to peer: {}", .{ height, err });
                    break;
                };
            } else |err| {
                std.log.err("Failed to get block {}: {}", .{ height, err });
                break;
            }
        }
        
        std.log.info("✅ [GET_BLOCKS] Sent {} blocks to peer {any}", .{ current_height, peer.address });
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

    fn onGetBlockHash(self: *Self, peer: *network.Peer, msg: network.message_types.GetBlockHashMessage) !void {
        std.log.info("🔍 [GET_BLOCK_HASH] Request for height {} from {any}", .{ msg.height, peer.address });
        
        // Get block hash at requested height using chain_state
        if (self.blockchain.chain_state.getBlockHash(msg.height)) |hash| {
            // Send successful response
            const response = network.message_types.BlockHashMessage{
                .height = msg.height,
                .hash = hash,
                .exists = true,
            };
            _ = try peer.sendMessage(.block_hash, response);
        } else {
            // Send response indicating block doesn't exist
            const response = network.message_types.BlockHashMessage{
                .height = msg.height,
                .hash = std.mem.zeroes(types.Hash),
                .exists = false,
            };
            _ = try peer.sendMessage(.block_hash, response);
        }
    }

    fn onBlockHash(self: *Self, peer: *network.Peer, msg: network.message_types.BlockHashMessage) !void {
        std.log.info("📥 [BLOCK_HASH] Response for height {} from {any} (exists: {})", .{ msg.height, peer.address, msg.exists });
        
        // Block hash responses are typically used during consensus verification
        // For now, just log the response - future consensus logic can be added here
        if (msg.exists) {
            std.log.info("✓ [BLOCK_HASH] Peer {any} has block at height {} with hash {}", .{ peer.address, msg.height, std.fmt.fmtSliceHexUpper(&msg.hash) });
        } else {
            std.log.info("✗ [BLOCK_HASH] Peer {any} does not have block at height {}", .{ peer.address, msg.height });
        }
        
        // Future: Store consensus response for verification logic
        _ = self; // Placeholder for future consensus implementation
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

fn onGetBlockHashGlobal(peer: *network.Peer, msg: network.message_types.GetBlockHashMessage) anyerror!void {
    return global_handler.?.onGetBlockHash(peer, msg);
}

fn onBlockHashGlobal(peer: *network.Peer, msg: network.message_types.BlockHashMessage) anyerror!void {
    return global_handler.?.onBlockHash(peer, msg);
}