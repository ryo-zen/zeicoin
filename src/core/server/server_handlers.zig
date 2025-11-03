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
            .getBestBlockHash = getBestBlockHashGlobal,
            .getGenesisHash = getGenesisHashGlobal,
            .getCurrentDifficulty = getCurrentDifficultyGlobal,
            .onPeerConnected = onPeerConnectedGlobal,
            .onBlock = onBlockGlobal,
            .onTransaction = onTransactionGlobal,
            .onGetBlocks = onGetBlocksGlobal,
            .onGetPeers = onGetPeersGlobal,
            .onPeers = onPeersGlobal,
            .onGetBlockHash = onGetBlockHashGlobal,
            .onBlockHash = onBlockHashGlobal,
            .onGetMempool = onGetMempoolGlobal,
            .onMempoolInv = onMempoolInvGlobal,
            .onPeerDisconnected = onPeerDisconnectedGlobal,
        };
    }
    
    fn getHeight(self: *Self) !u32 {
        return self.blockchain.getHeight();
    }
    
    fn getBestBlockHash(self: *Self) ![32]u8 {
        return self.blockchain.getBestBlockHash();
    }
    
    fn getGenesisHash(self: *Self) ![32]u8 {
        _ = self; // Not used, but required for interface
        // Get the canonical genesis hash for the current network
        const genesis = @import("../chain/genesis.zig");
        return genesis.getCanonicalGenesisHash();
    }
    
    fn getCurrentDifficulty(self: *Self) !u64 {
        return self.blockchain.getCurrentDifficulty();
    }
    
    fn onPeerConnected(self: *Self, peer: *network.Peer) !void {
        const our_height = try self.blockchain.getHeight();
        const our_best_hash = try self.blockchain.getBestBlockHash();
        
        std.log.info("👥 [PEER CONNECT] Peer {any} connected at height {} (our height: {})", .{
            peer.address, peer.height, our_height
        });
        std.log.info("🔍 [PEER CONNECT] Peer state: {}, services: 0x{x}", .{peer.state, peer.services});
        std.log.info("🔍 [PEER CONNECT] Sync manager status: {}", .{self.blockchain.sync_manager != null});
        
        // Check for chain divergence first
        const has_diverged = (peer.height == our_height and !std.mem.eql(u8, &peer.best_block_hash, &our_best_hash));
        if (has_diverged) {
            std.log.warn("⚠️ [CHAIN DIVERGENCE] Detected at height {} - forcing sync!", .{our_height});
            std.log.warn("📊 Peer hash: {s}, Our hash: {s}", .{
                std.fmt.fmtSliceHexLower(&peer.best_block_hash),
                std.fmt.fmtSliceHexLower(&our_best_hash),
            });
            // Force sync even at same height due to divergence
            if (self.blockchain.sync_manager) |sync_manager| {
                if (sync_manager.getSyncState().canStart()) {
                    std.log.info("🔄 [DIVERGENCE] Starting sync to resolve chain divergence", .{});
                    // We'll sync from height 0 to rebuild the correct chain
                    try sync_manager.startSync(peer, peer.height);
                }
            }
        }
        // Check if we need to sync from peer (they have more blocks)
        else if (peer.height > our_height) {
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

        // After blockchain sync check, request mempool from peer
        std.log.info("📋 [MEMPOOL SYNC] Requesting mempool from peer {}", .{peer.id});
        const get_mempool = network.message_types.GetMempoolMessage.init();
        _ = peer.sendMessage(.get_mempool, get_mempool) catch |err| {
            std.log.debug("Failed to request mempool from peer: {}", .{err});
        };

        // Also send our mempool to the new peer
        {
            const mempool = self.blockchain.mempool_manager;
            const transactions = mempool.storage.getAllTransactions() catch |err| {
                std.log.debug("Failed to get mempool transactions: {}", .{err});
                return;
            };
            defer mempool.storage.freeTransactionArray(transactions);

            if (transactions.len > 0) {
                std.log.info("📤 [MEMPOOL SYNC] Sending {} transactions to new peer {}", .{ transactions.len, peer.id });

                // Send each transaction individually
                for (transactions) |tx| {
                    const tx_msg = network.message_types.TransactionMessage{
                        .transaction = tx,
                    };
                    _ = peer.sendMessage(.transaction, tx_msg) catch |err| {
                        std.log.debug("Failed to send transaction to peer: {}", .{err});
                    };
                }

                std.log.info("✅ [MEMPOOL SYNC] Sent {} mempool transactions to peer {}", .{ transactions.len, peer.id });
            } else {
                std.log.info("📋 [MEMPOOL SYNC] No transactions to send to peer {}", .{peer.id});
            }
        }
    }

    fn onBlock(self: *Self, peer: *network.Peer, msg: network.message_types.BlockMessage) !void {
        std.log.info("📦 [BLOCK] Received block from {any}", .{peer.address});
        try self.blockchain.chain_processor.acceptBlock(msg.block);
    }

    fn onTransaction(self: *Self, peer: *network.Peer, msg: network.message_types.TransactionMessage) !void {
        std.log.info("💳 [TX] Received transaction from {any}", .{peer.address});
        // Use handleIncomingTransaction for network-received transactions
        // This prevents re-broadcasting and duplicate additions
        _ = self.blockchain.mempool_manager.handleIncomingTransaction(msg.transaction) catch |err| {
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
        
        var blocks_sent: u32 = 0;
        
        // Process each requested hash - decode ZSP-001 height encoding if present
        for (msg.hashes) |hash| {
            const requested_height = if (isZSP001HeightEncoded(hash)) |height| blk: {
                std.log.info("📋 [ZSP-001] Decoded height-encoded request: {}", .{height});
                break :blk height;
            } else blk: {
                // Legacy hash-based request - look up block by hash
                std.log.info("📋 [LEGACY] Hash-based request: {s}", .{std.fmt.fmtSliceHexLower(hash[0..8])});
                // For now, fallback to old behavior for legacy requests
                break :blk null;
            };
            
            if (requested_height) |height| {
                // ZSP-001 height-based request
                if (height > current_height) {
                    std.log.info("📋 [GET_BLOCKS] Requested height {} beyond current height {}", .{ height, current_height });
                    continue;
                }
                
                if (self.blockchain.database.getBlock(height)) |block| {
                    std.log.info("📤 [GET_BLOCKS] Sending block {} to peer {any}", .{ height, peer.address });
                    
                    // Send block to peer
                    const block_msg = network.message_types.BlockMessage{ .block = block };
                    _ = peer.sendMessage(.block, block_msg) catch |err| {
                        std.log.err("Failed to send block {} to peer: {}", .{ height, err });
                        std.log.info("📊 [GET_BLOCKS] Sent {} blocks before connection error", .{ blocks_sent });
                        return;
                    };
                    blocks_sent += 1;
                } else |err| {
                    std.log.err("Failed to get block {}: {}", .{ height, err });
                }
            } else {
                // Legacy hash-based request - fallback to old behavior
                std.log.info("📋 [LEGACY] Processing hash-based request - sending all blocks from height 1", .{});
                var height: u32 = 1;
                while (height <= current_height) : (height += 1) {
                    if (self.blockchain.database.getBlock(height)) |block| {
                        const block_msg = network.message_types.BlockMessage{ .block = block };
                        _ = peer.sendMessage(.block, block_msg) catch |err| {
                            std.log.err("Failed to send block {} to peer: {}", .{ height, err });
                            return;
                        };
                        blocks_sent += 1;
                    } else |err| {
                        std.log.err("Failed to get block {}: {}", .{ height, err });
                        break;
                    }
                }
                break; // Exit loop after processing legacy request
            }
        }
        
        if (blocks_sent == current_height) {
            std.log.info("✅ [GET_BLOCKS] Successfully sent all {} blocks to peer {any}", .{ blocks_sent, peer.address });
        } else if (blocks_sent > 0) {
            std.log.info("⚠️ [GET_BLOCKS] Sent {} of {} blocks to peer {any}", .{ blocks_sent, current_height, peer.address });
        }
    }

    /// Decode ZSP-001 height-encoded hash and return the height if valid
    /// Supports both encoding formats: batch sync and peer manager
    /// Returns null if not a valid ZSP-001 height-encoded hash
    fn isZSP001HeightEncoded(hash: [32]u8) ?u32 {
        const ZSP_001_MAGIC: u32 = 0xDEADBEEF;
        
        // Check batch sync format: [0xDEADBEEF:4][height:4][zeros:24]
        const batch_magic = std.mem.readInt(u32, hash[0..4], .little);
        if (batch_magic == ZSP_001_MAGIC) {
            const height = std.mem.readInt(u32, hash[4..8], .little);
            // Verify remaining bytes are zero
            for (hash[8..]) |byte| {
                if (byte != 0) return null;
            }
            return height;
        }
        
        // Check peer manager format: [height:4][0xDEADBEEF:4][zeros:24]
        const peer_magic = std.mem.readInt(u32, hash[4..8], .little);
        if (peer_magic == ZSP_001_MAGIC) {
            const height = std.mem.readInt(u32, hash[0..4], .little);
            // Verify remaining bytes are zero
            for (hash[8..]) |byte| {
                if (byte != 0) return null;
            }
            return height;
        }
        
        return null; // Not a ZSP-001 encoded hash
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
    
    fn onGetMempool(self: *Self, peer: *network.Peer) !void {
        // Send mempool inventory to requesting peer
        std.log.info("📋 [MEMPOOL] Peer {} requesting mempool inventory", .{peer.id});

        {
            const mempool = self.blockchain.mempool_manager;
            // Get all transaction hashes from mempool
            const transactions = try mempool.storage.getAllTransactions();
            defer mempool.storage.freeTransactionArray(transactions);

            // Create array of hashes
            const tx_hashes = try self.blockchain.allocator.alloc(types.Hash, transactions.len);
            defer self.blockchain.allocator.free(tx_hashes);

            for (transactions, tx_hashes) |tx, *hash| {
                hash.* = tx.hash();
            }

            // Send mempool inventory message
            const mempool_inv = try network.message_types.MempoolInvMessage.init(
                self.blockchain.allocator,
                tx_hashes
            );
            defer {
                var mut_inv = mempool_inv;
                mut_inv.deinit();
            }

            _ = try peer.sendMessage(.mempool_inv, mempool_inv);
            std.log.info("📤 [MEMPOOL] Sent {} transaction hashes to peer {}", .{ tx_hashes.len, peer.id });
        }
    }

    fn onMempoolInv(self: *Self, peer: *network.Peer, msg: network.message_types.MempoolInvMessage) !void {
        std.log.info("📥 [MEMPOOL] Received {} transaction hashes from peer {}", .{ msg.tx_hashes.len, peer.id });

        {
            const mempool = self.blockchain.mempool_manager;
            var requested_count: usize = 0;

            // Request transactions we don't have
            for (msg.tx_hashes) |tx_hash| {
                // Check if we already have this transaction
                if (mempool.getTransaction(tx_hash) == null) {
                    // We don't have it, request it from the peer
                    // For now, we'll log this. In a full implementation, we'd send a
                    // getdata message or similar to request the full transaction
                    requested_count += 1;

                    // TODO: Send request for full transaction data
                    // This would require implementing a getdata/inv protocol similar to Bitcoin
                    std.log.debug("📋 [MEMPOOL] Need to request transaction {s}", .{
                        std.fmt.fmtSliceHexLower(&tx_hash)
                    });
                }
            }

            if (requested_count > 0) {
                std.log.info("📋 [MEMPOOL] Need to request {} transactions from peer {}", .{ requested_count, peer.id });
            } else {
                std.log.info("✅ [MEMPOOL] Already have all transactions from peer {}", .{peer.id});
            }
        }
    }

    fn onPeerDisconnected(self: *Self, peer: *network.Peer, err: anyerror) !void {
        // If sync is active and we got a block validation error, reset sync state
        if (self.blockchain.sync_manager) |sync_manager| {
            const sync_state = sync_manager.getSyncState();
            
            // Check if this is a block validation error during sync
            const is_block_error = switch (err) {
                error.InvalidPreviousHash,
                error.InvalidBlock,
                error.InvalidDifficulty,
                error.InvalidProofOfWork => true,
                else => false,
            };
            
            if (sync_state.isActive() and is_block_error) {
                std.log.info("🔄 [SYNC] Resetting sync state due to block validation error: {}", .{err});
                // Reset sync to allow retry with next peer
                sync_manager.batch_sync.failSync("Block validation failed");
                sync_manager.sync_state = .idle;  // Also reset manager state
            }
        }
        
        _ = peer;
    }
};

// Global wrapper functions for function pointers
fn getHeightGlobal() anyerror!u32 {
    return global_handler.?.getHeight();
}

fn getBestBlockHashGlobal() anyerror![32]u8 {
    return global_handler.?.getBestBlockHash();
}

fn getGenesisHashGlobal() anyerror![32]u8 {
    return global_handler.?.getGenesisHash();
}

fn getCurrentDifficultyGlobal() anyerror!u64 {
    return global_handler.?.getCurrentDifficulty();
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

fn onGetMempoolGlobal(peer: *network.Peer) anyerror!void {
    return global_handler.?.onGetMempool(peer);
}

fn onMempoolInvGlobal(peer: *network.Peer, msg: network.message_types.MempoolInvMessage) anyerror!void {
    return global_handler.?.onMempoolInv(peer, msg);
}

fn onPeerDisconnectedGlobal(peer: *network.Peer, err: anyerror) anyerror!void {
    if (global_handler) |handler| {
        return handler.onPeerDisconnected(peer, err);
    }
}