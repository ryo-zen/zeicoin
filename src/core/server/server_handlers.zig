// server_handlers.zig - Server-side network message handler implementations
// Handles all incoming network messages for the server

const std = @import("std");
const network = @import("../network/peer.zig");
const types = @import("../types/types.zig");
const zen = @import("../node.zig");
const sync = @import("../sync/manager.zig");
const util = @import("../util/util.zig");

// Global handler for function pointer access
var global_handler: ?*ServerHandlers = null;

// Clear global handler (call during cleanup)
pub fn clearGlobalHandler() void {
    global_handler = null;
}

/// Compare two hashes lexicographically (Ethereum-style tie-breaker)
/// Returns: positive if hash1 > hash2, negative if hash1 < hash2, zero if equal
fn compareHashes(hash1: *const [32]u8, hash2: *const [32]u8) i32 {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        if (hash1[i] > hash2[i]) return 1;
        if (hash1[i] < hash2[i]) return -1;
    }
    return 0; // Hashes are equal
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
            .onGetMissingBlocks = onGetMissingBlocksGlobal,
            .onMissingBlocksResponse = onMissingBlocksResponseGlobal,
            .onGetChainWork = onGetChainWorkGlobal,
            .onChainWorkResponse = onChainWorkResponseGlobal,
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
        std.log.info("🔍 [PEER CONNECT] Peer best hash: {s}", .{std.fmt.fmtSliceHexLower(&peer.best_block_hash)});
        std.log.info("🔍 [PEER CONNECT] Our best hash:  {s}", .{std.fmt.fmtSliceHexLower(&our_best_hash)});

        // Check for chain divergence first (equal height, different hash)
        const has_diverged = (peer.height == our_height and !std.mem.eql(u8, &peer.best_block_hash, &our_best_hash));
        if (has_diverged) {
            std.log.warn("⚠️ [CHAIN DIVERGENCE] Detected at height {}", .{our_height});
            std.log.warn("📊 Peer hash: {s}", .{std.fmt.fmtSliceHexLower(&peer.best_block_hash)});
            std.log.warn("📊 Our hash:  {s}", .{std.fmt.fmtSliceHexLower(&our_best_hash)});

            // FORK RESOLUTION: Trigger fork detection to find fork point and compare cumulative work
            // This handles network partition scenarios where both miners built separate chains
            std.log.warn("🔄 [FORK RESOLUTION] Triggering fork detection and cumulative work comparison", .{});

            if (self.blockchain.sync_manager) |sync_manager| {
                std.log.info("🔍 [FORK RESOLUTION] Sync manager available, initiating fork resolution", .{});

                // Check fork cooldown before attempting fork resolution
                const can_sync_at_height = sync_manager.canSyncAtForkHeight(our_height);
                std.log.info("🔍 [FORK RESOLUTION] Cooldown check for height {}: {}", .{our_height, can_sync_at_height});

                if (!can_sync_at_height) {
                    std.log.info("⏳ [FORK RESOLUTION] Height {} in cooldown, deferring fork resolution", .{our_height});
                    return;
                }

                if (sync_manager.getSyncState().canStart()) {
                    std.log.warn("🔄 [FORK RESOLUTION] Spawning fork resolution thread", .{});

                    // Increment reference count for the new thread
                    peer.addRef();

                    // Spawn thread to trigger fork resolution (blocking operation)
                    // triggerForkResolution uses force_reorg=true for fork detection at equal heights
                    _ = std.Thread.spawn(.{}, triggerForkResolution, .{ sync_manager, peer, peer.height }) catch |err| {
                        std.log.err("Failed to spawn fork resolution thread: {}", .{err});
                        peer.release();
                    };

                    std.log.warn("✅ [FORK RESOLUTION] Fork resolution thread spawned", .{});
                    return;
                } else {
                    std.log.warn("⏳ [FORK RESOLUTION] Sync cannot start (state: {}), deferring fork resolution", .{sync_manager.getSyncState()});
                    return;
                }
            } else {
                std.log.err("❌ [FORK RESOLUTION] Sync manager is null, cannot resolve fork!", .{});
                std.log.err("💡 [FORK RESOLUTION] Keeping our block (first-seen rule as fallback)", .{});
                return;
            }
        }
        // Check if we need to sync from peer (they have more blocks or are at same height - fork check)
        else if (peer.height >= our_height and peer.height > 0) {
            const blocks_behind = if (peer.height > our_height) peer.height - our_height else 0;
            if (blocks_behind > 0) {
                std.log.info("🚀 [PEER CONNECT] Peer has {} more blocks! Starting sync process...", .{blocks_behind});
            } else {
                std.log.info("🚀 [PEER CONNECT] Peer at same height! Checking for competing chain...", .{});
            }

            if (self.blockchain.sync_manager) |sync_manager| {
                std.log.info("🔄 [PEER CONNECT] Sync manager available, checking if sync can start: {}", .{sync_manager.getSyncState().canStart()});

                // CRITICAL FIX: Check fork cooldown before attempting sync on peer connection
                // This prevents immediate sync attempts after fork-related disconnections
                const can_sync_at_height = sync_manager.canSyncAtForkHeight(our_height);
                std.log.info("🔍 [PEER CONNECT] Cooldown check for current height {}: {}", .{our_height, can_sync_at_height});

                if (!can_sync_at_height) {
                    std.log.info("⏳ [PEER CONNECT] Current height {} in cooldown period, deferring sync", .{our_height});
                    std.log.info("💡 [PEER CONNECT] Sync will retry via periodic check after cooldown expires", .{});
                    std.log.info("🔗 [PEER CONNECT] Keeping peer connected for future sync attempt", .{});
                    // Keep peer connected - periodic sync retry will handle this after cooldown
                    return;
                }

                if (sync_manager.getSyncState().canStart()) {
                    if (blocks_behind > 0) {
                        std.log.info("📥 [PEER CONNECT] Starting batch sync to download {} blocks", .{blocks_behind});
                    } else {
                        std.log.info("📥 [PEER CONNECT] Checking for competing chain at height {}", .{our_height});
                    }
                    
                    // Increment reference count for the new thread
                    peer.addRef();
                    
                    // Spawn thread to initiate sync/fork-check (blocking operation)
                    _ = std.Thread.spawn(.{}, triggerStartSync, .{ sync_manager, peer, peer.height }) catch |err| {
                        std.log.err("Failed to spawn initial sync thread: {}", .{err});
                        peer.release();
                    };
                    
                    std.log.info("✅ [PEER CONNECT] Sync/Fork check thread spawned", .{});
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
        const block = msg.block;
        const block_hash = block.hash();

        std.log.info("📦 [BLOCK] Received block from {any} at height {}", .{peer.address, block.height});
        std.log.debug("   Hash: {s}", .{std.fmt.fmtSliceHexLower(&block_hash)});
        std.log.debug("   Previous: {s}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

        // Add to peer's received blocks cache for synchronous sync logic
        peer.addReceivedBlock(block) catch |err| {
            std.log.warn("⚠️ Failed to cache received block: {}", .{err});
        };

        // CRITICAL FIX: During active sync/reorg, defer block processing to sync manager
        // Blocks are cached above and will be processed by the sync protocol in correct order
        // This prevents validation failures when receiving competing chain blocks during reorg
        if (self.blockchain.sync_manager) |sync_manager| {
            if (sync_manager.isActive()) {
                std.log.info("🔄 [SYNC ACTIVE] Block height {} cached for sync processing, deferring validation", .{block.height});
                std.log.debug("   Block will be processed by sync manager in correct order", .{});
                return; // Exit early - sync manager will handle block processing
            }
        }

        // CRITICAL FIX: Update peer height when receiving blocks (Bitcoin/Ethereum style)
        // This keeps peer heights current without requiring re-handshakes
        if (block.height > peer.height) {
            std.log.info("🔧 [PEER UPDATE] Updating peer {d} height: {d} -> {d}", .{peer.id, peer.height, block.height});
            peer.height = block.height;
            peer.best_block_hash = block_hash;

            // Trigger sync/reorg check if needed
            if (self.blockchain.sync_manager) |sync_manager| {
                peer.addRef();
                _ = std.Thread.spawn(.{}, triggerPeerSync, .{ sync_manager, peer }) catch |err| {
                    std.log.err("Failed to spawn peer sync thread: {}", .{err});
                    peer.release();
                };
            }
        }

        // Check if parent block exists (orphan detection)
        const parent_hash = block.header.previous_hash;

        // Check if this is the genesis block (null parent hash = all zeros)
        const null_hash = [_]u8{0} ** 32;
        const is_genesis = std.mem.eql(u8, &parent_hash, &null_hash);

        // Genesis block should never be treated as an orphan
        if (is_genesis) {
            std.log.debug("   Genesis block detected (null parent), processing directly", .{});
        } else {
            const has_parent = self.blockchain.chain_processor.chain_state.getBlockHeight(parent_hash) != null;

            if (!has_parent) {
                std.log.info("🔍 [ORPHAN] Block parent not found!", .{});
                std.log.debug("   Missing parent: {s}", .{std.fmt.fmtSliceHexLower(&parent_hash)});

                // Add to orphan pool
                self.blockchain.chain_processor.orphan_pool.addOrphan(block) catch |err| {
                    std.log.warn("Failed to add orphan block: {}", .{err});
                    return;
                };

                // Trigger sync/reorg check via sync manager
                // This is much more efficient than requesting one block at a time
                if (self.blockchain.sync_manager) |sync_manager| {
                    peer.addRef();
                    _ = std.Thread.spawn(.{}, triggerPeerSync, .{ sync_manager, peer }) catch |err| {
                        std.log.err("Failed to spawn reorg check thread for orphan: {}", .{err});
                        peer.release();
                    };
                }

                return; // Don't process the block yet
            }
        }

        // Process block normally
        try self.blockchain.chain_processor.acceptBlock(block);

        // After successfully processing, check for orphans that can now be processed
        try self.processOrphanChain(block_hash);

        // Notify sync manager if actively syncing - allows sync completion detection
        if (self.blockchain.sync_manager) |sync_manager| {
            if (sync_manager.isActive()) {
                // Get current height after block was applied
                const height = self.blockchain.getHeight() catch 0;
                if (height > 0) {
                    sync_manager.notifyBlockReceived(height);
                }
            }
        }
    }

    /// Process any orphan blocks that can now be applied
    fn processOrphanChain(self: *Self, parent_hash: [32]u8) !void {
        var current_hash = parent_hash;
        var processed_count: usize = 0;

        std.log.info("🔗 [ORPHAN] Checking for orphan blocks to process...", .{});

        // Keep processing orphans in a chain
        while (self.blockchain.chain_processor.orphan_pool.hasOrphansForParent(current_hash)) {
            // Get all orphans that reference this parent
            const orphans_opt = self.blockchain.chain_processor.orphan_pool.getOrphansByParent(current_hash);
            if (orphans_opt == null) break;

            const orphans = orphans_opt.?;
            defer self.blockchain.allocator.free(orphans);

            std.log.info("   Found {} orphan(s) ready to process", .{orphans.len});

            // Process each orphan
            for (orphans) |orphan_block| {
                std.log.info("   Processing orphan at height {}", .{orphan_block.height});

                // Process directly through acceptBlock to avoid recursion issues
                const orphan_hash = orphan_block.hash();
                self.blockchain.chain_processor.acceptBlock(orphan_block) catch |err| {
                    std.log.warn("   ❌ Orphan block processing failed: {}", .{err});
                    continue;
                };

                processed_count += 1;
                current_hash = orphan_hash; // Continue chain
                std.log.info("   ✅ Orphan block processed successfully", .{});

                // After processing, recursively check for more orphans
                self.processOrphanChain(orphan_hash) catch |err| {
                    std.log.warn("   ⚠️ Orphan chain processing error: {}", .{err});
                };
            }
        }

        if (processed_count > 0) {
            std.log.info("✅ [ORPHAN] Processed {} orphan block(s)", .{processed_count});
        } else {
            std.log.debug("   No orphans found for this block", .{});
        }
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

        if (msg.exists) {
            std.log.info("✓ [BLOCK_HASH] Peer {any} has block at height {} with hash {}", .{ peer.address, msg.height, std.fmt.fmtSliceHexUpper(&msg.hash) });
        } else {
            std.log.info("✗ [BLOCK_HASH] Peer {any} does not have block at height {}", .{ peer.address, msg.height });
        }

        // Queue the response for fork detection (used by fork_detector.zig)
        try peer.queueBlockHashResponse(msg.height, msg.hash, msg.exists);

        _ = self; // Unused in current implementation
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

    fn onGetMissingBlocks(self: *Self, peer: *network.Peer, msg: network.message_types.GetMissingBlocksMessage) !void {
        std.log.info("📤 [REQUEST] Peer {} requesting {} missing block(s)", .{
            peer.id,
            msg.block_hashes.items.len,
        });

        // Create response
        var response = network.message_types.MissingBlocksResponseMessage.init(self.blockchain.allocator);
        defer response.deinit(self.blockchain.allocator);

        // Look up each requested block
        for (msg.block_hashes.items) |block_hash| {
            std.log.debug("   Looking for: {s}", .{std.fmt.fmtSliceHexLower(&block_hash)});

            // Try to find block by hash
            if (try self.findBlockByHash(block_hash)) |block| {
                try response.addBlock(block);
                std.log.debug("   ✅ Found block at height {}", .{block.height});
            } else {
                std.log.debug("   ❌ Block not found", .{});
            }
        }

        // Send response (even if empty - tells peer we don't have them)
        _ = try peer.sendMessage(.missing_blocks_response, response);

        std.log.info("✅ [REQUEST] Sent {} block(s) in response", .{response.blocks.items.len});
    }

    fn onMissingBlocksResponse(self: *Self, peer: *network.Peer, msg: network.message_types.MissingBlocksResponseMessage) !void {
        std.log.info("📥 [RESPONSE] Received {} missing block(s) from peer {}", .{
            msg.blocks.items.len,
            peer.id,
        });

        // Process each received block through the normal block handler
        // This handles orphan resolution - blocks are validated and added to the chain
        for (msg.blocks.items) |block| {
            std.log.debug("   Processing block at height {}", .{block.height});

            // Create a BlockMessage wrapper
            const block_msg = network.message_types.BlockMessage{ .block = block };
            try self.onBlock(peer, block_msg);
        }

        std.log.info("✅ [RESPONSE] All missing blocks processed", .{});
    }

    fn onGetChainWork(self: *Self, peer: *network.Peer, msg: network.message_types.GetChainWorkMessage) !void {
        std.log.info("📊 [GET_CHAIN_WORK] Request for range {}-{} from {any}", .{
            msg.start_height,
            msg.end_height,
            peer.address,
        });

        // Calculate cumulative chain work for the requested range
        var total_work: types.ChainWork = 0;

        var height = msg.start_height;
        while (height <= msg.end_height) : (height += 1) {
            // Get block at this height
            var block = try self.blockchain.database.getBlock(height);
            defer block.deinit(self.blockchain.allocator);

            // Add this block's work to the total
            const block_work = block.header.getWork();
            total_work += block_work;
        }

        std.log.info("📊 [GET_CHAIN_WORK] Calculated work: {}", .{total_work});

        // Send response
        const response = network.message_types.ChainWorkResponseMessage{
            .total_work = total_work,
        };
        _ = try peer.sendMessage(.chain_work_response, response);

        std.log.info("✅ [GET_CHAIN_WORK] Sent chain work response to peer", .{});
    }

    fn onChainWorkResponse(self: *Self, peer: *network.Peer, msg: network.message_types.ChainWorkResponseMessage) !void {
        std.log.info("📥 [CHAIN_WORK] Response from {any}: total_work={}", .{
            peer.address,
            msg.total_work,
        });

        // Queue the response for fork detection (used by fork_detector.zig)
        peer.queueChainWorkResponse(msg.total_work);

        _ = self; // Unused in current implementation
    }

    /// Find a block by its hash in our blockchain
    fn findBlockByHash(self: *Self, block_hash: [32]u8) !?types.Block {
        // Get current chain height
        const current_height = try self.blockchain.database.getHeight();

        // Search through blocks (from recent to old for better cache locality)
        // Must check current_height down to 0 (inclusive), avoiding unsigned underflow
        var height: u32 = current_height;
        while (true) {
            const block = try self.blockchain.database.getBlock(height);
            const hash = block.hash();
            if (std.mem.eql(u8, &hash, &block_hash)) {
                return block;
            }

            // Break before decrementing to avoid underflow at height 0
            if (height == 0) break;
            height -= 1;
        }

        return null;
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

                // Add 30-second fork cooldown to prevent immediate retry loops
                const current_height = self.blockchain.getHeight() catch 0;
                sync_manager.addForkCooldown(current_height, 30) catch |cooldown_err| {
                    std.log.warn("Failed to add fork cooldown: {}", .{cooldown_err});
                };

                // Record failure on peer
                peer.failure_reason = @errorName(err);
                peer.recordFailedRequest();

                // Reset sync (existing code)
                sync_manager.batch_sync.failSync("Block validation failed");
                sync_manager.sync_state = .idle; // Also reset manager state

                std.log.info("💡 [SYNC] Automatic sync retry will occur after cooldown period", .{});
            }
        }
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

fn triggerStartSync(sync_manager: *sync.SyncManager, peer: *network.Peer, target_height: u32) void {
    defer peer.release();
    sync_manager.startSync(peer, target_height, false) catch |err| {
        std.log.err("Asynchronous startSync failed: {}", .{err});
    };
}

/// Trigger fork resolution with force_reorg=true for equal-height divergence
fn triggerForkResolution(sync_manager: *sync.SyncManager, peer: *network.Peer, target_height: u32) void {
    defer peer.release();
    sync_manager.startSync(peer, target_height, true) catch |err| {
        std.log.err("Asynchronous fork resolution failed: {}", .{err});
    };
}

/// Global callback for sync manager to start sync from thread
fn triggerPeerSync(sync_manager: *sync.SyncManager, peer: *network.Peer) void {
    defer peer.release();
    sync_manager.handlePeerSync(peer) catch |err| {
        std.log.err("Asynchronous peer sync failed: {}", .{err});
    };
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

fn onGetMissingBlocksGlobal(peer: *network.Peer, msg: network.message_types.GetMissingBlocksMessage) anyerror!void {
    return global_handler.?.onGetMissingBlocks(peer, msg);
}

fn onMissingBlocksResponseGlobal(peer: *network.Peer, msg: network.message_types.MissingBlocksResponseMessage) anyerror!void {
    return global_handler.?.onMissingBlocksResponse(peer, msg);
}

fn onGetChainWorkGlobal(peer: *network.Peer, msg: network.message_types.GetChainWorkMessage) anyerror!void {
    return global_handler.?.onGetChainWork(peer, msg);
}

fn onChainWorkResponseGlobal(peer: *network.Peer, msg: network.message_types.ChainWorkResponseMessage) anyerror!void {
    return global_handler.?.onChainWorkResponse(peer, msg);
}

fn onPeerDisconnectedGlobal(peer: *network.Peer, err: anyerror) anyerror!void {
    if (global_handler) |handler| {
        return handler.onPeerDisconnected(peer, err);
    }
}