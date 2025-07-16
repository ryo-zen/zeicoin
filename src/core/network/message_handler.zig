const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const net = @import("peer.zig");
const forkmanager = @import("../fork/main.zig");
const sync_mod = @import("../sync/sync.zig");

const ZeiCoin = @import("../node.zig").ZeiCoin;
const Transaction = types.Transaction;
const Block = types.Block;

pub const NetworkMessageHandler = struct {
    allocator: std.mem.Allocator,
    blockchain: *ZeiCoin,
    
    const Self = @This();
    
    /// Initialize message handler
    pub fn init(allocator: std.mem.Allocator, blockchain: *ZeiCoin) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
        };
    }
    
    /// Cleanup message handler resources
    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to cleanup currently
    }
    
    /// Handle incoming block from network peer with longest chain consensus
    /// NOTE: We take ownership of the block - the caller transfers ownership to us.
    pub fn handleIncomingBlock(self: *Self, block: Block, peer: ?*net.Peer) !void {
        // Take ownership - we'll transfer it to chain_processor if accepted
        var owned_block = block;
        // Note: Manual cleanup needed - we may transfer ownership
        
        // Log peer info if available
        if (peer) |p| {
            print("🌊 Block flows in from peer {} with {} transactions\n", .{p.id, block.transactions.len});
        } else {
            print("🌊 Block flows in from network peer with {} transactions\n", .{block.transactions.len});
        }
        
        const current_height = try self.blockchain.getHeight();
        const block_height = current_height + 1; // Block would be at next height if accepted

        // First validate the block before fork evaluation
        const is_valid = self.blockchain.validateBlock(owned_block, block_height) catch |err| {
            print("❌ Block validation failed: {}\n", .{err});
            owned_block.deinit(self.allocator); // Clean up on validation failure
            return;
        };
        
        if (!is_valid) {
            print("❌ Invalid block rejected\n", .{});
            owned_block.deinit(self.allocator); // Clean up invalid block
            return;
        }

        // Calculate cumulative work for this block
        const block_work = owned_block.header.getWork();
        const cumulative_work = if (current_height > 0) parent_calc: {
            // Get parent block work
            var parent_block = self.blockchain.database.getBlock(current_height - 1) catch {
                print("❌ Cannot find parent block for height {}\n", .{current_height - 1});
                owned_block.deinit(self.allocator); // Clean up on error
                return;
            };
            defer parent_block.deinit(self.allocator);

            // Get current total work from chain operations
            const parent_work = self.blockchain.getTotalWork() catch 0;
            break :parent_calc parent_work + block_work;
        } else block_work;

        // Evaluate block using fork manager
        const decision = self.blockchain.fork_manager.evaluateBlock(owned_block, block_height, cumulative_work) catch |err| {
            print("❌ Fork evaluation failed: {}\n", .{err});
            owned_block.deinit(self.allocator); // Clean up on error
            return;
        };

        switch (decision) {
            .ignore => {
                print("🌊 Block already seen - gracefully ignored\n", .{});
                owned_block.deinit(self.allocator); // Clean up ignored block
                return;
            },
            .store_orphan => {
                print("🔀 Block stored as orphan - waiting for parent\n", .{});
                // Note: ForkManager takes ownership when storing orphan, so no cleanup needed

                // Auto-sync logic: If we're storing orphan blocks, we're likely behind
                // The block was stored as orphan, which means it doesn't fit our current chain
                // This indicates we're likely behind - trigger auto-sync to catch up
                print("🔄 Orphan block detected - we may be behind, triggering auto-sync\n", .{});

                // Use a defer to ensure auto-sync happens after current processing completes
                // This avoids any issues with peer references during message handling
                defer {
                    self.triggerAutoSyncWithPeerQuery() catch |err| {
                        print("⚠️  Auto-sync trigger failed: {}\n", .{err});
                    };
                }
                return;
            },
            .extends_chain => |chain_info| {
                if (chain_info.requires_reorg) {
                    print("🏆 New best chain detected! Starting reorganization...\n", .{});
                    
                    // Import modern reorganization architecture
                    const ReorgManager = @import("../chain/reorganization/manager.zig").ReorgManager;
                    const ChainValidator = @import("../chain/validator.zig").ChainValidator;
                    const ChainOperations = @import("../chain/operations.zig").ChainOperations;
                    
                    // Initialize reorganization components
                    var chain_validator = ChainValidator.init(self.allocator, &self.blockchain.chain_state);
                    defer chain_validator.deinit();
                    
                    var chain_operations = ChainOperations.init(
                        self.allocator,
                        &self.blockchain.chain_state,
                        &chain_validator
                    );
                    defer chain_operations.deinit();
                    
                    // Initialize modern reorganization manager
                    var reorg_manager = ReorgManager.init(
                        self.allocator,
                        &self.blockchain.chain_state,
                        &chain_validator,
                        &chain_operations,
                    ) catch |err| {
                        print("❌ Failed to initialize reorganization manager: {}\n", .{err});
                        owned_block.deinit(self.allocator);
                        return;
                    };
                    defer reorg_manager.deinit();
                    
                    // Execute complete reorganization
                    const new_chain_tip = owned_block.hash();
                    const reorg_result = reorg_manager.executeReorganization(owned_block, new_chain_tip) catch |err| {
                        print("❌ Chain reorganization failed: {}\n", .{err});
                        owned_block.deinit(self.allocator);
                        return;
                    };
                    
                    // Check reorganization result
                    if (reorg_result.success) {
                        print("✅ Modern reorganization completed successfully!\n", .{});
                        print("📊 Stats: {} blocks reverted, {} applied, {} txs replayed ({} ms)\n", .{
                            reorg_result.blocks_reverted,
                            reorg_result.blocks_applied,
                            reorg_result.transactions_replayed,
                            reorg_result.duration_ms
                        });
                        
                        // Broadcast the new block to peers (create copy for broadcast)
                        const block_copy = owned_block.dupe(self.allocator) catch |err| {
                            print("⚠️  Failed to duplicate block for broadcast: {}\n", .{err});
                            owned_block.deinit(self.allocator);
                            return;
                        };
                        
                        self.broadcastNewBlock(block_copy) catch |err| {
                            print("⚠️  Failed to broadcast reorganization block: {}\n", .{err});
                        };
                        // Cleanup handled by broadcastNewBlock
                        
                        // Original block cleanup
                        owned_block.deinit(self.allocator);
                        
                    } else {
                        print("❌ Reorganization failed: {s}\n", .{reorg_result.error_message orelse "Unknown error"});
                        owned_block.deinit(self.allocator);
                    }
                } else {
                    // Block extends the main chain - add it!
                    print("📈 Block extends main chain - adding to blockchain\n", .{});
                    
                    // Create a deep copy of the block for chain processor
                    // This is necessary because broadcastNewBlock also needs the block
                    var block_copy = try owned_block.dupe(self.allocator);
                    
                    // Transfer ownership to chain processor
                    self.blockchain.chain_processor.addBlockToChain(block_copy, block_height) catch |err| {
                        print("❌ Failed to add block to chain: {}\n", .{err});
                        block_copy.deinit(self.allocator); // Clean up on error
                        owned_block.deinit(self.allocator); // Clean up original too
                        return;
                    };
                    // Note: chain_processor now owns block_copy
                    
                    // Broadcast the new block to peers (using original)
                    self.broadcastNewBlock(owned_block) catch |err| {
                        print("⚠️  Failed to broadcast block: {}\n", .{err});
                    };
                    // Cleanup handled by broadcastNewBlock
                }
            },
            .new_best_chain => |chain_index| {
                print("🏆 New best chain {} detected!\n", .{chain_index});
                // For now, if this is chain 0 (main chain), add the block
                if (chain_index == 0) {
                    print("📈 Block creates new best chain - adding to blockchain\n", .{});
                    
                    // Create a deep copy of the block for chain processor
                    // This is necessary because broadcastNewBlock also needs the block
                    var block_copy = try owned_block.dupe(self.allocator);
                    
                    // Transfer ownership to chain processor
                    self.blockchain.chain_processor.addBlockToChain(block_copy, block_height) catch |err| {
                        print("❌ Failed to add block to chain: {}\n", .{err});
                        block_copy.deinit(self.allocator); // Clean up on error
                        owned_block.deinit(self.allocator); // Clean up original too
                        return;
                    };
                    // Note: chain_processor now owns block_copy
                    
                    // Broadcast the new block to peers (using original)
                    self.broadcastNewBlock(owned_block) catch |err| {
                        print("⚠️  Failed to broadcast block: {}\n", .{err});
                    };
                    // Cleanup handled by broadcastNewBlock
                } else {
                    // Handle side chain block
                    print("📦 Processing side chain block (chain {})\n", .{chain_index});
                    
                    // Get block work (use existing getWork method)
                    const side_block_work = owned_block.header.getWork();
                    
                    // Add to side chain manager
                    const side_chain_action = self.blockchain.fork_manager.handleSideChainBlock(
                        owned_block,
                        owned_block.header.previous_hash,
                        block_height - 1, // Parent height
                        side_block_work
                    ) catch |err| {
                        print("❌ Failed to handle side chain block: {}\n", .{err});
                        owned_block.deinit(self.allocator);
                        return;
                    };
                    
                    // Handle the result
                    switch (side_chain_action) {
                        .stored => {
                            print("✅ Side chain block stored successfully\n", .{});
                            // Check if this side chain should trigger reorganization
                            if (self.blockchain.fork_manager.getActiveChain()) |active_chain| {
                                if (self.blockchain.fork_manager.evaluateSideChains(active_chain.cumulative_work)) |_| {
                                    print("🏆 Side chain has more work! Triggering reorganization\n", .{});
                                    // TODO: Implement side chain reorganization
                                    print("⚠️ Side chain reorganization not yet implemented\n", .{});
                                }
                            }
                        },
                        .rejected => {
                            print("❌ Side chain block rejected (capacity/limits)\n", .{});
                            owned_block.deinit(self.allocator);
                        },
                        else => {
                            owned_block.deinit(self.allocator);
                        },
                    }
                }
            },
        }
    }
    
    /// Handle incoming transaction from network peer  
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction, peer: ?*net.Peer) !void {
        // Log peer info if available
        if (peer) |p| {
            print("💰 Transaction received from peer {}\n", .{p.id});
        } else {
            print("💰 Transaction received from network peer\n", .{});
        }
        
        // Forward to blockchain's transaction handler
        // The mempool manager will handle validation and broadcasting
        try self.blockchain.handleIncomingTransaction(transaction);
        
        print("✅ Transaction processed successfully\n", .{});
    }
    
    /// Broadcast new block to network peers
    pub fn broadcastNewBlock(self: *Self, block: Block) !void {
        if (self.blockchain.network_coordinator.getNetworkManager()) |network| {
            print("📡 Broadcasting new block to {} peers\n", .{network.peer_manager.getConnectedCount()});
            try network.broadcastBlock(block);
        } else {
            print("⚠️  No network manager - block not broadcasted\n", .{});
        }
    }
    
    /// Check connected peers for new blocks (periodic operation)
    /// Periodically check connected peers for new blocks when synced
    pub fn checkForNewBlocks(self: *Self) !void {
        // Only check if we're not already syncing
        if (self.getSyncState() != .synced) {
            return;
        }

        if (self.blockchain.network == null) {
            return;
        }

        const network = self.blockchain.network.?;

        // Only query one random connected peer to reduce message traffic
        network.peers_mutex.lock();
        defer network.peers_mutex.unlock();

        var connected_count: usize = 0;
        for (network.peers.items) |peer| {
            if (peer.state == .connected) connected_count += 1;
        }

        if (connected_count == 0) return;

        // Find a connected peer to query (simple round-robin approach)
        var peer_index: usize = 0;
        for (network.peers.items, 0..) |*peer, i| {
            if (peer.state == .connected) {
                peer_index = i;
                break;
            }
        }

        // Query only one peer to avoid message storm
        if (peer_index < network.peers.items.len) {
            const peer = &network.peers.items[peer_index];
            if (peer.state == .connected) {
                self.requestHeightUpdate(peer) catch {
                    // If height request fails, peer might be disconnected
                    print("⚠️  Height request failed for peer {}\n", .{peer.address});
                };
            }
        }
    }
    
    /// Handle chain reorganization when better chain is found
    pub fn handleChainReorganization(self: *Self, new_block: Block, new_chain_state: types.ChainState) !void {
        const current_height = try self.blockchain.getHeight();

        // Safety check: prevent very deep reorganizations
        if (self.blockchain.fork_manager.isReorgTooDeep(current_height, new_chain_state.tip_height)) {
            print("❌ Reorganization too deep ({} -> {}) - rejected for safety\n", .{ current_height, new_chain_state.tip_height });
            return;
        }

        print("🔄 Starting reorganization: {} -> {} (depth: {})\n", .{ current_height, new_chain_state.tip_height, if (current_height > new_chain_state.tip_height) current_height - new_chain_state.tip_height else new_chain_state.tip_height - current_height });

        // Find common ancestor (simplified - assume we need to rebuild from genesis for now)
        const common_ancestor_height = try self.findCommonAncestor(new_chain_state.tip_hash);

        if (common_ancestor_height == 0) {
            print("⚠️ Deep reorganization required - rebuilding from genesis\n", .{});
        }

        // Rollback to common ancestor (no transaction backup needed - new block contains valid transactions)
        try self.blockchain.rollbackToHeight(common_ancestor_height);

        // Accept the new block (this will become the new tip)
        try self.blockchain.acceptBlock(new_block);

        // Update fork manager
        self.blockchain.fork_manager.updateChain(0, new_chain_state); // Update main chain

        print("✅ Reorganization complete! New chain tip: {s}\n", .{std.fmt.fmtSliceHexLower(new_chain_state.tip_hash[0..8])});
    }
    
    pub fn processDownloadedBlock(self: *Self, block: Block, expected_height: u32) !void {
        if (!try self.blockchain.validateSyncBlock(block, expected_height)) {
            return error.InvalidBlock;
        }
        try self.blockchain.addBlockToChain(block, expected_height);
    }
    
    pub fn validateSyncBlock(self: *Self, block: Block, expected_height: u32) !bool {
        return try self.blockchain.validateSyncBlock(block, expected_height);
    }
    
    pub fn startNetwork(self: *Self, port: u16) !void {
        try self.blockchain.startNetwork(port);
    }
    
    pub fn stopNetwork(self: *Self) void {
        self.blockchain.stopNetwork();
    }
    
    pub fn connectToPeer(self: *Self, address: []const u8) !void {
        try self.blockchain.connectToPeer(address);
    }
    
    pub fn shouldSync(self: *Self, peer_height: u32) !bool {
        return try self.blockchain.shouldSync(peer_height);
    }
    
    /// Get current sync state for network coordination
    pub fn getSyncState(self: *Self) sync_mod.SyncState {
        // Check if sync manager is available
        if (self.blockchain.sync_manager) |sync_manager| {
            return sync_manager.getSyncState();
        }
        
        // Default to synced if no sync manager
        return .synced;
    }
    
    // Private helper functions for handleIncomingBlock
    
    /// Find common ancestor between current chain and new chain
    fn findCommonAncestor(self: *Self, new_tip_hash: types.BlockHash) !u32 {
        // Simplified: return 0 for now (rebuild from genesis)
        // In a full implementation, we'd traverse back through both chains
        _ = self;
        _ = new_tip_hash;
        return 0;
    }
    
    /// Trigger auto-sync with peer query when orphan blocks are detected
    fn triggerAutoSyncWithPeerQuery(self: *Self) !void {
        // Simplified auto-sync: just trigger sync if we have a sync manager
        if (self.blockchain.sync_manager) |sync_manager| {
            try sync_manager.startSync();
            print("🔄 Auto-sync triggered due to orphan block\n", .{});
        } else {
            print("⚠️ No sync manager available for auto-sync\n", .{});
        }
    }
    
    /// Request height update from a specific peer
    /// This sends a request to the peer to get their current blockchain height
    fn requestHeightUpdate(self: *Self, peer: *net.Peer) !void {
        // For now, we'll use a simple approach: request headers starting from our current height
        // This allows us to see if the peer has blocks beyond our current height
        const our_height = try self.blockchain.getHeight();
        
        // Request a small batch of headers starting from our current height
        // If they have more blocks, they'll send us headers and we can detect the difference
        try peer.sendGetHeaders(our_height, 1);
        
        print("📤 Requested height update from peer {} (starting from height {})\n", .{ peer.address, our_height });
    }
};