// message_handler.zig - Network Message Handler
// Handles incoming network messages and coordinates with blockchain
// Extracted from node.zig for clean separation of network concerns

const std = @import("std");
const print = std.debug.print;

const types = @import("../types/types.zig");
const util = @import("../util/util.zig");
const net = @import("peer.zig");
const forkmanager = @import("../fork/main.zig");
const headerchain = @import("headerchain.zig");
const sync_mod = @import("../sync/sync.zig");

// Forward declaration for blockchain dependency
const ZeiCoin = @import("../node.zig").ZeiCoin;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Hash = types.Hash;

/// Network Message Handler - Coordinates network messages with blockchain
/// Handles incoming blocks, transactions, and network coordination
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
        // Take ownership and ensure cleanup
        var owned_block = block;
        defer owned_block.deinit(self.allocator);
        
        // Log peer info if available
        if (peer) |p| {
            print("🌊 Block flows in from peer {} with {} transactions\n", .{p.id, block.transactions.len});
        } else {
            print("🌊 Block flows in from network peer with {} transactions\n", .{block.transactions.len});
        }
        
        const current_height = try self.blockchain.getHeight();
        const block_height = current_height + 1; // Block would be at next height if accepted

        // Calculate cumulative work for this block
        const block_work = owned_block.header.getWork();
        const cumulative_work = if (current_height > 0) parent_calc: {
            // Get parent block work
            var parent_block = self.blockchain.database.getBlock(current_height - 1) catch {
                print("❌ Cannot find parent block for height {}\n", .{current_height - 1});
                return;
            };
            defer parent_block.deinit(self.allocator);

            // For now, estimate parent cumulative work (should be stored in future)
            const parent_work = self.blockchain.estimateCumulativeWork(current_height - 1) catch 0;
            break :parent_calc parent_work + block_work;
        } else block_work;

        // Evaluate block using fork manager
        const decision = self.blockchain.fork_manager.evaluateBlock(owned_block, block_height, cumulative_work) catch |err| {
            print("❌ Fork evaluation failed: {}\n", .{err});
            return;
        };

        switch (decision) {
            .already_seen => {
                print("🌊 Block already seen - gracefully ignored\n", .{});
                return;
            },
            .orphan_stored => {
                print("🔀 Block stored as orphan - waiting for parent\n", .{});

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
                if (chain_info.is_new_best) {
                    print("🏆 New best chain detected! Starting reorganization...\n", .{});
                    try self.handleChainReorganization(owned_block, chain_info.new_chain_state);
                } else {
                    print("📈 Block extends side chain {}\n", .{chain_info.chain_index});
                    // Just update the side chain for now
                    self.blockchain.fork_manager.updateChain(chain_info.chain_index, chain_info.new_chain_state);
                }
            },
        }
    }
    
    /// Handle incoming transaction from network peer  
    pub fn handleIncomingTransaction(self: *Self, transaction: Transaction, peer: ?*net.Peer) !void {
        // Implementation will be extracted from node.zig
        _ = self;
        _ = transaction;
        _ = peer;
        print("💰 NetworkMessageHandler: Processing incoming transaction...\n", .{});
        // TODO: Extract handleIncomingTransaction implementation
    }
    
    /// Broadcast new block to network peers
    pub fn broadcastNewBlock(self: *Self, block: Block) !void {
        if (self.blockchain.network) |network| {
            print("📡 Broadcasting new block to {} peers\n", .{network.peers.items.len});
            network.broadcastBlock(block);
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
    
    /// Process downloaded block during headers-first sync
    pub fn processDownloadedBlock(self: *Self, block: Block, expected_height: u32) !void {
        // Implementation will be extracted from node.zig
        _ = self;
        _ = block;
        _ = expected_height;
        print("📥 NetworkMessageHandler: Processing downloaded block...\n", .{});
        // TODO: Extract processDownloadedBlock implementation
    }
    
    /// Validate block during sync (network-specific validation)
    pub fn validateSyncBlock(self: *Self, block: Block, expected_height: u32) !bool {
        // Implementation will be extracted from node.zig
        _ = self;
        _ = block;
        _ = expected_height;
        print("✅ NetworkMessageHandler: Validating sync block...\n", .{});
        // TODO: Extract validateSyncBlock implementation
        return true;
    }
    
    /// Network management functions
    
    /// Start network operations
    pub fn startNetwork(self: *Self) !void {
        _ = self;
        print("🌐 NetworkMessageHandler: Starting network operations...\n", .{});
        // TODO: Extract startNetwork implementation
    }
    
    /// Stop network operations
    pub fn stopNetwork(self: *Self) void {
        _ = self;
        print("🛑 NetworkMessageHandler: Stopping network operations...\n", .{});
        // TODO: Extract stopNetwork implementation
    }
    
    /// Connect to a specific peer
    pub fn connectToPeer(self: *Self, peer: *net.Peer) !void {
        _ = self;
        _ = peer;
        print("🤝 NetworkMessageHandler: Connecting to peer...\n", .{});
        // TODO: Extract connectToPeer implementation
    }
    
    /// Check if sync is needed with peer
    pub fn shouldSync(self: *Self, peer_height: u32) !bool {
        _ = self;
        _ = peer_height;
        print("🔍 NetworkMessageHandler: Checking if sync needed...\n", .{});
        // TODO: Extract shouldSync implementation
        return false;
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
        // Delegate to blockchain's sync system
        // This will query peers for their heights and trigger sync if needed
        if (self.blockchain.network) |network| {
            try network.triggerAutoSyncWithPeerQuery();
        } else {
            print("⚠️ No network available for auto-sync\n", .{});
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