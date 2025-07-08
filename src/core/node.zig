// ZeiCoin Blockchain Core - Node coordinator with modular architecture

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;

const types = @import("types/types.zig");
const util = @import("util/util.zig");
const serialize = @import("storage/serialize.zig");
const db = @import("storage/db.zig");
const key = @import("crypto/key.zig");
const net = @import("network/peer.zig");
const randomx = @import("crypto/randomx.zig");
const genesis = @import("chain/genesis.zig");
const forkmanager = @import("fork/main.zig");
const headerchain = @import("network/headerchain.zig");
const sync = @import("network/sync.zig");
const sync_mod = @import("sync/sync.zig");
const message_handler = @import("network/message_handler.zig");
const validator_mod = @import("validation/validator.zig");
const miner_mod = @import("miner/main.zig");
const MempoolManager = @import("mempool/manager.zig").MempoolManager;

// Type aliases
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

// Import new modular components
const ChainQuery = @import("chain/query.zig").ChainQuery;
const ChainProcessor = @import("chain/processor.zig").ChainProcessor;
const DifficultyCalculator = @import("chain/difficulty.zig").DifficultyCalculator;
const StatusReporter = @import("monitoring/status.zig").StatusReporter;

pub const ZeiCoin = struct {
    database: *db.Database,
    chain_state: @import("chain/state.zig").ChainState,
    network: ?*net.NetworkManager,
    allocator: std.mem.Allocator,
    fork_manager: forkmanager.ForkManager,
    header_chain: headerchain.HeaderChain,
    sync_manager: ?*sync.SyncManager,
    sync_state: sync_mod.SyncState,
    sync_progress: ?sync_mod.SyncProgress,
    sync_peer: ?*net.Peer,
    failed_peers: ArrayList(*net.Peer),
    blocks_to_download: ArrayList(u32),
    active_block_downloads: std.AutoHashMap(u32, i64),
    headers_progress: ?sync_mod.HeadersProgress,
    message_handler: message_handler.NetworkMessageHandler,
    chain_validator: validator_mod.ChainValidator,
    chain_query: ChainQuery,
    chain_processor: ChainProcessor,
    difficulty_calculator: DifficultyCalculator,
    status_reporter: StatusReporter,
    mempool_manager: *MempoolManager,
    mining_state: types.MiningState,
    mining_manager: ?*miner_mod.MiningManager,

    pub fn init(allocator: std.mem.Allocator) !*ZeiCoin {
        const data_dir = switch (types.CURRENT_NETWORK) {
            .testnet => "zeicoin_data_testnet",
            .mainnet => "zeicoin_data_mainnet",
        };
        
        // PHASE 1: Create core resources with guaranteed cleanup
        const database = try allocator.create(db.Database);
        errdefer allocator.destroy(database);
        
        database.* = try db.Database.init(allocator, data_dir);
        errdefer database.deinit();
        
        if (!database.validate()) {
            print("❌ Database validation failed during initialization\n", .{});
            return error.DatabaseCorrupted;
        }
        
        // Pre-allocate ZeiCoin on heap to get stable memory address
        const instance_ptr = try allocator.create(ZeiCoin);
        errdefer allocator.destroy(instance_ptr);
        
        // Initialize all collections with proper cleanup
        var failed_peers = ArrayList(*net.Peer).init(allocator);
        errdefer failed_peers.deinit();
        
        var blocks_to_download = ArrayList(u32).init(allocator);
        errdefer blocks_to_download.deinit();
        
        var active_block_downloads = std.AutoHashMap(u32, i64).init(allocator);
        errdefer active_block_downloads.deinit();
        
        var fork_manager = forkmanager.ForkManager.init(allocator);
        errdefer fork_manager.deinit();
        
        var header_chain = headerchain.HeaderChain.init(allocator);
        errdefer header_chain.deinit();
        
        const chain_state = @import("chain/state.zig").ChainState.init(allocator, database);
        
        // PHASE 2: Initialize struct in stable memory location
        instance_ptr.* = ZeiCoin{
            .database = database,
            .chain_state = chain_state,
            .network = null,
            .allocator = allocator,
            .fork_manager = fork_manager,
            .header_chain = header_chain,
            .sync_manager = null,
            .sync_state = .synced,
            .sync_progress = null,
            .sync_peer = null,
            .failed_peers = failed_peers,
            .blocks_to_download = blocks_to_download,
            .active_block_downloads = active_block_downloads,
            .headers_progress = null,
            .message_handler = undefined,
            .chain_validator = undefined,
            .chain_query = undefined,
            .chain_processor = undefined,
            .difficulty_calculator = undefined,
            .status_reporter = undefined,
            .mempool_manager = undefined,
            .mining_state = types.MiningState.init(),
            .mining_manager = null,
        };
        
        // Custom cleanup function for partial initialization
        var components_initialized: u8 = 0;
        errdefer {
            // Clean up components in reverse order
            if (components_initialized >= 7) {
                instance_ptr.mempool_manager.deinit(); // This will also free the mempool_manager
            }
            if (components_initialized >= 6) instance_ptr.status_reporter.deinit();
            if (components_initialized >= 5) instance_ptr.difficulty_calculator.deinit();
            if (components_initialized >= 4) instance_ptr.chain_processor.deinit();
            if (components_initialized >= 3) instance_ptr.chain_query.deinit();
            if (components_initialized >= 2) instance_ptr.chain_validator.deinit();
            if (components_initialized >= 1) instance_ptr.message_handler.deinit();
        }

        // PHASE 3: Initialize components with stable instance address
        // Now &instance_ptr points to stable memory, safe to pass to components
        
        instance_ptr.message_handler = message_handler.NetworkMessageHandler.init(allocator, instance_ptr);
        components_initialized = 1;
        
        if (!database.validate()) {
            print("❌ Database corrupted after message_handler init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.chain_validator = validator_mod.ChainValidator.init(allocator, instance_ptr);
        components_initialized = 2;
        
        if (!database.validate()) {
            print("❌ Database corrupted after chain_validator init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.chain_query = ChainQuery.init(allocator, instance_ptr.database, &instance_ptr.chain_state);
        components_initialized = 3;
        
        if (!database.validate()) {
            print("❌ Database corrupted after chain_query init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.chain_processor = ChainProcessor.init(allocator, instance_ptr.database, &instance_ptr.chain_state, &instance_ptr.fork_manager, &instance_ptr.chain_validator);
        components_initialized = 4;
        
        if (!database.validate()) {
            print("❌ Database corrupted after chain_processor init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.difficulty_calculator = DifficultyCalculator.init(allocator, instance_ptr.database);
        components_initialized = 5;
        
        if (!database.validate()) {
            print("❌ Database corrupted after difficulty_calculator init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.status_reporter = StatusReporter.init(allocator, instance_ptr.database, &instance_ptr.network);
        components_initialized = 6;
        
        if (!database.validate()) {
            print("❌ Database corrupted after status_reporter init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.mempool_manager = try MempoolManager.init(allocator, &instance_ptr.chain_state);
        components_initialized = 7;
        
        // Connect MempoolManager to MiningState
        instance_ptr.mempool_manager.setMiningState(&instance_ptr.mining_state);
        
        if (!database.validate()) {
            print("❌ Database corrupted after mempool_manager init\n", .{});
            return error.DatabaseCorrupted;
        }

        // PHASE 4: Initialize blockchain data
        if (try instance_ptr.getHeight() == 0) {
            print("🌐 No blockchain found - creating canonical genesis block\n", .{});
            try instance_ptr.createCanonicalGenesis();
            print("✅ Genesis block created successfully!\n", .{});
        } else {
            const height = try instance_ptr.getHeight();
            print("📊 Existing blockchain found with {} blocks\n", .{height});
        }

        if (!database.validate()) {
            print("❌ Database corrupted after full initialization\n", .{});
            return error.DatabaseCorrupted;
        }

        print("✅ ZeiCoin initialization completed successfully\n", .{});
        
        // Return pointer directly, transferring ownership to caller
        return instance_ptr;
    }

    pub fn initializeBlockchain(self: *ZeiCoin) !void {
        const current_height = try self.getHeight();
        print("🔗 Blockchain initialized at height {}, ready for network sync\n", .{current_height});
    }

    pub fn deinit(self: *ZeiCoin) void {
        print("🧹 Starting ZeiCoin cleanup...\n", .{});
        
        // Validate Database integrity before cleanup
        if (!self.database.validate()) {
            print("⚠️ Database corruption detected during cleanup!\n", .{});
        }
        
        // Clean up in REVERSE order of initialization
        // Components first (they may access Database during cleanup)
        
        // Step 1: Stop mining if active
        if (self.mining_manager) |manager| {
            manager.stopMining();
            self.allocator.destroy(manager);
        }
        self.mining_state.deinit();
        
        // Step 2: Clean up high-level components
        self.mempool_manager.deinit(); // This will also free self.mempool_manager
        self.status_reporter.deinit();
        self.difficulty_calculator.deinit();
        self.chain_processor.deinit();
        self.chain_query.deinit();
        self.chain_validator.deinit();
        self.message_handler.deinit();
        
        // Step 3: Clean up collections
        self.active_block_downloads.deinit();
        self.blocks_to_download.deinit();
        self.failed_peers.deinit();
        
        // Step 4: Clean up core components
        self.header_chain.deinit();
        self.fork_manager.deinit();
        
        // Step 5: Clean up sync manager if allocated
        if (self.sync_manager) |sm| {
            sm.deinit();
            self.allocator.destroy(sm);
        }
        
        // Step 6: Clean up ChainState (does NOT touch Database)
        self.chain_state.deinit();
        
        // Step 7: Finally clean up Database (owned by ZeiCoin)
        // Use defer to ensure this happens even if something above fails
        defer self.allocator.destroy(self.database);
        defer self.database.deinit();
        
        print("✅ ZeiCoin cleanup completed\n", .{});
    }

    fn createCanonicalGenesis(self: *ZeiCoin) !void {
        var genesis_block = try genesis.createGenesis(self.allocator);
        defer genesis_block.deinit(self.allocator);
        for (genesis_block.transactions) |tx| {
            if (tx.isCoinbase()) {
                try self.chain_state.processCoinbaseTransaction(tx, tx.recipient, 0);
            }
        }
        try self.database.saveBlock(0, genesis_block);

        // Initialize fork manager with genesis
        const genesis_hash = genesis_block.hash();
        const genesis_work = genesis_block.header.getWork();
        self.fork_manager.initWithGenesis(genesis_hash, genesis_work);

        print("\n🎉 ===============================================\n", .{});
        print("🎉 GENESIS BLOCK CREATED SUCCESSFULLY!\n", .{});
        print("🎉 ===============================================\n", .{});
        print("📦 Block Height: 0\n", .{});
        print("📦 Transactions: {}\n", .{genesis_block.txCount()});
        print("🌐 Network: {s} (Canonical Genesis)\n", .{types.NetworkConfig.networkName()});
        print("🔗 Fork manager initialized with genesis chain\n", .{});
        print("✅ Blockchain ready for operation!\n\n", .{});
    }

    fn createGenesis(self: *ZeiCoin) !void {
        try self.createCanonicalGenesis();
    }

    pub fn getAccount(self: *ZeiCoin, address: Address) !Account {
        // Validate Database before delegating to chain_query
        if (!self.database.validate()) {
            print("❌ Database corruption detected in ZeiCoin.getAccount()!\n", .{});
            print("  ZeiCoin ptr: {*}\n", .{self});
            print("  Database ptr: {*}\n", .{self.database});
            return error.DatabaseCorrupted;
        }
        
        return try self.chain_query.getAccount(address);
    }

    pub fn addTransaction(self: *ZeiCoin, transaction: Transaction) !void {
        try self.mempool_manager.addTransaction(transaction);
    }

    pub fn getHeight(self: *ZeiCoin) !u32 {
        return try self.chain_query.getHeight();
    }

    pub fn getBlockByHeight(self: *ZeiCoin, height: u32) !Block {
        return try self.chain_query.getBlockByHeight(height);
    }
    fn getMedianTimePast(self: *ZeiCoin, height: u32) !u64 {
        return try self.chain_query.getMedianTimePast(height);
    }

    pub fn validateBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        return try self.chain_validator.validateBlock(block, expected_height);
    }

    pub fn validateSyncBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        return try self.chain_validator.validateSyncBlock(block, expected_height);
    }
    fn validateTransactionSignature(self: *ZeiCoin, tx: Transaction) !bool {
        _ = self;
        const tx_hash = tx.hashForSigning();
        print("     🔍 Transaction hash for signing: {s}\n", .{std.fmt.fmtSliceHexLower(&tx_hash)});
        print("     🔍 Sender public key: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.sender_public_key)});
        print("     🔍 Transaction signature: {s}\n", .{std.fmt.fmtSliceHexLower(&tx.signature)});
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            print("❌ Invalid signature: transaction not signed by sender\n", .{});
            print("❌ Signature verification failed - detailed info above\n", .{});
            return false;
        }
        print("     ✅ Signature verification passed\n", .{});
        return true;
    }

    pub fn validateReorgBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        return try self.chain_validator.validateReorgBlock(block, expected_height);
    }

    fn isValidForkBlock(self: *ZeiCoin, block: types.Block) !bool {
        const current_height = try self.getHeight();
        for (0..current_height) |height| {
            var existing_block = self.database.getBlock(@intCast(height)) catch continue;
            defer existing_block.deinit(self.allocator);
            const existing_hash = existing_block.hash();
            if (std.mem.eql(u8, &block.header.previous_hash, &existing_hash)) {
                print("🔗 Fork block builds on height {} (current tip: {})\n", .{ height, current_height - 1 });
                return true;
            }
        }
        return false;
    }

    fn storeForkBlock(self: *ZeiCoin, block: types.Block, fork_height: u32) !void {
        _ = self;
        _ = block;
        _ = fork_height;
        print("⚠️ Fork storage not yet implemented - longest chain rule needed\n", .{});
    }

    /// Apply a valid block to the blockchain
    pub fn addBlockToChain(self: *ZeiCoin, block: Block, height: u32) !void {
        return try self.chain_processor.addBlockToChain(block, height);
    }

    /// Apply a valid block to the blockchain
    fn applyBlock(self: *ZeiCoin, block: Block) !void {
        return try self.chain_processor.applyBlock(block);
    }

    fn cleanMempool(self: *ZeiCoin, block: Block) void {
        _ = self;
        _ = block;
    }

    /// Start networking on specified port
    pub fn startNetwork(self: *ZeiCoin, port: u16) !void {
        if (self.network != null) return; // Already started

        var network = net.NetworkManager.init(self.allocator);
        try network.start(port);
        self.network = &network;

        print("🌐 ZeiCoin network started on port {}\n", .{port});
    }

    /// Stop networking
    pub fn stopNetwork(self: *ZeiCoin) void {
        if (self.network) |*network| {
            network.stop();
            network.deinit();
            self.network = null;
            print("🛑 ZeiCoin network stopped\n", .{});
        }
    }

    /// Connect to a peer
    pub fn connectToPeer(self: *ZeiCoin, address: []const u8) !void {
        if (self.network) |*network| {
            try network.addPeer(address);
        } else {
            return error.NetworkNotStarted;
        }
    }

    /// Print blockchain status
    pub fn printStatus(self: *ZeiCoin) void {
        self.status_reporter.printStatus();
    }

    pub fn handleIncomingTransaction(self: *ZeiCoin, transaction: types.Transaction) !void {
        _ = self;
        _ = transaction;
        return error.MovedToMempoolManager;
    }

    /// Estimate cumulative work for a block height (temporary until we store it properly)
    pub fn estimateCumulativeWork(self: *ZeiCoin, height: u32) !types.ChainWork {
        return try self.chain_query.estimateCumulativeWork(height);
    }

    /// Handle chain reorganization when a better chain is found
    fn handleChainReorganization(self: *ZeiCoin, new_block: types.Block, new_chain_state: types.ChainState) !void {
        const current_height = try self.getHeight();

        // Safety check: prevent very deep reorganizations
        if (self.fork_manager.isReorgTooDeep(current_height, new_chain_state.tip_height)) {
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
        try self.rollbackToHeight(common_ancestor_height);

        // Accept the new block (this will become the new tip)
        try self.acceptBlock(new_block);

        // Update fork manager
        self.fork_manager.updateChain(0, new_chain_state); // Update main chain

        print("✅ Reorganization complete! New chain tip: {s}\n", .{std.fmt.fmtSliceHexLower(new_chain_state.tip_hash[0..8])});
    }

    /// Find common ancestor between current chain and new chain
    fn findCommonAncestor(self: *ZeiCoin, new_tip_hash: types.BlockHash) !u32 {
        // Simplified: return 0 for now (rebuild from genesis)
        // In a full implementation, we'd traverse back through both chains
        _ = self;
        _ = new_tip_hash;
        return 0;
    }

    /// Backup transactions from orphaned blocks
    fn backupOrphanedTransactions(self: *ZeiCoin, from_height: u32, to_height: u32) !void {
        print("💾 Backing up transactions from orphaned blocks ({} to {})\n", .{ from_height, to_height });

        for (from_height..to_height) |height| {
            const block = self.database.getBlock(@intCast(height)) catch continue;
            defer block.deinit(self.allocator);

            // Re-validate and add non-coinbase transactions back to mempool
            for (block.transactions) |tx| {
                if (!tx.isCoinbase()) {
                    // Validate transaction is still valid
                    if (self.validateTransaction(tx) catch false) {
                        // TODO: Restore to MempoolManager instead
                        print("🔄 Orphaned transaction backup (moved to MempoolManager)\n", .{});
                    } else {
                        print("❌ Orphaned transaction no longer valid - discarded\n", .{});
                    }
                }
            }
        }
    }

    /// Accept a block after validation (used in reorganization)
    fn acceptBlock(self: *ZeiCoin, block: types.Block) !void {
        return try self.chain_processor.acceptBlock(block);
    }

    /// Check if we need to sync with a peer
    pub fn shouldSync(self: *ZeiCoin, peer_height: u32) !bool {
        const our_height = try self.getHeight();

        // If we have no blockchain and peer has blocks, always sync (including genesis)
        if (our_height == 0 and peer_height > 0) {
            print("🌐 Network has blockchain (height {}), will sync from genesis\n", .{peer_height});
            return true;
        }

        if (self.sync_state != .synced) {
            return false; // Already syncing or in error state
        }

        return peer_height > our_height;
    }

    /// Get sync state
    pub fn getSyncState(self: *const ZeiCoin) sync_mod.SyncState {
        return self.sync_state;
    }

    /// Get block by height (used by network layer for sending blocks)
    pub fn getBlock(self: *ZeiCoin, height: u32) !types.Block {
        return try self.chain_query.getBlock(height);
    }

    // Helper methods for cleaner code

    /// Reset sync retry count and update timestamp
    fn resetSyncRetry(self: *ZeiCoin) void {
        if (self.sync_progress) |*progress| {
            progress.retry_count = 0;
            progress.last_request_time = util.getTime();
        }
    }

    pub fn cleanupProcessedTransactions(self: *ZeiCoin) void {
        _ = self;
    }

    /// Switch to a different peer for sync (peer fallback mechanism)
    fn switchSyncPeer(self: *ZeiCoin) !void {
        if (self.network == null) {
            return error.NoNetworkManager;
        }

        // Add current peer to failed list
        if (self.sync_peer) |failed_peer| {
            try self.failed_peers.append(failed_peer);
            print("🚫 Added peer to blacklist (total: {})\n", .{self.failed_peers.items.len});
        }

        // Find a new peer that's not in the failed list
        const network = self.network.?;
        var new_peer: ?*net.Peer = null;

        for (network.peers.items) |*peer| {
            if (peer.state != .connected) continue;

            // Check if this peer is in the failed list
            var is_failed = false;
            for (self.failed_peers.items) |failed_peer| {
                if (peer == failed_peer) {
                    is_failed = true;
                    break;
                }
            }

            if (!is_failed) {
                new_peer = peer;
                break;
            }
        }

        if (new_peer) |peer| {
            print("🔄 Switching to new sync peer\n", .{});
            self.sync_peer = peer;

            // Reset retry count - caller will retry the request
            self.resetSyncRetry();
        } else {
            print("❌ No more peers available for sync\n", .{});
            self.failSync("No more peers available");
        }
    }

    /// Fail sync process with error message
    fn failSync(self: *ZeiCoin, reason: []const u8) void {
        print("❌ Sync failed: {s}\n", .{reason});
        self.sync_state = .sync_failed;
        self.sync_progress = null;
        self.sync_peer = null;

        // Clear failed peers list for future attempts
        self.failed_peers.clearAndFree();
    }

    /// Check if sync has timed out and needs recovery
    pub fn checkForNewBlocks(self: *ZeiCoin) !void {
        try self.message_handler.checkForNewBlocks();
    }

    pub fn handleIncomingBlock(self: *ZeiCoin, block: Block, peer: ?*net.Peer) !void {
        try self.message_handler.handleIncomingBlock(block, peer);
    }

    pub fn broadcastNewBlock(self: *ZeiCoin, block: Block) !void {
        try self.message_handler.broadcastNewBlock(block);
    }

    pub fn initHeaderChain(self: *ZeiCoin) !void {
        _ = self;
        return;
    }
    pub fn getHeadersRange(self: *ZeiCoin, start_height: u32, count: u32) ![]BlockHeader {
        const headers = try self.allocator.alloc(BlockHeader, count);
        errdefer self.allocator.free(headers);

        var retrieved: usize = 0;
        for (0..count) |i| {
            const height = start_height + @as(u32, @intCast(i));
            if (height > try self.getHeight()) break;

            const block = try self.database.getBlock(height);
            headers[retrieved] = block.header;
            retrieved += 1;
        }

        if (retrieved < count) {
            const actual_headers = try self.allocator.alloc(BlockHeader, retrieved);
            @memcpy(actual_headers, headers[0..retrieved]);
            self.allocator.free(headers);
            return actual_headers;
        }

        return headers;
    }

    fn startBlockDownloads(self: *ZeiCoin) !void {
        const current_block_height = try self.getHeight();
        const header_height = self.header_chain.?.validated_height;

        if (current_block_height >= header_height) {
            util.logInfo("Already have all blocks", .{});
            self.completeHeadersSync();
            return;
        }

        // Queue blocks for download
        self.blocks_to_download.clearRetainingCapacity();
        for (current_block_height + 1..header_height + 1) |height| {
            try self.blocks_to_download.append(@intCast(height));
        }

        util.logInfo("Queued {} blocks for download", .{self.blocks_to_download.items.len});

        // Start parallel downloads
        try self.requestNextBlocks();
    }

    fn requestNextBlocks(self: *ZeiCoin) !void {
        if (self.network == null) return;

        const network = self.network.?;
        const now = util.getTime();

        // Clean up timed out downloads
        var iter = self.active_block_downloads.iterator();
        while (iter.next()) |entry| {
            if (now - entry.value_ptr.* > types.HEADERS_SYNC.BLOCK_DOWNLOAD_TIMEOUT) {
                // Re-queue timed out block
                try self.blocks_to_download.append(entry.key_ptr.*);
                _ = self.active_block_downloads.remove(entry.key_ptr.*);
                print("❌ Block {} download timed out, re-queuing\n", .{entry.key_ptr.*});
            }
        }

        // Start new downloads up to concurrent limit
        while (self.active_block_downloads.count() < types.HEADERS_SYNC.MAX_CONCURRENT_DOWNLOADS and
            self.blocks_to_download.items.len > 0)
        {
            const height = self.blocks_to_download.orderedRemove(0);

            // Find available peer
            var sent = false;
            for (network.peers.items) |*peer| {
                if (peer.state == .connected) {
                    peer.sendGetBlock(height) catch continue;
                    try self.active_block_downloads.put(height, now);
                    util.logProcess("Requested block {}", .{height});
                    sent = true;
                    break;
                }
            }

            if (!sent) {
                // No peers available, re-queue
                try self.blocks_to_download.insert(0, height);
                break;
            }
        }
    }

    pub fn processDownloadedBlock(self: *ZeiCoin, block: Block, height: u32) !void {
        // Verify block matches expected header
        if (self.header_chain) |chain| {
            const expected_header = chain.getHeader(height);
            if (expected_header == null or !std.mem.eql(u8, &block.header.hash(), &expected_header.?.hash())) {
                print("❌ Block header mismatch at height {}\n", .{height});
                return error.BlockHeaderMismatch;
            }
        }

        // Process the block
        try self.handleSyncBlock(height, block);

        // Remove from active downloads
        _ = self.active_block_downloads.remove(height);

        // Request more blocks
        try self.requestNextBlocks();

        // Check if sync is complete
        if (self.blocks_to_download.items.len == 0 and self.active_block_downloads.count() == 0) {
            self.completeHeadersSync();
        }
    }

    fn completeHeadersSync(self: *ZeiCoin) void {
        util.logSuccess("Headers-first sync completed!", .{});

        if (self.headers_progress) |progress| {
            const elapsed = util.getTime() - progress.start_time;
            const headers_per_sec = progress.getHeadersPerSecond();
            util.logInfo("Downloaded {} headers in {}s ({:.2} headers/sec)", .{ progress.headers_downloaded, elapsed, headers_per_sec });
        }

        // Clean up
        self.headers_progress = null;
        if (self.header_chain) |chain| {
            chain.deinit();
            self.allocator.destroy(chain);
            self.header_chain.deinit();
        }

        self.sync_state = .synced;
    }

    pub fn calculateNextDifficulty(self: *ZeiCoin) !types.DifficultyTarget {
        return try self.difficulty_calculator.calculateNextDifficulty();
    }
};
