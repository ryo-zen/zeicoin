const std = @import("std");
const log = std.log.scoped(.node);
const ArrayList = std.ArrayList;

const types = @import("types/types.zig");
const util = @import("util/util.zig");
const serialize = @import("storage/serialize.zig");
const db = @import("storage/db.zig");
const net = @import("network/peer.zig");
const NetworkCoordinator = @import("network/coordinator.zig").NetworkCoordinator;
const randomx = @import("crypto/randomx.zig");
const genesis = @import("chain/genesis.zig");
// const headerchain = @import("network/headerchain.zig"); // ZSP-001: Disabled headers-first sync
const sync_mod = @import("sync/manager.zig");
const message_dispatcher = @import("network/message_dispatcher.zig");
const validator_mod = @import("validation/validator.zig");
const miner_mod = @import("miner/main.zig");
const MempoolManager = @import("mempool/manager.zig").MempoolManager;

const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

const ChainQuery = @import("chain/query.zig").ChainQuery;
const ChainProcessor = @import("chain/processor.zig").ChainProcessor;
const DifficultyCalculator = @import("chain/difficulty.zig").DifficultyCalculator;
const StatusReporter = @import("monitoring/status.zig").StatusReporter;

pub const ZeiCoin = struct {
    database: *db.Database,
    chain_state: @import("chain/state.zig").ChainState,
    network_coordinator: NetworkCoordinator,
    allocator: std.mem.Allocator,
    // header_chain: headerchain.HeaderChain, // ZSP-001: Disabled headers-first sync
    sync_manager: ?*sync_mod.SyncManager,
    message_dispatcher: message_dispatcher.MessageDispatcher,
    chain_validator: validator_mod.ChainValidator,
    chain_query: ChainQuery,
    chain_processor: ChainProcessor,
    difficulty_calculator: DifficultyCalculator,
    status_reporter: StatusReporter,
    mempool_manager: *MempoolManager,
    mining_state: types.MiningState,
    mining_manager: ?*miner_mod.MiningManager,
    mining_keypair: ?@import("crypto/key.zig").KeyPair,

    pub fn init(allocator: std.mem.Allocator) !*ZeiCoin {
        const data_dir = switch (types.CURRENT_NETWORK) {
            .testnet => "zeicoin_data_testnet",
            .mainnet => "zeicoin_data_mainnet",
        };

        const database = try allocator.create(db.Database);
        errdefer allocator.destroy(database);

        database.* = try db.Database.init(allocator, data_dir);
        errdefer database.deinit();

        const instance_ptr = try allocator.create(ZeiCoin);
        errdefer allocator.destroy(instance_ptr);

        // var header_chain = headerchain.HeaderChain.init(allocator); // ZSP-001: Disabled headers-first sync
        // errdefer header_chain.deinit(); // ZSP-001: Disabled headers-first sync

        const chain_state = @import("chain/state.zig").ChainState.init(allocator, database);

        instance_ptr.* = ZeiCoin{
            .database = database,
            .chain_state = chain_state,
            .network_coordinator = undefined,
            .allocator = allocator,
            // .header_chain = header_chain, // ZSP-001: Disabled headers-first sync
            .sync_manager = null,
            .message_dispatcher = undefined,
            .chain_validator = undefined,
            .chain_query = undefined,
            .chain_processor = undefined,
            .difficulty_calculator = undefined,
            .status_reporter = undefined,
            .mempool_manager = undefined,
            .mining_state = types.MiningState.init(),
            .mining_manager = null,
            .mining_keypair = null,
        };

        // CRITICAL FIX: Rebuild block index from database on startup
        // This ensures getBlockHash() works for blocks loaded from disk
        instance_ptr.chain_state.initializeBlockIndex() catch |err| {
            log.err("❌ Failed to initialize block index: {}", .{err});
            return err;
        };

        var components_initialized: u8 = 0;
        errdefer {
            if (components_initialized >= 8) {
                instance_ptr.mempool_manager.deinit();
            }
            if (components_initialized >= 6) instance_ptr.status_reporter.deinit();
            if (components_initialized >= 5) instance_ptr.difficulty_calculator.deinit();
            if (components_initialized >= 4) instance_ptr.chain_processor.deinit();
            if (components_initialized >= 3) instance_ptr.chain_query.deinit();
            if (components_initialized >= 2) instance_ptr.chain_validator.deinit();
            if (components_initialized >= 1) instance_ptr.message_dispatcher.deinit();
        }

        instance_ptr.message_dispatcher = message_dispatcher.MessageDispatcher.init(allocator, instance_ptr);
        components_initialized = 1;

        instance_ptr.network_coordinator = NetworkCoordinator.init(allocator, instance_ptr.message_dispatcher);

        instance_ptr.chain_validator = validator_mod.ChainValidator.init(allocator, instance_ptr);
        components_initialized = 2;

        instance_ptr.chain_query = ChainQuery.init(allocator, instance_ptr.database, &instance_ptr.chain_state);
        components_initialized = 3;


        instance_ptr.chain_processor = ChainProcessor.init(allocator, instance_ptr.database, &instance_ptr.chain_state, &instance_ptr.chain_validator, null);
        components_initialized = 4;

        instance_ptr.difficulty_calculator = DifficultyCalculator.init(allocator, instance_ptr.database);
        components_initialized = 5;


        instance_ptr.status_reporter = StatusReporter.init(allocator, instance_ptr.database, &instance_ptr.network_coordinator);
        components_initialized = 6;


        components_initialized = 7;


        instance_ptr.mempool_manager = try MempoolManager.init(allocator, &instance_ptr.chain_state);
        components_initialized = 8;

        instance_ptr.mempool_manager.setMiningState(&instance_ptr.mining_state);
        instance_ptr.chain_processor.setMempoolManager(instance_ptr.mempool_manager);

        // Wire up network coordinator for sync triggers
        instance_ptr.mempool_manager.network_handler.setNetworkCoordinator(&instance_ptr.network_coordinator);


        // Check if genesis block already exists in database
        const genesis_exists = blk: {
            var genesis_block = instance_ptr.database.getBlock(0) catch |err| switch (err) {
                db.DatabaseError.NotFound => break :blk false,
                else => return err,
            };
            defer genesis_block.deinit(instance_ptr.allocator);
            break :blk true;
        };

        if (!genesis_exists) {
            log.info("🌐 No blockchain found - creating canonical genesis block", .{});
            try instance_ptr.createCanonicalGenesis();
            log.info("✅ Genesis block created successfully!", .{});
        } else {
            const height = try instance_ptr.getHeight();
            log.info("📊 Existing blockchain found with {} blocks", .{height});
        }


        log.info("✅ ZeiCoin initialization completed successfully", .{});

        return instance_ptr;
    }

    pub fn initializeBlockchain(self: *ZeiCoin) !void {
        const current_height = self.getHeight() catch {
            log.info("❌ ERROR: Cannot retrieve blockchain height!", .{});
            return error.BlockchainNotInitialized;
        };

        // Genesis block is at height 0, so this is normal
        log.info("🔗 Blockchain initialized at height {}, ready for network sync", .{current_height});
        log.info("", .{});
    }

    pub fn deinit(self: *ZeiCoin) void {
        log.info("🧹 Starting ZeiCoin cleanup...", .{});


        if (self.mining_manager) |manager| {
            manager.stopMining();
            self.allocator.destroy(manager);
        }
        self.mining_state.deinit();

        self.mempool_manager.deinit();
        self.status_reporter.deinit();
        self.difficulty_calculator.deinit();
        self.chain_processor.deinit();
        self.chain_query.deinit();
        self.chain_validator.deinit();
        self.network_coordinator.deinit();
        self.message_dispatcher.deinit();

        // self.header_chain.deinit(); // ZSP-001: Disabled headers-first sync

        if (self.sync_manager) |sm| {
            sm.deinit();
            self.allocator.destroy(sm);
        }

        self.chain_state.deinit();

        defer self.allocator.destroy(self.database);
        defer self.database.deinit();

        log.info("✅ ZeiCoin cleanup completed", .{});
    }

    pub fn createCanonicalGenesis(self: *ZeiCoin) !void {
        var genesis_block = try genesis.createGenesis(self.allocator);
        defer genesis_block.deinit(self.allocator);
        for (genesis_block.transactions) |tx| {
            if (tx.isCoinbase()) {
                try self.chain_state.processCoinbaseTransaction(tx, tx.recipient, 0, true);
            }
        }
        try self.database.saveBlock(0, genesis_block);

        // CRITICAL FIX: Index genesis block
        try self.chain_state.indexBlock(0, genesis_block.hash());

        // Genesis initialization handled by chain state
        // Modern reorganization system doesn't require explicit genesis setup

        log.info("", .{});
        log.info("🎉 ===============================================", .{});
        log.info("🎉 GENESIS BLOCK CREATED SUCCESSFULLY!", .{});
        log.info("🎉 ===============================================", .{});
        log.info("📦 Block Height: 0", .{});
        log.info("📦 Transactions: {}", .{genesis_block.txCount()});
        log.info("🌐 Network: {s} (Canonical Genesis)", .{types.NetworkConfig.networkName()});
        log.info("🔗 Fork manager initialized with genesis chain", .{});
        log.info("✅ Blockchain ready for operation!", .{});
    }

    fn createGenesis(self: *ZeiCoin) !void {
        try self.createCanonicalGenesis();
    }

    pub fn getAccount(self: *ZeiCoin, address: Address) !Account {

        return try self.chain_query.getAccount(address);
    }

    pub fn addTransaction(self: *ZeiCoin, transaction: Transaction) !void {
        try self.mempool_manager.addTransaction(transaction);
    }

    pub fn getHeight(self: *ZeiCoin) !u32 {
        return try self.chain_query.getHeight();
    }

    pub fn getBlockByHeight(self: *ZeiCoin, height: u32) !Block {
        return try self.chain_query.getBlock(height);
    }
    
    pub fn getBlockHashAtHeight(self: *ZeiCoin, height: u32) ![32]u8 {
        const block = try self.chain_query.getBlock(height);
        return block.hash();
    }
    
    pub fn getBestBlockHash(self: *ZeiCoin) ![32]u8 {
        const current_height = try self.getHeight();
        if (current_height == 0) {
            // Return genesis block hash if at height 0
            return genesis.getCanonicalGenesisHash();
        }
        return try self.getBlockHashAtHeight(current_height);
    }

    /// Get transaction by hash - checks mempool first, then database
    pub fn getTransaction(self: *ZeiCoin, tx_hash: Hash) !struct {
        transaction: Transaction,
        status: enum { pending, confirmed },
        block_height: ?u32,
    } {
        // Check mempool first for pending transactions
        if (self.mempool_manager.getTransaction(tx_hash)) |tx| {
            return .{
                .transaction = tx,
                .status = .pending,
                .block_height = null,
            };
        }

        // Check database for confirmed transactions
        const tx = try self.database.getTransactionByHash(tx_hash);
        // TODO: Get block height where transaction was included
        // For now, return confirmed with unknown height
        return .{
            .transaction = tx,
            .status = .confirmed,
            .block_height = null, // Would need to scan blocks to find this
        };
    }

    pub fn getCurrentDifficulty(self: *ZeiCoin) !u64 {
        // Calculate what the current difficulty should be for the next block
        var difficulty_calc = DifficultyCalculator.init(self.allocator, self.database);
        defer difficulty_calc.deinit();
        
        const difficulty_target = try difficulty_calc.calculateNextDifficulty();
        return difficulty_target.toU64();
    }
    fn getMedianTimePast(self: *ZeiCoin, height: u32) !u64 {
        return try self.chain_query.getMedianTimePast(height);
    }

    fn isValidForkBlock(self: *ZeiCoin, block: types.Block) !bool {
        // Fork validation now handled by chain validator
        return try self.chain_validator.validateBlock(block, 0); // Height will be determined by validator
    }

    fn storeForkBlock(self: *ZeiCoin, block: types.Block, fork_height: u32) !void {
        // Fork storage now handled by adding block to chain
        _ = self;
        _ = fork_height;
        log.info("🔄 Fork block storage delegated to chain processor", .{});
        // Modern system handles fork blocks through normal block processing
        _ = block; // Block will be processed through regular channels
    }

    pub fn addBlockToChain(self: *ZeiCoin, block: Block, height: u32) !void {
        return try self.chain_processor.addBlockToChain(block, height);
    }

    /// Add sync block directly to chain processor, bypassing block processor validation
    pub fn addSyncBlockToChain(self: *ZeiCoin, block: Block, height: u32) !void {
        log.info("🔄 [SYNC] Adding block {} directly to chain processor (bypassing block processor)", .{height});
        return try self.chain_processor.addBlockToChain(block, height);
    }

    fn applyBlock(self: *ZeiCoin, block: Block) !void {
        return try self.chain_processor.applyBlock(block);
    }

    pub fn startNetwork(self: *ZeiCoin, port: u16) !void {
        try self.network_coordinator.startNetwork(port);
    }

    pub fn stopNetwork(self: *ZeiCoin) void {
        self.network_coordinator.stopNetwork();
    }

    pub fn connectToPeer(self: *ZeiCoin, address: []const u8) !void {
        try self.network_coordinator.connectToPeer(address);
    }

    pub fn printStatus(self: *ZeiCoin) void {
        self.status_reporter.printStatus();
    }

    pub fn handleIncomingTransaction(self: *ZeiCoin, transaction: types.Transaction) !void {
        try self.mempool_manager.handleIncomingTransaction(transaction);
    }

    /// Get total cumulative work for the main chain
    /// This implements proper Nakamoto Consensus by summing proof-of-work
    pub fn getTotalWork(self: *ZeiCoin) !types.ChainWork {
        const current_height = try self.database.getHeight();
        var cumulative_work: types.ChainWork = 0;

        // Sum the work contribution of each block in the chain
        for (0..current_height + 1) |height| {
            var block = self.database.getBlock(@intCast(height)) catch {
                log.info("⚠️  Failed to load block at height {} for work calculation", .{height});
                continue;
            };
            defer block.deinit(self.allocator);

            const block_work = block.header.getWork();
            cumulative_work = std.math.add(types.ChainWork, cumulative_work, block_work) catch {
                // Saturate at max value if overflow
                return std.math.maxInt(types.ChainWork);
            };
        }

        return cumulative_work;
    }

    fn handleChainReorganization(self: *ZeiCoin, new_block: types.Block, new_chain_state: types.ChainState) !void {
        _ = new_chain_state;
        _ = new_block;
        // Reorganization is now handled by sync manager via bulk reorg
        log.debug("handleChainReorganization called - delegating to sync manager", .{});
        _ = self;
    }

    fn rollbackToHeight(self: *ZeiCoin, target_height: u32) !void {
        _ = self;
        log.info("🔄 Rollback to height {} delegated to chain processor", .{target_height});
    }

    fn handleSyncBlock(self: *ZeiCoin, height: u32, block: Block) !void {
        _ = height;
        try self.handleIncomingBlock(block, null);
    }

    pub fn validateBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        log.info("🔧 [NODE] validateBlock() ENTRY - height: {}", .{expected_height});
        log.info("🔧 [NODE] Delegating to chain_validator.validateBlock()", .{});
        const result = try self.chain_validator.validateBlock(block, expected_height);
        log.info("🔧 [NODE] validateBlock() result: {}", .{result});
        return result;
    }

    pub fn validateSyncBlock(self: *ZeiCoin, block: *const Block, expected_height: u32) !bool {
        log.info("🔧 [NODE] validateSyncBlock() ENTRY - height: {}", .{expected_height});
        log.info("🔧 [NODE] Delegating to chain_validator.validateSyncBlock()", .{});
        const result = try self.chain_validator.validateSyncBlock(block, expected_height);
        log.info("🔧 [NODE] validateSyncBlock() result: {}", .{result});
        return result;
    }

    pub fn validateTransaction(self: *ZeiCoin, tx: Transaction) !bool {
        return try self.chain_validator.validateTransaction(tx);
    }

    pub fn shouldSync(self: *ZeiCoin, peer_height: u32) !bool {
        if (self.sync_manager) |sm| {
            return try sm.shouldSyncWithPeer(peer_height);
        }
        return false;
    }

    pub fn getSyncState(self: *const ZeiCoin) sync_mod.SyncState {
        if (self.sync_manager) |sm| {
            return sm.getSyncState();
        }
        return self.sync_state;
    }

    pub fn getBlock(self: *ZeiCoin, height: u32) !types.Block {
        return try self.chain_query.getBlock(height);
    }

    fn switchSyncPeer(self: *ZeiCoin) !void {
        if (self.sync_manager) |sm| {
            try sm.switchToNewPeer();
        }
    }

    fn failSync(self: *ZeiCoin, reason: []const u8) void {
        if (self.sync_manager) |sm| {
            sm.failSyncWithReason(reason);
        } else {
            log.info("❌ Sync failed: {s}", .{reason});
            self.sync_state = .sync_failed;
            self.sync_progress = null;
            self.sync_peer = null;
            self.failed_peers.clearAndFree();
        }
    }

    pub fn checkForNewBlocks(self: *ZeiCoin) !void {
        try self.message_dispatcher.checkForNewBlocks();
    }

    pub fn handleIncomingBlock(self: *ZeiCoin, block: Block, peer: ?*net.Peer) !void {
        log.info("🔧 [NODE] handleIncomingBlock() ENTRY - delegating to message handler", .{});
        try self.message_dispatcher.handleIncomingBlock(block, peer);
        log.info("🔧 [NODE] handleIncomingBlock() completed successfully", .{});
    }

    pub fn broadcastNewBlock(self: *ZeiCoin, block: Block) !void {
        try self.message_dispatcher.broadcastNewBlock(block);
    }

    pub fn getHeadersRange(self: *ZeiCoin, start_height: u32, count: u32) ![]BlockHeader {
        return try self.chain_query.getHeadersRange(start_height, count);
    }

    /// Get the next available nonce for an address, considering pending transactions in mempool
    pub fn getNextAvailableNonce(self: *ZeiCoin, address: types.Address) !u64 {
        // Get current account nonce
        const account = try self.chain_query.getAccount(address);
        var next_nonce = account.nonce;

        // Check mempool for pending transactions from this address
        const highest_pending_nonce = self.mempool_manager.getHighestPendingNonce(address);

        // If there are pending transactions, use highest nonce + 1
        // getHighestPendingNonce returns maxInt(u64) as sentinel if no transactions found
        if (highest_pending_nonce != std.math.maxInt(u64)) {
            next_nonce = highest_pending_nonce + 1;
        }

        return next_nonce;
    }

    fn startBlockDownloads(self: *ZeiCoin) !void {
        if (self.sync_manager) |sm| {
            try sm.startBlockDownloads();
        }
    }

    fn requestNextBlocks(self: *ZeiCoin) !void {
        if (self.sync_manager) |sm| {
            try sm.requestNextBlocks();
        }
    }

    pub fn processDownloadedBlock(self: *ZeiCoin, block: Block, height: u32) !void {
        if (self.sync_manager) |sm| {
            try sm.processDownloadedBlock(block, height);
        }
    }

    pub fn calculateNextDifficulty(self: *ZeiCoin) !types.DifficultyTarget {
        return try self.difficulty_calculator.calculateNextDifficulty();
    }
};
