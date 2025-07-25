const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;

const types = @import("types/types.zig");
const util = @import("util/util.zig");
const serialize = @import("storage/serialize.zig");
const db = @import("storage/db.zig");
const net = @import("network/peer.zig");
const NetworkCoordinator = @import("network/coordinator.zig").NetworkCoordinator;
const randomx = @import("crypto/randomx.zig");
const genesis = @import("chain/genesis.zig");
const forkmanager = @import("fork/main.zig");
// const headerchain = @import("network/headerchain.zig"); // ZSP-001: Disabled headers-first sync
const sync_mod = @import("sync/manager.zig");
const message_handler = @import("network/message_handler.zig");
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
    fork_manager: forkmanager.ForkManager,
    // header_chain: headerchain.HeaderChain, // ZSP-001: Disabled headers-first sync
    sync_manager: ?*sync_mod.SyncManager,
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

        const database = try allocator.create(db.Database);
        errdefer allocator.destroy(database);

        database.* = try db.Database.init(allocator, data_dir);
        errdefer database.deinit();

        if (!database.validate()) {
            print("❌ Database validation failed during initialization\n", .{});
            return error.DatabaseCorrupted;
        }

        const instance_ptr = try allocator.create(ZeiCoin);
        errdefer allocator.destroy(instance_ptr);

        var fork_manager = forkmanager.ForkManager.init(allocator);
        errdefer fork_manager.deinit();

        // var header_chain = headerchain.HeaderChain.init(allocator); // ZSP-001: Disabled headers-first sync
        // errdefer header_chain.deinit(); // ZSP-001: Disabled headers-first sync

        const chain_state = @import("chain/state.zig").ChainState.init(allocator, database);

        instance_ptr.* = ZeiCoin{
            .database = database,
            .chain_state = chain_state,
            .network_coordinator = undefined,
            .allocator = allocator,
            .fork_manager = fork_manager,
            // .header_chain = header_chain, // ZSP-001: Disabled headers-first sync
            .sync_manager = null,
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
            if (components_initialized >= 1) instance_ptr.message_handler.deinit();
        }

        instance_ptr.message_handler = message_handler.NetworkMessageHandler.init(allocator, instance_ptr);
        components_initialized = 1;

        if (!database.validate()) {
            print("❌ Database corrupted after message_handler init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.network_coordinator = NetworkCoordinator.init(allocator, instance_ptr.message_handler);

        if (!database.validate()) {
            print("❌ Database corrupted after network_coordinator init\n", .{});
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

        instance_ptr.chain_processor = ChainProcessor.init(allocator, instance_ptr.database, &instance_ptr.chain_state, &instance_ptr.fork_manager, &instance_ptr.chain_validator, null);
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

        instance_ptr.status_reporter = StatusReporter.init(allocator, instance_ptr.database, &instance_ptr.network_coordinator);
        components_initialized = 6;

        if (!database.validate()) {
            print("❌ Database corrupted after status_reporter init\n", .{});
            return error.DatabaseCorrupted;
        }

        components_initialized = 7;

        if (!database.validate()) {
            print("❌ Database corrupted after blockchain_manager init\n", .{});
            return error.DatabaseCorrupted;
        }

        instance_ptr.mempool_manager = try MempoolManager.init(allocator, &instance_ptr.chain_state);
        components_initialized = 8;

        instance_ptr.mempool_manager.setMiningState(&instance_ptr.mining_state);
        instance_ptr.chain_processor.setMempoolManager(instance_ptr.mempool_manager);
        
        // Wire up network coordinator for sync triggers
        instance_ptr.mempool_manager.network_handler.setNetworkCoordinator(&instance_ptr.network_coordinator);

        if (!database.validate()) {
            print("❌ Database corrupted after mempool_manager init\n", .{});
            return error.DatabaseCorrupted;
        }

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

        return instance_ptr;
    }

    pub fn initializeBlockchain(self: *ZeiCoin) !void {
        const current_height = self.getHeight() catch {
            print("❌ CRITICAL ERROR: Cannot retrieve blockchain height!\n", .{});
            return error.BlockchainNotInitialized;
        };
        
        // Genesis block is at height 0, so this is normal
        print("🔗 Blockchain initialized at height {}, ready for network sync\n", .{current_height});
    }

    pub fn deinit(self: *ZeiCoin) void {
        print("🧹 Starting ZeiCoin cleanup...\n", .{});

        if (!self.database.validate()) {
            print("⚠️ Database corruption detected during cleanup!\n", .{});
        }

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
        self.message_handler.deinit();

        // self.header_chain.deinit(); // ZSP-001: Disabled headers-first sync
        self.fork_manager.deinit();

        if (self.sync_manager) |sm| {
            sm.deinit();
            self.allocator.destroy(sm);
        }

        self.chain_state.deinit();

        defer self.allocator.destroy(self.database);
        defer self.database.deinit();

        print("✅ ZeiCoin cleanup completed\n", .{});
    }

    pub fn createCanonicalGenesis(self: *ZeiCoin) !void {
        var genesis_block = try genesis.createGenesis(self.allocator);
        defer genesis_block.deinit(self.allocator);
        for (genesis_block.transactions) |tx| {
            if (tx.isCoinbase()) {
                try self.chain_state.processCoinbaseTransaction(tx, tx.recipient, 0);
            }
        }
        try self.database.saveBlock(0, genesis_block);

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
        return try self.chain_query.getBlock(height);
    }
    fn getMedianTimePast(self: *ZeiCoin, height: u32) !u64 {
        return try self.chain_query.getMedianTimePast(height);
    }

    fn isValidForkBlock(self: *ZeiCoin, block: types.Block) !bool {
        return try self.fork_manager.isValidForkBlock(block, self);
    }

    fn storeForkBlock(self: *ZeiCoin, block: types.Block, fork_height: u32) !void {
        return try self.fork_manager.storeForkBlock(block, fork_height);
    }

    pub fn addBlockToChain(self: *ZeiCoin, block: Block, height: u32) !void {
        return try self.chain_processor.addBlockToChain(block, height);
    }

    /// Add sync block directly to chain processor, bypassing block processor validation
    pub fn addSyncBlockToChain(self: *ZeiCoin, block: Block, height: u32) !void {
        print("🔄 [SYNC] Adding block {} directly to chain processor (bypassing block processor)\n", .{height});
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

    pub fn getTotalWork(self: *ZeiCoin) !types.ChainWork {
        const current_height = try self.database.getHeight();

        return @as(types.ChainWork, current_height);
    }

    fn handleChainReorganization(self: *ZeiCoin, new_block: types.Block, new_chain_state: types.ChainState) !void {
        try self.fork_manager.handleChainReorganization(self, new_block, new_chain_state);
    }

    fn rollbackToHeight(self: *ZeiCoin, target_height: u32) !void {
        _ = self;
        print("🔄 Rollback to height {} delegated to chain processor\n", .{target_height});
    }

    fn handleSyncBlock(self: *ZeiCoin, height: u32, block: Block) !void {
        _ = height;
        try self.handleIncomingBlock(block, null);
    }

    pub fn validateBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        print("🔧 [NODE] validateBlock() ENTRY - height: {}\n", .{expected_height});
        print("🔧 [NODE] Delegating to chain_validator.validateBlock()\n", .{});
        const result = try self.chain_validator.validateBlock(block, expected_height);
        print("🔧 [NODE] validateBlock() result: {}\n", .{result});
        return result;
    }

    pub fn validateSyncBlock(self: *ZeiCoin, block: *const Block, expected_height: u32) !bool {
        print("🔧 [NODE] validateSyncBlock() ENTRY - height: {}\n", .{expected_height});
        print("🔧 [NODE] Delegating to chain_validator.validateSyncBlock()\n", .{});
        const result = try self.chain_validator.validateSyncBlock(block, expected_height);
        print("🔧 [NODE] validateSyncBlock() result: {}\n", .{result});
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
            print("❌ Sync failed: {s}\n", .{reason});
            self.sync_state = .sync_failed;
            self.sync_progress = null;
            self.sync_peer = null;
            self.failed_peers.clearAndFree();
        }
    }

    pub fn checkForNewBlocks(self: *ZeiCoin) !void {
        try self.message_handler.checkForNewBlocks();
    }

    pub fn handleIncomingBlock(self: *ZeiCoin, block: Block, peer: ?*net.Peer) !void {
        print("🔧 [NODE] handleIncomingBlock() ENTRY - delegating to message handler\n", .{});
        try self.message_handler.handleIncomingBlock(block, peer);
        print("🔧 [NODE] handleIncomingBlock() completed successfully\n", .{});
    }

    pub fn broadcastNewBlock(self: *ZeiCoin, block: Block) !void {
        try self.message_handler.broadcastNewBlock(block);
    }

    pub fn getHeadersRange(self: *ZeiCoin, start_height: u32, count: u32) ![]BlockHeader {
        return try self.chain_query.getHeadersRange(start_height, count);
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
