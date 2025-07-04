const std = @import("std");
const testing = std.testing;
const print = std.debug.print;
const ArrayList = std.ArrayList;

const types = @import("types/types.zig");
const util = @import("util/util.zig");
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
const db = @import("storage/db.zig");
const MempoolManager = @import("mempool/manager.zig").MempoolManager;

// Import the main blockchain module
const blockchain = @import("node.zig");
const ZeiCoin = blockchain.ZeiCoin;

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

// Test helper functions for blockchain testing
// Note: Basic helper functions are in /home/iliya/zeicoin/src/tests.zig to avoid duplication

// Test wrapper function for mining (delegates to miner module)
pub fn zenMineBlockForTesting(zeicoin: *ZeiCoin, miner_keypair: key.KeyPair) !types.Block {
    // Create a temporary mempool manager for testing
    var temp_mempool = MempoolManager.init(zeicoin.allocator, &zeicoin.database, zeicoin);
    defer temp_mempool.deinit();

    // Create temporary mining state
    var mining_state = types.MiningState.init();
    defer mining_state.deinit();

    const mining_context = createTestMiningContext(zeicoin, &temp_mempool, &mining_state);
    return miner_mod.zenMineBlock(mining_context, miner_keypair);
}

// Test helper function for creating a mining context for tests
fn createTestMiningContext(zeicoin: *ZeiCoin, mempool_manager: *MempoolManager, mining_state: *types.MiningState) miner_mod.MiningContext {
    return miner_mod.MiningContext{
        .allocator = zeicoin.allocator,
        .database = &zeicoin.database,
        .mempool_manager = mempool_manager,
        .mining_state = mining_state,
        .network = zeicoin.network,
        .fork_manager = &zeicoin.fork_manager,
        .blockchain = zeicoin,
    };
}

// Test utility function for creating test blockchain instances
pub fn createTestZeiCoinInstance(data_dir: []const u8) !ZeiCoin {
    std.fs.cwd().deleteTree(data_dir) catch {};

    var instance = ZeiCoin{
        .database = try db.Database.init(testing.allocator, data_dir),
        .chain_state = @import("chain/state.zig").ChainState.init(testing.allocator, undefined), // Will be fixed
        .network = null,
        .allocator = testing.allocator,
        .sync_state = .synced,
        .sync_progress = null,
        .sync_peer = null,
        .failed_peers = ArrayList(*net.Peer).init(testing.allocator),
        .fork_manager = forkmanager.ForkManager.init(testing.allocator),
        .header_chain = headerchain.HeaderChain.init(testing.allocator),
        .sync_manager = null,
        .blocks_to_download = ArrayList(u32).init(testing.allocator),
        .active_block_downloads = std.AutoHashMap(u32, i64).init(testing.allocator),
        .headers_progress = null,
        .message_handler = undefined,
        .chain_validator = undefined,
    };

    // Initialize chain state properly
    instance.chain_state = @import("chain/state.zig").ChainState.init(testing.allocator, instance.database);

    // Initialize components
    instance.message_handler = message_handler.NetworkMessageHandler.init(testing.allocator, &instance);
    instance.chain_validator = validator_mod.ChainValidator.init(testing.allocator, &instance);

    // Initialize fork manager with genesis (database should be empty now)
    if (try instance.getHeight() == 0) {
        try instance.createCanonicalGenesis();
    }

    return instance;
}
