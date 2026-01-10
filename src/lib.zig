// lib.zig - ZeiCoin Library Public API
// This file exports all public components of the ZeiCoin blockchain

// Core blockchain components
pub const blockchain = @import("core/node.zig");
pub const genesis = @import("core/chain/genesis.zig");
pub const miner = @import("core/miner/main.zig");

// Chain management components
pub const chain = struct {
    pub const state = @import("core/chain/state.zig");
    pub const validator = @import("core/chain/validator.zig");
};

// Mempool management components
pub const mempool = struct {
    pub const manager = @import("core/mempool/manager.zig");
    pub const pool = @import("core/mempool/pool.zig");
    pub const validator = @import("core/mempool/validator.zig");
    pub const limits = @import("core/mempool/limits.zig");
    pub const network = @import("core/mempool/network.zig");
    pub const cleaner = @import("core/mempool/cleaner.zig");
};

// Network components
pub const peer = @import("core/network/peer.zig");
pub const server = @import("core/server/server.zig");


// Sync components (new modular system)
pub const sync = @import("core/sync/sync.zig");

// Storage components
pub const db = @import("core/storage/db.zig");
pub const serialize = @import("core/storage/serialize.zig");

// Type definitions
pub const types = @import("core/types/types.zig");

// Cryptographic components
pub const key = @import("core/crypto/key.zig");
pub const bech32 = @import("core/crypto/bech32.zig");
pub const randomx = @import("core/crypto/randomx.zig");
pub const bip39 = @import("core/crypto/bip39.zig");
pub const hd = @import("core/crypto/hd.zig");

// Wallet components
pub const wallet = @import("core/wallet/wallet.zig");

// Utility components
pub const util = @import("core/util/util.zig");
pub const clispinners = @import("core/util/clispinners.zig");
pub const password = @import("core/util/password.zig");
pub const dotenv = @import("core/util/dotenv.zig");
pub const nonce_manager = @import("core/util/nonce_manager.zig");

// RPC components
pub const rpc = struct {
    pub const types = @import("core/rpc/types.zig");
    pub const format = @import("core/rpc/format.zig");
    pub const server = @import("core/rpc/server.zig");
};

// Applications are separate executables and should not be part of the library API

// Re-export commonly used types for convenience
pub const Transaction = types.Transaction;
pub const Block = types.Block;
pub const BlockHeader = types.BlockHeader;
pub const Account = types.Account;
pub const Address = types.Address;
pub const Hash = types.Hash;
pub const ZeiCoin = blockchain.ZeiCoin;