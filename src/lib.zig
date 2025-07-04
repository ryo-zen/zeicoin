// lib.zig - ZeiCoin Library Public API
// This file exports all public components of the ZeiCoin blockchain

// Core blockchain components
pub const blockchain = @import("core/node.zig");
pub const genesis = @import("core/chain/genesis.zig");
pub const forkmanager = @import("core/fork/main.zig");
pub const headerchain = @import("core/network/headerchain.zig");
pub const miner = @import("core/miner/main.zig");

// Chain management components
pub const chain = struct {
    pub const manager = @import("core/chain/manager.zig");
    pub const state = @import("core/chain/state.zig");
    pub const validator = @import("core/chain/validator.zig");
    pub const operations = @import("core/chain/operations.zig");
    pub const reorganization = @import("core/chain/reorganization.zig");
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
pub const server = @import("core/network/server.zig");

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

// Wallet components
pub const wallet = @import("core/wallet/wallet.zig");

// Utility components
pub const util = @import("core/util/util.zig");
pub const clispinners = @import("core/util/clispinners.zig");

// Applications are separate executables and should not be part of the library API

// Re-export commonly used types for convenience
pub const Transaction = types.Transaction;
pub const Block = types.Block;
pub const BlockHeader = types.BlockHeader;
pub const Account = types.Account;
pub const Address = types.Address;
pub const Hash = types.Hash;
pub const ZeiCoin = blockchain.ZeiCoin;