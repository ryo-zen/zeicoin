// main.zig - ZeiCoin Mining Module Entry Point (Modular)
// Public API that delegates to the modular mining system

// Re-export the modular mining system
// Note: Zig 0.16.0 deprecated 'pub usingnamespace', use explicit re-exports
const miner = @import("miner.zig");

pub const MiningContext = miner.MiningContext;
pub const MiningManager = miner.MiningManager;
pub const zenMineBlock = miner.zenMineBlock;
pub const zenProofOfWork = miner.zenProofOfWork;
pub const zenProofOfWorkRandomX = miner.zenProofOfWorkRandomX;
pub const validateBlockPoW = miner.validateBlockPoW;
pub const miningThreadFn = miner.miningThreadFn;
pub const startMining = miner.startMining;
pub const stopMining = miner.stopMining;