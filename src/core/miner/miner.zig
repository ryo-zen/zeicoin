// miner.zig - Main Miner Module
// Public API for the modular mining system

// Re-export core components
pub const MiningContext = @import("context.zig").MiningContext;
pub const MiningManager = @import("manager.zig").MiningManager;

// Re-export core mining functions for backward compatibility
pub const zenMineBlock = @import("core.zig").zenMineBlock;
pub const zenProofOfWork = @import("core.zig").zenProofOfWork;

// Re-export algorithm-specific functions
pub const zenProofOfWorkSHA256 = @import("algorithms/sha256.zig").zenProofOfWorkSHA256;
pub const zenProofOfWorkRandomX = @import("algorithms/randomx.zig").zenProofOfWorkRandomX;

// Re-export validation functions
pub const validateBlockPoW = @import("validation.zig").validateBlockPoW;

// Re-export thread management functions for backward compatibility
pub const miningThreadFn = @import("manager.zig").miningThreadFn;
pub const startMining = @import("manager.zig").MiningManager.startMining;
pub const stopMining = @import("manager.zig").MiningManager.stopMining;