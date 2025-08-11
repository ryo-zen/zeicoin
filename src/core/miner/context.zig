// context.zig - Mining Context and Dependencies
// Defines the structure for dependency injection into mining components

const std = @import("std");
const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");

/// Mining context that holds references to blockchain state
pub const MiningContext = struct {
    allocator: std.mem.Allocator,
    database: *@import("../storage/db.zig").Database,
    mempool_manager: *@import("../mempool/manager.zig").MempoolManager,
    mining_state: *types.MiningState,
    network: ?*@import("../network/peer.zig").NetworkManager,
    // fork_manager removed - using modern reorganization system
    
    // Reference to the blockchain for method calls
    blockchain: *@import("../node.zig").ZeiCoin,
};