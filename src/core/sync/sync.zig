// sync.zig - Sync Module Public API
// ZSP-001 compliant synchronization system

// Core sync components
pub const manager = @import("manager.zig");
pub const state = @import("state.zig");

// Protocol implementations
pub const protocol = @import("protocol/lib.zig");

// Re-export main types for convenience
pub const SyncManager = manager.SyncManager;
pub const SyncState = state.SyncState;
pub const SyncProgress = state.SyncProgress;
pub const SyncStateManager = state.SyncStateManager;

// ZSP-001 Protocol types
pub const BatchSyncProtocol = protocol.BatchSyncProtocol;
pub const sequential = protocol.sequential;

// Legacy protocol (to be phased out)
pub const BlockSyncProtocol = protocol.BlockSyncProtocol;