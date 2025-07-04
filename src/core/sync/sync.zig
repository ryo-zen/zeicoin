// sync.zig - Sync Module Public API
// Main entry point for the modular sync system

// Core sync components
pub const manager = @import("manager.zig");
pub const state = @import("state.zig");

// Protocol implementations
pub const protocol = @import("protocol/lib.zig");

// Re-export main types for convenience
pub const SyncManager = manager.SyncManager;
pub const SyncState = state.SyncState;
pub const SyncProgress = state.SyncProgress;
pub const HeadersProgress = state.HeadersProgress;
pub const SyncStateManager = state.SyncStateManager;

// Protocol types
pub const BlockSyncProtocol = protocol.BlockSyncProtocol;
pub const HeadersFirstProtocol = protocol.HeadersFirstProtocol;