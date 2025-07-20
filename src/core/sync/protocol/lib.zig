// lib.zig - ZSP-001 Sync Protocol Library Exports
// Central export module for ZeiCoin Synchronization Protocol implementation
//
// This module provides the public API for ZSP-001 compliant blockchain
// synchronization with high-performance batch downloading and sequential
// block request utilities for error recovery.

// ============================================================================
// ZSP-001 PRIMARY PROTOCOL EXPORTS
// ============================================================================

/// ZSP-001 compliant batch synchronization protocol
/// High-performance batch downloading with up to 50x improvement over sequential sync
pub const BatchSyncProtocol = @import("batch_sync.zig").BatchSyncProtocol;

/// Dependency injection context for batch sync integration
pub const BatchSyncContext = @import("batch_sync.zig").BatchSyncContext;

/// ZSP-001 synchronization states
pub const SyncState = @import("batch_sync.zig").BatchSyncProtocol.SyncState;

/// Sequential sync utilities for single block requests
/// Used by batch sync for error recovery and specific block fetching
pub const sequential = @import("sequential_sync.zig");

// ============================================================================
// ZSP-001 UTILITY FUNCTIONS
// ============================================================================

/// Check if a hash represents a ZSP-001 height-encoded request
pub const isHeightEncodedRequest = @import("batch_sync.zig").isHeightEncodedRequest;

/// Run ZSP-001 protocol test suite
pub const runTests = @import("batch_sync.zig").runTests;

// ============================================================================
// LEGACY PROTOCOL (DEPRECATED - WILL BE REMOVED)
// ============================================================================

/// Legacy block sync protocol (deprecated in favor of ZSP-001 batch sync)
/// This will be removed in a future version
pub const BlockSyncProtocol = @import("block_sync.zig").BlockSyncProtocol;

/// Legacy block sync context (deprecated)
pub const BlockSyncContext = @import("block_sync.zig").BlockSyncContext;

// ============================================================================
// MODULE RE-EXPORTS FOR CONVENIENCE
// ============================================================================

/// Complete batch sync module for advanced usage
pub const batch_sync = @import("batch_sync.zig");

/// Sequential sync utilities module
pub const sequential_sync = @import("sequential_sync.zig");

/// Legacy block sync module (deprecated)
pub const block_sync = @import("block_sync.zig");