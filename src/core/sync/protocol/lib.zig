// lib.zig - Sync Protocol Library Exports
// Central export module for all sync protocol implementations

// Protocol implementations
pub const BlockSyncProtocol = @import("block_sync.zig").BlockSyncProtocol;
pub const HeadersFirstProtocol = @import("headers_first.zig").HeadersFirstProtocol;

// Context structs for dependency injection
pub const BlockSyncContext = @import("block_sync.zig").BlockSyncContext;
pub const ProtocolDependencies = @import("headers_first.zig").ProtocolDependencies;

// Re-export commonly used types for convenience
pub const block_sync = @import("block_sync.zig");
pub const headers_first = @import("headers_first.zig");