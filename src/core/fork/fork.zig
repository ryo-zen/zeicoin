// fork.zig - Main Fork Module
// Public API for the modular fork management system

// Re-export main components
pub const ForkManager = @import("manager.zig").ForkManager;

// Re-export types for external use
pub const ForkDecision = @import("types.zig").ForkDecision;
pub const ForkStats = @import("types.zig").ForkStats;

// Re-export specialized components for advanced use
pub const chains = @import("chains.zig");
pub const orphans = @import("orphans.zig");
pub const decisions = @import("decisions.zig");