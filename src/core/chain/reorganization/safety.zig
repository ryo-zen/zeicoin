// safety.zig - Reorganization Safety Mechanisms
// Comprehensive safety checks and limits for chain reorganization

const std = @import("std");
const types = @import("../../types/types.zig");

/// Work type for chain work comparison
pub const ChainWork = struct {
    value: u256,
    
    pub fn lessThan(self: ChainWork, other: ChainWork) bool {
        return self.value < other.value;
    }
    
    pub fn lessThanOrEqual(self: ChainWork, other: ChainWork) bool {
        return self.value <= other.value;
    }
};

/// Reorganization safety checker
pub const ReorgSafety = struct {
    // Safety configuration
    max_reorg_depth: u32,
    finality_depth: u32,
    checkpoint_heights: std.ArrayList(u32),
    
    // Network-specific limits
    max_reorg_time_ms: u64,
    max_memory_usage_mb: u64,
    
    // Security features
    require_confirmation: bool,
    emergency_brake: bool,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize safety checker with default values
    pub fn init() Self {
        // Create with default allocator for simplicity
        const allocator = std.heap.page_allocator;
        return .{
            .max_reorg_depth = 100,        // Maximum 100 blocks deep
            .finality_depth = 6,           // 6 blocks considered final
            .checkpoint_heights = std.ArrayList(u32).init(allocator),
            .max_reorg_time_ms = 30000,    // 30 second timeout
            .max_memory_usage_mb = 500,    // 500MB memory limit
            .require_confirmation = false,  // Auto-approve safe reorgs
            .emergency_brake = false,      // Emergency stop disabled
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.checkpoint_heights.deinit();
    }
    
    /// Main reorganization validation function
    pub fn validateReorganization(self: *Self, depth: u32, current_height: u32) !void {
        std.debug.print("🔒 Safety check: depth={}, height={}\n", .{ depth, current_height });
        
        // Emergency brake check
        if (self.emergency_brake) {
            return error.EmergencyBrakeActivated;
        }
        
        // Depth limit check
        try self.checkDepthLimit(depth);
        
        // Finality check
        try self.checkFinality(depth, current_height);
        
        // Checkpoint verification
        try self.checkCheckpoints(current_height - depth);
        
        // Resource limits
        try self.checkResourceLimits(depth);
        
        std.debug.print("✅ Safety validation passed\n", .{});
    }
    
    /// Validate reorganization work requirements (from atomic_reorg)
    /// Returns true if new chain has more work and reorg should proceed
    pub fn validateWorkRequirements(self: *Self, current_work: ChainWork, new_work: ChainWork, current_tip_hash: types.Hash, new_tip_hash: types.Hash) bool {
        _ = self;
        
        // Must have more work to justify reorganization
        if (new_work.lessThanOrEqual(current_work)) {
            std.debug.print("⚠️ [REORG] New chain has insufficient work: {} <= {}\n", .{ new_work.value, current_work.value });
            return false;
        }
        
        // Check if already on the same chain
        if (std.mem.eql(u8, &current_tip_hash, &new_tip_hash)) {
            std.debug.print("ℹ️ [REORG] Already on best chain\n", .{});
            return false;
        }
        
        std.debug.print("✅ [REORG] Work validation passed: new_work={} > current_work={}\n", .{ new_work.value, current_work.value });
        return true;
    }
    
    /// Check if reorganization depth is within limits
    fn checkDepthLimit(self: *Self, depth: u32) !void {
        if (depth > self.max_reorg_depth) {
            std.debug.print("❌ Reorganization too deep: {} > {}\n", .{ depth, self.max_reorg_depth });
            return error.ReorgTooDeep;
        }
        
        // Special handling for deep reorganizations
        if (depth > 10) {
            std.debug.print("⚠️ Deep reorganization detected: {} blocks\n", .{depth});
            
            if (self.require_confirmation) {
                // In a full implementation, would prompt for confirmation
                std.debug.print("🛑 Deep reorganization requires manual confirmation\n", .{});
                return error.ConfirmationRequired;
            }
        }
    }
    
    /// Check if reorganization violates finality rules
    fn checkFinality(self: *Self, depth: u32, current_height: u32) !void {
        // Check if reorganization would affect "final" blocks
        const final_height = if (current_height > self.finality_depth) 
            current_height - self.finality_depth 
        else 
            0;
        
        const fork_height = current_height - depth;
        
        if (fork_height < final_height) {
            std.debug.print("❌ Reorganization violates finality: fork_height={}, final_height={}\n", .{ fork_height, final_height });
            return error.FinalityViolation;
        }
    }
    
    /// Check reorganization against known checkpoints
    fn checkCheckpoints(self: *Self, fork_height: u32) !void {
        for (self.checkpoint_heights.items) |checkpoint| {
            if (fork_height < checkpoint) {
                std.debug.print("❌ Reorganization beyond checkpoint: fork_height={}, checkpoint={}\n", .{ fork_height, checkpoint });
                return error.ReorgBeyondCheckpoint;
            }
        }
    }
    
    /// Check resource limits for reorganization
    fn checkResourceLimits(self: *Self, depth: u32) !void {
        // Estimate memory usage (simplified calculation)
        const estimated_memory_mb = depth * 2; // ~2MB per block
        
        if (estimated_memory_mb > self.max_memory_usage_mb) {
            std.debug.print("❌ Reorganization exceeds memory limit: {}MB > {}MB\n", .{ estimated_memory_mb, self.max_memory_usage_mb });
            return error.MemoryLimitExceeded;
        }
    }
    
    /// Add a checkpoint height
    pub fn addCheckpoint(self: *Self, height: u32) !void {
        // Insert in sorted order
        var insert_pos: usize = 0;
        for (self.checkpoint_heights.items, 0..) |checkpoint, i| {
            if (height < checkpoint) {
                insert_pos = i;
                break;
            }
            if (height == checkpoint) {
                return; // Checkpoint already exists
            }
            insert_pos = i + 1;
        }
        
        try self.checkpoint_heights.insert(insert_pos, height);
        std.debug.print("📍 Checkpoint added at height {}\n", .{height});
    }
    
    /// Remove a checkpoint height
    pub fn removeCheckpoint(self: *Self, height: u32) bool {
        for (self.checkpoint_heights.items, 0..) |checkpoint, i| {
            if (checkpoint == height) {
                _ = self.checkpoint_heights.orderedRemove(i);
                std.debug.print("📍 Checkpoint removed at height {}\n", .{height});
                return true;
            }
        }
        return false;
    }
    
    /// Get all checkpoint heights
    pub fn getCheckpoints(self: *const Self) []const u32 {
        return self.checkpoint_heights.items;
    }
    
    /// Update safety configuration
    pub fn updateConfig(self: *Self, config: SafetyConfig) void {
        self.max_reorg_depth = config.max_reorg_depth;
        self.finality_depth = config.finality_depth;
        self.max_reorg_time_ms = config.max_reorg_time_ms;
        self.max_memory_usage_mb = config.max_memory_usage_mb;
        self.require_confirmation = config.require_confirmation;
        
        std.debug.print("🔒 Safety configuration updated\n", .{});
    }
    
    /// Activate emergency brake (stops all reorganizations)
    pub fn activateEmergencyBrake(self: *Self) void {
        self.emergency_brake = true;
        std.debug.print("🚨 EMERGENCY BRAKE ACTIVATED - All reorganizations stopped\n", .{});
    }
    
    /// Deactivate emergency brake
    pub fn deactivateEmergencyBrake(self: *Self) void {
        self.emergency_brake = false;
        std.debug.print("✅ Emergency brake deactivated\n", .{});
    }
    
    /// Check if specific reorganization operation is safe
    pub fn canReorg(self: *Self, fork_height: u32, current_height: u32) !bool {
        const depth = current_height - fork_height;
        
        // Run all safety checks
        self.validateReorganization(depth, current_height) catch |err| {
            std.debug.print("🚫 Reorganization rejected: {}\n", .{err});
            return false;
        };
        
        return true;
    }
    
    /// Get safety statistics
    pub fn getStats(self: *const Self) SafetyStats {
        return SafetyStats{
            .max_reorg_depth = self.max_reorg_depth,
            .finality_depth = self.finality_depth,
            .checkpoint_count = self.checkpoint_heights.items.len,
            .emergency_brake_active = self.emergency_brake,
            .require_confirmation = self.require_confirmation,
        };
    }
    
    /// Network-specific safety presets
    pub fn applyNetworkPreset(self: *Self, network: types.Network) void {
        switch (network) {
            .testnet => {
                // More permissive for testing
                self.max_reorg_depth = 1000;
                self.finality_depth = 3;
                self.require_confirmation = false;
                self.max_reorg_time_ms = 60000; // 1 minute
                std.debug.print("🧪 Applied TestNet safety preset\n", .{});
            },
            .mainnet => {
                // Conservative for production
                self.max_reorg_depth = 100;
                self.finality_depth = 6;
                self.require_confirmation = true; // Require confirmation for deep reorgs
                self.max_reorg_time_ms = 30000; // 30 seconds
                std.debug.print("🏭 Applied MainNet safety preset\n", .{});
            },
        }
    }
};

/// Safety configuration structure
pub const SafetyConfig = struct {
    max_reorg_depth: u32,
    finality_depth: u32,
    max_reorg_time_ms: u64,
    max_memory_usage_mb: u64,
    require_confirmation: bool,
};

/// Safety statistics
pub const SafetyStats = struct {
    max_reorg_depth: u32,
    finality_depth: u32,
    checkpoint_count: usize,
    emergency_brake_active: bool,
    require_confirmation: bool,
};

/// Reorganization risk assessment
pub const RiskLevel = enum {
    low,        // < 3 blocks
    medium,     // 3-10 blocks  
    high,       // 11-50 blocks
    critical,   // > 50 blocks
    
    pub fn fromDepth(depth: u32) RiskLevel {
        return if (depth < 3) .low
        else if (depth < 11) .medium
        else if (depth < 51) .high
        else .critical;
    }
    
    pub fn getDescription(self: RiskLevel) []const u8 {
        return switch (self) {
            .low => "Low risk - Normal operation",
            .medium => "Medium risk - Monitor carefully", 
            .high => "High risk - Requires attention",
            .critical => "Critical risk - Manual intervention required",
        };
    }
};

/// Safety utilities
pub const SafetyUtils = struct {
    /// Assess reorganization risk level
    pub fn assessRisk(depth: u32, current_height: u32) struct { level: RiskLevel, description: []const u8 } {
        _ = current_height;
        const level = RiskLevel.fromDepth(depth);
        return .{
            .level = level,
            .description = level.getDescription(),
        };
    }
    
    /// Check if reorganization is in safe operating parameters
    pub fn isInSafeParameters(depth: u32, time_since_last_reorg_ms: u64) bool {
        // Conservative safety checks
        const max_safe_depth = 10;
        const min_time_between_reorgs_ms = 60000; // 1 minute
        
        return depth <= max_safe_depth and time_since_last_reorg_ms >= min_time_between_reorgs_ms;
    }
};