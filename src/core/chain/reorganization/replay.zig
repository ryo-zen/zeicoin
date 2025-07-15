// replay.zig - Transaction Replay Engine
// Advanced transaction handling during reorganization operations

const std = @import("std");
const types = @import("../../types/types.zig");
const ChainState = @import("../state.zig").ChainState;
const ChainValidator = @import("../validator.zig").ChainValidator;

// Type aliases
const Transaction = types.Transaction;
const Hash = types.Hash;

/// Transaction validation result cache entry
pub const ValidationResult = struct {
    is_valid: bool,
    error_reason: ?[]const u8,
    timestamp: i64,
    
    /// Check if cache entry is still fresh
    pub fn isFresh(self: *const ValidationResult, max_age_ms: i64) bool {
        const now = std.time.milliTimestamp();
        return (now - self.timestamp) < max_age_ms;
    }
};

/// Transaction dependency for topological sorting
pub const TxDependency = struct {
    tx_hash: Hash,
    depends_on: std.ArrayList(Hash),
    
    pub fn deinit(self: *TxDependency) void {
        self.depends_on.deinit();
    }
};

/// Transaction dependency graph for proper replay ordering
pub const TxDependencyGraph = struct {
    dependencies: std.HashMap(Hash, TxDependency, HashContext, std.hash_map.default_max_load_percentage),
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Hash context for transaction hash keys
    const HashContext = struct {
        pub fn hash(self: @This(), s: Hash) u64 {
            _ = self;
            return std.hash_map.hashString(&s);
        }
        pub fn eql(self: @This(), a: Hash, b: Hash) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .dependencies = std.HashMap(Hash, TxDependency, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Self) void {
        var iter = self.dependencies.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.dependencies.deinit();
    }
    
    /// Add transaction dependency
    pub fn addDependency(self: *Self, tx_hash: Hash, depends_on: Hash) !void {
        var entry = self.dependencies.getPtr(tx_hash) orelse blk: {
            const new_dep = TxDependency{
                .tx_hash = tx_hash,
                .depends_on = std.ArrayList(Hash).init(self.allocator),
            };
            try self.dependencies.put(tx_hash, new_dep);
            break :blk self.dependencies.getPtr(tx_hash).?;
        };
        
        try entry.depends_on.append(depends_on);
    }
    
    /// Perform topological sort to get dependency-ordered transactions
    pub fn topologicalSort(self: *Self, transactions: []Transaction) !std.ArrayList(Transaction) {
        var sorted = std.ArrayList(Transaction).init(self.allocator);
        var visited = std.HashMap(Hash, bool, HashContext, std.hash_map.default_max_load_percentage).init(self.allocator);
        defer visited.deinit();
        
        // For now, return simple FIFO order (topological sort is complex)
        // In a full implementation, this would implement Kahn's algorithm
        for (transactions) |tx| {
            try sorted.append(tx);
        }
        
        return sorted;
    }
};

/// Failed transaction information
pub const FailedTx = struct {
    tx: Transaction,
    reason: FailureReason,
    
    pub const FailureReason = enum {
        InvalidAfterReorg,
        InsufficientBalance,
        InvalidNonce,
        ValidationFailed,
        DependencyFailed,
    };
};

/// Transaction replay result
pub const ReplayResult = struct {
    replayed: std.ArrayList(Transaction),
    failed: std.ArrayList(FailedTx),
    
    pub fn deinit(self: *ReplayResult) void {
        // Note: Individual transactions are owned by the caller
        self.replayed.deinit();
        
        // Free failed transaction data
        for (self.failed.items) |*failed_tx| {
            failed_tx.tx.deinit(self.replayed.allocator);
        }
        self.failed.deinit();
    }
    
    pub fn getStats(self: *const ReplayResult) struct {
        replayed_count: usize,
        failed_count: usize,
        success_rate: f64,
    } {
        const total = self.replayed.items.len + self.failed.items.len;
        const success_rate = if (total > 0) @as(f64, @floatFromInt(self.replayed.items.len)) / @as(f64, @floatFromInt(total)) else 0.0;
        
        return .{
            .replayed_count = self.replayed.items.len,
            .failed_count = self.failed.items.len,
            .success_rate = success_rate,
        };
    }
};

/// Advanced Transaction Replay Engine
pub const TxReplayEngine = struct {
    // Validation cache for performance
    validation_cache: std.HashMap(Hash, ValidationResult, HashContext, std.hash_map.default_max_load_percentage),
    
    // Dependency tracking
    dependency_graph: TxDependencyGraph,
    
    // Configuration
    cache_max_age_ms: i64,
    max_cache_size: usize,
    
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Hash context for transaction hash keys
    const HashContext = struct {
        pub fn hash(self: @This(), s: Hash) u64 {
            _ = self;
            return std.hash_map.hashString(&s);
        }
        pub fn eql(self: @This(), a: Hash, b: Hash) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    /// Initialize replay engine
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .validation_cache = std.HashMap(Hash, ValidationResult, HashContext, std.hash_map.default_max_load_percentage).init(allocator),
            .dependency_graph = TxDependencyGraph.init(allocator),
            .cache_max_age_ms = 60000, // 1 minute cache
            .max_cache_size = 10000,   // Max 10k cached validations
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.validation_cache.deinit();
        self.dependency_graph.deinit();
    }
    
    /// Main transaction replay function
    pub fn replayTransactions(
        self: *Self,
        orphaned_txs: []Transaction,
        chain_state: *ChainState,
        chain_validator: *ChainValidator,
    ) !ReplayResult {
        std.debug.print("🔄 Replaying {} orphaned transactions\n", .{orphaned_txs.len});
        
        // Initialize result containers
        var result = ReplayResult{
            .replayed = std.ArrayList(Transaction).init(self.allocator),
            .failed = std.ArrayList(FailedTx).init(self.allocator),
        };
        
        // Sort transactions by dependency order
        const sorted_txs = try self.dependency_graph.topologicalSort(orphaned_txs);
        defer sorted_txs.deinit();
        
        // Replay each transaction in order
        for (sorted_txs.items) |tx| {
            const validation_result = try self.validateTxCached(tx, chain_state, chain_validator);
            
            if (validation_result.is_valid) {
                // Apply transaction to chain state
                chain_state.processTransaction(tx) catch |err| {
                    // Transaction failed to apply
                    const failed_tx = FailedTx{
                        .tx = try tx.dupe(self.allocator),
                        .reason = switch (err) {
                            error.InsufficientBalance => .InsufficientBalance,
                            error.InvalidNonce => .InvalidNonce,
                            else => .ValidationFailed,
                        },
                    };
                    try result.failed.append(failed_tx);
                    continue;
                };
                
                // Transaction successfully replayed
                try result.replayed.append(tx);
                std.debug.print("✅ Replayed transaction: {}\n", .{std.fmt.fmtSliceHexLower(tx.hash()[0..8])});
                
            } else {
                // Transaction validation failed
                const failed_tx = FailedTx{
                    .tx = try tx.dupe(self.allocator),
                    .reason = .InvalidAfterReorg,
                };
                try result.failed.append(failed_tx);
                std.debug.print("❌ Transaction invalid after reorg: {}\n", .{std.fmt.fmtSliceHexLower(tx.hash()[0..8])});
            }
        }
        
        const stats = result.getStats();
        std.debug.print("🎯 Replay complete: {}/{} success ({:.1}%)\n", .{
            stats.replayed_count, stats.replayed_count + stats.failed_count, stats.success_rate * 100
        });
        
        return result;
    }
    
    /// Validate transaction with caching
    fn validateTxCached(
        self: *Self,
        tx: Transaction,
        chain_state: *ChainState,
        chain_validator: *ChainValidator,
    ) !ValidationResult {
        const tx_hash = tx.hash();
        
        // Check cache first
        if (self.validation_cache.get(tx_hash)) |cached_result| {
            if (cached_result.isFresh(self.cache_max_age_ms)) {
                return cached_result;
            }
            // Cache entry is stale, remove it
            _ = self.validation_cache.remove(tx_hash);
        }
        
        // Perform fresh validation
        const is_valid = chain_validator.validateTransaction(tx, chain_state) catch false;
        
        const result = ValidationResult{
            .is_valid = is_valid,
            .error_reason = if (!is_valid) "Validation failed" else null,
            .timestamp = std.time.milliTimestamp(),
        };
        
        // Cache the result
        try self.cacheValidationResult(tx_hash, result);
        
        return result;
    }
    
    /// Cache validation result with size management
    fn cacheValidationResult(self: *Self, tx_hash: Hash, result: ValidationResult) !void {
        // Check cache size limit
        if (self.validation_cache.count() >= self.max_cache_size) {
            try self.evictOldCacheEntries();
        }
        
        try self.validation_cache.put(tx_hash, result);
    }
    
    /// Evict old cache entries to manage memory
    fn evictOldCacheEntries(self: *Self) !void {
        const now = std.time.milliTimestamp();
        const eviction_age = self.cache_max_age_ms / 2; // Evict entries older than half max age
        
        var to_remove = std.ArrayList(Hash).init(self.allocator);
        defer to_remove.deinit();
        
        // Find old entries
        var iter = self.validation_cache.iterator();
        while (iter.next()) |entry| {
            if ((now - entry.value_ptr.timestamp) > eviction_age) {
                try to_remove.append(entry.key_ptr.*);
            }
        }
        
        // Remove old entries
        for (to_remove.items) |hash| {
            _ = self.validation_cache.remove(hash);
        }
        
        std.debug.print("🧹 Evicted {} old validation cache entries\n", .{to_remove.items.len});
    }
    
    /// Build dependency graph for transactions
    pub fn buildDependencyGraph(self: *Self, transactions: []Transaction) !void {
        // Clear existing dependencies
        self.dependency_graph.deinit();
        self.dependency_graph = TxDependencyGraph.init(self.allocator);
        
        // In a full implementation, this would analyze transaction dependencies
        // For now, we assume transactions are independent
        for (transactions) |tx| {
            _ = tx;
            // Would analyze tx inputs/outputs to build dependency graph
        }
    }
    
    /// Get replay engine statistics
    pub fn getStats(self: *const Self) struct {
        cache_size: usize,
        cache_hit_rate: f64,
        dependency_count: usize,
    } {
        // In a full implementation, would track cache hit rate
        return .{
            .cache_size = self.validation_cache.count(),
            .cache_hit_rate = 0.0, // Would track actual hit rate
            .dependency_count = self.dependency_graph.dependencies.count(),
        };
    }
    
    /// Clear all caches and reset state
    pub fn reset(self: *Self) void {
        self.validation_cache.clearRetainingCapacity();
        self.dependency_graph.deinit();
        self.dependency_graph = TxDependencyGraph.init(self.allocator);
        
        std.debug.print("🔄 Transaction replay engine reset\n", .{});
    }
};