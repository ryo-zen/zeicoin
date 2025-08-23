// events.zig - Event-Driven Reorganization Architecture
// Modern event handling for reorganization operations

const std = @import("std");
const types = @import("../../types/types.zig");
const ReorgManager = @import("manager.zig");

const log = std.log.scoped(.reorg);

// Type aliases
const Block = types.Block;
const Transaction = types.Transaction;
const Hash = types.Hash;
const ReorgState = ReorgManager.ReorgState;

/// Reorganization events for comprehensive monitoring
pub const ReorgEvent = union(enum) {
    started: ReorgStarted,
    block_reverted: BlockReverted,
    block_applied: BlockApplied,
    completed: ReorgCompleted,
    failed: ReorgFailed,
    state_changed: StateChanged,
};

pub const ReorgStarted = struct {
    fork_height: u32,
    current_height: u32,
    depth: u32,
    new_chain_tip: Hash,
};

pub const BlockReverted = struct {
    height: u32,
    block_hash: Hash,
    transaction_count: u32,
};

pub const BlockApplied = struct {
    height: u32,
    block_hash: Hash,
    transaction_count: u32,
};

pub const ReorgCompleted = struct {
    blocks_reverted: u32,
    blocks_applied: u32,
    transactions_replayed: u32,
    transactions_orphaned: u32,
    duration_ms: u64,
};

pub const ReorgFailed = struct {
    error_stage: []const u8,
    error_message: []const u8,
    partial_completion: bool,
};

pub const StateChanged = struct {
    from_state: ReorgState,
    to_state: ReorgState,
};

/// Event handler function type
pub const EventHandler = *const fn (event: ReorgEvent) void;

/// Event-driven reorganization handler
pub const ReorgEventHandler = struct {
    handlers: std.ArrayList(EventHandler),
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize event handler
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .handlers = std.ArrayList(EventHandler).init(allocator),
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.handlers.deinit();
    }
    
    /// Register an event handler
    pub fn addHandler(self: *Self, handler: EventHandler) !void {
        try self.handlers.append(handler);
    }
    
    /// Remove an event handler
    pub fn removeHandler(self: *Self, handler: EventHandler) void {
        for (self.handlers.items, 0..) |h, i| {
            if (h == handler) {
                _ = self.handlers.orderedRemove(i);
                return;
            }
        }
    }
    
    /// Emit event to all registered handlers
    pub fn emit(self: *Self, event: ReorgEvent) void {
        for (self.handlers.items) |handler| {
            handler(event);
        }
    }
    
    // Convenience methods for specific events
    
    pub fn emitStarted(self: *Self, fork_height: u32, current_height: u32, new_chain_tip: Hash) !void {
        const event = ReorgEvent{
            .started = ReorgStarted{
                .fork_height = fork_height,
                .current_height = current_height,
                .depth = current_height - fork_height,
                .new_chain_tip = new_chain_tip,
            },
        };
        self.emit(event);
    }
    
    pub fn emitBlockReverted(self: *Self, height: u32, block_hash: Hash, tx_count: u32) !void {
        const event = ReorgEvent{
            .block_reverted = BlockReverted{
                .height = height,
                .block_hash = block_hash,
                .transaction_count = tx_count,
            },
        };
        self.emit(event);
    }
    
    pub fn emitBlockApplied(self: *Self, height: u32, block_hash: Hash, tx_count: u32) !void {
        const event = ReorgEvent{
            .block_applied = BlockApplied{
                .height = height,
                .block_hash = block_hash,
                .transaction_count = tx_count,
            },
        };
        self.emit(event);
    }
    
    pub fn emitCompleted(self: *Self, blocks_reverted: u32, blocks_applied: u32, tx_replayed: u32, tx_orphaned: u32, duration_ms: u64) !void {
        const event = ReorgEvent{
            .completed = ReorgCompleted{
                .blocks_reverted = blocks_reverted,
                .blocks_applied = blocks_applied,
                .transactions_replayed = tx_replayed,
                .transactions_orphaned = tx_orphaned,
                .duration_ms = duration_ms,
            },
        };
        self.emit(event);
    }
    
    pub fn emitFailed(self: *Self, stage: []const u8, message: []const u8, partial: bool) !void {
        const event = ReorgEvent{
            .failed = ReorgFailed{
                .error_stage = stage,
                .error_message = message,
                .partial_completion = partial,
            },
        };
        self.emit(event);
    }
    
    pub fn emitStateChange(self: *Self, from_state: ReorgState, to_state: ReorgState) !void {
        const event = ReorgEvent{
            .state_changed = StateChanged{
                .from_state = from_state,
                .to_state = to_state,
            },
        };
        self.emit(event);
    }
};

/// Default event handlers for logging
pub fn defaultLoggingHandler(event: ReorgEvent) void {
    switch (event) {
        .started => |e| {
            log.info("🔄 Reorganization started: depth={}, fork_height={}", .{ e.depth, e.fork_height });
        },
        .block_reverted => |e| {
            log.info("⏪ Block reverted: height={}, txs={}", .{ e.height, e.transaction_count });
        },
        .block_applied => |e| {
            log.info("📈 Block applied: height={}, txs={}", .{ e.height, e.transaction_count });
        },
        .completed => |e| {
            log.info("✅ Reorganization completed: {}/{}ms, {}/{} blocks, {}/{} txs", .{
                e.duration_ms, e.blocks_reverted, e.blocks_applied, e.transactions_replayed, e.transactions_orphaned
            });
        },
        .failed => |e| {
            log.info("❌ Reorganization failed at {}: {}", .{ e.error_stage, e.error_message });
        },
        .state_changed => |e| {
            log.info("🔄 Reorg state: {} → {}", .{ e.from_state, e.to_state });
        },
    }
}

/// Metrics collection handler
pub fn metricsHandler(event: ReorgEvent) void {
    // In a full implementation, this would update metrics
    switch (event) {
        .completed => |e| {
            // Update reorganization metrics
            _ = e;
            // metrics.total_reorgs.fetchAdd(1, .SeqCst);
            // metrics.deepest_reorg.fetchMax(e.blocks_reverted, .SeqCst);
        },
        else => {},
    }
}