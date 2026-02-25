// nonce_manager.zig - Client-side transaction nonce management
// Enables high-throughput transaction sending by managing nonces locally

const std = @import("std");
const types = @import("../types/types.zig");
const util = @import("util.zig");

pub const NonceManagerError = error{
    AllocationFailed,
    NonceOverflow,
    InvalidAddress,
};

/// Client-side nonce manager for high-throughput transaction sending
/// Prevents race conditions by tracking pending nonces locally
pub const NonceManager = struct {
    const Self = @This();
    
    /// Per-address nonce state
    const AddressNonceState = struct {
        base_nonce: u64,      // Last confirmed nonce from server
        next_nonce: u64,      // Next nonce to assign
        pending_count: u32,   // Number of pending transactions
        last_sync: i64,       // Timestamp of last server sync
        
        /// Get next available nonce and increment counter
        fn allocateNonce(self: *@This()) u64 {
            const nonce = self.next_nonce;
            self.next_nonce += 1;
            self.pending_count += 1;
            return nonce;
        }
        
        /// Reset to server-provided base nonce
        fn reset(self: *@This(), server_nonce: u64) void {
            self.base_nonce = server_nonce;
            self.next_nonce = server_nonce + 1;
            self.pending_count = 0;
            self.last_sync = util.getTime();
        }
        
        /// Check if sync with server is needed (optimized for high throughput)
        fn needsSync(self: *const @This()) bool {
            const current_time = util.getTime();
            const sync_age = current_time - self.last_sync;
            
            // Optimized for high-throughput: less frequent syncs
            if (self.pending_count > 100) {
                // Ultra-high load: sync every 10 seconds (was 2)
                return sync_age > 10;
            } else if (self.pending_count > 50) {
                // High load: sync every 30 seconds (was 5)
                return sync_age > 30;
            } else if (self.pending_count > 20) {
                // Medium load: sync every 60 seconds (was 10)
                return sync_age > 60;
            } else {
                // Low load: sync every 120 seconds (was 30)
                return sync_age > 120;
            }
        }
    };
    
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    nonce_states: std.HashMap([20]u8, AddressNonceState, AddressHashContext, std.hash_map.default_max_load_percentage),
    
    /// Hash context for address keys
    const AddressHashContext = struct {
        pub fn hash(self: @This(), key: [20]u8) u64 {
            _ = self;
            return std.hash.Wyhash.hash(0, &key);
        }
        
        pub fn eql(self: @This(), a: [20]u8, b: [20]u8) bool {
            _ = self;
            return std.mem.eql(u8, &a, &b);
        }
    };
    
    /// Initialize nonce manager
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .mutex = std.Thread.Mutex{},
            .nonce_states = std.HashMap([20]u8, AddressNonceState, AddressHashContext, std.hash_map.default_max_load_percentage).init(allocator),
        };
    }
    
    /// Clean up resources
    pub fn deinit(self: *Self) void {
        self.nonce_states.deinit();
    }
    
    /// Get or sync nonce for an address
    pub fn getNextNonce(
        self: *Self, 
        address: types.Address, 
        io: std.Io,
        getNonceCallback: *const fn (address: types.Address, io: std.Io) anyerror!u64
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const state = self.nonce_states.getPtr(address.hash) orelse {
            // New address, initialize from server
            const server_nonce = try getNonceCallback(address, io);
            var new_state = AddressNonceState{
                .base_nonce = server_nonce,
                .next_nonce = server_nonce, // Start with server nonce
                .pending_count = 0,
                .last_sync = util.getTime(),
            };
            const nonce = new_state.allocateNonce();
            try self.nonce_states.put(address.hash, new_state);
            return nonce;
        };

        // Check if we need to sync with server
        if (state.needsSync()) {
            const server_nonce = getNonceCallback(address, io) catch state.base_nonce;
            if (server_nonce > state.base_nonce) {
                // Server has higher nonce, reset our state
                state.reset(server_nonce);
            }
        }

        return state.allocateNonce();
    }

    /// Force immediate sync with server
    pub fn forceSync(
        self: *Self, 
        address: types.Address, 
        io: std.Io,
        getNonceCallback: *const fn (address: types.Address, io: std.Io) anyerror!u64
    ) !void {
        const server_nonce = try getNonceCallback(address, io);
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.nonce_states.getPtr(address.hash)) |state| {
            state.reset(server_nonce);
        } else {
            try self.nonce_states.put(address.hash, AddressNonceState{
                .base_nonce = server_nonce,
                .next_nonce = server_nonce,
                .pending_count = 0,
                .last_sync = util.getTime(),
            });
        }
    }

    /// Emergency nonce recovery - resets to server nonce directly
    pub fn emergencyNonceRecovery(
        self: *Self, 
        address: types.Address, 
        io: std.Io,
        getNonceCallback: *const fn (address: types.Address, io: std.Io) anyerror!u64
    ) !u64 {
        try self.forceSync(address, io, getNonceCallback);
        return self.getNextNonce(address, io, getNonceCallback);
    }

    /// Mark a transaction as failed (decrements pending count)
    pub fn markTransactionFailed(self: *Self, address: types.Address) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.nonce_states.getPtr(address.hash)) |state| {
            if (state.pending_count > 0) {
                state.pending_count -= 1;
            }
        }
    }
    
    /// Get nonce with immediate retry on failure (ultra-reliable)
    pub fn getNextNonceWithRetry(
        self: *Self, 
        address: types.Address,
        io: std.Io,
        getNonceCallback: *const fn (address: types.Address, io: std.Io) anyerror!u64,
        max_retries: u32
    ) !u64 {
        var attempts: u32 = 0;
        
        while (attempts <= max_retries) : (attempts += 1) {
            // First attempt or retry: get nonce normally
            const nonce = self.getNextNonce(address, io, getNonceCallback) catch |err| {
                if (attempts < max_retries) {
                    // Force immediate sync and try again
                    self.forceSync(address, io, getNonceCallback) catch {};
                    continue;
                } else {
                    return err;
                }
            };
            
            return nonce;
        }
        
        return error.NonceRecoveryFailed;
    }
    
    /// Get status information for debugging
    pub fn getStatus(self: *Self, address: types.Address) ?AddressNonceState {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.nonce_states.get(address.hash);
    }
    
    /// Clear all cached nonce states (useful for testing)
    pub fn clear(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        self.nonce_states.clearAndFree();
    }
};

// Test suite
const testing = std.testing;

test "NonceManager basic functionality" {
    var manager = NonceManager.init(testing.allocator);
    defer manager.deinit();
    
    // Mock address
    const test_address = types.Address{
        .version = 0,
        .hash = [_]u8{1} ** 20,
    };
    
    // Simple test callback that returns a fixed nonce
    const testCallback = struct {
        fn getNonce(addr: types.Address) !u64 {
            _ = addr;
            return 100; // Always return 100 for simplicity
        }
    }.getNonce;
    
    // First call should sync with server and return server_nonce
    const nonce1 = try manager.getNextNonce(test_address, testCallback);
    try testing.expectEqual(@as(u64, 100), nonce1);
    
    // Second call should increment without server call
    const nonce2 = try manager.getNextNonce(test_address, testCallback);
    try testing.expectEqual(@as(u64, 101), nonce2);
}

test "NonceManager concurrent access simulation" {
    var manager = NonceManager.init(testing.allocator);
    defer manager.deinit();
    
    const test_address = types.Address{
        .version = 0,
        .hash = [_]u8{2} ** 20,
    };
    
    const testCallback = struct {
        fn getNonce(addr: types.Address) !u64 {
            _ = addr;
            return 200; // Fixed server nonce
        }
    }.getNonce;
    
    // Simulate sequential access (mimics concurrent behavior for testing)
    var nonces: [5]u64 = undefined;
    
    // First call syncs with server
    nonces[0] = try manager.getNextNonce(test_address, testCallback);
    try testing.expectEqual(@as(u64, 200), nonces[0]);
    
    // Subsequent calls should increment locally
    for (nonces[1..], 1..) |*nonce, i| {
        nonce.* = try manager.getNextNonce(test_address, testCallback);
        try testing.expectEqual(@as(u64, 200 + i), nonce.*);
    }
}
