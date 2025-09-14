// nonce_manager.zig - Client-side transaction nonce management
// Enables high-throughput transaction sending by managing nonces locally

const std = @import("std");
const types = @import("../types/types.zig");

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
            self.last_sync = std.time.timestamp();
        }
        
        /// Check if sync with server is needed (optimized for high throughput)
        fn needsSync(self: *const @This()) bool {
            const current_time = std.time.timestamp();
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
    
    /// Get next nonce for address, with automatic server sync when needed
    /// getNonceCallback should fetch current nonce from server
    pub fn getNextNonce(
        self: *Self, 
        address: types.Address,
        getNonceCallback: *const fn (address: types.Address) anyerror!u64
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const address_key = address.hash;
        
        // Get or create nonce state for this address
        const gop = try self.nonce_states.getOrPut(address_key);
        if (!gop.found_existing) {
            // First time seeing this address - sync with server
            const server_nonce = try getNonceCallback(address);
            gop.value_ptr.* = AddressNonceState{
                .base_nonce = server_nonce,
                .next_nonce = server_nonce,  // Start at server nonce (not +1)
                .pending_count = 0,
                .last_sync = std.time.timestamp(),
            };
        } else if (gop.value_ptr.needsSync()) {
            // Periodic sync - but DON'T block on it for high throughput
            // Just skip sync if we have pending nonces available
            if (gop.value_ptr.pending_count < 100) {
                // Only sync if not in burst mode
                const server_nonce = getNonceCallback(address) catch {
                    // If sync fails, continue with local nonces
                    return gop.value_ptr.allocateNonce();
                };
                
                // Only update if server nonce is higher (transactions confirmed)
                if (server_nonce > gop.value_ptr.base_nonce) {
                    const confirmed_transactions = server_nonce - gop.value_ptr.base_nonce;
                    gop.value_ptr.base_nonce = server_nonce;
                    
                    // Adjust pending count based on confirmations
                    if (confirmed_transactions <= gop.value_ptr.pending_count) {
                        gop.value_ptr.pending_count -= @intCast(confirmed_transactions);
                    } else {
                        // More confirmations than expected - reset
                        gop.value_ptr.pending_count = 0;
                    }
                    
                    // Ensure next_nonce is at least server_nonce
                    if (gop.value_ptr.next_nonce < server_nonce) {
                        gop.value_ptr.next_nonce = server_nonce;
                    }
                    
                    gop.value_ptr.last_sync = std.time.timestamp();
                }
            }
        }
        
        // Allocate next nonce
        return gop.value_ptr.allocateNonce();
    }
    
    /// Mark a transaction as failed (reduces pending count)
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
        getNonceCallback: *const fn (address: types.Address) anyerror!u64,
        max_retries: u32
    ) !u64 {
        var attempts: u32 = 0;
        
        while (attempts <= max_retries) : (attempts += 1) {
            // First attempt or retry: get nonce normally
            const nonce = self.getNextNonce(address, getNonceCallback) catch |err| {
                if (attempts < max_retries) {
                    // Force immediate sync and try again
                    self.forceSync(address, getNonceCallback) catch {};
                    continue;
                } else {
                    return err;
                }
            };
            
            return nonce;
        }
        
        return error.MaxRetriesExceeded;
    }
    
    /// Emergency nonce recovery - force sync and get conservative nonce
    pub fn emergencyNonceRecovery(
        self: *Self, 
        address: types.Address,
        getNonceCallback: *const fn (address: types.Address) anyerror!u64
    ) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Force fresh sync from server
        const server_nonce = try getNonceCallback(address);
        
        // Reset state completely
        if (self.nonce_states.getPtr(address.hash)) |state| {
            state.base_nonce = server_nonce;
            state.next_nonce = server_nonce + 1; // Conservative: only allocate 1 ahead
            state.pending_count = 1; // Mark as having 1 pending
            state.last_sync = std.time.timestamp();
        } else {
            try self.nonce_states.put(address.hash, AddressNonceState{
                .base_nonce = server_nonce,
                .next_nonce = server_nonce + 1,
                .pending_count = 1,
                .last_sync = std.time.timestamp(),
            });
        }
        
        return server_nonce + 1;
    }
    
    /// Force resync with server for an address (useful after transaction failures)
    pub fn forceSync(
        self: *Self, 
        address: types.Address,
        getNonceCallback: *const fn (address: types.Address) anyerror!u64
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        const server_nonce = try getNonceCallback(address);
        
        if (self.nonce_states.getPtr(address.hash)) |state| {
            state.reset(server_nonce);
        } else {
            try self.nonce_states.put(address.hash, AddressNonceState{
                .base_nonce = server_nonce,
                .next_nonce = server_nonce + 1,
                .pending_count = 0,
                .last_sync = std.time.timestamp(),
            });
        }
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