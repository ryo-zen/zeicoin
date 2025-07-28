// pool.zig - Core Mempool Storage Manager
// Manages the core mempool data structures and basic operations
// Provides thread-safe access to transaction storage

const std = @import("std");
const types = @import("../types/types.zig");
const ArrayList = std.ArrayList;
const Mutex = std.Thread.Mutex;

// Type aliases for clarity
const Transaction = types.Transaction;
const Hash = types.Hash;

/// Core mempool storage with thread-safe access
/// - Manages ArrayList<Transaction> and size tracking
/// - Provides basic add/remove operations
/// - Handles memory management for transactions
/// - Ensures thread-safe access patterns
pub const MempoolStorage = struct {
    // Core storage
    transactions: ArrayList(Transaction),
    total_size_bytes: usize,
    
    // Thread safety
    mutex: Mutex,
    
    // Resource management
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    /// Initialize mempool storage
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .transactions = ArrayList(Transaction).init(allocator),
            .total_size_bytes = 0,
            .mutex = Mutex{},
            .allocator = allocator,
        };
    }
    
    /// Cleanup resources
    pub fn deinit(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Free all transactions before freeing the list
        for (self.transactions.items) |*tx| {
            tx.deinit(self.allocator);
        }
        self.transactions.deinit();
    }
    
    /// Add transaction to pool (internal operation without validation)
    pub fn addTransactionToPool(self: *Self, transaction: Transaction) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Create owned copy of transaction
        var owned_tx = try transaction.dupe(self.allocator);
        errdefer owned_tx.deinit(self.allocator);
        
        // Add to storage
        try self.transactions.append(owned_tx);
        self.total_size_bytes += transaction.getSerializedSize();
    }
    
    /// Remove transaction from pool by hash
    pub fn removeTransactionFromPool(self: *Self, tx_hash: Hash) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.transactions.items, 0..) |*tx, i| {
            if (std.mem.eql(u8, &tx.hash(), &tx_hash)) {
                const tx_size = tx.getSerializedSize();
                
                // Free transaction memory
                tx.deinit(self.allocator);
                
                // Remove from list and update size
                _ = self.transactions.swapRemove(i);
                self.total_size_bytes -= tx_size;
                
                return true;
            }
        }
        
        return false; // Transaction not found
    }
    
    /// Check if transaction exists in pool
    pub fn containsTransaction(self: *Self, tx_hash: Hash) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        
        for (self.transactions.items) |tx| {
            if (std.mem.eql(u8, &tx.hash(), &tx_hash)) {
                return true;
            }
        }
        
        return false;
    }
    
    /// Get transaction from pool by hash
    pub fn getTransaction(self: *Self, tx_hash: Hash) ?Transaction {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        for (self.transactions.items) |tx| {
            if (std.mem.eql(u8, &tx.hash(), &tx_hash)) {
                // Return a copy of the transaction
                return tx.dupe(self.allocator) catch null;
            }
        }
        
        return null;
    }
    
    /// Get transaction count
    pub fn getTransactionCount(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.transactions.items.len;
    }
    
    /// Get total size in bytes
    pub fn getTotalSize(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.total_size_bytes;
    }
    
    /// Get all transactions (returns a copy for safety)
    pub fn getAllTransactions(self: *Self) ![]Transaction {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.transactions.items.len == 0) {
            return &[_]Transaction{};
        }
        
        // Create copies of all transactions
        var result = try self.allocator.alloc(Transaction, self.transactions.items.len);
        errdefer self.allocator.free(result);
        
        for (self.transactions.items, 0..) |tx, i| {
            result[i] = try tx.dupe(self.allocator);
        }
        
        return result;
    }
    
    /// Free transaction array returned by getAllTransactions
    pub fn freeTransactionArray(self: *Self, transactions: []Transaction) void {
        // Free each transaction
        for (transactions) |*tx| {
            tx.deinit(self.allocator);
        }
        
        // Free the array itself
        self.allocator.free(transactions);
    }
    
    /// Clear all transactions from pool
    pub fn clearPool(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Free all transactions
        for (self.transactions.items) |*tx| {
            tx.deinit(self.allocator);
        }
        
        // Clear the list and reset size
        self.transactions.clearRetainingCapacity();
        self.total_size_bytes = 0;
    }
    
    /// Remove transactions that match the provided hashes
    pub fn removeTransactionsByHashes(self: *Self, hashes: []const Hash) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var removed_count: usize = 0;
        var i: usize = 0;
        
        while (i < self.transactions.items.len) {
            const tx = &self.transactions.items[i];
            const tx_hash = tx.hash();
            var should_remove = false;
            
            // Check if this transaction hash is in the removal list
            for (hashes) |hash| {
                if (std.mem.eql(u8, &tx_hash, &hash)) {
                    should_remove = true;
                    break;
                }
            }
            
            if (should_remove) {
                const tx_size = tx.getSerializedSize();
                
                // Free transaction memory
                tx.deinit(self.allocator);
                
                // Remove from list and update size
                _ = self.transactions.swapRemove(i);
                self.total_size_bytes -= tx_size;
                removed_count += 1;
                
                // Don't increment i since we removed an item
            } else {
                i += 1;
            }
        }
        
        return removed_count;
    }
    
    /// Get the highest nonce for pending transactions from a specific address
    /// Returns the highest nonce found in mempool, or a sentinel value if none found
    pub fn getHighestNonceForAddress(self: *Self, address: types.Address) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var highest_nonce: u64 = 0;
        var found = false;
        
        for (self.transactions.items) |tx| {
            if (std.mem.eql(u8, &tx.sender.hash, &address.hash)) {
                if (!found or tx.nonce > highest_nonce) {
                    highest_nonce = tx.nonce;
                    found = true;
                }
            }
        }
        
        // Return highest found nonce, or max u64 as sentinel if no transactions found
        return if (found) highest_nonce else std.math.maxInt(u64);
    }
    
    /// Get mempool statistics
    pub fn getStats(self: *Self) MempoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return MempoolStats{
            .transaction_count = self.transactions.items.len,
            .total_size_bytes = self.total_size_bytes,
            .average_tx_size = if (self.transactions.items.len > 0) 
                self.total_size_bytes / self.transactions.items.len 
            else 0,
        };
    }
};

/// Mempool statistics for monitoring
pub const MempoolStats = struct {
    transaction_count: usize,
    total_size_bytes: usize,
    average_tx_size: usize,
};