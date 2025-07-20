// db.zig - ZeiCoin Minimal File Database
// Pure Zig file-based storage

const std = @import("std");
const testing = std.testing;

const serialize = @import("serialize.zig");
const types = @import("../types/types.zig");

// Re-export types for convenience
pub const Block = types.Block;
pub const Account = types.Account;
pub const Address = types.Address;

/// Database errors
pub const DatabaseError = error{
    OpenFailed,
    SaveFailed,
    LoadFailed,
    NotFound,
    InvalidPath,
    SerializationFailed,
    DeletionFailed,
};

/// ZeiCoin zen minimal database
/// File-based storage with pure Zig - no dependencies
pub const Database = struct {
    // Magic numbers for corruption detection
    magic_start: u32 = 0xDEADBEEF,
    
    blocks_dir: [256]u8,
    blocks_dir_len: usize,
    accounts_dir: [256]u8,
    accounts_dir_len: usize,
    wallets_dir: [256]u8,
    wallets_dir_len: usize,
    allocator: std.mem.Allocator,
    
    // End magic number
    magic_end: u32 = 0xFEEDFACE,

    /// Validate Database structure integrity
    pub fn validate(self: *const Database) bool {
        return self.magic_start == 0xDEADBEEF and 
               self.magic_end == 0xFEEDFACE and
               self.blocks_dir_len < 256 and
               self.accounts_dir_len < 256 and
               self.wallets_dir_len < 256;
    }

    /// Initialize ZeiCoin database directories
    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !Database {
        var db = Database{
            .blocks_dir = undefined,
            .blocks_dir_len = 0,
            .accounts_dir = undefined,
            .accounts_dir_len = 0,
            .wallets_dir = undefined,
            .wallets_dir_len = 0,
            .allocator = allocator,
        };

        // Create directory paths using static buffers
        db.blocks_dir_len = (std.fmt.bufPrint(&db.blocks_dir, "{s}/blocks", .{base_path}) catch return error.InvalidPath).len;
        db.accounts_dir_len = (std.fmt.bufPrint(&db.accounts_dir, "{s}/accounts", .{base_path}) catch return error.InvalidPath).len;
        db.wallets_dir_len = (std.fmt.bufPrint(&db.wallets_dir, "{s}/wallets", .{base_path}) catch return error.InvalidPath).len;

        // Ensure directories exist - bamboo grows
        std.fs.cwd().makePath(db.blocks_dir[0..db.blocks_dir_len]) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(db.accounts_dir[0..db.accounts_dir_len]) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(db.wallets_dir[0..db.wallets_dir_len]) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return db;
    }

    /// Cleanup database resources
    pub fn deinit(self: *Database) void {
        // No cleanup needed for static buffers
        _ = self;
    }

    /// Save block to file
    pub fn saveBlock(self: *Database, height: u32, block: Block) !void {
        // Create filename: blocks/000012.block
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir[0..self.blocks_dir_len], height });
        defer self.allocator.free(filename);

        // Serialize block to buffer
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        serialize.serialize(writer, block) catch return DatabaseError.SerializationFailed;

        // Write to file atomically
        const file = std.fs.cwd().createFile(filename, .{}) catch return DatabaseError.SaveFailed;
        defer file.close();

        file.writeAll(buffer.items) catch return DatabaseError.SaveFailed;
    }

    /// Load block from file
    pub fn getBlock(self: *Database, height: u32) !Block {
        // Create filename
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir[0..self.blocks_dir_len], height });
        defer self.allocator.free(filename);

        // Read file
        const file = std.fs.cwd().openFile(filename, .{}) catch return DatabaseError.NotFound;
        defer file.close();

        const file_size = try file.getEndPos();
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        // Deserialize block
        var stream = std.io.fixedBufferStream(buffer);
        const reader = stream.reader();

        return serialize.deserialize(reader, Block, self.allocator) catch DatabaseError.SerializationFailed;
    }

    /// Save account to file
    pub fn saveAccount(self: *Database, address: Address, account: Account) !void {
        // Create hex representation of address
        var hex_buffer: [42]u8 = undefined;
        const addr_bytes = address.toBytes();
        _ = std.fmt.bufPrint(&hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&addr_bytes)}) catch unreachable;
        
        // Create filename: accounts/1a2b3c4d...hex.account
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}.account", .{ self.accounts_dir[0..self.accounts_dir_len], hex_buffer });
        defer self.allocator.free(filename);

        // Serialize account to buffer
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        serialize.serialize(writer, account) catch return DatabaseError.SerializationFailed;

        // Write to file atomically
        const file = std.fs.cwd().createFile(filename, .{}) catch return DatabaseError.SaveFailed;
        defer file.close();

        file.writeAll(buffer.items) catch return DatabaseError.SaveFailed;
    }

    /// Load account from file
    pub fn getAccount(self: *Database, address: Address) !Account {
        // Validate Database integrity before use
        if (!self.validate()) {
            std.debug.print("ERROR: Database corruption detected in getAccount!\n", .{});
            std.debug.print("  magic_start: 0x{X} (expected: 0xDEADBEEF)\n", .{self.magic_start});
            std.debug.print("  magic_end: 0x{X} (expected: 0xFEEDFACE)\n", .{self.magic_end});
            std.debug.print("  accounts_dir_len: {} (max: 255)\n", .{self.accounts_dir_len});
            return DatabaseError.InvalidPath;
        }
        
        const accounts_dir_slice = self.accounts_dir[0..self.accounts_dir_len];
        
        // Create hex representation of address
        var hex_buffer: [42]u8 = undefined;
        const addr_bytes = address.toBytes();
        _ = std.fmt.bufPrint(&hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&addr_bytes)}) catch unreachable;
        
        // Create filename
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}.account", .{ accounts_dir_slice, hex_buffer });
        defer self.allocator.free(filename);

        // Read file
        const file = std.fs.cwd().openFile(filename, .{}) catch return DatabaseError.NotFound;
        defer file.close();

        const file_size = try file.getEndPos();
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        // Deserialize account
        var stream = std.io.fixedBufferStream(buffer);
        const reader = stream.reader();
        
        // Deserialize account from buffer

        const account = serialize.deserialize(reader, Account, self.allocator) catch {
            return DatabaseError.SerializationFailed;
        };
        
        // Account successfully loaded
        
        return account;
    }

    /// Get blockchain height (highest block number, genesis is 0)
    pub fn getHeight(self: *Database) !u32 {
        var dir = std.fs.cwd().openDir(self.blocks_dir[0..self.blocks_dir_len], .{ .iterate = true }) catch return 0;
        defer dir.close();

        var highest_block: u32 = 0;
        var found_any = false;
        var iterator = dir.iterate();
        
        while (try iterator.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".block")) {
                // Extract block number from filename (e.g., "000005.block" -> 5)
                const basename = std.fs.path.basename(entry.name);
                if (basename.len >= 7) { // At least "0.block"
                    const num_part = basename[0..basename.len - 6]; // Remove ".block"
                    const block_num = std.fmt.parseInt(u32, num_part, 10) catch continue;
                    
                    if (!found_any or block_num > highest_block) {
                        highest_block = block_num;
                        found_any = true;
                    }
                }
            }
        }

        // Return highest block number (genesis at 0, first mined block at 1, etc.)
        return if (found_any) highest_block else 0;
    }

    /// Get number of accounts (count account files)
    pub fn getAccountCount(self: *Database) !u32 {
        var dir = std.fs.cwd().openDir(self.accounts_dir[0..self.accounts_dir_len], .{ .iterate = true }) catch return 0;
        defer dir.close();

        var count: u32 = 0;
        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".account")) {
                count += 1;
            }
        }

        return count;
    }

    /// Get wallet file path - zen simplicity
    pub fn getWalletPath(self: *Database, wallet_name: []const u8) ![]u8 {
        // Sanitize wallet name to prevent path traversal
        for (wallet_name) |c| {
            // Allow alphanumeric, underscore, and dash only
            if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') {
                return DatabaseError.InvalidPath;
            }
        }
        
        // Limit wallet name length to prevent abuse
        if (wallet_name.len == 0 or wallet_name.len > 64) {
            return DatabaseError.InvalidPath;
        }
        
        // Reject wallet names starting with hyphen (command line safety)
        if (wallet_name[0] == '-') {
            return DatabaseError.InvalidPath;
        }
        
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.wallet", .{ self.wallets_dir[0..self.wallets_dir_len], wallet_name });
    }

    /// Get default wallet path - zen default
    pub fn getDefaultWalletPath(self: *Database) ![]u8 {
        return self.getWalletPath("default");
    }

    /// Check if wallet exists - zen wisdom
    pub fn walletExists(self: *Database, wallet_name: []const u8) bool {
        const wallet_path = self.getWalletPath(wallet_name) catch return false;
        defer self.allocator.free(wallet_path);

        std.fs.cwd().access(wallet_path, .{}) catch return false;
        return true;
    }

    /// Get block by hash - searches all blocks
    pub fn getBlockByHash(self: *Database, hash: [32]u8) !Block {
        var dir = std.fs.cwd().openDir(self.blocks_dir[0..self.blocks_dir_len], .{ .iterate = true }) catch return DatabaseError.NotFound;
        defer dir.close();

        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".block")) {
                // Parse height from filename
                const dot_pos = std.mem.indexOf(u8, entry.name, ".") orelse continue;
                const height = std.fmt.parseInt(u32, entry.name[0..dot_pos], 10) catch continue;
                
                // Load block and check hash
                var block = self.getBlock(height) catch continue;
                defer block.deinit(self.allocator);
                
                if (std.mem.eql(u8, &block.hash(), &hash)) {
                    // Return a copy of the block by serializing and deserializing
                    var buffer = std.ArrayList(u8).init(self.allocator);
                    defer buffer.deinit();
                    
                    try serialize.serialize(buffer.writer(), block);
                    var stream = std.io.fixedBufferStream(buffer.items);
                    return try serialize.deserialize(stream.reader(), types.Block, self.allocator);
                }
            }
        }
        
        return DatabaseError.NotFound;
    }

    /// Get transaction by hash - searches all blocks
    pub fn getTransactionByHash(self: *Database, hash: [32]u8) !types.Transaction {
        var dir = std.fs.cwd().openDir(self.blocks_dir[0..self.blocks_dir_len], .{ .iterate = true }) catch return DatabaseError.NotFound;
        defer dir.close();

        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".block")) {
                // Parse height from filename
                const dot_pos = std.mem.indexOf(u8, entry.name, ".") orelse continue;
                const height = std.fmt.parseInt(u32, entry.name[0..dot_pos], 10) catch continue;
                
                // Load block and search transactions
                var block = self.getBlock(height) catch continue;
                defer block.deinit(self.allocator);
                
                for (block.transactions) |tx| {
                    if (std.mem.eql(u8, &tx.hash(), &hash)) {
                        // Return a copy of the transaction by serializing and deserializing
                        var buffer = std.ArrayList(u8).init(self.allocator);
                        defer buffer.deinit();
                        
                        try serialize.serialize(buffer.writer(), tx);
                        var stream = std.io.fixedBufferStream(buffer.items);
                        return try serialize.deserialize(stream.reader(), types.Transaction, self.allocator);
                    }
                }
            }
        }
        
        return DatabaseError.NotFound;
    }

    /// Check if block exists by hash
    pub fn hasBlock(self: *Database, hash: [32]u8) bool {
        var block = self.getBlockByHash(hash) catch return false;
        block.deinit(self.allocator);
        return true;
    }

    /// Check if transaction exists by hash
    pub fn hasTransaction(self: *Database, hash: [32]u8) bool {
        var tx = self.getTransactionByHash(hash) catch return false;
        tx.deinit(self.allocator);
        return true;
    }
    
    /// Remove a block at a specific height
    pub fn removeBlock(self: *Database, height: u32) !void {
        // Create filename: blocks/000012.block
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir[0..self.blocks_dir_len], height });
        defer self.allocator.free(filename);
        
        // Delete the file
        std.fs.cwd().deleteFile(filename) catch |err| {
            if (err == error.FileNotFound) {
                // Block already removed, not an error
                return;
            }
            return DatabaseError.DeletionFailed;
        };
        
        std.debug.print("🗑️ Removed block at height {}\n", .{height});
    }
    
    /// Save the current blockchain height
    pub fn saveHeight(self: *Database, height: u32) !void {
        // Create height file path
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/HEIGHT", .{self.blocks_dir[0..self.blocks_dir_len]});
        defer self.allocator.free(filename);
        
        // Write height to file
        const file = std.fs.cwd().createFile(filename, .{}) catch return DatabaseError.SaveFailed;
        defer file.close();
        
        const height_str = try std.fmt.allocPrint(self.allocator, "{}", .{height});
        defer self.allocator.free(height_str);
        
        file.writeAll(height_str) catch return DatabaseError.SaveFailed;
    }
};

// Tests
test "database initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use temporary directory
    var db = try Database.init(allocator, "/tmp/zeicoin_test");
    defer db.deinit();

    // Should start with 0 blocks and accounts
    try testing.expectEqual(@as(u32, 0), try db.getHeight());
    try testing.expectEqual(@as(u32, 0), try db.getAccountCount());
}

test "block storage and retrieval" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db = try Database.init(allocator, "/tmp/zeicoin_test2");
    defer db.deinit();

    // Create test block
    const transactions = try allocator.alloc(types.Transaction, 0);
    defer allocator.free(transactions);

    const test_block = Block{
        .header = types.BlockHeader{
            .version = types.CURRENT_BLOCK_VERSION,
            .previous_hash = std.mem.zeroes(types.Hash),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = 1234567890,
            .difficulty = 0x1d00ffff,
            .nonce = 42,
            .witness_root = std.mem.zeroes(types.Hash),
            .state_root = std.mem.zeroes(types.Hash),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        },
        .transactions = transactions,
    };

    // Save and retrieve block
    try db.saveBlock(0, test_block);
    const retrieved_block = try db.getBlock(0);

    // Verify block data
    try testing.expectEqual(test_block.header.timestamp, retrieved_block.header.timestamp);
    try testing.expectEqual(test_block.header.nonce, retrieved_block.header.nonce);
    try testing.expectEqual(@as(u32, 1), try db.getHeight());

    // Cleanup retrieved block
    var block_to_free = retrieved_block;
    block_to_free.deinit(allocator);
}

test "account storage and retrieval" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db = try Database.init(allocator, "/tmp/zeicoin_test3");
    defer db.deinit();

    // Create test account
    const test_addr = std.mem.zeroes(Address);
    const test_account = Account{
        .address = test_addr,
        .balance = 1000000000, // 10 ZEI
        .nonce = 5,
    };

    // Save and retrieve account
    try db.saveAccount(test_addr, test_account);
    const retrieved_account = try db.getAccount(test_addr);

    // Verify account data
    try testing.expectEqual(test_account.balance, retrieved_account.balance);
    try testing.expectEqual(test_account.nonce, retrieved_account.nonce);
    try testing.expectEqual(@as(u32, 1), try db.getAccountCount());
}
