// db.zig - ZeiCoin Minimal File Database
// Pure Zig file-based storage

const std = @import("std");
const testing = std.testing;

const serialize = @import("serialize.zig");
const types = @import("types.zig");

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
};

/// ZeiCoin zen minimal database
/// File-based storage with pure Zig - no dependencies
pub const Database = struct {
    blocks_dir: []const u8,
    accounts_dir: []const u8,
    wallets_dir: []const u8,
    allocator: std.mem.Allocator,

    /// Initialize ZeiCoin database directories
    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !Database {
        // Create directories - zen minimalism
        const blocks_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "blocks" });
        const accounts_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "accounts" });
        const wallets_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "wallets" });

        // Ensure directories exist - bamboo grows
        std.fs.cwd().makePath(blocks_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(accounts_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return Database{
            .blocks_dir = blocks_dir,
            .accounts_dir = accounts_dir,
            .wallets_dir = wallets_dir,
            .allocator = allocator,
        };
    }

    /// Cleanup database resources
    pub fn deinit(self: *Database) void {
        self.allocator.free(self.blocks_dir);
        self.allocator.free(self.accounts_dir);
        self.allocator.free(self.wallets_dir);
    }

    /// Save block to file
    pub fn saveBlock(self: *Database, height: u32, block: Block) !void {
        // Create filename: blocks/000012.block
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir, height });
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
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir, height });
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
        var hex_buffer: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&address)}) catch unreachable;
        
        // Create filename: accounts/1a2b3c4d...hex.account
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}.account", .{ self.accounts_dir, hex_buffer });
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
        // Create hex representation of address
        var hex_buffer: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&address)}) catch unreachable;
        
        // Create filename
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}.account", .{ self.accounts_dir, hex_buffer });
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

        return serialize.deserialize(reader, Account, self.allocator) catch DatabaseError.SerializationFailed;
    }

    /// Get blockchain height (count block files)
    pub fn getHeight(self: *Database) !u32 {
        var dir = std.fs.cwd().openDir(self.blocks_dir, .{ .iterate = true }) catch return 0;
        defer dir.close();

        var count: u32 = 0;
        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".block")) {
                count += 1;
            }
        }

        return count;
    }

    /// Get number of accounts (count account files)
    pub fn getAccountCount(self: *Database) !u32 {
        var dir = std.fs.cwd().openDir(self.accounts_dir, .{ .iterate = true }) catch return 0;
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
        
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.wallet", .{ self.wallets_dir, wallet_name });
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
            .previous_hash = std.mem.zeroes(types.Hash),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = 1234567890,
            .difficulty = 0x1d00ffff,
            .nonce = 42,
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
    allocator.free(retrieved_block.transactions);
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
