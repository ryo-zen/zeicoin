const std = @import("std");
const testing = std.testing;
const serialize = @import("serialize.zig");
const types = @import("../types/types.zig");

const log = std.log.scoped(.storage);

const c = @cImport({
    @cInclude("rocksdb/c.h");
});

pub const Block = types.Block;
pub const Account = types.Account;
pub const Address = types.Address;

pub const DatabaseError = error{
    OpenFailed,
    SaveFailed,
    LoadFailed,
    NotFound,
    InvalidPath,
    SerializationFailed,
    DeletionFailed,
    RocksDBError,
};

pub const Database = struct {
    db: ?*c.rocksdb_t,
    options: ?*c.rocksdb_options_t,
    read_options: ?*c.rocksdb_readoptions_t,
    write_options: ?*c.rocksdb_writeoptions_t,
    allocator: std.mem.Allocator,
    base_path: []u8,

    const BLOCK_PREFIX = "block:";
    const ACCOUNT_PREFIX = "account:";
    const WALLET_PREFIX = "wallet:";
    const METADATA_PREFIX = "meta:";
    const HEIGHT_KEY = "meta:height";
    const ACCOUNT_COUNT_KEY = "meta:account_count";
    const TOTAL_SUPPLY_KEY = "meta:total_supply";
    const CIRCULATING_SUPPLY_KEY = "meta:circulating_supply";

    pub const TransactionWithHeight = struct {
        transaction: types.Transaction,
        block_height: u32,
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io, base_path: []const u8) !Database {
        var self = Database{
            .db = null,
            .options = null,
            .read_options = null,
            .write_options = null,
            .allocator = allocator,
            .base_path = try allocator.dupe(u8, base_path),
        };

        self.options = c.rocksdb_options_create();
        c.rocksdb_options_set_create_if_missing(self.options, 1);
        c.rocksdb_options_set_compression(self.options, c.rocksdb_snappy_compression);
        c.rocksdb_options_set_write_buffer_size(self.options, 64 * 1024 * 1024);
        c.rocksdb_options_set_max_write_buffer_number(self.options, 3);
        c.rocksdb_options_set_target_file_size_base(self.options, 64 * 1024 * 1024);
        c.rocksdb_options_set_level_compaction_dynamic_level_bytes(self.options, 1);
        
        c.rocksdb_options_set_block_based_table_factory(
            self.options,
            createBlockBasedTableOptions(),
        );

        self.read_options = c.rocksdb_readoptions_create();
        self.write_options = c.rocksdb_writeoptions_create();
        c.rocksdb_writeoptions_set_sync(self.write_options, 0);

        var err: ?[*:0]u8 = null;
        const db_path = try std.fmt.allocPrintSentinel(allocator, "{s}/rocksdb", .{base_path}, 0);
        defer allocator.free(db_path);

        std.Io.Dir.cwd().createDirPath(io, base_path) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };

        self.db = c.rocksdb_open(self.options, db_path.ptr, @ptrCast(&err));
        if (err != null) {
            log.err("Failed to open RocksDB at '{s}': {s}", .{db_path, err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            // Clean up partially constructed Database on failure
            self.deinit();
            return DatabaseError.OpenFailed;
        }

        return self;
    }

    /// Initialize as secondary instance for concurrent read-only access
    pub fn initSecondary(allocator: std.mem.Allocator, io: std.Io, base_path: []const u8, secondary_path: []const u8) !Database {
        var self = Database{
            .db = null,
            .options = null,
            .read_options = null,
            .write_options = null,
            .allocator = allocator,
            .base_path = try allocator.dupe(u8, base_path),
        };

        // Configure for secondary instance (read-only)
        self.options = c.rocksdb_options_create();
        c.rocksdb_options_set_create_if_missing(self.options, 0); // Don't create if missing
        c.rocksdb_options_set_compression(self.options, c.rocksdb_snappy_compression);
        c.rocksdb_options_set_max_open_files(self.options, 1000);
        
        c.rocksdb_options_set_block_based_table_factory(
            self.options,
            createBlockBasedTableOptions(),
        );

        self.read_options = c.rocksdb_readoptions_create();
        // No write_options needed for secondary instance

        var err: ?[*:0]u8 = null;
        const primary_db_path = try std.fmt.allocPrintSentinel(allocator, "{s}/rocksdb", .{base_path}, 0);
        defer allocator.free(primary_db_path);

        const secondary_db_path = try std.fmt.allocPrintSentinel(allocator, "{s}", .{secondary_path}, 0);
        defer allocator.free(secondary_db_path);

        // Create secondary path if it doesn't exist
        std.Io.Dir.cwd().createDirPath(io, secondary_path) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };

        // Open as secondary instance
        self.db = c.rocksdb_open_as_secondary(
            self.options, 
            primary_db_path.ptr, 
            secondary_db_path.ptr, 
            @ptrCast(&err)
        );

        if (err != null) {
            log.err("Failed to open RocksDB secondary instance at '{s}' -> '{s}': {s}", .{primary_db_path, secondary_db_path, err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            self.deinit();
            return DatabaseError.OpenFailed;
        }

        log.info("✅ Opened RocksDB secondary instance: {s} -> {s}", .{ primary_db_path, secondary_db_path });
        return self;
    }

    /// Try to catch up with primary database (for secondary instances)
    pub fn catchUpWithPrimary(self: *Database) !void {
        if (self.db == null) return DatabaseError.OpenFailed;
        
        var err: ?[*:0]u8 = null;
        c.rocksdb_try_catch_up_with_primary(self.db, @ptrCast(&err));
        
        if (err != null) {
            log.warn("Failed to catch up with primary: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            // Don't fail - just log warning
        }
    }

    fn createBlockBasedTableOptions() ?*c.rocksdb_block_based_table_options_t {
        const table_options = c.rocksdb_block_based_options_create();
        c.rocksdb_block_based_options_set_block_cache(
            table_options,
            c.rocksdb_cache_create_lru(128 * 1024 * 1024),
        );
        c.rocksdb_block_based_options_set_filter_policy(
            table_options,
            c.rocksdb_filterpolicy_create_bloom(10),
        );
        c.rocksdb_block_based_options_set_block_size(table_options, 16 * 1024);
        return table_options;
    }

    pub fn deinit(self: *Database) void {
        if (self.db) |db| {
            c.rocksdb_close(db);
        }
        if (self.options) |opts| {
            c.rocksdb_options_destroy(opts);
        }
        if (self.read_options) |opts| {
            c.rocksdb_readoptions_destroy(opts);
        }
        if (self.write_options) |opts| {
            c.rocksdb_writeoptions_destroy(opts);
        }
        self.allocator.free(self.base_path);
    }

    fn makeBlockKey(self: *Database, height: u32) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}{:0>10}", .{ BLOCK_PREFIX, height });
    }

    fn makeAccountKey(self: *Database, address: Address) ![]u8 {
        var hex_buffer: [42]u8 = undefined;
        const addr_bytes = address.toBytes();
        _ = std.fmt.bufPrint(&hex_buffer, "{x}", .{&addr_bytes}) catch unreachable;
        return std.fmt.allocPrint(self.allocator, "{s}{s}", .{ ACCOUNT_PREFIX, hex_buffer });
    }

    fn makeWalletKey(self: *Database, wallet_name: []const u8) ![]u8 {
        for (wallet_name) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') {
                return DatabaseError.InvalidPath;
            }
        }
        if (wallet_name.len == 0 or wallet_name.len > 64) {
            return DatabaseError.InvalidPath;
        }
        if (wallet_name[0] == '-') {
            return DatabaseError.InvalidPath;
        }
        return std.fmt.allocPrint(self.allocator, "{s}{s}", .{ WALLET_PREFIX, wallet_name });
    }

    fn readRawValue(self: *Database, key: []const u8) ![]u8 {
        var err: ?[*:0]u8 = null;
        var val_len: usize = 0;
        const val_ptr = c.rocksdb_get(
            self.db,
            self.read_options,
            key.ptr,
            key.len,
            &val_len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB read error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.LoadFailed;
        }

        if (val_ptr == null) {
            return DatabaseError.NotFound;
        }
        defer c.rocksdb_free(val_ptr);

        return try self.allocator.dupe(u8, val_ptr[0..val_len]);
    }

    fn writeRawValue(self: *Database, key: []const u8, value: []const u8) !void {
        var err: ?[*:0]u8 = null;
        c.rocksdb_put(
            self.db,
            self.write_options,
            key.ptr,
            key.len,
            value.ptr,
            value.len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB write error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.SaveFailed;
        }
    }

    fn readNumericMetadata(self: *Database, comptime T: type, key: []const u8) T {
        const data = self.readRawValue(key) catch return 0;
        defer self.allocator.free(data);

        if (data.len == @sizeOf(T)) {
            return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
        }

        return std.fmt.parseInt(T, data, 10) catch 0;
    }

    fn writeNumericMetadata(self: *Database, comptime T: type, key: []const u8, value: T) !void {
        var buffer: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &buffer, value, .little);
        try self.writeRawValue(key, &buffer);
    }

    pub fn putKey(self: *Database, key: []const u8, value: []const u8) !void {
        try self.writeRawValue(key, value);
    }

    pub fn getKey(self: *Database, key: []const u8) ![]u8 {
        return try self.readRawValue(key);
    }

    pub fn deleteKey(self: *Database, key: []const u8) !void {
        var err: ?[*:0]u8 = null;
        c.rocksdb_delete(
            self.db,
            self.write_options,
            key.ptr,
            key.len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB delete error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.DeletionFailed;
        }
    }

    pub fn saveBlock(self: *Database, io: std.Io, height: u32, block: Block) !void {
        _ = io;
        const key = try self.makeBlockKey(height);
        defer self.allocator.free(key);

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        serialize.serialize(&aw.writer, block) catch return DatabaseError.SerializationFailed;
        try self.writeRawValue(key, aw.written());

        try self.updateHeight(height);
    }

    pub fn getBlock(self: *Database, io: std.Io, height: u32) !Block {
        _ = io;
        const key = try self.makeBlockKey(height);
        defer self.allocator.free(key);

        const data = try self.readRawValue(key);
        defer self.allocator.free(data);
        var reader = std.Io.Reader.fixed(data);

        return serialize.deserialize(&reader, Block, self.allocator) catch DatabaseError.SerializationFailed;
    }

    pub fn saveAccount(self: *Database, address: Address, account: Account) !void {
        const key = try self.makeAccountKey(address);
        defer self.allocator.free(key);
        const is_new_account = try self.keyExists(key) == false;

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        serialize.serialize(&aw.writer, account) catch return DatabaseError.SerializationFailed;
        try self.writeRawValue(key, aw.written());

        if (is_new_account) {
            try self.incrementAccountCount();
        }
    }

    pub fn getAccount(self: *Database, address: Address) !Account {
        const key = try self.makeAccountKey(address);
        defer self.allocator.free(key);

        const data = try self.readRawValue(key);
        defer self.allocator.free(data);
        var reader = std.Io.Reader.fixed(data);

        return serialize.deserialize(&reader, Account, self.allocator) catch DatabaseError.SerializationFailed;
    }

    pub fn getHeight(self: *Database) !u32 {
        return self.readNumericMetadata(u32, HEIGHT_KEY);
    }

    fn updateHeight(self: *Database, height: u32) !void {
        const current_height = try self.getHeight();
        if (height > current_height) {
            try self.writeHeight(height);
        }
    }

    fn writeHeight(self: *Database, height: u32) !void {
        try self.writeNumericMetadata(u32, HEIGHT_KEY, height);
    }

    pub fn saveHeight(self: *Database, height: u32) !void {
        try self.writeHeight(height);
    }

    pub fn getAccountCount(self: *Database) !u32 {
        return self.readNumericMetadata(u32, ACCOUNT_COUNT_KEY);
    }

    fn incrementAccountCount(self: *Database) !void {
        const count = (try self.getAccountCount()) + 1;
        try self.saveAccountCount(count);
    }

    fn keyExists(self: *Database, key: []const u8) !bool {
        var err: ?[*:0]u8 = null;
        var val_len: usize = 0;
        const val_ptr = c.rocksdb_get(
            self.db,
            self.read_options,
            key.ptr,
            key.len,
            &val_len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB key existence check error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.LoadFailed;
        }

        if (val_ptr == null) {
            return false;
        }

        c.rocksdb_free(val_ptr);
        return true;
    }

    pub fn saveAccountCount(self: *Database, count: u32) !void {
        try self.writeNumericMetadata(u32, ACCOUNT_COUNT_KEY, count);
    }

    // ============================================
    // Supply Tracking Functions
    // ============================================

    /// Get current total supply (all minted coins including immature)
    pub fn getTotalSupply(self: *Database) u64 {
        return self.readNumericMetadata(u64, TOTAL_SUPPLY_KEY);
    }

    /// Update total supply (called when coinbase is processed)
    pub fn updateTotalSupply(self: *Database, new_supply: u64) !void {
        try self.writeNumericMetadata(u64, TOTAL_SUPPLY_KEY, new_supply);
    }

    /// Add to total supply atomically
    pub fn addToTotalSupply(self: *Database, amount: u64) !void {
        const current = self.getTotalSupply();
        const new_supply = current + amount;

        // Check for overflow
        if (new_supply < current) {
            log.err("Supply overflow detected: {} + {} would overflow", .{ current, amount });
            return DatabaseError.SaveFailed;
        }

        try self.updateTotalSupply(new_supply);
    }

    /// Get circulating supply (mature coins only, excludes immature coinbase)
    pub fn getCirculatingSupply(self: *Database) u64 {
        return self.readNumericMetadata(u64, CIRCULATING_SUPPLY_KEY);
    }

    /// Update circulating supply (called when coinbase matures)
    pub fn updateCirculatingSupply(self: *Database, new_supply: u64) !void {
        try self.writeNumericMetadata(u64, CIRCULATING_SUPPLY_KEY, new_supply);
    }

    /// Add to circulating supply (when coinbase matures)
    pub fn addToCirculatingSupply(self: *Database, amount: u64) !void {
        const current = self.getCirculatingSupply();
        const new_supply = current + amount;

        // Check for overflow
        if (new_supply < current) {
            log.err("Circulating supply overflow detected: {} + {} would overflow", .{ current, amount });
            return DatabaseError.SaveFailed;
        }

        try self.updateCirculatingSupply(new_supply);
    }

    /// Iterator callback function type for account iteration
    pub const AccountIteratorCallback = fn (account: Account, user_data: ?*anyopaque) bool;
    pub const KeyIteratorCallback = fn (key: []const u8, user_data: ?*anyopaque) bool;

    /// Iterate over all accounts in the database in deterministic order (sorted by address)
    /// The callback function should return true to continue iteration, false to stop
    pub fn iterateAccounts(self: *Database, callback: AccountIteratorCallback, user_data: ?*anyopaque) !void {
        const it = c.rocksdb_create_iterator(self.db, self.read_options);
        defer c.rocksdb_iter_destroy(it);

        // Collect all account keys first, then sort them for deterministic order
        var account_keys = std.array_list.Managed([]const u8).init(self.allocator);
        defer {
            for (account_keys.items) |key| {
                self.allocator.free(key);
            }
            account_keys.deinit();
        }

        // First pass: collect all account keys
        const prefix = ACCOUNT_PREFIX;
        c.rocksdb_iter_seek(it, prefix.ptr, prefix.len);
        
        while (c.rocksdb_iter_valid(it) == 1) {
            var key_len: usize = 0;
            const key_ptr = c.rocksdb_iter_key(it, &key_len);
            const key = key_ptr[0..key_len];

            if (!std.mem.startsWith(u8, key, prefix)) {
                break;
            }

            // Store a copy of the key
            const key_copy = try self.allocator.dupe(u8, key);
            try account_keys.append(key_copy);

            c.rocksdb_iter_next(it);
        }

        // Sort keys for deterministic order
        std.mem.sort([]const u8, account_keys.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);

        // Second pass: iterate in sorted order and call callback
        for (account_keys.items) |key| {
            var err: ?[*:0]u8 = null;
            var val_len: usize = 0;
            const val_ptr = c.rocksdb_get(
                self.db,
                self.read_options,
                key.ptr,
                key.len,
                &val_len,
                @ptrCast(&err),
            );

            if (err != null) {
                c.rocksdb_free(@constCast(@ptrCast(err)));
                continue; // Skip this account on error
            }

            if (val_ptr == null) {
                continue; // Skip if no value
            }
            defer c.rocksdb_free(val_ptr);

            const data = val_ptr[0..val_len];
            var reader = std.Io.Reader.fixed(data);
            
            const account = serialize.deserialize(&reader, Account, self.allocator) catch {
                continue; // Skip on deserialization error
            };

            // Call callback with account
            const should_continue = callback(account, user_data);
            if (!should_continue) {
                break;
            }
        }
    }

    pub fn iterateKeysWithPrefix(self: *Database, prefix: []const u8, callback: KeyIteratorCallback, user_data: ?*anyopaque) !void {
        const it = c.rocksdb_create_iterator(self.db, self.read_options);
        defer c.rocksdb_iter_destroy(it);

        c.rocksdb_iter_seek(it, prefix.ptr, prefix.len);

        while (c.rocksdb_iter_valid(it) == 1) {
            var key_len: usize = 0;
            const key_ptr = c.rocksdb_iter_key(it, &key_len);
            const key = key_ptr[0..key_len];

            if (!std.mem.startsWith(u8, key, prefix)) {
                break;
            }

            if (!callback(key, user_data)) {
                break;
            }

            c.rocksdb_iter_next(it);
        }
    }

    fn collectAccountKeys(self: *Database) !std.array_list.Managed([]u8) {
        const it = c.rocksdb_create_iterator(self.db, self.read_options);
        defer c.rocksdb_iter_destroy(it);

        var keys = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (keys.items) |key| {
                self.allocator.free(key);
            }
            keys.deinit();
        }

        const prefix = ACCOUNT_PREFIX;
        c.rocksdb_iter_seek(it, prefix.ptr, prefix.len);

        while (c.rocksdb_iter_valid(it) == 1) {
            var key_len: usize = 0;
            const key_ptr = c.rocksdb_iter_key(it, &key_len);
            const key = key_ptr[0..key_len];

            if (!std.mem.startsWith(u8, key, prefix)) {
                break;
            }

            try keys.append(try self.allocator.dupe(u8, key));
            c.rocksdb_iter_next(it);
        }

        return keys;
    }

    pub fn appendDeleteAllAccountsToBatch(self: *Database, batch: *WriteBatch) !u32 {
        var keys_to_delete = try self.collectAccountKeys();
        defer {
            for (keys_to_delete.items) |key| {
                self.allocator.free(key);
            }
            keys_to_delete.deinit();
        }

        for (keys_to_delete.items) |key| {
            batch.deleteKey(key);
        }

        batch.saveAccountCount(0);
        return @intCast(keys_to_delete.items.len);
    }

    /// Delete all accounts from the database (used for chain rollback/replay)
    /// This fixes the state corruption bug where reverted accounts would persist
    pub fn deleteAllAccounts(self: *Database) !void {
        var batch = self.createWriteBatch();
        defer batch.deinit();

        const deleted_count = try self.appendDeleteAllAccountsToBatch(&batch);
        if (deleted_count == 0) {
            return;
        }

        log.info("🗑️ Deleting {} accounts for state rollback", .{deleted_count});
        try batch.commit();
    }

    pub fn resetTotalSupply(self: *Database) !void {
        const batch = c.rocksdb_writebatch_create();
        defer c.rocksdb_writebatch_destroy(batch);

        const zero_supply = [_]u8{0} ** @sizeOf(u64);
        c.rocksdb_writebatch_put(batch, TOTAL_SUPPLY_KEY.ptr, TOTAL_SUPPLY_KEY.len, &zero_supply, zero_supply.len);
        c.rocksdb_writebatch_put(batch, CIRCULATING_SUPPLY_KEY.ptr, CIRCULATING_SUPPLY_KEY.len, &zero_supply, zero_supply.len);

        var err: ?[*:0]u8 = null;
        c.rocksdb_write(self.db, self.write_options, batch, @ptrCast(&err));

        if (err != null) {
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.SaveFailed;
        }
        
        log.info("📊 Supply metrics reset to 0", .{});
    }

    pub fn deleteBlocksFromHeight(self: *Database, from_height: u32, current_height: u32) !void {
        if (from_height > current_height) return;

        log.info("🗑️ Deleting blocks from height {} to {} from database", .{from_height, current_height});

        const batch = c.rocksdb_writebatch_create();
        defer c.rocksdb_writebatch_destroy(batch);

        var height = from_height;
        while (height <= current_height) : (height += 1) {
            const key = try self.makeBlockKey(height);
            defer self.allocator.free(key);
            c.rocksdb_writebatch_delete(batch, key.ptr, key.len);
        }

        var err: ?[*:0]u8 = null;
        c.rocksdb_write(self.db, self.write_options, batch, @ptrCast(&err));

        if (err != null) {
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.DeletionFailed;
        }
    }

    pub fn getWalletPath(self: *Database, wallet_name: []const u8) ![]u8 {
        _ = try self.makeWalletKey(wallet_name);
        return std.fmt.allocPrint(self.allocator, "{s}/wallets/{s}.wallet", .{ self.base_path, wallet_name });
    }

    pub fn getDefaultWalletPath(self: *Database) ![]u8 {
        return self.getWalletPath("default");
    }

    pub fn walletExists(self: *Database, io: std.Io, wallet_name: []const u8) bool {
        const wallet_path = self.getWalletPath(wallet_name) catch return false;
        defer self.allocator.free(wallet_path);

        std.Io.Dir.cwd().access(io, wallet_path, .{}) catch return false;
        return true;
    }

    pub fn getBlockByHash(self: *Database, io: std.Io, hash: [32]u8) !Block {
        _ = io;
        const it = c.rocksdb_create_iterator(self.db, self.read_options);
        defer c.rocksdb_iter_destroy(it);

        const prefix = BLOCK_PREFIX;
        c.rocksdb_iter_seek(it, prefix.ptr, prefix.len);

        while (c.rocksdb_iter_valid(it) == 1) {
            var key_len: usize = 0;
            const key_ptr = c.rocksdb_iter_key(it, &key_len);
            const key = key_ptr[0..key_len];

            if (!std.mem.startsWith(u8, key, prefix)) {
                break;
            }

            var val_len: usize = 0;
            const val_ptr = c.rocksdb_iter_value(it, &val_len);
            const data = val_ptr[0..val_len];

            var reader = std.Io.Reader.fixed(data);
            var block = serialize.deserialize(&reader, Block, self.allocator) catch {
                c.rocksdb_iter_next(it);
                continue;
            };
            errdefer block.deinit(self.allocator);

            if (std.mem.eql(u8, &block.hash(), &hash)) {
                return block;
            }

            block.deinit(self.allocator);
            c.rocksdb_iter_next(it);
        }

        return DatabaseError.NotFound;
    }

    pub fn getTransactionByHash(self: *Database, io: std.Io, hash: [32]u8) !types.Transaction {
        const tx_with_height = try self.getTransactionWithHeightByHash(io, hash);
        return tx_with_height.transaction;
    }

    pub fn getTransactionWithHeightByHash(self: *Database, io: std.Io, hash: [32]u8) !TransactionWithHeight {
        _ = io;
        const it = c.rocksdb_create_iterator(self.db, self.read_options);
        defer c.rocksdb_iter_destroy(it);

        const prefix = BLOCK_PREFIX;
        c.rocksdb_iter_seek(it, prefix.ptr, prefix.len);

        while (c.rocksdb_iter_valid(it) == 1) {
            var key_len: usize = 0;
            const key_ptr = c.rocksdb_iter_key(it, &key_len);
            const key = key_ptr[0..key_len];

            if (!std.mem.startsWith(u8, key, prefix)) {
                break;
            }

            var val_len: usize = 0;
            const val_ptr = c.rocksdb_iter_value(it, &val_len);
            const data = val_ptr[0..val_len];

            var reader = std.Io.Reader.fixed(data);
            var block = serialize.deserialize(&reader, Block, self.allocator) catch {
                c.rocksdb_iter_next(it);
                continue;
            };
            defer block.deinit(self.allocator);

            for (block.transactions) |tx| {
                if (std.mem.eql(u8, &tx.hash(), &hash)) {
                    var aw: std.Io.Writer.Allocating = .init(self.allocator);
                    defer aw.deinit();
                    try serialize.serialize(&aw.writer, tx);
                    var tx_reader = std.Io.Reader.fixed(aw.written());
                    return .{
                        .transaction = try serialize.deserialize(&tx_reader, types.Transaction, self.allocator),
                        .block_height = block.height,
                    };
                }
            }

            c.rocksdb_iter_next(it);
        }

        return DatabaseError.NotFound;
    }

    pub fn hasBlock(self: *Database, io: std.Io, hash: [32]u8) bool {
        var block = self.getBlockByHash(io, hash) catch return false;
        block.deinit(self.allocator);
        return true;
    }

    pub fn hasTransaction(self: *Database, io: std.Io, hash: [32]u8) bool {
        var tx = self.getTransactionByHash(io, hash) catch return false;
        tx.deinit(self.allocator);
        return true;
    }

    pub fn blockExistsByHeight(self: *Database, height: u32) bool {
        const key = self.makeBlockKey(height) catch return false;
        defer self.allocator.free(key);

        var err: ?[*:0]u8 = null;
        var val_len: usize = 0;
        const val_ptr = c.rocksdb_get(
            self.db,
            self.read_options,
            key.ptr,
            key.len,
            &val_len,
            @ptrCast(&err),
        );

        if (err != null) {
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return false;
        }

        if (val_ptr != null) {
            c.rocksdb_free(val_ptr);
            return true;
        }

        return false;
    }

    pub fn removeBlock(self: *Database, height: u32) !void {
        const key = try self.makeBlockKey(height);
        defer self.allocator.free(key);

        var err: ?[*:0]u8 = null;
        c.rocksdb_delete(
            self.db,
            self.write_options,
            key.ptr,
            key.len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB delete error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.DeletionFailed;
        }

        log.info("🗑️ Removed block at height {}", .{height});
    }



    pub fn createWriteBatch(self: *Database) WriteBatch {
        return WriteBatch{
            .batch = c.rocksdb_writebatch_create(),
            .db = self,
            .new_account_count_delta = 0,
            .account_count_overridden = false,
            .touched_accounts = .{},
        };
    }

    pub const WriteBatch = struct {
        batch: ?*c.rocksdb_writebatch_t,
        db: *Database,
        new_account_count_delta: u32,
        account_count_overridden: bool,
        touched_accounts: std.AutoHashMapUnmanaged(Address, void),

        pub fn saveBlock(self: *WriteBatch, height: u32, block: Block) !void {
            const key = try self.db.makeBlockKey(height);
            defer self.db.allocator.free(key);

            var aw: std.Io.Writer.Allocating = .init(self.db.allocator);
            defer aw.deinit();
            serialize.serialize(&aw.writer, block) catch return DatabaseError.SerializationFailed;
            const data = aw.written();

            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                data.ptr,
                data.len,
            );
        }

        pub fn saveAccount(self: *WriteBatch, address: Address, account: Account) !void {
            const key = try self.db.makeAccountKey(address);
            defer self.db.allocator.free(key);

            const account_entry = try self.touched_accounts.getOrPut(self.db.allocator, address);
            if (!account_entry.found_existing and !self.account_count_overridden) {
                const is_existing_account = try self.db.keyExists(key);
                if (!is_existing_account) {
                    self.new_account_count_delta += 1;
                }
            }

            var aw: std.Io.Writer.Allocating = .init(self.db.allocator);
            defer aw.deinit();
            serialize.serialize(&aw.writer, account) catch return DatabaseError.SerializationFailed;
            const data = aw.written();

            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                data.ptr,
                data.len,
            );
        }

        pub fn putKey(self: *WriteBatch, key: []const u8, value: []const u8) void {
            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                value.ptr,
                value.len,
            );
        }

        pub fn deleteKey(self: *WriteBatch, key: []const u8) void {
            c.rocksdb_writebatch_delete(
                self.batch,
                key.ptr,
                key.len,
            );
        }

        pub fn deleteBlock(self: *WriteBatch, height: u32) !void {
            const key = try self.db.makeBlockKey(height);
            defer self.db.allocator.free(key);
            self.deleteKey(key);
        }

        pub fn commit(self: *WriteBatch) !void {
            if (!self.account_count_overridden and self.new_account_count_delta > 0) {
                const updated_count = (try self.db.getAccountCount()) + self.new_account_count_delta;
                self.saveAccountCount(updated_count);
            }

            var err: ?[*:0]u8 = null;
            c.rocksdb_write(
                self.db.db,
                self.db.write_options,
                self.batch,
                @ptrCast(&err),
            );

            if (err != null) {
                log.info("RocksDB batch write error: {s}", .{err.?});
                c.rocksdb_free(@constCast(@ptrCast(err)));
                return DatabaseError.SaveFailed;
            }
        }

        pub fn updateTotalSupply(self: *WriteBatch, new_supply: u64) !void {
            const key = "meta:total_supply";
            var buffer: [8]u8 = undefined;
            std.mem.writeInt(u64, &buffer, new_supply, .little);

            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                &buffer,
                buffer.len,
            );
        }

        pub fn updateCirculatingSupply(self: *WriteBatch, new_supply: u64) !void {
            const key = "meta:circulating_supply";
            var buffer: [8]u8 = undefined;
            std.mem.writeInt(u64, &buffer, new_supply, .little);

            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                &buffer,
                buffer.len,
            );
        }

        pub fn saveAccountCount(self: *WriteBatch, count: u32) void {
            self.account_count_overridden = true;
            var buffer: [@sizeOf(u32)]u8 = undefined;
            std.mem.writeInt(u32, &buffer, count, .little);

            c.rocksdb_writebatch_put(
                self.batch,
                ACCOUNT_COUNT_KEY.ptr,
                ACCOUNT_COUNT_KEY.len,
                &buffer,
                buffer.len,
            );
        }

        pub fn saveHeight(self: *WriteBatch, height: u32) void {
            var buffer: [@sizeOf(u32)]u8 = undefined;
            std.mem.writeInt(u32, &buffer, height, .little);

            c.rocksdb_writebatch_put(
                self.batch,
                HEIGHT_KEY.ptr,
                HEIGHT_KEY.len,
                &buffer,
                buffer.len,
            );
        }

        pub fn deinit(self: *WriteBatch) void {
            self.touched_accounts.deinit(self.db.allocator);
            if (self.batch) |batch| {
                c.rocksdb_writebatch_destroy(batch);
            }
        }
    };

    pub fn compact(self: *Database) void {
        c.rocksdb_compact_range(self.db, null, 0, null, 0);
    }

    pub fn getStats(self: *Database) ![]u8 {
        const stats = c.rocksdb_property_value(self.db, "rocksdb.stats");
        if (stats == null) {
            return self.allocator.dupe(u8, "No stats available");
        }
        defer c.rocksdb_free(stats);

        const len = std.mem.len(stats);
        return self.allocator.dupe(u8, stats[0..len]);
    }
};
