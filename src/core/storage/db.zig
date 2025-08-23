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

    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !Database {
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
        const db_path = try std.fmt.allocPrintZ(allocator, "{s}/rocksdb", .{base_path});
        defer allocator.free(db_path);

        std.fs.cwd().makePath(base_path) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };

        self.db = c.rocksdb_open(self.options, db_path.ptr, @ptrCast(&err));
        if (err != null) {
            log.info("RocksDB open error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.OpenFailed;
        }

        return self;
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
        _ = std.fmt.bufPrint(&hex_buffer, "{}", .{std.fmt.fmtSliceHexLower(&addr_bytes)}) catch unreachable;
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

    pub fn saveBlock(self: *Database, height: u32, block: Block) !void {
        const key = try self.makeBlockKey(height);
        defer self.allocator.free(key);

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        serialize.serialize(writer, block) catch return DatabaseError.SerializationFailed;

        var err: ?[*:0]u8 = null;
        c.rocksdb_put(
            self.db,
            self.write_options,
            key.ptr,
            key.len,
            buffer.items.ptr,
            buffer.items.len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB write error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.SaveFailed;
        }

        try self.updateHeight(height);
    }

    pub fn getBlock(self: *Database, height: u32) !Block {
        const key = try self.makeBlockKey(height);
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
            log.info("RocksDB read error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.LoadFailed;
        }

        if (val_ptr == null) {
            return DatabaseError.NotFound;
        }
        defer c.rocksdb_free(val_ptr);

        const data = val_ptr[0..val_len];
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return serialize.deserialize(reader, Block, self.allocator) catch DatabaseError.SerializationFailed;
    }

    pub fn saveAccount(self: *Database, address: Address, account: Account) !void {
        const key = try self.makeAccountKey(address);
        defer self.allocator.free(key);

        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        serialize.serialize(writer, account) catch return DatabaseError.SerializationFailed;

        var err: ?[*:0]u8 = null;
        c.rocksdb_put(
            self.db,
            self.write_options,
            key.ptr,
            key.len,
            buffer.items.ptr,
            buffer.items.len,
            @ptrCast(&err),
        );

        if (err != null) {
            log.info("RocksDB write error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.SaveFailed;
        }

        try self.incrementAccountCount();
    }

    pub fn getAccount(self: *Database, address: Address) !Account {
        const key = try self.makeAccountKey(address);
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
            log.info("RocksDB read error: {s}", .{err.?});
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.LoadFailed;
        }

        if (val_ptr == null) {
            return DatabaseError.NotFound;
        }
        defer c.rocksdb_free(val_ptr);

        const data = val_ptr[0..val_len];
        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        return serialize.deserialize(reader, Account, self.allocator) catch DatabaseError.SerializationFailed;
    }

    pub fn getHeight(self: *Database) !u32 {
        var err: ?[*:0]u8 = null;
        var val_len: usize = 0;
        const val_ptr = c.rocksdb_get(
            self.db,
            self.read_options,
            HEIGHT_KEY.ptr,
            HEIGHT_KEY.len,
            &val_len,
            @ptrCast(&err),
        );

        if (err != null) {
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return 0;
        }

        if (val_ptr == null) {
            return 0;
        }
        defer c.rocksdb_free(val_ptr);

        const data = val_ptr[0..val_len];
        return std.fmt.parseInt(u32, data, 10) catch 0;
    }

    fn updateHeight(self: *Database, height: u32) !void {
        const current_height = try self.getHeight();
        if (height > current_height) {
            const height_str = try std.fmt.allocPrint(self.allocator, "{}", .{height});
            defer self.allocator.free(height_str);

            var err: ?[*:0]u8 = null;
            c.rocksdb_put(
                self.db,
                self.write_options,
                HEIGHT_KEY.ptr,
                HEIGHT_KEY.len,
                height_str.ptr,
                height_str.len,
                @ptrCast(&err),
            );

            if (err != null) {
                c.rocksdb_free(@constCast(@ptrCast(err)));
                return DatabaseError.SaveFailed;
            }
        }
    }

    pub fn getAccountCount(self: *Database) !u32 {
        var err: ?[*:0]u8 = null;
        var val_len: usize = 0;
        const val_ptr = c.rocksdb_get(
            self.db,
            self.read_options,
            ACCOUNT_COUNT_KEY.ptr,
            ACCOUNT_COUNT_KEY.len,
            &val_len,
            @ptrCast(&err),
        );

        if (err != null) {
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return 0;
        }

        if (val_ptr == null) {
            return 0;
        }
        defer c.rocksdb_free(val_ptr);

        const data = val_ptr[0..val_len];
        return std.fmt.parseInt(u32, data, 10) catch 0;
    }

    fn incrementAccountCount(self: *Database) !void {
        const count = (try self.getAccountCount()) + 1;
        const count_str = try std.fmt.allocPrint(self.allocator, "{}", .{count});
        defer self.allocator.free(count_str);

        var err: ?[*:0]u8 = null;
        c.rocksdb_put(
            self.db,
            self.write_options,
            ACCOUNT_COUNT_KEY.ptr,
            ACCOUNT_COUNT_KEY.len,
            count_str.ptr,
            count_str.len,
            @ptrCast(&err),
        );

        if (err != null) {
            c.rocksdb_free(@constCast(@ptrCast(err)));
            return DatabaseError.SaveFailed;
        }
    }

    pub fn getWalletPath(self: *Database, wallet_name: []const u8) ![]u8 {
        _ = try self.makeWalletKey(wallet_name);
        return std.fmt.allocPrint(self.allocator, "{s}/wallets/{s}.wallet", .{ self.base_path, wallet_name });
    }

    pub fn getDefaultWalletPath(self: *Database) ![]u8 {
        return self.getWalletPath("default");
    }

    pub fn walletExists(self: *Database, wallet_name: []const u8) bool {
        const wallet_path = self.getWalletPath(wallet_name) catch return false;
        defer self.allocator.free(wallet_path);

        std.fs.cwd().access(wallet_path, .{}) catch return false;
        return true;
    }

    pub fn getBlockByHash(self: *Database, hash: [32]u8) !Block {
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

            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();
            var block = serialize.deserialize(reader, Block, self.allocator) catch {
                c.rocksdb_iter_next(it);
                continue;
            };

            if (std.mem.eql(u8, &block.hash(), &hash)) {
                return block;
            }

            block.deinit(self.allocator);
            c.rocksdb_iter_next(it);
        }

        return DatabaseError.NotFound;
    }

    pub fn getTransactionByHash(self: *Database, hash: [32]u8) !types.Transaction {
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

            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();
            var block = serialize.deserialize(reader, Block, self.allocator) catch {
                c.rocksdb_iter_next(it);
                continue;
            };
            defer block.deinit(self.allocator);

            for (block.transactions) |tx| {
                if (std.mem.eql(u8, &tx.hash(), &hash)) {
                    var buffer = std.ArrayList(u8).init(self.allocator);
                    defer buffer.deinit();
                    
                    try serialize.serialize(buffer.writer(), tx);
                    var tx_stream = std.io.fixedBufferStream(buffer.items);
                    return try serialize.deserialize(tx_stream.reader(), types.Transaction, self.allocator);
                }
            }

            c.rocksdb_iter_next(it);
        }

        return DatabaseError.NotFound;
    }

    pub fn hasBlock(self: *Database, hash: [32]u8) bool {
        var block = self.getBlockByHash(hash) catch return false;
        block.deinit(self.allocator);
        return true;
    }

    pub fn hasTransaction(self: *Database, hash: [32]u8) bool {
        var tx = self.getTransactionByHash(hash) catch return false;
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

    pub fn saveHeight(self: *Database, height: u32) !void {
        try self.updateHeight(height);
    }

    pub fn createWriteBatch(self: *Database) WriteBatch {
        return WriteBatch{
            .batch = c.rocksdb_writebatch_create(),
            .db = self,
        };
    }

    pub const WriteBatch = struct {
        batch: ?*c.rocksdb_writebatch_t,
        db: *Database,

        pub fn saveBlock(self: *WriteBatch, height: u32, block: Block) !void {
            const key = try self.db.makeBlockKey(height);
            defer self.db.allocator.free(key);

            var buffer = std.ArrayList(u8).init(self.db.allocator);
            defer buffer.deinit();

            const writer = buffer.writer();
            serialize.serialize(writer, block) catch return DatabaseError.SerializationFailed;

            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                buffer.items.ptr,
                buffer.items.len,
            );
        }

        pub fn saveAccount(self: *WriteBatch, address: Address, account: Account) !void {
            const key = try self.db.makeAccountKey(address);
            defer self.db.allocator.free(key);

            var buffer = std.ArrayList(u8).init(self.db.allocator);
            defer buffer.deinit();

            const writer = buffer.writer();
            serialize.serialize(writer, account) catch return DatabaseError.SerializationFailed;

            c.rocksdb_writebatch_put(
                self.batch,
                key.ptr,
                key.len,
                buffer.items.ptr,
                buffer.items.len,
            );
        }

        pub fn commit(self: *WriteBatch) !void {
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

        pub fn deinit(self: *WriteBatch) void {
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