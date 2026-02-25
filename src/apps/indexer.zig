// indexer.zig - PostgreSQL blockchain indexer for ZeiCoin
const std = @import("std");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const db = zeicoin.db;
const util = zeicoin.util;
const postgres = util.postgres;
const Allocator = std.mem.Allocator;

// Helper to format strings and ensure they are null-terminated for PostgreSQL C API
fn fmtz(a: Allocator, comptime f: []const u8, args: anytype) ![:0]const u8 {
    return try a.dupeZ(u8, try std.fmt.allocPrint(a, f, args));
}

// Execute a SQL query with parameters and immediately clean up the result
fn exec(conn: *postgres.Connection, sql: [:0]const u8, params: []const [:0]const u8) !void {
    var res = try conn.queryParams(sql, params);
    res.deinit();
}

// Indexer manages the blockchain database connection (RocksDB)
pub const Indexer = struct {
    allocator: Allocator,
    io: std.Io,
    blockchain_path: []const u8,
    secondary_path: []const u8,
    database: ?db.Database = null,

    pub fn init(a: Allocator, io: std.Io, path: []const u8) !Indexer {
        return .{ .allocator = a, .io = io, .blockchain_path = path,
            .secondary_path = try std.fmt.allocPrint(a, "{s}_indexer_secondary", .{path}) };
    }

    pub fn deinit(self: *Indexer) void {
        if (self.database) |*d| d.deinit();
        self.allocator.free(self.secondary_path);
    }

    // Ensures we can read the blockchain; falls back to primary if secondary fails
    pub fn ensureDb(self: *Indexer) !*db.Database {
        if (self.database == null) {
            self.database = db.Database.initSecondary(self.allocator, self.io, self.blockchain_path, self.secondary_path) catch |err| blk: {
                if (err != db.DatabaseError.OpenFailed) return err;
                std.log.info("⚠️ Falling back to primary RocksDB", .{});
                break :blk try db.Database.init(self.allocator, self.io, self.blockchain_path);
            };
        }
        _ = self.database.?.catchUpWithPrimary() catch {};
        return &self.database.?;
    }
};

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Arena for configuration and database connection lifetime
    var arena_s = std.heap.ArenaAllocator.init(allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    zeicoin.dotenv.loadForNetwork(allocator) catch {};
    
    // Database configuration from environment
    const host = util.getEnvVarOwned(arena, "ZEICOIN_DB_HOST") catch try arena.dupe(u8, "127.0.0.1");
    const port = if (util.getEnvVarOwned(arena, "ZEICOIN_DB_PORT")) |p| std.fmt.parseInt(u16, p, 10) catch 5432 else |_| 5432;
    const database = util.getEnvVarOwned(arena, "ZEICOIN_DB_NAME") catch try arena.dupe(u8, if (types.CURRENT_NETWORK == .testnet) "zeicoin_testnet" else "zeicoin_mainnet");
    const user = util.getEnvVarOwned(arena, "ZEICOIN_DB_USER") catch try arena.dupe(u8, "zeicoin");
    const password = try util.getEnvVarOwned(arena, "ZEICOIN_DB_PASSWORD");

    const conninfo = try postgres.buildConnString(arena, host, port, database, user, password);
    var conn = try postgres.Connection.init(allocator, conninfo);
    defer conn.deinit();

    std.log.info("🚀 Indexer started on {s}@{s}:{d}/{s}", .{user, host, port, database});

    var idx = try Indexer.init(allocator, init.io, if (types.CURRENT_NETWORK == .testnet) "zeicoin_data_testnet" else "zeicoin_data_mainnet");
    defer idx.deinit();

    // Check where we left off
    const last_h = blk: {
        var res = try conn.query("SELECT value FROM indexer_state WHERE key = 'last_indexed_height'");
        defer res.deinit();
        break :blk if (res.rowCount() > 0) try std.fmt.parseInt(u32, res.getValue(0, 0).?, 10) else null;
    };

    var h = if (last_h) |lh| lh + 1 else 0;
    const current = try (try idx.ensureDb()).getHeight();

    // Main indexing loop: process each block since last height
    while (h <= current) : (h += 1) {
        var block = try (try idx.ensureDb()).getBlock(init.io, h);
        defer block.deinit(allocator);

        // Per-block arena for temporary strings used in SQL queries
        var tx_arena_s = std.heap.ArenaAllocator.init(allocator);
        defer tx_arena_s.deinit();
        const tx_arena = tx_arena_s.allocator();

        var b_res = try conn.query("BEGIN");
        b_res.deinit();
        errdefer if (conn.query("ROLLBACK")) |res| {
            var r = res;
            r.deinit();
        } else |_| {};

        const hash = block.hash();
        const h_hex = try fmtz(tx_arena, "{x}", .{&hash});
        const p_hex = try fmtz(tx_arena, "{x}", .{&block.header.previous_hash});
        
        var fees: u64 = 0;
        for (block.transactions) |tx| if (!tx.isCoinbase()) { fees += tx.fee; };

        // Insert block metadata
        try exec(&conn, "INSERT INTO blocks (timestamp, timestamp_ms, height, hash, previous_hash, difficulty, nonce, tx_count, total_fees, size) VALUES (to_timestamp($1/1000.0), $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            &.{ try fmtz(tx_arena, "{}", .{block.header.timestamp}), try fmtz(tx_arena, "{}", .{block.header.timestamp}), try fmtz(tx_arena, "{}", .{h}), h_hex, p_hex, try fmtz(tx_arena, "{}", .{block.header.difficulty}), try fmtz(tx_arena, "{}", .{block.header.nonce}), try fmtz(tx_arena, "{}", .{block.transactions.len}), try fmtz(tx_arena, "{}", .{fees}), try fmtz(tx_arena, "{}", .{block.getSize()}) });

        // Process each transaction in the block
        for (block.transactions, 0..) |tx, pos| {
            const tx_hash = tx.hash();
            const tx_hex = try fmtz(tx_arena, "{x}", .{&tx_hash});
            const sender = if (tx.isCoinbase()) try tx_arena.dupeZ(u8, "coinbase") else try tx_arena.dupeZ(u8, try tx.sender.toBech32(tx_arena, types.CURRENT_NETWORK));
            const recipient = try tx_arena.dupeZ(u8, try tx.recipient.toBech32(tx_arena, types.CURRENT_NETWORK));
            const ts = try fmtz(tx_arena, "{}", .{tx.timestamp});
            const h_str = try fmtz(tx_arena, "{}", .{h});

            try exec(&conn, "INSERT INTO transactions (block_timestamp, timestamp_ms, hash, block_height, block_hash, position, sender, recipient, amount, fee, nonce) VALUES (to_timestamp($1/1000.0), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &.{ ts, ts, tx_hex, h_str, h_hex, try fmtz(tx_arena, "{}", .{pos}), sender, recipient, try fmtz(tx_arena, "{}", .{tx.amount}), try fmtz(tx_arena, "{}", .{tx.fee}), try fmtz(tx_arena, "{}", .{tx.nonce}) });

            // Update balances
            if (!tx.isCoinbase()) {
                const diff = try fmtz(tx_arena, "{}", .{@as(i64, 0) - @as(i64, @intCast(tx.amount + tx.fee))});
                try exec(&conn, "SELECT update_account_balance_simple($1, $2, $3, to_timestamp($4/1000.0)::timestamp, true)", &.{ sender, diff, h_str, ts });
            }
            try exec(&conn, "SELECT update_account_balance_simple($1, $2, $3, to_timestamp($4/1000.0)::timestamp, false)", &.{ recipient, try fmtz(tx_arena, "{}", .{tx.amount}), h_str, ts });
        }

        // Update indexer state and commit
        try exec(&conn, "INSERT INTO indexer_state (key, value, updated_at) VALUES ('last_indexed_height', $1, CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = CURRENT_TIMESTAMP", &.{try fmtz(tx_arena, "{}", .{h})});
        var c_res = try conn.query("COMMIT");
        c_res.deinit();
        std.log.info("✅ Block {} indexed to PostgreSQL", .{h});
    }
    try showStats(&conn);
}

fn showStats(conn: *postgres.Connection) !void {
    const q = .{ .{"Total Blocks Mined", "SELECT COUNT(*) FROM blocks"}, .{"Total Transactions", "SELECT COUNT(*) FROM transactions"}, .{"Active Accounts", "SELECT COUNT(*) FROM accounts WHERE balance > 0"} };
    std.log.info("\n📊 Stats:", .{});
    inline for (q) |s| {
        var r = try conn.query(s[1]);
        defer r.deinit();
        std.log.info("   {s}: {s}", .{ s[0], r.getValue(0, 0) orelse "0" });
    }
    var r = try conn.query("SELECT CAST(COALESCE(SUM(balance), 0) AS BIGINT) FROM accounts");
    defer r.deinit();
    const supply = std.fmt.parseInt(i64, r.getValue(0, 0) orelse "0", 10) catch 0;
    std.log.info("   Total Supply: {d:.8} ZEI", .{@as(f64, @floatFromInt(supply)) / @as(f64, @floatFromInt(types.ZEI_COIN))});
}