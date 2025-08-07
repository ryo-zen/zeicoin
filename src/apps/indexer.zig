// indexer.zig - PostgreSQL blockchain indexer for ZeiCoin
const std = @import("std");
const pg = @import("pg");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const serialize = zeicoin.serialize;
const db = zeicoin.db;
const util = zeicoin.util;

const Pool = pg.Pool;

/// PostgreSQL connection config
pub const PgConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 5432,
    database: []const u8 = "zeicoin_testnet",
    user: []const u8 = "zeicoin",
    password: []const u8 = "zeicoin123",
    pool_size: u32 = 5,
    batch_size: u32 = 10,
};

/// Simple blockchain height reader
pub const Indexer = struct {
    allocator: std.mem.Allocator,
    blockchain_path: []const u8,
    config: PgConfig,

    pub fn init(allocator: std.mem.Allocator, blockchain_path: []const u8, config: PgConfig) !Indexer {
        return Indexer{
            .allocator = allocator,
            .blockchain_path = blockchain_path,
            .config = config,
        };
    }

    pub fn deinit(self: *Indexer) void {
        _ = self; // Nothing to clean up
    }

    /// Get the current blockchain height by counting block files
    pub fn getBlockchainHeight(self: *Indexer) !u32 {
        const blocks_path = try std.fmt.allocPrint(self.allocator, "{s}/blocks", .{self.blockchain_path});
        defer self.allocator.free(blocks_path);

        var dir = try std.fs.cwd().openDir(blocks_path, .{ .iterate = true });
        defer dir.close();

        var max_height: u32 = 0;
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".block")) {
                // Parse height from filename (e.g., "000042.block" -> 42)
                const height_str = entry.name[0..6];
                const height = try std.fmt.parseInt(u32, height_str, 10);
                if (height > max_height) {
                    max_height = height;
                }
            }
        }

        return max_height;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Configuration
    const blockchain_path = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };

    // Dynamic database name based on network
    const database_name = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_testnet",
        .mainnet => "zeicoin_mainnet",
    };

    std.log.info("🚀 Starting ZeiCoin PostgreSQL Indexer", .{});
    std.log.info("📁 Blockchain path: {s}", .{blockchain_path});
    std.log.info("🌐 Network: {s}", .{@tagName(types.CURRENT_NETWORK)});
    std.log.info("🗄️ Database: {s}", .{database_name});

    // Create indexer configuration
    const config = PgConfig{
        .database = database_name,
        // Use defaults for other fields
    };

    // Create connection pool using config
    var pool = try pg.Pool.init(allocator, .{
        .size = config.pool_size,
        .connect = .{
            .port = config.port,
            .host = config.host,
        },
        .auth = .{
            .username = config.user,
            .database = config.database,
            .password = config.password,
            .timeout = 10_000,
        },
    });
    defer pool.deinit();

    std.log.info("✅ Connected to PostgreSQL pool!", .{});

    // Test the connection
    var result = try pool.query("SELECT version()", .{});
    defer result.deinit();

    while (try result.next()) |row| {
        const version = row.get([]const u8, 0);
        std.log.info("📊 PostgreSQL version: {s}", .{version});
    }

    // Get last indexed height
    const last_height = try getLastIndexedHeight(pool);
    std.log.info("📈 Last indexed height: {}", .{last_height});

    // Initialize indexer
    var indexer = try Indexer.init(allocator, blockchain_path, config);
    defer indexer.deinit();

    // Get current blockchain height
    const current_height = try indexer.getBlockchainHeight();
    std.log.info("📊 Current blockchain height: {}", .{current_height});

    if (last_height < current_height) {
        std.log.info("🔄 Indexing blocks {} to {}...", .{ last_height + 1, current_height });

        // Index new blocks
        var height = last_height + 1;
        while (height <= current_height) : (height += 1) {
            try indexBlock(pool, allocator, blockchain_path, height);

            // Update last indexed height
            try updateLastIndexedHeight(pool, height);

            std.log.info("✅ Indexed block {}", .{height});
        }
    } else {
        std.log.info("✨ Already up to date!", .{});
    }

    // Show some statistics
    try showStats(pool);
}

fn getLastIndexedHeight(pool: *Pool) !u32 {
    var result = try pool.query("SELECT value FROM indexer_state WHERE key = 'last_indexed_height'", .{});
    defer result.deinit();

    while (try result.next()) |row| {
        const value_str = row.get([]const u8, 0);
        return try std.fmt.parseInt(u32, value_str, 10);
    }

    return 0;
}

fn updateLastIndexedHeight(pool: *Pool, height: u32) !void {
    var buf: [20]u8 = undefined;
    const height_str = try std.fmt.bufPrint(&buf, "{}", .{height});

    _ = try pool.exec(
        \\UPDATE indexer_state 
        \\SET value = $1, updated_at = CURRENT_TIMESTAMP 
        \\WHERE key = 'last_indexed_height'
    , .{height_str});
}

fn indexBlock(pool: *Pool, allocator: std.mem.Allocator, blockchain_path: []const u8, height: u32) !void {
    // Load block from disk
    const block_path = try std.fmt.allocPrint(allocator, "{s}/blocks/{d:0>6}.block", .{
        blockchain_path,
        height,
    });
    defer allocator.free(block_path);

    // Read block file directly
    const file = try std.fs.cwd().openFile(block_path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 16 * 1024 * 1024); // 16MB max
    defer allocator.free(contents);

    var fbs = std.io.fixedBufferStream(contents);
    const reader = fbs.reader();

    var block = try serialize.deserialize(reader, types.Block, allocator);
    defer block.deinit(allocator);

    // Begin transaction
    _ = try pool.exec("BEGIN", .{});
    errdefer _ = pool.exec("ROLLBACK", .{}) catch {};

    // Calculate block hash
    const block_hash = block.hash();
    var hash_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&block_hash)});

    // Calculate previous hash hex
    var prev_hash_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&prev_hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});

    // Calculate total fees
    var total_fees: u64 = 0;
    for (block.transactions) |tx| {
        if (!tx.isCoinbase()) {
            total_fees += tx.fee;
        }
    }

    // Create timestamp string for PostgreSQL
    const timestamp_str = try std.fmt.allocPrint(allocator, "{}", .{block.header.timestamp});
    defer allocator.free(timestamp_str);

    // Insert block using standard PostgreSQL approach (TimescaleDB best practice)
    _ = try pool.exec(
        \\INSERT INTO blocks (timestamp, height, hash, previous_hash, difficulty, nonce, tx_count, total_fees, size)
        \\VALUES (to_timestamp($1), $2, $3, $4, $5, $6, $7, $8, $9)
    , .{
        timestamp_str,
        height,
        &hash_hex,
        &prev_hash_hex,
        block.header.difficulty,
        block.header.nonce,
        block.transactions.len,
        total_fees,
        block.getSize(),
    });

    // Insert transactions
    for (block.transactions, 0..) |tx, pos| {
        try indexTransaction(pool, allocator, &tx, height, &hash_hex, @intCast(pos));
    }

    // Commit transaction
    _ = try pool.exec("COMMIT", .{});
}

fn indexTransaction(
    pool: *Pool,
    allocator: std.mem.Allocator,
    tx: *const types.Transaction,
    block_height: u32,
    block_hash: []const u8,
    position: u32,
) !void {
    // Calculate transaction hash
    const tx_hash = tx.hash();
    var tx_hash_hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&tx_hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&tx_hash)});

    // Convert addresses to bech32
    var sender_str: [70]u8 = undefined;
    var recipient_str: [70]u8 = undefined;

    if (tx.sender.isZero()) {
        @memcpy(sender_str[0..8], "coinbase");
        sender_str[8] = 0;
    } else {
        const sender_bech32 = try tx.sender.toBech32(allocator, types.CURRENT_NETWORK);
        defer allocator.free(sender_bech32);
        @memcpy(sender_str[0..sender_bech32.len], sender_bech32);
        sender_str[sender_bech32.len] = 0;
    }

    const recipient_bech32 = try tx.recipient.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(recipient_bech32);
    @memcpy(recipient_str[0..recipient_bech32.len], recipient_bech32);
    recipient_str[recipient_bech32.len] = 0;

    // Create timestamp string for transaction
    const tx_timestamp_str = try std.fmt.allocPrint(allocator, "{}", .{tx.timestamp});
    defer allocator.free(tx_timestamp_str);

    // Insert transaction (TimescaleDB hypertable)
    _ = try pool.exec(
        \\INSERT INTO transactions (block_timestamp, hash, block_height, block_hash, position, sender, recipient, amount, fee, nonce)
        \\VALUES (to_timestamp($1), $2, $3, $4, $5, $6, $7, $8, $9, $10)
    , .{
        tx_timestamp_str,
        &tx_hash_hex,
        block_height,
        block_hash,
        position,
        std.mem.sliceTo(&sender_str, 0),
        std.mem.sliceTo(&recipient_str, 0),
        tx.amount,
        tx.fee,
        tx.nonce,
    });

    // Update account balances using TimescaleDB function  
    if (!tx.sender.isZero()) {
        // Deduct from sender
        _ = try pool.exec(
            \\SELECT update_account_balance_simple($1, $2, $3, to_timestamp($4), true)
        , .{
            std.mem.sliceTo(&sender_str, 0),
            @as(i64, 0) - @as(i64, @intCast(tx.amount + tx.fee)),
            block_height,
            tx_timestamp_str,
        });
    }

    // Add to recipient
    _ = try pool.exec(
        \\SELECT update_account_balance_simple($1, $2, $3, to_timestamp($4), false)
    , .{
        std.mem.sliceTo(&recipient_str, 0),
        @as(i64, @intCast(tx.amount)),
        block_height,
        tx_timestamp_str,
    });
}

fn showStats(pool: *Pool) !void {
    std.log.info("\n📊 Blockchain Statistics:", .{});

    // Total blocks
    var blocks_result = try pool.query("SELECT COUNT(*) FROM blocks", .{});
    defer blocks_result.deinit();
    while (try blocks_result.next()) |row| {
        const count = row.get(i64, 0);
        std.log.info("   Total blocks: {}", .{count});
    }

    // Total transactions
    var txs_result = try pool.query("SELECT COUNT(*) FROM transactions", .{});
    defer txs_result.deinit();
    while (try txs_result.next()) |row| {
        const count = row.get(i64, 0);
        std.log.info("   Total transactions: {}", .{count});
    }

    // Total accounts
    var accounts_result = try pool.query("SELECT COUNT(*) FROM accounts WHERE balance > 0", .{});
    defer accounts_result.deinit();
    while (try accounts_result.next()) |row| {
        const count = row.get(i64, 0);
        std.log.info("   Active accounts: {}", .{count});
    }

    // Total supply - cast to BIGINT for pg.zig compatibility
    var supply_result = try pool.query("SELECT CAST(COALESCE(SUM(balance), 0) AS BIGINT) FROM accounts", .{});
    defer supply_result.deinit();
    while (try supply_result.next()) |row| {
        const supply = row.get(i64, 0);
        const supply_zei = @as(f64, @floatFromInt(supply)) / @as(f64, @floatFromInt(types.ZEI_COIN));
        std.log.info("   Total supply: {d:.8} ZEI", .{supply_zei});
    }
}
