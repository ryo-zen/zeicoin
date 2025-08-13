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
    host: []const u8,
    port: u16,
    database: []const u8,
    user: []const u8,
    password: []const u8,  // Required - no default
    pool_size: u32,
    batch_size: u32,
    timeout: u32,
};

/// Load configuration from environment variables (required)
fn loadConfig(allocator: std.mem.Allocator) !PgConfig {
    // Get database name 
    const database = if (std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_NAME")) |db_name| 
        db_name
    else |_| blk: {
        // Fallback to network-based naming
        const network_db = if (types.CURRENT_NETWORK == .testnet) "zeicoin_testnet" else "zeicoin_mainnet";
        break :blk try allocator.dupe(u8, network_db);
    };
    errdefer allocator.free(database);
    
    // Get host
    const host = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_HOST") catch 
        try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(host);
    
    // Get port
    const port_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PORT") catch null;
    const port = if (port_str) |p| blk: {
        defer allocator.free(p);
        break :blk std.fmt.parseInt(u16, p, 10) catch 5432;
    } else 5432;
    
    // Get user (with default for convenience)
    const user = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_USER") catch 
        try allocator.dupe(u8, "zeicoin");
    errdefer allocator.free(user);
    
    // Get password (required - no default for security)
    const password = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PASSWORD") catch |err| {
        std.log.err("❌ ZEICOIN_DB_PASSWORD environment variable is required", .{});
        std.log.err("   Set it in your .env file or export it:", .{});
        std.log.err("   export ZEICOIN_DB_PASSWORD=your_password_here", .{});
        return err;
    };
    errdefer allocator.free(password);
    
    // Get pool size
    const pool_size_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_POOL_SIZE") catch null;
    const pool_size = if (pool_size_str) |p| blk: {
        defer allocator.free(p);
        break :blk std.fmt.parseInt(u32, p, 10) catch 5;
    } else 5;
    
    // Get batch size
    const batch_size_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_BATCH_SIZE") catch null;
    const batch_size = if (batch_size_str) |b| blk: {
        defer allocator.free(b);
        break :blk std.fmt.parseInt(u32, b, 10) catch 10;
    } else 10;
    
    // Get timeout
    const timeout_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_TIMEOUT") catch null;
    const timeout = if (timeout_str) |t| blk: {
        defer allocator.free(t);
        break :blk std.fmt.parseInt(u32, t, 10) catch 10000;
    } else 10000;
    
    return PgConfig{
        .host = host,
        .port = port,
        .database = database,
        .user = user,
        .password = password,
        .pool_size = pool_size,
        .batch_size = batch_size,
        .timeout = timeout,
    };
}


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

    /// Get the current blockchain height from database
    pub fn getBlockchainHeight(self: *Indexer) !u32 {
        var database = try db.Database.init(self.allocator, self.blockchain_path);
        defer database.deinit();
        
        return try database.getHeight();
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

    std.log.info("🚀 Starting ZeiCoin PostgreSQL Indexer", .{});
    std.log.info("📁 Blockchain path: {s}", .{blockchain_path});
    std.log.info("🌐 Network: {s}", .{@tagName(types.CURRENT_NETWORK)});

    // Load .env files first
    zeicoin.dotenv.loadForNetwork(std.heap.page_allocator) catch |err| {
        if (err != error.FileNotFound) {
            std.log.warn("Failed to load .env file: {}", .{err});
        }
    };
    
    // Load configuration from environment variables (required)
    const config = try loadConfig(allocator);
    defer {
        allocator.free(config.host);
        allocator.free(config.database);
        allocator.free(config.user);
        allocator.free(config.password);
    }

    std.log.info("🗄️ Database: {s}@{s}:{d}/{s}", .{ config.user, config.host, config.port, config.database });

    // Create connection pool using config
    var pool = try pg.Pool.init(allocator, .{
        .size = @intCast(config.pool_size),
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
    // Initialize database to read block
    var database = try db.Database.init(allocator, blockchain_path);
    defer database.deinit();
    
    // Load block from database
    var block = try database.getBlock(height);
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
