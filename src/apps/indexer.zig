// indexer.zig - PostgreSQL blockchain indexer for ZeiCoin
const std = @import("std");
const pg = @import("pg");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const serialize = zeicoin.serialize;
const db = zeicoin.db;
const util = zeicoin.util;
const l2_service = @import("l2_service.zig");

const Pool = pg.Pool;
const DatabaseError = zeicoin.db.DatabaseError;
const print = std.debug.print;

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


/// Concurrent blockchain indexer using RocksDB secondary instance
pub const Indexer = struct {
    allocator: std.mem.Allocator,
    blockchain_path: []const u8,
    secondary_path: []const u8,
    config: PgConfig,
    database: ?db.Database,
    last_checked_height: u32,

    pub fn init(allocator: std.mem.Allocator, blockchain_path: []const u8, config: PgConfig) !Indexer {
        const secondary_path = try std.fmt.allocPrint(allocator, "{s}_indexer_secondary", .{blockchain_path});
        
        return Indexer{
            .allocator = allocator,
            .blockchain_path = blockchain_path,
            .secondary_path = secondary_path,
            .config = config,
            .database = null,
            .last_checked_height = 0,
        };
    }

    pub fn deinit(self: *Indexer) void {
        if (self.database) |*database| {
            database.deinit();
        }
        self.allocator.free(self.secondary_path);
    }

    /// Initialize secondary database connection
    pub fn initSecondaryDatabase(self: *Indexer) !void {
        if (self.database != null) return; // Already initialized
        
        // Try secondary instance first (concurrent access)
        self.database = db.Database.initSecondary(
            self.allocator, 
            self.blockchain_path, 
            self.secondary_path
        ) catch |err| switch (err) {
            DatabaseError.OpenFailed => {
                std.log.info("⚠️  Secondary instance failed, trying primary (mining node may be stopped)", .{});
                // Fallback to primary instance if secondary fails
                self.database = db.Database.init(self.allocator, self.blockchain_path) catch |primary_err| {
                    std.log.err("❌ Cannot access blockchain database in any mode", .{});
                    std.log.err("   Primary error: {}", .{primary_err});  
                    std.log.err("   Secondary error: {}", .{err});
                    std.log.err("🛑 Ensure zen_server is running or database exists", .{});
                    return primary_err;
                };
                return;
            },
            else => return err,
        };
        
        std.log.info("✅ Secondary database initialized: {s}", .{self.secondary_path});
    }

    /// Get the current blockchain height with secondary instance sync
    pub fn getBlockchainHeight(self: *Indexer) !u32 {
        if (self.database == null) {
            try self.initSecondaryDatabase();
        }
        
        var database = &self.database.?;
        
        // Try to catch up with primary database changes
        database.catchUpWithPrimary() catch |err| {
            std.log.warn("Failed to sync with primary: {}", .{err});
        };
        
        const height = try database.getHeight();
        self.last_checked_height = height;
        return height;
    }

    /// Check if new blocks are available since last check
    pub fn hasNewBlocks(self: *Indexer) !bool {
        const current_height = try self.getBlockchainHeight();
        return current_height > self.last_checked_height;
    }

    /// Get block safely with error handling
    pub fn getBlock(self: *Indexer, height: u32) !types.Block {
        if (self.database == null) {
            try self.initSecondaryDatabase();
        }
        
        var database = &self.database.?;
        
        // Try to catch up with primary before reading
        database.catchUpWithPrimary() catch |err| {
            std.log.warn("Failed to sync with primary: {}", .{err});
        };
        
        return try database.getBlock(height);
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
    const last_height_opt = try getLastIndexedHeight(pool);
    if (last_height_opt) |h| {
        std.log.info("📈 Last indexed height: {}", .{h});
    } else {
        std.log.info("📈 Last indexed height: none (starting from genesis)", .{});
    }

    // Initialize indexer
    var indexer = try Indexer.init(allocator, blockchain_path, config);
    defer indexer.deinit();

    // Get current blockchain height
    const current_height = try indexer.getBlockchainHeight();
    std.log.info("📊 Current blockchain height: {}", .{current_height});

    // Determine starting height (0 for genesis, last_height + 1 for continuation)
    const start_height = if (last_height_opt) |h| h + 1 else 0;

    if (start_height <= current_height) {
        std.log.info("🔄 Indexing blocks {} to {}...", .{ start_height, current_height });

        // Index new blocks
        var height = start_height;
        while (height <= current_height) : (height += 1) {
            try indexBlock(pool, allocator, &indexer, height);

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

fn getLastIndexedHeight(pool: *Pool) !?u32 {
    var result = try pool.query("SELECT value FROM indexer_state WHERE key = 'last_indexed_height'", .{});
    defer result.deinit();

    while (try result.next()) |row| {
        const value_str = row.get([]const u8, 0);
        return try std.fmt.parseInt(u32, value_str, 10);
    }

    return null; // No previous indexing - need to start from genesis
}

fn updateLastIndexedHeight(pool: *Pool, height: u32) !void {
    var buf: [20]u8 = undefined;
    const height_str = try std.fmt.bufPrint(&buf, "{}", .{height});

    _ = try pool.exec(
        \\INSERT INTO indexer_state (key, value, updated_at) 
        \\VALUES ('last_indexed_height', $1, CURRENT_TIMESTAMP)
        \\ON CONFLICT (key) 
        \\DO UPDATE SET value = $1, updated_at = CURRENT_TIMESTAMP
    , .{height_str});
}

fn indexBlock(pool: *Pool, allocator: std.mem.Allocator, indexer: *Indexer, height: u32) !void {
    // Initialize L2 service for enhancement confirmation  
    var l2_svc = l2_service.L2Service.init(allocator, pool);
    
    // Load block from indexer (uses secondary instance)
    var block = try indexer.getBlock(height);
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
    // Block timestamps are in milliseconds, store directly
    const timestamp_ms = block.header.timestamp;
    const timestamp_str = try std.fmt.allocPrint(allocator, "{}", .{timestamp_ms});
    defer allocator.free(timestamp_str);


    // Insert block using standard PostgreSQL approach (TimescaleDB best practice)
    _ = try pool.exec(
        \\INSERT INTO blocks (timestamp, timestamp_ms, height, hash, previous_hash, difficulty, nonce, tx_count, total_fees, size)
        \\VALUES (to_timestamp($1/1000.0), $2, $3, $4, $5, $6, $7, $8, $9, $10)
    , .{
        timestamp_str,
        timestamp_ms,
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
        
        // Check for pending L2 enhancements to confirm
        if (!tx.isCoinbase()) {
            // Convert addresses to bech32 for L2 matching
            const sender_bech32 = try tx.sender.toBech32(allocator, types.CURRENT_NETWORK);
            defer allocator.free(sender_bech32);
            
            const recipient_bech32 = try tx.recipient.toBech32(allocator, types.CURRENT_NETWORK);
            defer allocator.free(recipient_bech32);
            
            // Query for pending enhancements matching this transaction
            const pending_enhancements = l2_svc.queryEnhancementsBySenderRecipient(
                sender_bech32,
                recipient_bech32,
                .pending
            ) catch |err| {
                std.log.warn("Failed to query L2 enhancements: {}", .{err});
                continue;
            };
            defer l2_svc.freeEnhancements(pending_enhancements);
            
            // Confirm the first matching enhancement
            if (pending_enhancements.len > 0) {
                const enhancement = pending_enhancements[0];
                const tx_hash = tx.hash();
                var tx_hash_hex: [64]u8 = undefined;
                _ = try std.fmt.bufPrint(&tx_hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&tx_hash)});
                
                l2_svc.confirmEnhancement(
                    enhancement.temp_id,
                    &tx_hash_hex,
                    height
                ) catch |err| {
                    std.log.warn("Failed to confirm L2 enhancement {s}: {}", .{enhancement.temp_id, err});
                    continue;
                };
                
                std.log.info("✅ Confirmed L2 enhancement {s} with tx {s}", .{enhancement.temp_id, &tx_hash_hex});
            }
        }
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

    // Create timestamp string for transaction (store milliseconds directly)
    const tx_timestamp_ms = tx.timestamp;
    const tx_timestamp_str = try std.fmt.allocPrint(allocator, "{}", .{tx_timestamp_ms});
    defer allocator.free(tx_timestamp_str);


    // Insert transaction (TimescaleDB hypertable)
    _ = try pool.exec(
        \\INSERT INTO transactions (block_timestamp, timestamp_ms, hash, block_height, block_hash, position, sender, recipient, amount, fee, nonce)
        \\VALUES (to_timestamp($1/1000.0), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    , .{
        tx_timestamp_str,
        tx_timestamp_ms,
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
            \\SELECT update_account_balance_simple($1, $2, $3, to_timestamp($4/1000.0)::timestamp, true)
        , .{
            std.mem.sliceTo(&sender_str, 0),
            @as(i64, 0) - @as(i64, @intCast(tx.amount + tx.fee)),
            block_height,
            tx_timestamp_str,
        });
    }

    // Add to recipient
    _ = try pool.exec(
        \\SELECT update_account_balance_simple($1, $2, $3, to_timestamp($4/1000.0)::timestamp, false)
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
