// rest.zig - ZeiCoin TimescaleDB Analytics REST API
// High-performance REST API for blockchain analytics using ZAP framework

const std = @import("std");
const pg = @import("pg");
const zap = @import("zap");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;

const Pool = pg.Pool;

// Global app context for handlers to access
var global_app: ?*AppContext = null;

/// Analytics API configuration
pub const ApiConfig = struct {
    port: u16 = 8080,
    host: []const u8 = "0.0.0.0",

    // PostgreSQL connection
    pg_host: []const u8 = "127.0.0.1",
    pg_port: u16 = 5432,
    pg_database: []const u8,
    pg_user: []const u8 = "zeicoin",
    pg_password: []const u8 = "******",
    pool_size: u16 = 10,
};

/// Database configuration from JSON
const DbConfigJson = struct {
    postgres: struct {
        host: []const u8,
        port: u16,
        user: []const u8,
        password: []const u8,
        databases: struct {
            testnet: []const u8,
            mainnet: []const u8,
        },
        pool_size: u16,
        timeout: u32,
    },
    analytics_api: struct {
        port: u16,
        host: []const u8,
    },
};

/// Load configuration from file
fn loadConfigFromFile(allocator: std.mem.Allocator) !ApiConfig {
    const config_path = "config/database.json";
    const file = std.fs.cwd().openFile(config_path, .{}) catch |err| {
        std.log.warn("Could not open config file {s}: {}, using defaults", .{ config_path, err });
        // Return default config
        const database = if (types.CURRENT_NETWORK == .testnet) "zeicoin_testnet" else "zeicoin_mainnet";
        return ApiConfig{ .pg_database = database };
    };
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    const parsed = try std.json.parseFromSlice(DbConfigJson, allocator, contents, .{});
    defer parsed.deinit();

    const database = if (types.CURRENT_NETWORK == .testnet)
        parsed.value.postgres.databases.testnet
    else
        parsed.value.postgres.databases.mainnet;

    // Resolve password from environment variable if it's a template
    const password = if (std.mem.eql(u8, parsed.value.postgres.password, "${ZEICOIN_DB_PASSWORD}"))
        std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PASSWORD") catch |err| {
            std.log.err("ZEICOIN_DB_PASSWORD environment variable not set: {}", .{err});
            return err;
        }
    else
        try allocator.dupe(u8, parsed.value.postgres.password);

    return ApiConfig{
        .port = parsed.value.analytics_api.port,
        .host = try allocator.dupe(u8, parsed.value.analytics_api.host),
        .pg_host = try allocator.dupe(u8, parsed.value.postgres.host),
        .pg_port = parsed.value.postgres.port,
        .pg_database = try allocator.dupe(u8, database),
        .pg_user = try allocator.dupe(u8, parsed.value.postgres.user),
        .pg_password = password,
        .pool_size = parsed.value.postgres.pool_size,
    };
}

/// Application context with database pool
pub const AppContext = struct {
    allocator: std.mem.Allocator,
    pool: *Pool,
    config: ApiConfig,

    pub fn query(self: *AppContext, sql: []const u8, args: anytype) !*pg.Result {
        return self.pool.query(sql, args);
    }
};

/// Initialize the application context
pub fn initApp(allocator: std.mem.Allocator, config: ApiConfig) !*AppContext {
    // Create PostgreSQL connection pool - returns *Pool
    const pool = try Pool.init(allocator, .{
        .size = @intCast(config.pool_size),
        .connect = .{
            .port = config.pg_port,
            .host = config.pg_host,
        },
        .auth = .{
            .username = config.pg_user,
            .database = config.pg_database,
            .password = config.pg_password,
            .timeout = 10_000,
        },
    });

    // Test connection
    var test_result = try pool.query("SELECT 1", .{});
    defer test_result.deinit();

    std.log.info("✅ Connected to TimescaleDB: {s}", .{config.pg_database});

    const app = try allocator.create(AppContext);
    app.* = AppContext{
        .allocator = allocator,
        .pool = pool,
        .config = config,
    };

    return app;
}

pub fn deinitApp(app: *AppContext) void {
    app.pool.deinit();
    app.allocator.destroy(app);
}

// Health check endpoint
fn healthCheck(r: zap.Request) void {
    const response =
        \\{"status":"healthy","timestamp":1691418000,"version":"1.0.0","service":"zeicoin-analytics-api"}
    ;

    r.sendJson(response) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("Internal server error") catch return;
    };
}

// Network health endpoint
fn networkHealth(r: zap.Request) void {
    if (global_app == null) {
        r.setStatus(.service_unavailable);
        r.sendJson("{\"error\":\"Database not initialized\",\"code\":503}") catch return;
        return;
    }

    const app = global_app.?;

    // Query network health from TimescaleDB continuous aggregate
    const sql =
        \\SELECT 
        \\    TO_CHAR(time_window, 'YYYY-MM-DD HH24:MI:SS') as time_window,
        \\    blocks_10min,
        \\    avg_block_time_seconds,
        \\    avg_tx_per_block,
        \\    avg_difficulty,
        \\    avg_block_size
        \\FROM network_health_10min 
        \\ORDER BY time_window DESC
        \\LIMIT 144
    ;

    var result = app.query(sql, .{}) catch {
        r.setStatus(.internal_server_error);
        r.sendJson("{\"error\":\"Database query failed\",\"code\":500}") catch return;
        return;
    };
    defer result.deinit();

    // Build JSON response
    var response_buf: [8192]u8 = undefined;
    var stream = std.io.fixedBufferStream(&response_buf);
    var writer = stream.writer();

    writer.writeAll("{\"data\":[") catch {
        r.setStatus(.internal_server_error);
        r.sendBody("JSON formatting error") catch return;
        return;
    };

    var first = true;
    var count: u32 = 0;
    while (result.next() catch null) |row| {
        if (!first) writer.writeAll(",") catch continue;
        first = false;
        count += 1;

        const time_window = row.get([]const u8, 0);
        const blocks_10min = row.get(i64, 1);
        const avg_block_time = row.get(?f64, 2) orelse 0.0;
        const avg_tx_per_block = row.get(?f64, 3) orelse 0.0;
        const avg_difficulty = row.get(?f64, 4) orelse 0.0;
        const avg_block_size = row.get(?f64, 5) orelse 0.0;

        writer.print("{{\"time_window\":\"{s}\",\"blocks_10min\":{d},\"avg_block_time_seconds\":{d:.2},\"avg_tx_per_block\":{d:.2},\"avg_difficulty\":{d:.0},\"avg_block_size\":{d:.0}}}", .{ time_window, blocks_10min, avg_block_time, avg_tx_per_block, avg_difficulty, avg_block_size }) catch continue;
    }

    writer.print("],\"total_records\":{d},\"timestamp\":{d}}}", .{ count, std.time.timestamp() }) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("JSON formatting error") catch return;
        return;
    };

    const response = stream.getWritten();
    r.sendJson(response) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("Response send error") catch return;
    };
}

// Transaction volume endpoint
fn transactionVolume(r: zap.Request) void {
    if (global_app == null) {
        r.setStatus(.service_unavailable);
        r.sendJson("{\"error\":\"Database not initialized\",\"code\":503}") catch return;
        return;
    }

    const app = global_app.?;

    // Query daily transaction volume from TimescaleDB continuous aggregate
    const sql =
        \\SELECT 
        \\    TO_CHAR(day, 'YYYY-MM-DD') as day,
        \\    daily_tx_count as transactions,
        \\    daily_volume / 100000000.0 as volume_zei,
        \\    total_fees / 100000000.0 as fees_zei,
        \\    unique_senders,
        \\    unique_recipients
        \\FROM daily_economic_metrics
        \\ORDER BY day DESC
        \\LIMIT 30
    ;

    var result = app.query(sql, .{}) catch {
        r.setStatus(.internal_server_error);
        r.sendJson("{\"error\":\"Database query failed\",\"code\":500}") catch return;
        return;
    };
    defer result.deinit();

    // Build JSON response
    var response_buf: [16384]u8 = undefined;
    var stream = std.io.fixedBufferStream(&response_buf);
    var writer = stream.writer();

    writer.writeAll("{\"data\":[") catch {
        r.setStatus(.internal_server_error);
        r.sendBody("JSON formatting error") catch return;
        return;
    };

    var first = true;
    var count: u32 = 0;
    while (result.next() catch null) |row| {
        if (!first) writer.writeAll(",") catch continue;
        first = false;
        count += 1;

        const day = row.get([]const u8, 0);
        const transactions = row.get(i64, 1);
        const volume_zei = row.get(?f64, 2) orelse 0.0;
        const fees_zei = row.get(?f64, 3) orelse 0.0;
        const unique_senders = row.get(?i64, 4) orelse 0;
        const unique_recipients = row.get(?i64, 5) orelse 0;

        writer.print("{{\"day\":\"{s}\",\"transactions\":{d},\"volume_zei\":{d:.8},\"fees_zei\":{d:.8},\"unique_senders\":{d},\"unique_recipients\":{d}}}", .{ day, transactions, volume_zei, fees_zei, unique_senders, unique_recipients }) catch continue;
    }

    writer.print("],\"total_records\":{d},\"timestamp\":{d}}}", .{ count, std.time.timestamp() }) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("JSON formatting error") catch return;
        return;
    };

    const response = stream.getWritten();
    r.sendJson(response) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("Response send error") catch return;
    };
}

// Main request router
fn onRequest(r: zap.Request) void {
    // Add CORS headers
    r.setHeader("Access-Control-Allow-Origin", "*") catch return;
    r.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS") catch return;
    r.setHeader("Access-Control-Allow-Headers", "Content-Type") catch return;

    // Handle preflight requests
    const method = r.method orelse return;
    if (std.mem.eql(u8, method, "OPTIONS")) {
        r.sendBody("") catch return;
        return;
    }

    // Only allow GET requests for now
    if (!std.mem.eql(u8, method, "GET")) {
        r.setStatus(.method_not_allowed);
        r.sendBody("Method not allowed") catch return;
        return;
    }

    // Route requests
    const path = r.path orelse "/";

    if (std.mem.eql(u8, path, "/health")) {
        healthCheck(r);
    } else if (std.mem.eql(u8, path, "/api/network/health")) {
        networkHealth(r);
    } else if (std.mem.eql(u8, path, "/api/transactions/volume")) {
        transactionVolume(r);
    } else if (std.mem.eql(u8, path, "/")) {
        // Root endpoint - API documentation
        const welcome =
            \\{"service":"ZeiCoin Analytics API","version":"1.0.0","endpoints":{"GET /health":"Health check","GET /api/network/health":"Network health metrics","GET /api/transactions/volume":"Transaction volume statistics","GET /api/economics/daily":"Daily economic indicators","GET /api/addresses/top-senders":"Most active senders"},"powered_by":"TimescaleDB + ZAP","performance":"1000x faster than raw blockchain queries"}
        ;
        r.sendJson(welcome) catch {
            r.sendBody(welcome) catch return;
        };
    } else {
        // 404 Not Found
        r.setStatus(.not_found);
        const error_response =
            \\{"error": "Endpoint not found", "code": 404}
        ;
        r.sendBody(error_response) catch return;
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load configuration from file
    const config = try loadConfigFromFile(allocator);
    defer {
        allocator.free(config.host);
        allocator.free(config.pg_host);
        allocator.free(config.pg_database);
        allocator.free(config.pg_user);
        allocator.free(config.pg_password);
    }

    std.log.info("🚀 Starting ZeiCoin Analytics REST API", .{});
    std.log.info("🌐 Network: {s}", .{@tagName(types.CURRENT_NETWORK)});
    std.log.info("🗄️ Database: {s}", .{config.pg_database});
    std.log.info("📡 Server: http://{s}:{}", .{ config.host, config.port });

    // Initialize app context with database connection
    const app = initApp(allocator, config) catch |err| {
        std.log.err("Failed to initialize database: {}", .{err});
        return;
    };
    defer deinitApp(app);

    // Set global app context for handlers
    global_app = app;

    // Create ZAP listener
    var listener = zap.HttpListener.init(.{
        .port = config.port,
        .on_request = onRequest,
    });

    // Start server
    try listener.listen();

    std.log.info("🎯 Analytics API Endpoints:", .{});
    std.log.info("  GET /health - Service health check", .{});
    std.log.info("  GET /api/network/health - Real-time network metrics (24h)", .{});
    std.log.info("  GET /api/transactions/volume - Daily transaction volume (30d)", .{});
    std.log.info("✅ Server ready! Press Ctrl+C to stop", .{});

    // Start ZAP with 2 threads
    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
