// rest.zig - ZeiCoin TimescaleDB Analytics REST API
// High-performance REST API for blockchain analytics using ZAP framework

const std = @import("std");
const pg = @import("pg");
const zap = @import("zap");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const l2_service = @import("l2_service.zig");

const Pool = pg.Pool;

// Global app context for handlers to access
var global_app: ?*AppContext = null;

/// Analytics API configuration
pub const ApiConfig = struct {
    port: u16,
    host: []const u8,

    // PostgreSQL connection
    pg_host: []const u8,
    pg_port: u16,
    pg_database: []const u8,
    pg_user: []const u8,
    pg_password: []const u8,  // Required - no default
    pool_size: u16,
    timeout: u32,
};

/// Load configuration from environment variables (required)
fn loadConfig(allocator: std.mem.Allocator) !ApiConfig {
    // API settings
    const api_host = std.process.getEnvVarOwned(allocator, "ZEICOIN_API_HOST") catch 
        try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(api_host);
    
    const api_port_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_API_PORT") catch null;
    const api_port = if (api_port_str) |p| blk: {
        defer allocator.free(p);
        break :blk std.fmt.parseInt(u16, p, 10) catch 8080;
    } else 8080;
    
    // Database settings
    const database = if (std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_NAME")) |db_name| 
        db_name
    else |_| blk: {
        const network_db = if (types.CURRENT_NETWORK == .testnet) "zeicoin_testnet" else "zeicoin_mainnet";
        break :blk try allocator.dupe(u8, network_db);
    };
    errdefer allocator.free(database);
    
    const pg_host = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_HOST") catch 
        try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(pg_host);
    
    const pg_port_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PORT") catch null;
    const pg_port = if (pg_port_str) |p| blk: {
        defer allocator.free(p);
        break :blk std.fmt.parseInt(u16, p, 10) catch 5432;
    } else 5432;
    
    const pg_user = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_USER") catch 
        try allocator.dupe(u8, "zeicoin");
    errdefer allocator.free(pg_user);
    
    const pg_password = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PASSWORD") catch |err| {
        std.log.err("❌ ZEICOIN_DB_PASSWORD environment variable is required", .{});
        std.log.err("   Set it in your .env file or export it:", .{});
        std.log.err("   export ZEICOIN_DB_PASSWORD=your_password_here", .{});
        return err;
    };
    errdefer allocator.free(pg_password);
    
    const pool_size_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_POOL_SIZE") catch null;
    const pool_size = if (pool_size_str) |p| blk: {
        defer allocator.free(p);
        break :blk std.fmt.parseInt(u16, p, 10) catch 10;
    } else 10;
    
    const timeout_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_TIMEOUT") catch null;
    const timeout = if (timeout_str) |t| blk: {
        defer allocator.free(t);
        break :blk std.fmt.parseInt(u32, t, 10) catch 10000;
    } else 10000;
    
    return ApiConfig{
        .host = api_host,
        .port = api_port,
        .pg_host = pg_host,
        .pg_port = pg_port,
        .pg_database = database,
        .pg_user = pg_user,
        .pg_password = pg_password,
        .pool_size = pool_size,
        .timeout = timeout,
    };
}


/// Application context with database pool
pub const AppContext = struct {
    allocator: std.mem.Allocator,
    pool: *Pool,
    config: ApiConfig,
    l2_service: ?*l2_service.L2Service,

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
            .timeout = config.timeout,
        },
    });

    // Test connection and get TimescaleDB version
    var test_result = try pool.query("SELECT 1", .{});
    defer test_result.deinit();

    // Get TimescaleDB version
    var version_result = try pool.query("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'", .{});
    defer version_result.deinit();
    
    const timescale_version = if (version_result.next() catch null) |row| 
        row.get([]const u8, 0)
    else 
        "unknown";

    std.log.info("✅ Connected to TimescaleDB: {s} (v{s})", .{config.pg_database, timescale_version});

    // Initialize L2 service
    const l2_svc = try allocator.create(l2_service.L2Service);
    l2_svc.* = l2_service.L2Service.init(allocator, pool);
    
    const app = try allocator.create(AppContext);
    app.* = AppContext{
        .allocator = allocator,
        .pool = pool,
        .config = config,
        .l2_service = l2_svc,
    };

    return app;
}

pub fn deinitApp(app: *AppContext) void {
    if (app.l2_service) |l2| {
        app.allocator.destroy(l2);
    }
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

// L2 Messaging Endpoints

// Create a new transaction enhancement
fn createEnhancement(r: zap.Request) void {
    const app = global_app orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("Server not initialized") catch return;
        return;
    };
    
    const l2 = app.l2_service orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("L2 service not initialized") catch return;
        return;
    };
    
    r.parseBody() catch |err| {
        std.log.err("Failed to parse body: {}", .{err});
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid request body\"}") catch return;
        return;
    };
    
    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Missing request body\"}") catch return;
        return;
    };
    
    // Parse JSON body
    const parsed = std.json.parseFromSlice(struct {
        sender: []const u8,
        recipient: ?[]const u8 = null,
        message: ?[]const u8 = null,
        tags: [][]const u8 = &.{},
        category: ?[]const u8 = null,
        reference_id: ?[]const u8 = null,
        is_private: bool = false,
    }, app.allocator, body, .{}) catch |err| {
        std.log.err("Failed to parse JSON: {}", .{err});
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid JSON format\"}") catch return;
        return;
    };
    defer parsed.deinit();
    
    const data = parsed.value;
    
    // Create enhancement
    const temp_id = l2.createEnhancement(
        data.sender,
        data.recipient,
        data.message,
        data.tags,
        data.category,
        data.reference_id,
        data.is_private,
    ) catch |err| {
        std.log.err("Failed to create enhancement: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Failed to create enhancement\"}") catch return;
        return;
    };
    defer app.allocator.free(temp_id);
    
    // Return success response
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();
    
    writer.print("{{\"success\":true,\"temp_id\":\"{s}\",\"status\":\"draft\"}}", .{temp_id}) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Response formatting error\"}") catch return;
        return;
    };
    
    r.sendBody(stream.getWritten()) catch return;
}

// Update enhancement to pending status
fn setEnhancementPending(r: zap.Request) void {
    const app = global_app orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("Server not initialized") catch return;
        return;
    };
    
    const l2 = app.l2_service orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("L2 service not initialized") catch return;
        return;
    };
    
    // Extract temp_id from path
    const path = r.path orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid path\"}") catch return;
        return;
    };
    
    // Path format: /api/l2/enhancements/{temp_id}/pending
    const prefix = "/api/l2/enhancements/";
    const suffix = "/pending";
    
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix)) {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid path format\"}") catch return;
        return;
    }
    
    const temp_id = path[prefix.len..path.len - suffix.len];
    
    // Update status to pending
    l2.setEnhancementPending(temp_id) catch |err| {
        std.log.err("Failed to set enhancement pending: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Failed to update enhancement\"}") catch return;
        return;
    };
    
    r.sendBody("{\"success\":true,\"status\":\"pending\"}") catch return;
}

// Confirm enhancement with transaction hash
fn confirmEnhancement(r: zap.Request) void {
    const app = global_app orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("Server not initialized") catch return;
        return;
    };
    
    const l2 = app.l2_service orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("L2 service not initialized") catch return;
        return;
    };
    
    // Extract temp_id from path
    const path = r.path orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid path\"}") catch return;
        return;
    };
    
    // Path format: /api/l2/enhancements/{temp_id}/confirm
    const prefix = "/api/l2/enhancements/";
    const suffix = "/confirm";
    
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix)) {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid path format\"}") catch return;
        return;
    }
    
    const temp_id = path[prefix.len..path.len - suffix.len];
    
    // Parse request body for tx_hash and block_height
    r.parseBody() catch |err| {
        std.log.err("Failed to parse body: {}", .{err});
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid request body\"}") catch return;
        return;
    };
    
    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Missing request body\"}") catch return;
        return;
    };
    
    const parsed = std.json.parseFromSlice(struct {
        tx_hash: []const u8,
        block_height: u32,
    }, app.allocator, body, .{}) catch |err| {
        std.log.err("Failed to parse JSON: {}", .{err});
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid JSON format\"}") catch return;
        return;
    };
    defer parsed.deinit();
    
    const data = parsed.value;
    
    // Confirm enhancement
    l2.confirmEnhancement(temp_id, data.tx_hash, data.block_height) catch |err| {
        std.log.err("Failed to confirm enhancement: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Failed to confirm enhancement\"}") catch return;
        return;
    };
    
    r.sendBody("{\"success\":true,\"status\":\"confirmed\"}") catch return;
}

// Query enhancements
fn queryEnhancements(r: zap.Request) void {
    const app = global_app orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("Server not initialized") catch return;
        return;
    };
    
    const l2 = app.l2_service orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("L2 service not initialized") catch return;
        return;
    };
    
    // Parse query parameters (simplified for now)
    const enhancements = l2.queryEnhancements(null, null, .pending, 100) catch |err| {
        std.log.err("Failed to query enhancements: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Failed to query enhancements\"}") catch return;
        return;
    };
    defer app.allocator.free(enhancements);
    
    // Format response
    var buffer: [8192]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();
    
    writer.print("{{\"enhancements\":[", .{}) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Response formatting error\"}") catch return;
        return;
    };
    
    for (enhancements, 0..) |enhancement, i| {
        if (i > 0) writer.print(",", .{}) catch return;
        
        writer.print("{{\"id\":{},\"temp_id\":\"{s}\",\"sender\":\"{s}\",\"status\":\"{s}\"}}", .{
            enhancement.id orelse 0,
            enhancement.temp_id,
            enhancement.sender_address,
            enhancement.status.toString(),
        }) catch return;
    }
    
    writer.print("],\"count\":{}}}", .{enhancements.len}) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Response formatting error\"}") catch return;
        return;
    };
    
    r.sendBody(stream.getWritten()) catch return;
}

// Query enhanced transactions  
fn queryEnhancedTransactions(r: zap.Request) void {
    const app = global_app orelse {
        r.setStatus(.internal_server_error);
        r.sendBody("Server not initialized") catch return;
        return;
    };
    
    // Query all transactions including coinbase transactions
    const path = r.path orelse "";
    const has_sender_param = std.mem.indexOf(u8, path, "sender=") != null;
    
    std.log.info("Query enhanced transactions: path={s}, has_sender={}", .{ path, has_sender_param });
    
    // Query all transactions with L2 enhancements (LEFT JOIN to include non-enhanced transactions)
    var result = app.query(
        \\SELECT t.hash, t.sender, t.recipient, t.amount, t.fee, t.block_height, 
        \\       t.block_timestamp, l2.message, l2.category, l2.status,
        \\       (SELECT MAX(height) FROM blocks) - t.block_height + 1 as confirmations
        \\FROM transactions t
        \\LEFT JOIN l2_transaction_enhancements l2 ON t.hash = l2.tx_hash
        \\ORDER BY t.block_height DESC
        \\LIMIT 100
    , .{}) catch |err| {
        std.log.err("Failed to query transactions: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Database query failed\"}") catch return;
        return;
    };
    defer result.deinit();
    
    // Format response - increased buffer size for 40+ transactions
    var buffer: [32768]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();
    
    writer.print("{{\"transactions\":[", .{}) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Response formatting error\"}") catch return;
        return;
    };
    
    var count: usize = 0;
    while (result.next() catch null) |row| {
        std.log.info("Processing transaction row {}", .{count});
        if (count > 0) writer.print(",", .{}) catch return;
        
        const hash = row.get(?[]const u8, 0); // tx_hash can be null for coinbase
        const sender = row.get(?[]const u8, 1); // sender can be null for coinbase
        const recipient = row.get(?[]const u8, 2); // recipient can be null 
        const amount = row.get(i64, 3);
        const fee = row.get(i64, 4);
        const block_height = row.get(i64, 5); // block_height is bigint in PostgreSQL
        // Get timestamp as proper timestamp from database 
        const block_timestamp = row.get(?i64, 6);
        // L2 enhancement fields (can be null)
        const message = row.get(?[]const u8, 7);
        const category = row.get(?[]const u8, 8);
        const l2_status = row.get(?[]const u8, 9);
        const confirmations = row.get(i64, 10);
        
        writer.print("{{\"hash\":\"{s}\",\"sender\":\"{s}\",\"recipient\":\"{s}\",\"amount\":{},\"fee\":{},\"block_height\":{},\"confirmations\":{}", .{
            hash orelse "", sender orelse "coinbase", recipient orelse "", amount, fee, block_height, confirmations,
        }) catch return;
        
        if (block_timestamp) |ts| {
            // Format timestamp as ISO 8601 string or Unix timestamp
            writer.print(",\"timestamp\":{}", .{ts}) catch return;
            // Also provide block_timestamp for compatibility
            writer.print(",\"block_timestamp\":{}", .{ts}) catch return;
        }
        
        if (message) |msg| {
            writer.print(",\"message\":\"", .{}) catch return;
            for (msg) |char| {
                switch (char) {
                    '"' => writer.print("\\\"", .{}) catch return,
                    '\\' => writer.print("\\\\", .{}) catch return,
                    '\n' => writer.print("\\n", .{}) catch return,
                    '\r' => writer.print("\\r", .{}) catch return,
                    '\t' => writer.print("\\t", .{}) catch return,
                    else => writer.print("{c}", .{char}) catch return,
                }
            }
            writer.print("\"", .{}) catch return;
        }
        
        if (category) |cat| {
            writer.print(",\"category\":\"{s}\"", .{cat}) catch return;
        }
        
        if (l2_status) |status| {
            writer.print(",\"status\":\"{s}\"", .{status}) catch return;
        } else {
            // Default status for transactions without L2 enhancements
            writer.print(",\"status\":\"confirmed\"", .{}) catch return;
        }
        
        writer.print("}}", .{}) catch return;
        count += 1;
    }
    
    writer.print("],\"count\":{}}}", .{count}) catch {
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Response formatting error\"}") catch return;
        return;
    };
    
    r.sendBody(stream.getWritten()) catch return;
}

// Main request router
fn onRequest(r: zap.Request) void {
    // Add CORS headers
    r.setHeader("Access-Control-Allow-Origin", "*") catch return;
    r.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS") catch return;
    r.setHeader("Access-Control-Allow-Headers", "Content-Type") catch return;

    // Handle preflight requests
    const method = r.method orelse return;
    if (std.mem.eql(u8, method, "OPTIONS")) {
        r.sendBody("") catch return;
        return;
    }

    // Route based on method and path
    const is_get = std.mem.eql(u8, method, "GET");
    const is_post = std.mem.eql(u8, method, "POST");
    const is_put = std.mem.eql(u8, method, "PUT");

    // Route requests
    const path = r.path orelse "/";

    // GET endpoints
    if (is_get) {
        if (std.mem.eql(u8, path, "/health")) {
            healthCheck(r);
        } else if (std.mem.eql(u8, path, "/api/network/health")) {
            networkHealth(r);
        } else if (std.mem.eql(u8, path, "/api/transactions/volume")) {
            transactionVolume(r);
        } else if (std.mem.eql(u8, path, "/api/l2/enhancements")) {
            queryEnhancements(r);
        } else if (std.mem.eql(u8, path, "/api/transactions/enhanced")) {
            queryEnhancedTransactions(r);
        } else if (std.mem.eql(u8, path, "/")) {
        // Root endpoint - API documentation
        const welcome =
            \\{"service":"ZeiCoin Analytics API","version":"1.0.0","endpoints":{"GET /health":"Health check","GET /api/network/health":"Network health metrics","GET /api/transactions/volume":"Transaction volume statistics","POST /api/l2/enhancements":"Create L2 enhancement","PUT /api/l2/enhancements/{id}/pending":"Update enhancement to pending","PUT /api/l2/enhancements/{id}/confirm":"Confirm enhancement","GET /api/l2/enhancements":"Query enhancements","GET /api/transactions/enhanced":"Query enhanced transactions"},"powered_by":"TimescaleDB + ZAP + L2","performance":"1000x faster than raw blockchain queries"}
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
    // POST endpoints
    } else if (is_post) {
        if (std.mem.eql(u8, path, "/api/l2/enhancements")) {
            createEnhancement(r);
        } else {
            r.setStatus(.not_found);
            const error_response =
                \\{"error": "Endpoint not found", "code": 404}
            ;
            r.sendBody(error_response) catch return;
        }
    // PUT endpoints  
    } else if (is_put) {
        if (std.mem.startsWith(u8, path, "/api/l2/enhancements/")) {
            if (std.mem.endsWith(u8, path, "/pending")) {
                setEnhancementPending(r);
            } else if (std.mem.endsWith(u8, path, "/confirm")) {
                confirmEnhancement(r);
            } else {
                r.setStatus(.not_found);
                const error_response =
                    \\{"error": "Invalid L2 enhancement operation", "code": 404}
                ;
                r.sendBody(error_response) catch return;
            }
        } else {
            r.setStatus(.not_found);
            const error_response =
                \\{"error": "Endpoint not found", "code": 404}
            ;
            r.sendBody(error_response) catch return;
        }
    } else {
        r.setStatus(.method_not_allowed);
        r.sendBody("Method not allowed") catch return;
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
    listener.listen() catch |err| {
        // ZAP returns a generic ListenError, so provide helpful context
        std.log.err("❌ Failed to start server on {s}:{}", .{ config.host, config.port });
        std.log.err("💡 Common solutions:", .{});
        std.log.err("   • Port already in use: pkill -f analytics_api", .{});
        std.log.err("   • Change port: ZEICOIN_API_PORT=8081", .{});
        std.log.err("   • Check if port < 1024 requires root privileges", .{});
        return err;
    };

    std.log.info("🎯 Analytics API Endpoints:", .{});
    std.log.info("  GET /health - Service health check", .{});
    std.log.info("  GET /api/network/health - Real-time network metrics (24h)", .{});
    std.log.info("  GET /api/transactions/volume - Daily transaction volume (30d)", .{});
    std.log.info("✅ Server ready! Press Ctrl+C to stop", .{});

    // Start ZAP with graceful shutdown handling
    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
    
    std.log.info("👋 Server stopped gracefully", .{});
}
