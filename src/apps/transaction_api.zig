const std = @import("std");
const zap = @import("zap");
const pg = @import("pg");
const RPCClient = @import("rpc_client.zig").RPCClient;
const zeicoin = @import("zeicoin");
const wallet_mod = zeicoin.wallet;
const types = zeicoin.types;
const bech32 = zeicoin.bech32;

var rpc: RPCClient = undefined;
var pg_pool: *pg.Pool = undefined;

fn onRequest(r: zap.Request) void {
    // CORS
    r.setHeader("Access-Control-Allow-Origin", "*") catch return;
    r.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS") catch return;
    r.setHeader("Access-Control-Allow-Headers", "Content-Type") catch return;

    if (r.methodAsEnum() == .OPTIONS) {
        r.sendBody("") catch return;
        return;
    }

    const path = r.path orelse return;

    // GET /api/nonce/{address}
    if (std.mem.startsWith(u8, path, "/api/nonce/")) {
        handleNonce(r, path[11..]) catch |err| {
            std.log.err("Nonce error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendBody("{\"error\":\"internal error\"}") catch return;
        };
        return;
    }

    // GET /api/balance/{address}
    if (std.mem.startsWith(u8, path, "/api/balance/")) {
        handleBalance(r, path[13..]) catch |err| {
            std.log.err("Balance error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendBody("{\"error\":\"internal error\"}") catch return;
        };
        return;
    }

    // GET /api/account/{address}
    if (std.mem.startsWith(u8, path, "/api/account/")) {
        handleAccount(r, path[13..]) catch |err| {
            std.log.err("Account error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendBody("{\"error\":\"internal error\"}") catch return;
        };
        return;
    }

    // GET /api/transaction/{hash}
    if (std.mem.startsWith(u8, path, "/api/transaction/")) {
        handleTransactionStatus(r, path[17..]) catch |err| {
            std.log.err("Transaction status error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendBody("{\"error\":\"internal error\"}") catch return;
        };
        return;
    }

    // GET /api/transactions/{address}
    if (std.mem.startsWith(u8, path, "/api/transactions/")) {
        handleTransactionHistory(r, path[18..]) catch |err| {
            std.log.err("Transaction history error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendBody("{\"error\":\"internal error\"}") catch return;
        };
        return;
    }

    // POST /api/transaction
    if (std.mem.eql(u8, path, "/api/transaction") and r.methodAsEnum() == .POST) {
        handleTransaction(r) catch |err| {
            std.log.err("Transaction error: {}", .{err});
            r.setStatus(.internal_server_error);
            r.sendBody("{\"error\":\"internal error\"}") catch return;
        };
        return;
    }

    // 404
    r.setStatus(.not_found);
    r.sendBody("{\"error\":\"not found\"}") catch return;
}

fn handleNonce(r: zap.Request, address: []const u8) !void {
    const nonce = rpc.getNonce(address) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\":\"invalid address\"}");
        return;
    };

    const allocator = std.heap.page_allocator;
    const response = try std.fmt.allocPrint(allocator, "{{\"nonce\":{d}}}", .{nonce});
    defer allocator.free(response);

    r.setStatus(.ok);
    try r.sendBody(response);
}

fn handleBalance(r: zap.Request, address: []const u8) !void {
    const result = rpc.getBalance(address) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\":\"invalid address\"}");
        return;
    };

    const allocator = std.heap.page_allocator;
    const response = try std.fmt.allocPrint(allocator, "{{\"balance\":{d},\"nonce\":{d}}}", .{ result.balance, result.nonce });
    defer allocator.free(response);

    r.setStatus(.ok);
    try r.sendBody(response);
}

fn handleAccount(r: zap.Request, address: []const u8) !void {
    const result = rpc.getBalance(address) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\":\"invalid address\"}");
        return;
    };

    const allocator = std.heap.page_allocator;
    // For now, we'll use balance and nonce from getBalance
    // tx_count, total_received, total_sent would require additional RPC methods
    const response = try std.fmt.allocPrint(
        allocator,
        "{{\"address\":\"{s}\",\"balance\":{d},\"nonce\":{d},\"tx_count\":0,\"total_received\":{d},\"total_sent\":0}}",
        .{ address, result.balance, result.nonce, result.balance },
    );
    defer allocator.free(response);

    r.setStatus(.ok);
    try r.sendBody(response);
}

fn handleTransactionStatus(r: zap.Request, tx_hash: []const u8) !void {
    const allocator = std.heap.page_allocator;

    // Get transaction from RPC
    const tx = rpc.getTransaction(tx_hash) catch {
        r.setStatus(.not_found);
        try r.sendBody("{\"error\":\"transaction not found\"}");
        return;
    };
    defer allocator.free(tx.sender);
    defer allocator.free(tx.recipient);
    defer allocator.free(tx.status);

    // Format response
    const block_height_str = if (tx.block_height) |height|
        try std.fmt.allocPrint(allocator, "{d}", .{height})
    else
        try allocator.dupe(u8, "null");
    defer allocator.free(block_height_str);

    const response = try std.fmt.allocPrint(
        allocator,
        "{{\"hash\":\"{s}\",\"status\":\"{s}\",\"block_height\":{s},\"sender\":\"{s}\",\"recipient\":\"{s}\",\"amount\":{d},\"fee\":{d},\"nonce\":{d},\"timestamp\":{d},\"expiry_height\":{d}}}",
        .{ tx_hash, tx.status, block_height_str, tx.sender, tx.recipient, tx.amount, tx.fee, tx.nonce, tx.timestamp, tx.expiry_height },
    );
    defer allocator.free(response);

    r.setStatus(.ok);
    try r.sendBody(response);
}

fn handleTransactionHistory(r: zap.Request, address: []const u8) !void {
    const allocator = std.heap.page_allocator;

    // Parse query parameters for pagination
    const query = r.query orelse "";
    var limit: u32 = 50; // Default limit
    var offset: u32 = 0; // Default offset

    // Simple query parsing for limit and offset
    var iter = std.mem.tokenizeScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.indexOf(u8, param, "limit=")) |_| {
            if (std.fmt.parseInt(u32, param[6..], 10)) |val| {
                limit = @min(val, 100); // Cap at 100
            } else |_| {}
        } else if (std.mem.indexOf(u8, param, "offset=")) |_| {
            if (std.fmt.parseInt(u32, param[7..], 10)) |val| {
                offset = val;
            } else |_| {}
        }
    }

    // Query PostgreSQL for transaction history
    const conn = pg_pool.acquire() catch {
        r.setStatus(.service_unavailable);
        try r.sendBody("{\"error\":\"database unavailable\"}");
        return;
    };
    defer pg_pool.release(conn);

    // Query transactions where sender or recipient matches address
    const query_sql =
        \\SELECT hash, block_height, sender, recipient, amount, fee, nonce, timestamp_ms
        \\FROM transactions
        \\WHERE sender = $1 OR recipient = $1
        \\ORDER BY block_height DESC, position DESC
        \\LIMIT $2 OFFSET $3
    ;

    const result = conn.query(query_sql, .{ address, limit, offset }) catch {
        r.setStatus(.internal_server_error);
        try r.sendBody("{\"error\":\"query failed\"}");
        return;
    };
    defer result.deinit();

    // Build JSON response
    var response = std.ArrayList(u8).init(allocator);
    defer response.deinit();

    try response.appendSlice("{\"address\":\"");
    try response.appendSlice(address);
    try response.appendSlice("\",\"transactions\":[");

    var first = true;
    while (try result.next()) |row| {
        if (!first) try response.append(',');
        first = false;

        const hash = row.get([]const u8, 0);
        const block_height = row.get(i32, 1);
        const sender = row.get([]const u8, 2);
        const recipient = row.get([]const u8, 3);
        const amount = row.get(i64, 4);
        const fee = row.get(i64, 5);
        const nonce = row.get(i64, 6);
        const timestamp_ms = row.get(i64, 7);

        // PostgreSQL stores Unix timestamps directly from blockchain (already absolute time)
        // Database stores milliseconds, API returns milliseconds - no conversion needed
        const unix_timestamp_ms = timestamp_ms;

        const tx_json = try std.fmt.allocPrint(
            allocator,
            "{{\"hash\":\"{s}\",\"block_height\":{d},\"sender\":\"{s}\",\"recipient\":\"{s}\",\"amount\":{d},\"fee\":{d},\"nonce\":{d},\"timestamp\":{d}}}",
            .{ hash, block_height, sender, recipient, amount, fee, nonce, unix_timestamp_ms },
        );
        defer allocator.free(tx_json);
        try response.appendSlice(tx_json);
    }

    try response.appendSlice("],\"limit\":");
    try response.writer().print("{d}", .{limit});
    try response.appendSlice(",\"offset\":");
    try response.writer().print("{d}", .{offset});
    try response.append('}');

    r.setStatus(.ok);
    try r.sendBody(response.items);
}

fn handleTransaction(r: zap.Request) !void {
    const allocator = std.heap.page_allocator;

    // Get request body
    const body = r.body orelse {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\":\"missing request body\"}");
        return;
    };

    // Parse JSON request
    const parsed = std.json.parseFromSlice(
        struct {
            sender: []const u8,
            recipient: []const u8,
            amount: u64,
            fee: u64,
            nonce: u64,
            timestamp: u64,
            expiry_height: u64,
            signature: []const u8,
            sender_public_key: []const u8,
        },
        allocator,
        body,
        .{},
    ) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\":\"invalid json\"}");
        return;
    };
    defer parsed.deinit();

    const tx = parsed.value;

    // Broadcast via RPC
    const tx_hash = rpc.broadcastTransaction(
        tx.sender,
        tx.recipient,
        tx.amount,
        tx.fee,
        tx.nonce,
        tx.timestamp,
        tx.expiry_height,
        tx.signature,
        tx.sender_public_key,
    ) catch {
        r.setStatus(.bad_request);
        try r.sendBody("{\"error\":\"transaction rejected\"}");
        return;
    };
    defer allocator.free(tx_hash);

    const response = try std.fmt.allocPrint(allocator, "{{\"success\":true,\"tx_hash\":\"{s}\"}}", .{tx_hash});
    defer allocator.free(response);

    r.setStatus(.ok);
    try r.sendBody(response);
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Initialize RPC client
    rpc = RPCClient.init(allocator, "127.0.0.1", 10803);

    // Test RPC connection
    rpc.ping() catch {
        std.log.err("❌ Cannot connect to RPC server at 127.0.0.1:10803", .{});
        std.log.err("💡 Start zen_server first", .{});
        return error.RPCUnavailable;
    };

    std.log.info("✅ Connected to RPC server", .{});

    // Initialize PostgreSQL connection pool
    const db_password = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PASSWORD") catch {
        std.log.err("❌ ZEICOIN_DB_PASSWORD not set", .{});
        return error.MissingPassword;
    };
    defer allocator.free(db_password);

    const db_host = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_HOST") catch
        try allocator.dupe(u8, "127.0.0.1");
    defer allocator.free(db_host);

    const db_name = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_NAME") catch
        try allocator.dupe(u8, "zeicoin_testnet");
    defer allocator.free(db_name);

    pg_pool = try pg.Pool.init(allocator, .{
        .size = 5,
        .connect = .{
            .host = db_host,
            .port = 5432,
        },
        .auth = .{
            .username = "zeicoin",
            .database = db_name,
            .password = db_password,
            .timeout = 10_000,
        },
    });
    defer pg_pool.deinit();

    std.log.info("✅ Connected to PostgreSQL", .{});

    // Start HTTP server
    var listener = zap.HttpListener.init(.{
        .port = 8080,
        .on_request = onRequest,
        .log = false,
    });
    try listener.listen();

    std.log.info("🚀 Transaction API listening on port 8080", .{});
    std.log.info("   GET  /api/nonce/{{address}}", .{});
    std.log.info("   GET  /api/balance/{{address}}", .{});
    std.log.info("   GET  /api/account/{{address}}", .{});
    std.log.info("   GET  /api/transaction/{{hash}}", .{});
    std.log.info("   GET  /api/transactions/{{address}}?limit=50&offset=0", .{});
    std.log.info("   POST /api/transaction", .{});

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
