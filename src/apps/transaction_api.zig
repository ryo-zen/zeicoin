const std = @import("std");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const bech32 = zeicoin.bech32;
const util = zeicoin.util;
const postgres = util.postgres;
const RPCClient = @import("rpc_client.zig").RPCClient;
const faucet = @import("faucet.zig");
const net = std.Io.net;

var rpc: RPCClient = undefined;
var db_pool: *DBPool = undefined;
var faucet_service: faucet.FaucetService = undefined;

const log = std.log.scoped(.api);

// Database Connection Pool
const DBPool = struct {
    allocator: std.mem.Allocator,
    conninfo: [:0]const u8,
    connections: std.array_list.Managed(postgres.Connection),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, conninfo: [:0]const u8, size: usize) !*DBPool {
        const self = try allocator.create(DBPool);
        self.* = .{
            .allocator = allocator,
            .conninfo = conninfo,
            .connections = std.array_list.Managed(postgres.Connection).init(allocator),
            .mutex = .{},
        };

        // Pre-fill pool
        for (0..size) |_| {
            const conn = try postgres.Connection.init(allocator, conninfo);
            try self.connections.append(conn);
        }

        return self;
    }

    pub fn deinit(self: *DBPool) void {
        for (self.connections.items) |*conn| {
            conn.deinit();
        }
        self.connections.deinit();
        self.allocator.destroy(self);
    }

    pub fn acquire(self: *DBPool) !postgres.Connection {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.connections.items.len > 0) {
            return self.connections.pop() orelse unreachable;
        }

        // Create new connection if pool is empty
        return postgres.Connection.init(self.allocator, self.conninfo);
    }

    pub fn release(self: *DBPool, conn: postgres.Connection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Simple pool: just put it back. In production, check max size etc.
        self.connections.append(conn) catch {
            // If we can't append, close it
            var c = conn;
            c.deinit();
        };
    }
};

// Simple HTTP Server
const HttpServer = struct {
    allocator: std.mem.Allocator,
    port: u16,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, port: u16) HttpServer {
        return .{
            .allocator = allocator,
            .port = port,
            .io = io,
        };
    }

    pub fn start(self: *HttpServer) !void {
        const address = try net.IpAddress.parse("0.0.0.0", self.port);
        var server = try address.listen(self.io, .{ .reuse_address = true });
        defer server.deinit(self.io);

        log.info("🚀 Transaction API listening on 0.0.0.0:{d}", .{self.port});

        while (true) {
            const connection = server.accept(self.io) catch |err| {
                if (err == error.WouldBlock) {
                    self.io.sleep(std.Io.Duration.fromMilliseconds(10), std.Io.Clock.awake) catch {};
                    continue;
                }
                log.err("Accept error: {}", .{err});
                continue;
            };

            self.handleConnection(connection);
        }
    }

    fn handleConnection(self: *HttpServer, connection: net.Stream) void {
        defer connection.close(self.io);

        var buffer: [16384]u8 = undefined;
        const msg = connection.socket.receive(self.io, &buffer) catch |err| {
            log.err("Read error: {}", .{err});
            return;
        };
        
        if (msg.data.len == 0) return;
        const request_data = buffer[0..msg.data.len];

        // Simple HTTP parsing
        // Request line: GET /path HTTP/1.1
        var iter = std.mem.tokenizeScalar(u8, request_data, '\n');
        const request_line = iter.next() orelse return;
        
        var req_iter = std.mem.tokenizeScalar(u8, request_line, ' ');
        const method = req_iter.next() orelse return;
        const full_path = req_iter.next() orelse return;

        // Parse path and query
        var path = full_path;
        var query: []const u8 = "";
        if (std.mem.indexOfScalar(u8, full_path, '?')) |idx| {
            path = full_path[0..idx];
            query = full_path[idx+1..];
        }

        // Extract body (find double newline)
        var body: []const u8 = "";
        if (std.mem.indexOf(u8, request_data, "\r\n\r\n")) |idx| {
            body = request_data[idx+4..];
        } else if (std.mem.indexOf(u8, request_data, "\n\n")) |idx| {
            body = request_data[idx+2..];
        }

        const response = self.route(method, path, query, body) catch |err| {
            log.err("Handler error: {}", .{err});
            self.sendError(connection, 500, "Internal Server Error");
            return;
        };
        defer self.allocator.free(response);

        self.sendResponse(connection, 200, response);
    }

    fn sendResponse(self: *HttpServer, connection: net.Stream, status: u16, body: []const u8) void {
        _ = status; // Assumed 200 OK for now
        const header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nConnection: close\r\nContent-Length: ";
        
        const len_str = std.fmt.allocPrint(self.allocator, "{d}", .{body.len}) catch return;
        defer self.allocator.free(len_str);

        var write_buf: [4096]u8 = undefined;
        var writer = connection.writer(self.io, &write_buf);
        
        _ = writer.interface.writeAll(header) catch {};
        _ = writer.interface.writeAll(len_str) catch {};
        _ = writer.interface.writeAll("\r\n\r\n") catch {};
        _ = writer.interface.writeAll(body) catch {};
        _ = writer.interface.flush() catch {};
    }

    fn sendError(self: *HttpServer, connection: net.Stream, status: u16, message: []const u8) void {
        _ = status; // TODO: Use status code
        const json = std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{message}) catch return;
        defer self.allocator.free(json);

        const header = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\nContent-Length: ";
        const len_str = std.fmt.allocPrint(self.allocator, "{d}", .{json.len}) catch return;
        defer self.allocator.free(len_str);

        var write_buf: [4096]u8 = undefined;
        var writer = connection.writer(self.io, &write_buf);

        _ = writer.interface.writeAll(header) catch {};
        _ = writer.interface.writeAll(len_str) catch {};
        _ = writer.interface.writeAll("\r\n\r\n") catch {};
        _ = writer.interface.writeAll(json) catch {};
        _ = writer.interface.flush() catch {};
    }

    fn route(self: *HttpServer, method: []const u8, path: []const u8, query: []const u8, body: []const u8) ![]const u8 {
        // OPTIONS (CORS)
        if (std.mem.eql(u8, method, "OPTIONS")) {
            return try self.allocator.dupe(u8, "");
        }

        // GET /api/nonce/{address}
        if (std.mem.startsWith(u8, path, "/api/nonce/")) {
            return try handleNonce(self.allocator, path[11..]);
        }

        // GET /api/balance/{address}
        if (std.mem.startsWith(u8, path, "/api/balance/")) {
            return try handleBalance(self.allocator, path[13..]);
        }

        // GET /api/account/{address}
        if (std.mem.startsWith(u8, path, "/api/account/")) {
            return try handleAccount(self.allocator, path[13..]);
        }

        // GET /api/transaction/{hash}
        if (std.mem.startsWith(u8, path, "/api/transaction/")) {
            return try handleTransactionStatus(self.allocator, path[17..]);
        }

        // GET /api/transactions/{address}
        if (std.mem.startsWith(u8, path, "/api/transactions/")) {
            return try handleTransactionHistory(self.allocator, path[18..], query);
        }

        // POST /api/transaction
        if (std.mem.eql(u8, path, "/api/transaction") and std.mem.eql(u8, method, "POST")) {
            return try handleTransaction(self.allocator, body);
        }

        // POST /api/l2/messages
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/l2/messages"))
        {
            return try handleCreateL2Message(self.allocator, body);
        }

        // PUT /api/l2/messages/{temp_id}/pending
        if (std.mem.eql(u8, method, "PUT") and
            (std.mem.startsWith(u8, path, "/api/l2/messages/") and
            std.mem.endsWith(u8, path, "/pending")))
        {
            return try handleSetL2MessagePending(self.allocator, path);
        }

        // PUT /api/l2/messages/{temp_id}/confirm
        if (std.mem.eql(u8, method, "PUT") and
            (std.mem.startsWith(u8, path, "/api/l2/messages/") and
            std.mem.endsWith(u8, path, "/confirm")))
        {
            return try handleConfirmL2Message(self.allocator, path, body);
        }

        // POST /faucet
        if (std.mem.eql(u8, path, "/faucet") and std.mem.eql(u8, method, "POST")) {
            return try faucet_service.handleRequest(self.allocator, db_pool, body);
        }

        return try self.allocator.dupe(u8, "{\"error\":\"not found\"}");
    }
};

fn handleNonce(allocator: std.mem.Allocator, address: []const u8) ![]const u8 {
    _ = bech32.decodeAddress(allocator, address) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid address\"}}", .{});
    };
    const nonce = rpc.getNonce(address) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"rpc unavailable\"}}", .{});
    };
    return try std.fmt.allocPrint(allocator, "{{\"nonce\":{d}}}", .{nonce});
}

fn handleBalance(allocator: std.mem.Allocator, address: []const u8) ![]const u8 {
    _ = bech32.decodeAddress(allocator, address) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid address\"}}", .{});
    };
    const result = rpc.getBalance(address) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"rpc unavailable\"}}", .{});
    };
    return try std.fmt.allocPrint(allocator, "{{\"balance\":{d},\"nonce\":{d}}}", .{ result.balance, result.nonce });
}

fn handleAccount(allocator: std.mem.Allocator, address: []const u8) ![]const u8 {
    _ = bech32.decodeAddress(allocator, address) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid address\"}}", .{});
    };
    const result = rpc.getBalance(address) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"rpc unavailable\"}}", .{});
    };
    return try std.fmt.allocPrint(
        allocator,
        "{{\"address\":\"{s}\",\"balance\":{d},\"nonce\":{d},\"tx_count\":0,\"total_received\":{d},\"total_sent\":0}}",
        .{ address, result.balance, result.nonce, result.balance },
    );
}

fn handleTransactionStatus(allocator: std.mem.Allocator, tx_hash: []const u8) ![]const u8 {
    const tx = rpc.getTransaction(tx_hash) catch return try std.fmt.allocPrint(allocator, "{{\"error\":\"transaction not found\"}}", .{});
    defer allocator.free(tx.sender);
    defer allocator.free(tx.recipient);
    defer allocator.free(tx.status);

    const block_height_str = if (tx.block_height) |height|
        try std.fmt.allocPrint(allocator, "{d}", .{height})
    else
        try allocator.dupe(u8, "null");
    defer allocator.free(block_height_str);

    return try std.fmt.allocPrint(
        allocator,
        "{{\"hash\":\"{s}\",\"status\":\"{s}\",\"block_height\":{s},\"sender\":\"{s}\",\"recipient\":\"{s}\",\"amount\":{d},\"fee\":{d},\"nonce\":{d},\"timestamp\":{d},\"expiry_height\":{d}}}",
        .{ tx_hash, tx.status, block_height_str, tx.sender, tx.recipient, tx.amount, tx.fee, tx.nonce, tx.timestamp, tx.expiry_height },
    );
}

fn handleTransactionHistory(allocator: std.mem.Allocator, address: []const u8, query: []const u8) ![]const u8 {
    var limit: u32 = 50;
    var offset: u32 = 0;

    var iter = std.mem.tokenizeScalar(u8, query, '&');
    while (iter.next()) |param| {
        if (std.mem.startsWith(u8, param, "limit=")) {
            if (std.fmt.parseInt(u32, param[6..], 10)) |val| {
                limit = @min(val, 100);
            } else |_| {}
        } else if (std.mem.startsWith(u8, param, "offset=")) {
            if (std.fmt.parseInt(u32, param[7..], 10)) |val| {
                offset = val;
            } else |_| {}
        }
    }

    var conn = try db_pool.acquire();
    defer db_pool.release(conn);

    const limit_str = try std.fmt.allocPrint(allocator, "{d}", .{limit});
    defer allocator.free(limit_str);
    const offset_str = try std.fmt.allocPrint(allocator, "{d}", .{offset});
    defer allocator.free(offset_str);

    const sql = 
        \\SELECT hash, block_height, sender, recipient, amount, fee, nonce, timestamp_ms
        \\FROM transactions
        \\WHERE sender = $1 OR recipient = $1
        \\ORDER BY block_height DESC, position DESC
        \\LIMIT $2 OFFSET $3
    ;

    // Use zero-terminated strings for libpq
    const sql_z = try allocator.dupeZ(u8, sql);
    defer allocator.free(sql_z);
    
    const address_z = try allocator.dupeZ(u8, address);
    defer allocator.free(address_z);

    const limit_z = try allocator.dupeZ(u8, limit_str);
    defer allocator.free(limit_z);

    const offset_z = try allocator.dupeZ(u8, offset_str);
    defer allocator.free(offset_z);

    const params = [_][:0]const u8{ address_z, limit_z, offset_z };

    var result = try conn.queryParams(sql_z, &params);
    defer result.deinit();

    var response = std.array_list.Managed(u8).init(allocator);
    defer response.deinit();

    try response.appendSlice("{\"address\":\"");
    try response.appendSlice(address);
    try response.appendSlice("\",\"transactions\":[");

    const rows = result.rowCount();
    for (0..rows) |i| {
        if (i > 0) try response.append(',');

        const hash = result.getValue(i, 0) orelse "";
        const block_height = result.getValue(i, 1) orelse "0";
        const sender = result.getValue(i, 2) orelse "";
        const recipient = result.getValue(i, 3) orelse "";
        const amount = result.getValue(i, 4) orelse "0";
        const fee = result.getValue(i, 5) orelse "0";
        const nonce = result.getValue(i, 6) orelse "0";
        const timestamp_ms = result.getValue(i, 7) orelse "0";

        const tx_json = try std.fmt.allocPrint(
            allocator,
            "{{\"hash\":\"{s}\",\"block_height\":{s},\"sender\":\"{s}\",\"recipient\":\"{s}\",\"amount\":{s},\"fee\":{s},\"nonce\":{s},\"timestamp\":{s}}}",
            .{ hash, block_height, sender, recipient, amount, fee, nonce, timestamp_ms },
        );
        defer allocator.free(tx_json);
        try response.appendSlice(tx_json);
    }

    try response.appendSlice("],\"limit\":");
    try response.print("{d}", .{limit});
    try response.appendSlice(",\"offset\":");
    try response.print("{d}", .{offset});
    try response.append('}');

    return try response.toOwnedSlice();
}

fn handleTransaction(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    // Parse JSON request
    // We trim to avoid issues with extra whitespace
    const trimmed = std.mem.trim(u8, body, &std.ascii.whitespace);
    
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
        trimmed,
        .{},
    ) catch return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid json\"}}", .{});
    defer parsed.deinit();

    const tx = parsed.value;

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
    ) catch return try std.fmt.allocPrint(allocator, "{{\"error\":\"transaction rejected\"}}", .{});
    defer allocator.free(tx_hash);

    return try std.fmt.allocPrint(allocator, "{{\"success\":true,\"tx_hash\":\"{s}\"}}", .{tx_hash});
}

fn handleCreateL2Message(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    const parsed = std.json.parseFromSlice(
        struct {
            sender: []const u8,
            recipient: ?[]const u8 = null,
            message: ?[]const u8 = null,
            category: ?[]const u8 = null,
        },
        allocator,
        body,
        .{},
    ) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid json\"}}", .{});
    };
    defer parsed.deinit();

    const payload = parsed.value;

    const sql =
        \\SELECT create_l2_message($1, $2, $3, $4)::text
    ;
    const sql_z = try allocator.dupeZ(u8, sql);
    defer allocator.free(sql_z);

    const sender_z = try allocator.dupeZ(u8, payload.sender);
    defer allocator.free(sender_z);
    const recipient_z = try allocator.dupeZ(u8, payload.recipient orelse "");
    defer allocator.free(recipient_z);
    const message_z = try allocator.dupeZ(u8, payload.message orelse "");
    defer allocator.free(message_z);
    const category_z = try allocator.dupeZ(u8, payload.category orelse "");
    defer allocator.free(category_z);

    const params = [_][:0]const u8{ sender_z, recipient_z, message_z, category_z };

    var conn = try db_pool.acquire();
    defer db_pool.release(conn);

    var result = try conn.queryParams(sql_z, &params);
    defer result.deinit();
    if (result.rowCount() == 0) {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"failed to create message\"}}", .{});
    }

    const temp_id = result.getValue(0, 0) orelse {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"failed to create message\"}}", .{});
    };

    return try std.fmt.allocPrint(
        allocator,
        "{{\"success\":true,\"temp_id\":\"{s}\",\"status\":\"draft\"}}",
        .{temp_id},
    );
}

fn handleSetL2MessagePending(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const temp_id = extractTempIdFromPath(path) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid temp_id\"}}", .{});
    };

    const sql =
        \\SELECT set_l2_message_pending($1::uuid)
    ;
    const sql_z = try allocator.dupeZ(u8, sql);
    defer allocator.free(sql_z);

    const temp_id_z = try allocator.dupeZ(u8, temp_id);
    defer allocator.free(temp_id_z);
    const params = [_][:0]const u8{temp_id_z};

    var conn = try db_pool.acquire();
    defer db_pool.release(conn);

    var result = try conn.queryParams(sql_z, &params);
    defer result.deinit();
    if (result.rowCount() == 0) {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"message not found\"}}", .{});
    }

    return try std.fmt.allocPrint(
        allocator,
        "{{\"success\":true,\"temp_id\":\"{s}\",\"status\":\"pending\"}}",
        .{temp_id},
    );
}

fn handleConfirmL2Message(allocator: std.mem.Allocator, path: []const u8, body: []const u8) ![]const u8 {
    const temp_id = extractTempIdFromPath(path) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid temp_id\"}}", .{});
    };

    const parsed = std.json.parseFromSlice(
        struct {
            tx_hash: []const u8,
            block_height: u32,
        },
        allocator,
        body,
        .{},
    ) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"invalid json\"}}", .{});
    };
    defer parsed.deinit();

    const payload = parsed.value;
    const block_height = try std.fmt.allocPrint(allocator, "{d}", .{payload.block_height});
    defer allocator.free(block_height);

    const sql =
        \\SELECT confirm_l2_message($1::uuid, $2, $3)
    ;
    const sql_z = try allocator.dupeZ(u8, sql);
    defer allocator.free(sql_z);

    const temp_id_z = try allocator.dupeZ(u8, temp_id);
    defer allocator.free(temp_id_z);
    const tx_hash_z = try allocator.dupeZ(u8, payload.tx_hash);
    defer allocator.free(tx_hash_z);
    const block_height_z = try allocator.dupeZ(u8, block_height);
    defer allocator.free(block_height_z);
    const params = [_][:0]const u8{ temp_id_z, tx_hash_z, block_height_z };

    var conn = try db_pool.acquire();
    defer db_pool.release(conn);

    var result = try conn.queryParams(sql_z, &params);
    defer result.deinit();
    if (result.rowCount() == 0) {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"message not found\"}}", .{});
    }

    return try std.fmt.allocPrint(
        allocator,
        "{{\"success\":true,\"temp_id\":\"{s}\",\"tx_hash\":\"{s}\",\"status\":\"confirmed\"}}",
        .{ temp_id, payload.tx_hash },
    );
}

fn extractTempIdFromPath(path: []const u8) ![]const u8 {
    var iter = std.mem.tokenizeScalar(u8, path, '/');
    while (iter.next()) |part| {
        if (part.len == 36 and std.mem.indexOfScalar(u8, part, '-') != null) {
            return part;
        }
    }
    return error.TempIdNotFound;
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Arena for config
    var arena_s = std.heap.ArenaAllocator.init(allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    zeicoin.dotenv.loadForNetwork(allocator) catch {};

    // Initialize RPC client
    rpc = RPCClient.init(allocator, init.io, "127.0.0.1", 10803);

    // Test RPC connection
    rpc.ping() catch {
        std.log.err("❌ Cannot connect to RPC server at 127.0.0.1:10803", .{});
        std.log.err("💡 Start zen_server first", .{});
        // We'll continue anyway, maybe server starts later
    };

    std.log.info("✅ RPC Client initialized", .{});

    // Initialize PostgreSQL connection pool
    const db_password = util.getEnvVarOwned(arena, "ZEICOIN_DB_PASSWORD") catch {
        std.log.err("❌ ZEICOIN_DB_PASSWORD not set", .{});
        return error.MissingPassword;
    };

    const db_host = util.getEnvVarOwned(arena, "ZEICOIN_DB_HOST") catch try arena.dupe(u8, "127.0.0.1");
    const db_name = util.getEnvVarOwned(arena, "ZEICOIN_DB_NAME") catch try arena.dupe(u8, "zeicoin_testnet");
    const db_port_str = util.getEnvVarOwned(arena, "ZEICOIN_DB_PORT") catch try arena.dupe(u8, "5432");
    const db_port = std.fmt.parseInt(u16, db_port_str, 10) catch 5432;
    const db_user = util.getEnvVarOwned(arena, "ZEICOIN_DB_USER") catch try arena.dupe(u8, "zeicoin");

    const conninfo = try postgres.buildConnString(arena, db_host, db_port, db_name, db_user, db_password);
    
    db_pool = try DBPool.init(allocator, conninfo, 5); // Pool size 5
    defer db_pool.deinit();

    std.log.info("✅ Connected to PostgreSQL ({s})", .{db_name});

    faucet_service = faucet.FaucetService.init(allocator, init.io, &rpc);
    defer faucet_service.deinit();
    faucet_service.loadFromEnv();

    // Start HTTP server
    var server = HttpServer.init(allocator, init.io, 8080);
    try server.start();
}
