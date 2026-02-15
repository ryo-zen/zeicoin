// l2_service.zig - Consolidated L2 Messaging Service and REST API for ZeiCoin
// Provides transaction enhancements, messaging capabilities, and HTTP API endpoints

const std = @import("std");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const util = zeicoin.util;
const postgres = util.postgres;
const net = std.Io.net;

const log = std.log.scoped(.l2_service);

// Database Connection Pool
const DBPool = struct {
    allocator: std.mem.Allocator,
    conninfo: [:0]const u8,
    connections: std.array_list.Managed(postgres.Connection),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, conninfo: [:0]const u8, size: usize) !*DBPool {
        const self = try allocator.create(DBPool);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .conninfo = conninfo,
            .connections = std.array_list.Managed(postgres.Connection).init(allocator),
            .mutex = .{},
        };
        errdefer {
            for (self.connections.items) |*conn| {
                conn.deinit();
            }
            self.connections.deinit();
        }

        // Pre-fill pool
        for (0..size) |_| {
            var conn = try postgres.Connection.init(allocator, conninfo);
            self.connections.append(conn) catch |err| {
                conn.deinit();
                return err;
            };
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

        // Simple pool: just put it back
        self.connections.append(conn) catch {
            // If we can't append, close it
            var c = conn;
            c.deinit();
        };
    }
};

/// L2 Enhancement status
pub const EnhancementStatus = enum {
    draft,
    pending,
    confirmed,
    failed,

    pub fn toString(self: EnhancementStatus) []const u8 {
        return switch (self) {
            .draft => "draft",
            .pending => "pending",
            .confirmed => "confirmed",
            .failed => "failed",
        };
    }

    pub fn fromString(str: []const u8) !EnhancementStatus {
        if (std.mem.eql(u8, str, "draft")) return .draft;
        if (std.mem.eql(u8, str, "pending")) return .pending;
        if (std.mem.eql(u8, str, "confirmed")) return .confirmed;
        if (std.mem.eql(u8, str, "failed")) return .failed;
        return error.InvalidStatus;
    }
};

/// Transaction Enhancement structure
pub const TransactionEnhancement = struct {
    id: ?u32 = null,
    tx_hash: ?[]const u8 = null,
    temp_id: []const u8,
    sender_address: []const u8,
    recipient_address: ?[]const u8 = null,
    message: ?[]const u8 = null,
    tags: [][]const u8 = &.{},
    category: ?[]const u8 = null,
    reference_id: ?[]const u8 = null,
    is_private: bool = false,
    is_editable: bool = true,
    status: EnhancementStatus = .draft,
    confirmation_block_height: ?u32 = null,
    created_at: ?i64 = null,
    updated_at: ?i64 = null,
    confirmed_at: ?i64 = null,
};

/// Message Channel structure
pub const MessageChannel = struct {
    id: []const u8,
    name: []const u8,
    channel_hash: []const u8,
    anchor_tx_hash: ?[]const u8 = null,
    anchor_height: ?u32 = null,
    creator_address: []const u8,
    created_at: i64,
    channel_type: []const u8 = "public",
    message_count: u32 = 0,
    last_message_at: ?i64 = null,
};

/// Individual Message structure
pub const Message = struct {
    id: []const u8,
    channel_id: []const u8,
    sender_address: []const u8,
    content: []const u8,
    content_hash: []const u8,
    signature: []const u8,
    nonce: u64,
    reply_to: ?[]const u8 = null,
    created_at: i64,
    anchor_tx_hash: ?[]const u8 = null,
};

/// L2 Messaging Service
pub const L2Service = struct {
    allocator: std.mem.Allocator,
    pool: *DBPool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pool: *DBPool) Self {
        return Self{
            .allocator = allocator,
            .pool = pool,
        };
    }

    /// Create a new transaction enhancement draft
    pub fn createEnhancement(
        self: *Self,
        sender: []const u8,
        recipient: ?[]const u8,
        message: ?[]const u8,
        tags: [][]const u8,
        category: ?[]const u8,
        reference_id: ?[]const u8,
        is_private: bool,
    ) ![]const u8 {
        // Convert tags to PostgreSQL array format
        var tags_array = std.array_list.Managed(u8).init(self.allocator);
        defer tags_array.deinit();

        try tags_array.append('{');
        for (tags, 0..) |tag, i| {
            if (i > 0) try tags_array.append(',');
            try tags_array.append('"');
            try tags_array.appendSlice(tag);
            try tags_array.append('"');
        }
        try tags_array.append('}');

        const sql =
            \\SELECT create_transaction_enhancement($1, $2, $3, $4::text[], $5, $6, $7::boolean)::text
        ;
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        const sender_z = try self.allocator.dupeZ(u8, sender);
        defer self.allocator.free(sender_z);
        const recipient_z = try self.allocator.dupeZ(u8, recipient orelse "");
        defer self.allocator.free(recipient_z);
        const message_z = try self.allocator.dupeZ(u8, message orelse "");
        defer self.allocator.free(message_z);
        const tags_z = try self.allocator.dupeZ(u8, tags_array.items);
        defer self.allocator.free(tags_z);
        const category_z = try self.allocator.dupeZ(u8, category orelse "");
        defer self.allocator.free(category_z);
        const reference_id_z = try self.allocator.dupeZ(u8, reference_id orelse "");
        defer self.allocator.free(reference_id_z);
        const is_private_z: [:0]const u8 = if (is_private) "true" else "false";

        const params = [_][:0]const u8{
            sender_z,
            recipient_z,
            message_z,
            tags_z,
            category_z,
            reference_id_z,
            is_private_z,
        };

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.queryParams(sql_z, &params);
        defer result.deinit();

        if (result.rowCount() > 0) {
            const temp_id_val = result.getValue(0, 0) orelse return error.FailedToCreateEnhancement;
            const temp_id = try self.allocator.dupe(u8, temp_id_val);
            log.info("Created enhancement draft with temp_id: {s}", .{temp_id});
            return temp_id;
        }

        return error.FailedToCreateEnhancement;
    }

    /// Update enhancement status to pending (when transaction submitted)
    pub fn setEnhancementPending(self: *Self, temp_id: []const u8) !void {
        const sql =
            \\SELECT set_enhancement_pending($1::uuid)
        ;
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        const temp_id_z = try self.allocator.dupeZ(u8, temp_id);
        defer self.allocator.free(temp_id_z);
        const params = [_][:0]const u8{temp_id_z};

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.queryParams(sql_z, &params);
        defer result.deinit();

        if (result.rowCount() > 0) {
            const success_val = result.getValue(0, 0) orelse return error.FailedToUpdateEnhancement;
            if (std.mem.eql(u8, success_val, "t") or std.mem.eql(u8, success_val, "true")) {
                log.info("Set enhancement {s} to pending", .{temp_id});
            } else {
                return error.EnhancementNotFound;
            }
        } else {
            return error.FailedToUpdateEnhancement;
        }
    }

    /// Confirm enhancement when transaction is mined
    pub fn confirmEnhancement(
        self: *Self,
        temp_id: []const u8,
        tx_hash: []const u8,
        block_height: u32,
    ) !void {
        const sql =
            \\SELECT confirm_transaction_enhancement($1::uuid, $2, $3)
        ;
        const sql_z = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_z);

        const temp_id_z = try self.allocator.dupeZ(u8, temp_id);
        defer self.allocator.free(temp_id_z);
        const tx_hash_z = try self.allocator.dupeZ(u8, tx_hash);
        defer self.allocator.free(tx_hash_z);
        const block_height_str = try std.fmt.allocPrint(self.allocator, "{d}", .{block_height});
        defer self.allocator.free(block_height_str);
        const block_height_z = try self.allocator.dupeZ(u8, block_height_str);
        defer self.allocator.free(block_height_z);
        const params = [_][:0]const u8{ temp_id_z, tx_hash_z, block_height_z };

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.queryParams(sql_z, &params);
        defer result.deinit();

        if (result.rowCount() > 0) {
            const success_val = result.getValue(0, 0) orelse return error.FailedToConfirmEnhancement;
            if (std.mem.eql(u8, success_val, "t") or std.mem.eql(u8, success_val, "true")) {
                log.info("Confirmed enhancement {s} with tx_hash {s} at height {}", .{ temp_id, tx_hash, block_height });
            } else {
                log.warn("Enhancement {s} not found or already confirmed", .{temp_id});
            }
        }
    }

    /// Query enhancements by sender and recipient
    pub fn queryEnhancementsBySenderRecipient(
        self: *Self,
        sender: []const u8,
        recipient: []const u8,
        status: EnhancementStatus,
    ) ![]TransactionEnhancement {
        _ = sender;
        _ = recipient;
        _ = status;

        // TODO: Implement with proper SQL
        var enhancements = std.array_list.Managed(TransactionEnhancement).init(self.allocator);
        return enhancements.toOwnedSlice();
    }

    /// Free memory allocated for TransactionEnhancement array
    pub fn freeEnhancements(self: *Self, enhancements: []TransactionEnhancement) void {
        for (enhancements) |enhancement| {
            if (enhancement.tx_hash) |h| self.allocator.free(h);
            self.allocator.free(enhancement.temp_id);
            self.allocator.free(enhancement.sender_address);
            if (enhancement.recipient_address) |r| self.allocator.free(r);
            if (enhancement.message) |m| self.allocator.free(m);
            if (enhancement.category) |c| self.allocator.free(c);
            if (enhancement.reference_id) |r| self.allocator.free(r);
        }
        self.allocator.free(enhancements);
    }

    /// Query enhancements with filters
    pub fn queryEnhancements(
        self: *Self,
        sender: ?[]const u8,
        recipient: ?[]const u8,
        status: EnhancementStatus,
        limit: u32,
    ) ![]TransactionEnhancement {
        _ = sender;
        _ = recipient;
        _ = status;
        _ = limit;

        // TODO: Implement complex query with result parsing
        var enhancements = std.array_list.Managed(TransactionEnhancement).init(self.allocator);
        return enhancements.toOwnedSlice();
    }

    /// Get enhanced transaction by hash
    pub fn getEnhancedTransaction(self: *Self, tx_hash: []const u8) !?TransactionEnhancement {
        _ = self;
        _ = tx_hash;

        // TODO: Implement complex query with result parsing
        return null;
    }

    /// Get enhanced transactions for an address
    pub fn getEnhancedTransactionsForAddress(
        self: *Self,
        address: []const u8,
        limit: u32,
        offset: u32,
    ) ![]TransactionEnhancement {
        _ = address;
        _ = limit;
        _ = offset;

        var enhancements = std.array_list.Managed(TransactionEnhancement).init(self.allocator);

        return enhancements.toOwnedSlice();
    }

    /// Search enhanced transactions by message content
    pub fn searchEnhancedTransactions(
        self: *Self,
        search_query: []const u8,
        address: ?[]const u8,
        limit: u32,
    ) ![]TransactionEnhancement {
        _ = search_query;
        _ = address;
        _ = limit;

        var results = std.array_list.Managed(TransactionEnhancement).init(self.allocator);

        return results.toOwnedSlice();
    }

    /// Clean up orphaned enhancements (pending for too long)
    pub fn cleanupOrphanedEnhancements(self: *Self) !u32 {
        const sql_str = try std.fmt.allocPrint(
            self.allocator,
            "SELECT cleanup_orphaned_enhancements()",
            .{},
        );
        defer self.allocator.free(sql_str);

        const sql = try self.allocator.dupeZ(u8, sql_str);
        defer self.allocator.free(sql);

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.query(sql);
        defer result.deinit();

        if (result.rowCount() > 0) {
            const count_val = result.getValue(0, 0) orelse return 0;
            const count = std.fmt.parseInt(u32, count_val, 10) catch 0;
            if (count > 0) {
                log.info("Cleaned up {} orphaned enhancements", .{count});
            }
            return count;
        }

        return 0;
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

/// Create transaction enhancement endpoint
/// POST /api/l2/enhancements
fn handleCreateEnhancement(service: *L2Service, allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    const parsed = std.json.parseFromSlice(struct {
        sender: []const u8,
        recipient: ?[]const u8 = null,
        message: ?[]const u8 = null,
        tags: [][]const u8 = &.{},
        category: ?[]const u8 = null,
        reference_id: ?[]const u8 = null,
        is_private: bool = false,
    }, allocator, body, .{}) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Invalid JSON format\"}}", .{});
    };
    defer parsed.deinit();

    const data = parsed.value;

    const temp_id = service.createEnhancement(
        data.sender,
        data.recipient,
        data.message,
        data.tags,
        data.category,
        data.reference_id,
        data.is_private,
    ) catch |err| {
        log.err("Failed to create enhancement: {}", .{err});
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Failed to create enhancement\"}}", .{});
    };
    defer allocator.free(temp_id);

    return try std.fmt.allocPrint(allocator, "{{\"success\":true,\"temp_id\":\"{s}\",\"status\":\"draft\"}}", .{temp_id});
}

/// Update enhancement to pending status
/// PUT /api/l2/enhancements/{temp_id}/pending
fn handleSetEnhancementPending(service: *L2Service, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const temp_id = extractTempIdFromPath(path) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Invalid temp_id in path\"}}", .{});
    };

    service.setEnhancementPending(temp_id) catch |err| {
        log.err("Failed to update enhancement: {}", .{err});
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Failed to update enhancement\"}}", .{});
    };

    return try std.fmt.allocPrint(allocator, "{{\"success\":true,\"temp_id\":\"{s}\",\"status\":\"pending\"}}", .{temp_id});
}

/// Confirm enhancement with transaction hash
/// PUT /api/l2/enhancements/{temp_id}/confirm
fn handleConfirmEnhancement(service: *L2Service, allocator: std.mem.Allocator, path: []const u8, body: []const u8) ![]const u8 {
    const temp_id = extractTempIdFromPath(path) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Invalid temp_id in path\"}}", .{});
    };

    const parsed = std.json.parseFromSlice(struct {
        tx_hash: []const u8,
        block_height: u32,
    }, allocator, body, .{}) catch {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Invalid JSON format\"}}", .{});
    };
    defer parsed.deinit();

    const data = parsed.value;

    service.confirmEnhancement(
        temp_id,
        data.tx_hash,
        data.block_height,
    ) catch |err| {
        log.err("Failed to confirm enhancement: {}", .{err});
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Failed to confirm enhancement\"}}", .{});
    };

    return try std.fmt.allocPrint(allocator, "{{\"success\":true,\"temp_id\":\"{s}\",\"tx_hash\":\"{s}\",\"status\":\"confirmed\"}}", .{ temp_id, data.tx_hash });
}

/// Get enhanced transactions for an address
/// GET /api/transactions/enhanced?address={address}&limit={limit}&offset={offset}
fn handleGetEnhancedTransactions(service: *L2Service, allocator: std.mem.Allocator, query: []const u8) ![]const u8 {
    const address = parseQueryParam(query, "address") orelse {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Missing address parameter\"}}", .{});
    };

    const limit = parseQueryParamInt(query, "limit") orelse 50;
    const offset = parseQueryParamInt(query, "offset") orelse 0;

    // Note: getEnhancedTransactionsForAddress is currently a stub
    const transactions = service.getEnhancedTransactionsForAddress(
        address,
        @intCast(limit),
        @intCast(offset),
    ) catch |err| {
        log.err("Failed to get enhanced transactions: {}", .{err});
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Failed to retrieve transactions\"}}", .{});
    };
    defer allocator.free(transactions);

    // Simple JSON array response (stub returns empty array)
    return try std.fmt.allocPrint(allocator, "{{\"transactions\":[],\"count\":{},\"offset\":{},\"limit\":{}}}", .{ transactions.len, offset, limit });
}

/// Search enhanced transactions by message content
/// GET /api/l2/search?q={query}&address={address}&limit={limit}
fn handleSearchEnhancedTransactions(service: *L2Service, allocator: std.mem.Allocator, query_string: []const u8) ![]const u8 {
    const search_query = parseQueryParam(query_string, "q") orelse {
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Missing search query\"}}", .{});
    };

    const address = parseQueryParam(query_string, "address");
    const limit = parseQueryParamInt(query_string, "limit") orelse 50;

    // Note: searchEnhancedTransactions is currently a stub
    const results = service.searchEnhancedTransactions(
        search_query,
        address,
        @intCast(limit),
    ) catch |err| {
        log.err("Failed to search transactions: {}", .{err});
        return try std.fmt.allocPrint(allocator, "{{\"error\":\"Search failed\"}}", .{});
    };
    defer allocator.free(results);

    return try std.fmt.allocPrint(allocator, "{{\"results\":[],\"count\":{},\"query\":\"{s}\"}}", .{ results.len, search_query });
}

/// Health check endpoint
/// GET /health, /api/l2/health
fn handleHealthCheck(service: *L2Service, allocator: std.mem.Allocator) !HttpResponse {
    const db_ok = checkDatabaseHealth(service) catch |err| blk: {
        log.warn("Health check DB probe failed: {}", .{err});
        break :blk false;
    };

    const now = util.getTime();
    const status_str = if (db_ok) "ok" else "degraded";
    const db_status = if (db_ok) "ok" else "down";
    const http_status: u16 = if (db_ok) 200 else 503;
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"status\":\"{s}\",\"service\":\"l2_service\",\"database\":\"{s}\",\"timestamp\":{}}}",
        .{ status_str, db_status, now },
    );

    return .{
        .status = http_status,
        .body = body,
    };
}

fn checkDatabaseHealth(service: *L2Service) !bool {
    const sql: [:0]const u8 = "SELECT 1";

    var conn = try service.pool.acquire();
    defer service.pool.release(conn);

    var result = try conn.query(sql);
    defer result.deinit();

    if (result.rowCount() == 0) return error.NoResult;
    const value = result.getValue(0, 0) orelse return error.NoResult;
    if (!std.mem.eql(u8, value, "1")) return error.InvalidProbeResult;

    return true;
}

/// Helper function to extract temp_id from path
fn extractTempIdFromPath(path: []const u8) ![]const u8 {
    var iter = std.mem.tokenizeScalar(u8, path, '/');

    while (iter.next()) |part| {
        if (part.len == 36 and std.mem.indexOf(u8, part, "-") != null) {
            return part;
        }
    }

    return error.TempIdNotFound;
}

/// Parse query parameter from query string
fn parseQueryParam(query: []const u8, param_name: []const u8) ?[]const u8 {
    var iter = std.mem.tokenizeScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq_idx| {
            const key = pair[0..eq_idx];
            const value = pair[eq_idx + 1 ..];
            if (std.mem.eql(u8, key, param_name)) {
                return value;
            }
        }
    }
    return null;
}

/// Parse integer query parameter
fn parseQueryParamInt(query: []const u8, param_name: []const u8) ?u32 {
    const value_str = parseQueryParam(query, param_name) orelse return null;
    return std.fmt.parseInt(u32, value_str, 10) catch null;
}

// Simple HTTP Server
const HttpServer = struct {
    allocator: std.mem.Allocator,
    l2_service: *L2Service,
    port: u16,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, l2_service: *L2Service, io: std.Io, port: u16) HttpServer {
        return .{
            .allocator = allocator,
            .l2_service = l2_service,
            .port = port,
            .io = io,
        };
    }

    pub fn start(self: *HttpServer) !void {
        const address = try net.IpAddress.parse("0.0.0.0", self.port);
        var server = try address.listen(self.io, .{ .reuse_address = true });
        defer server.deinit(self.io);

        log.info("🚀 L2 Service listening on 0.0.0.0:{d}", .{self.port});

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
        const request_data = self.readHttpRequest(connection, &buffer) catch |err| {
            log.err("Read/parse error: {}", .{err});
            switch (err) {
                error.RequestTooLarge => self.sendError(connection, 413, "Request Entity Too Large"),
                error.IncompleteRequest => self.sendError(connection, 400, "Incomplete Request Body"),
                else => self.sendError(connection, 400, "Bad Request"),
            }
            return;
        };

        if (request_data.len == 0) return;

        // Simple HTTP parsing
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
            query = full_path[idx + 1 ..];
        }

        // Extract body
        var body: []const u8 = "";
        if (findHeaderEnd(request_data)) |idx| {
            body = request_data[idx..];
        }

        const response = self.route(method, path, query, body) catch |err| {
            log.err("Handler error: {}", .{err});
            self.sendError(connection, 500, "Internal Server Error");
            return;
        };
        defer self.allocator.free(response.body);

        self.sendResponse(connection, response.status, response.body);
    }

    fn sendResponse(self: *HttpServer, connection: net.Stream, status: u16, body: []const u8) void {
        const reason = statusReason(status);
        const status_line = std.fmt.allocPrint(self.allocator, "HTTP/1.1 {d} {s}\r\n", .{ status, reason }) catch return;
        defer self.allocator.free(status_line);
        const header = "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, OPTIONS\r\nConnection: close\r\nContent-Length: ";

        const len_str = std.fmt.allocPrint(self.allocator, "{d}", .{body.len}) catch return;
        defer self.allocator.free(len_str);

        var write_buf: [4096]u8 = undefined;
        var writer = connection.writer(self.io, &write_buf);

        _ = writer.interface.writeAll(status_line) catch {};
        _ = writer.interface.writeAll(header) catch {};
        _ = writer.interface.writeAll(len_str) catch {};
        _ = writer.interface.writeAll("\r\n\r\n") catch {};
        _ = writer.interface.writeAll(body) catch {};
        _ = writer.interface.flush() catch {};
    }

    fn sendError(self: *HttpServer, connection: net.Stream, status: u16, message: []const u8) void {
        const json = std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\"}}", .{message}) catch return;
        defer self.allocator.free(json);
        self.sendResponse(connection, status, json);
    }

    fn route(self: *HttpServer, method: []const u8, path: []const u8, query: []const u8, body: []const u8) !HttpResponse {
        // OPTIONS (CORS)
        if (std.mem.eql(u8, method, "OPTIONS")) {
            return .{
                .status = 204,
                .body = try self.allocator.dupe(u8, ""),
            };
        }

        // GET /health or /api/l2/health
        if (std.mem.eql(u8, method, "GET") and (std.mem.eql(u8, path, "/health") or std.mem.eql(u8, path, "/api/l2/health"))) {
            return try handleHealthCheck(self.l2_service, self.allocator);
        }

        // POST /api/l2/enhancements
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/l2/enhancements")) {
            return .{
                .status = 200,
                .body = try handleCreateEnhancement(self.l2_service, self.allocator, body),
            };
        }

        // PUT /api/l2/enhancements/{temp_id}/pending
        if (std.mem.eql(u8, method, "PUT") and std.mem.startsWith(u8, path, "/api/l2/enhancements/") and std.mem.endsWith(u8, path, "/pending")) {
            return .{
                .status = 200,
                .body = try handleSetEnhancementPending(self.l2_service, self.allocator, path),
            };
        }

        // PUT /api/l2/enhancements/{temp_id}/confirm
        if (std.mem.eql(u8, method, "PUT") and std.mem.startsWith(u8, path, "/api/l2/enhancements/") and std.mem.endsWith(u8, path, "/confirm")) {
            return .{
                .status = 200,
                .body = try handleConfirmEnhancement(self.l2_service, self.allocator, path, body),
            };
        }

        // GET /api/transactions/enhanced
        if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/api/transactions/enhanced")) {
            return .{
                .status = 200,
                .body = try handleGetEnhancedTransactions(self.l2_service, self.allocator, query),
            };
        }

        // GET /api/l2/search
        if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/api/l2/search")) {
            return .{
                .status = 200,
                .body = try handleSearchEnhancedTransactions(self.l2_service, self.allocator, query),
            };
        }

        // Default: 404
        return .{
            .status = 404,
            .body = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"Not found\"}}", .{}),
        };
    }

    fn readHttpRequest(self: *HttpServer, connection: net.Stream, buffer: []u8) ![]const u8 {
        var used: usize = 0;
        var header_end: ?usize = null;
        var content_length: usize = 0;

        while (used < buffer.len) {
            const msg = try connection.socket.receive(self.io, buffer[used..]);
            if (msg.data.len == 0) break;
            used += msg.data.len;

            const current = buffer[0..used];
            if (header_end == null) {
                header_end = findHeaderEnd(current);
                if (header_end) |h| {
                    content_length = parseContentLength(current[0..h]) orelse 0;
                    if (used >= h + content_length) {
                        return current[0 .. h + content_length];
                    }
                }
            } else if (used >= header_end.? + content_length) {
                return current[0 .. header_end.? + content_length];
            }
        }

        if (used == buffer.len) return error.RequestTooLarge;
        if (header_end) |h| {
            if (used < h + content_length) return error.IncompleteRequest;
            return buffer[0..used];
        }
        return buffer[0..used];
    }
};

const HttpResponse = struct {
    status: u16,
    body: []const u8,
};

fn statusReason(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        503 => "Service Unavailable",
        413 => "Request Entity Too Large",
        500 => "Internal Server Error",
        else => "OK",
    };
}

fn findHeaderEnd(request_data: []const u8) ?usize {
    if (std.mem.indexOf(u8, request_data, "\r\n\r\n")) |idx| {
        return idx + 4;
    }
    if (std.mem.indexOf(u8, request_data, "\n\n")) |idx| {
        return idx + 2;
    }
    return null;
}

fn parseContentLength(headers: []const u8) ?usize {
    var line_iter = std.mem.tokenizeAny(u8, headers, "\r\n");
    while (line_iter.next()) |line| {
        if (line.len == 0) continue;
        if (std.ascii.startsWithIgnoreCase(line, "Content-Length:")) {
            const value = std.mem.trim(u8, line["Content-Length:".len..], " \t");
            return std.fmt.parseInt(usize, value, 10) catch null;
        }
    }
    return null;
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

    // PostgreSQL configuration
    const db_host = util.getEnvVarOwned(arena, "ZEICOIN_DB_HOST") catch try arena.dupe(u8, "localhost");
    const db_port_str = util.getEnvVarOwned(arena, "ZEICOIN_DB_PORT") catch try arena.dupe(u8, "5432");
    const db_port = std.fmt.parseInt(u16, db_port_str, 10) catch 5432;
    const db_name = util.getEnvVarOwned(arena, "ZEICOIN_DB_NAME") catch try arena.dupe(u8, "zeicoin_testnet");
    const db_password = util.getEnvVarOwned(arena, "ZEICOIN_DB_PASSWORD") catch return error.MissingDBPassword;
    const db_user = util.getEnvVarOwned(arena, "ZEICOIN_DB_USER") catch try arena.dupe(u8, "zeicoin");

    const conninfo = try postgres.buildConnString(arena, db_host, db_port, db_name, db_user, db_password);

    const db_pool = try DBPool.init(allocator, conninfo, 5);
    defer db_pool.deinit();

    log.info("✅ Connected to PostgreSQL ({s})", .{db_name});

    // Initialize L2 service
    var service = L2Service.init(allocator, db_pool);

    log.info("✅ L2 Service initialized", .{});

    // Start HTTP server on port 8081
    var server = HttpServer.init(allocator, &service, init.io, 8081);
    try server.start();
}
