// l2_service.zig - Consolidated L2 Messaging Service and REST API for ZeiCoin
// Provides transaction enhancements, messaging capabilities, and HTTP API endpoints

const std = @import("std");
const zap = @import("zap");
const pg = @import("pg");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;

const log = std.log.scoped(.l2_service);

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
    pool: *pg.Pool,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, pool: *pg.Pool) Self {
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
        const query =
            \\SELECT create_transaction_enhancement($1, $2, $3, $4, $5, $6, $7)::text
        ;

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        // Convert tags to PostgreSQL array format with proper escaping
        var tags_array = std.ArrayList(u8).init(self.allocator);
        defer tags_array.deinit();

        try tags_array.append('{');
        for (tags, 0..) |tag, i| {
            if (i > 0) try tags_array.append(',');
            try tags_array.append('"');
            // SECURITY: Escape special characters to prevent SQL injection
            for (tag) |c| {
                switch (c) {
                    '"' => try tags_array.appendSlice("\\\""), // Escape double quotes
                    '\\' => try tags_array.appendSlice("\\\\"), // Escape backslashes
                    else => try tags_array.append(c),
                }
            }
            try tags_array.append('"');
        }
        try tags_array.append('}');

        var result = try conn.query(
            query,
            .{
                sender,
                recipient orelse "",
                message orelse "",
                tags_array.items,
                category orelse "",
                reference_id orelse "",
                is_private,
            },
        );
        defer result.deinit();

        if (try result.next()) |row| {
            const temp_id = row.get([]const u8, 0);
            const id_copy = try self.allocator.dupe(u8, temp_id);
            log.info("Created enhancement draft with temp_id: {s}", .{id_copy});
            return id_copy;
        }

        return error.FailedToCreateEnhancement;
    }

    /// Update enhancement status to pending (when transaction submitted)
    pub fn setEnhancementPending(self: *Self, temp_id: []const u8) !void {
        const query = 
            \\SELECT set_enhancement_pending($1::uuid)
        ;

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.query(query, .{temp_id});
        defer result.deinit();
        
        if (try result.next()) |row| {
            const success = row.get(bool, 0);
            if (!success) {
                return error.EnhancementNotFound;
            }
            log.info("Set enhancement {s} to pending", .{temp_id});
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
        const query = 
            \\SELECT confirm_transaction_enhancement($1::uuid, $2, $3)
        ;

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.query(query, .{ temp_id, tx_hash, block_height });
        defer result.deinit();
        
        if (try result.next()) |row| {
            const success = row.get(bool, 0);
            if (!success) {
                log.warn("Enhancement {s} not found or already confirmed", .{temp_id});
                return;
            }
            log.info("Confirmed enhancement {s} with tx_hash {s} at height {}", .{ temp_id, tx_hash, block_height });
        } else {
            return error.FailedToConfirmEnhancement;
        }
    }

    /// Query enhancements by sender and recipient
    pub fn queryEnhancementsBySenderRecipient(
        self: *Self,
        sender: []const u8,
        recipient: []const u8,
        status: EnhancementStatus,
    ) ![]TransactionEnhancement {
        const query =
            \\SELECT 
            \\  e.id, e.tx_hash, e.temp_id::text, e.sender_address, e.recipient_address,
            \\  e.message, e.tags, e.category, e.reference_id,
            \\  e.is_private, e.is_editable, e.status,
            \\  e.confirmation_block_height,
            \\  EXTRACT(EPOCH FROM e.created_at)::bigint,
            \\  EXTRACT(EPOCH FROM e.updated_at)::bigint,
            \\  EXTRACT(EPOCH FROM e.confirmed_at)::bigint
            \\FROM l2_transaction_enhancements e
            \\WHERE e.sender_address = $1 
            \\  AND e.recipient_address = $2
            \\  AND e.status = $3
            \\ORDER BY e.created_at DESC
            \\LIMIT 10
        ;

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.query(query, .{ sender, recipient, status.toString() });
        defer result.deinit();

        var enhancements = std.ArrayList(TransactionEnhancement).init(self.allocator);
        
        while (try result.next()) |row| {
            const enhancement = TransactionEnhancement{
                .id = if (row.get(?i32, 0)) |v| @intCast(v) else null,
                .tx_hash = if (row.get(?[]const u8, 1)) |h| try self.allocator.dupe(u8, h) else null,
                .temp_id = try self.allocator.dupe(u8, row.get([]const u8, 2)),
                .sender_address = try self.allocator.dupe(u8, row.get([]const u8, 3)),
                .recipient_address = if (row.get(?[]const u8, 4)) |r| try self.allocator.dupe(u8, r) else null,
                .message = if (row.get(?[]const u8, 5)) |m| try self.allocator.dupe(u8, m) else null,
                .category = if (row.get(?[]const u8, 7)) |c| try self.allocator.dupe(u8, c) else null,
                .reference_id = if (row.get(?[]const u8, 8)) |r| try self.allocator.dupe(u8, r) else null,
                .is_private = row.get(bool, 9),
                .is_editable = row.get(bool, 10),
                .status = try EnhancementStatus.fromString(row.get([]const u8, 11)),
                .confirmation_block_height = if (row.get(?i64, 12)) |v| @intCast(v) else null,
                .created_at = row.get(?i64, 13),
                .updated_at = row.get(?i64, 14),
                .confirmed_at = row.get(?i64, 15),
            };
            
            try enhancements.append(enhancement);
        }

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
        var query_buf: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&query_buf);
        const writer = stream.writer();
        
        try writer.writeAll(
            \\SELECT 
            \\  e.id, e.tx_hash, e.temp_id::text, e.sender_address, e.recipient_address,
            \\  e.message, e.tags, e.category, e.reference_id,
            \\  e.is_private, e.is_editable, e.status,
            \\  e.confirmation_block_height,
            \\  EXTRACT(EPOCH FROM e.created_at)::bigint,
            \\  EXTRACT(EPOCH FROM e.updated_at)::bigint,
            \\  EXTRACT(EPOCH FROM e.confirmed_at)::bigint
            \\FROM l2_transaction_enhancements e
            \\WHERE e.status = $1
        );
        
        var param_count: u32 = 1;
        
        if (sender) |_| {
            param_count += 1;
            try writer.print(" AND e.sender_address = ${}", .{param_count});
        }
        
        if (recipient) |_| {
            param_count += 1;
            try writer.print(" AND e.recipient_address = ${}", .{param_count});
        }
        
        try writer.print(" ORDER BY e.created_at DESC LIMIT {}", .{limit});
        
        const query = stream.getWritten();
        
        var conn = try self.pool.acquire();
        defer self.pool.release(conn);
        
        // Build parameters array dynamically
        var result = if (sender != null and recipient != null) 
            try conn.query(query, .{ status.toString(), sender.?, recipient.? })
        else if (sender != null)
            try conn.query(query, .{ status.toString(), sender.? })
        else if (recipient != null)
            try conn.query(query, .{ status.toString(), recipient.? })
        else
            try conn.query(query, .{ status.toString() });
            
        defer result.deinit();
        
        var enhancements = std.ArrayList(TransactionEnhancement).init(self.allocator);
        
        while (try result.next()) |row| {
            const enhancement = TransactionEnhancement{
                .id = if (row.get(?i32, 0)) |v| @intCast(v) else null,
                .tx_hash = if (row.get(?[]const u8, 1)) |h| try self.allocator.dupe(u8, h) else null,
                .temp_id = try self.allocator.dupe(u8, row.get([]const u8, 2)),
                .sender_address = try self.allocator.dupe(u8, row.get([]const u8, 3)),
                .recipient_address = if (row.get(?[]const u8, 4)) |r| try self.allocator.dupe(u8, r) else null,
                .message = if (row.get(?[]const u8, 5)) |m| try self.allocator.dupe(u8, m) else null,
                .category = if (row.get(?[]const u8, 7)) |c| try self.allocator.dupe(u8, c) else null,
                .reference_id = if (row.get(?[]const u8, 8)) |r| try self.allocator.dupe(u8, r) else null,
                .is_private = row.get(bool, 9),
                .is_editable = row.get(bool, 10),
                .status = try EnhancementStatus.fromString(row.get([]const u8, 11)),
                .confirmation_block_height = if (row.get(?i64, 12)) |v| @intCast(v) else null,
                .created_at = row.get(?i64, 13),
                .updated_at = row.get(?i64, 14),
                .confirmed_at = row.get(?i64, 15),
            };
            
            try enhancements.append(enhancement);
        }
        
        return enhancements.toOwnedSlice();
    }

    /// Get enhanced transaction by hash
    pub fn getEnhancedTransaction(self: *Self, tx_hash: []const u8) !?TransactionEnhancement {
        const query =
            \\SELECT 
            \\  e.id, e.tx_hash, e.temp_id::text, e.sender_address, e.recipient_address,
            \\  e.message, e.tags, e.category, e.reference_id,
            \\  e.is_private, e.is_editable, e.status,
            \\  e.confirmation_block_height,
            \\  EXTRACT(EPOCH FROM e.created_at)::bigint,
            \\  EXTRACT(EPOCH FROM e.updated_at)::bigint,
            \\  EXTRACT(EPOCH FROM e.confirmed_at)::bigint
            \\FROM l2_transaction_enhancements e
            \\WHERE e.tx_hash = $1
        ;

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.query(query, .{tx_hash});
        defer result.deinit();
        
        if (try result.next()) |row| {
            var tags = std.ArrayList([]const u8).init(self.allocator);
            defer tags.deinit();
            
            return TransactionEnhancement{
                .id = if (row.get(?i32, 0)) |v| @intCast(v) else null,
                .tx_hash = if (row.get(?[]const u8, 1)) |h| try self.allocator.dupe(u8, h) else null,
                .temp_id = try self.allocator.dupe(u8, row.get([]const u8, 2)),
                .sender_address = try self.allocator.dupe(u8, row.get([]const u8, 3)),
                .recipient_address = if (row.get(?[]const u8, 4)) |r| try self.allocator.dupe(u8, r) else null,
                .message = if (row.get(?[]const u8, 5)) |m| try self.allocator.dupe(u8, m) else null,
                .tags = try tags.toOwnedSlice(),
                .category = if (row.get(?[]const u8, 7)) |c| try self.allocator.dupe(u8, c) else null,
                .reference_id = if (row.get(?[]const u8, 8)) |r| try self.allocator.dupe(u8, r) else null,
                .is_private = row.get(bool, 9),
                .is_editable = row.get(bool, 10),
                .status = try EnhancementStatus.fromString(row.get([]const u8, 11)),
                .confirmation_block_height = if (row.get(?i64, 12)) |v| @intCast(v) else null,
                .created_at = row.get(?i64, 13),
                .updated_at = row.get(?i64, 14),
                .confirmed_at = row.get(?i64, 15),
            };
        }
        
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

        var enhancements = std.ArrayList(TransactionEnhancement).init(self.allocator);
        
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

        var results = std.ArrayList(TransactionEnhancement).init(self.allocator);
        
        return results.toOwnedSlice();
    }

    /// Clean up orphaned enhancements (pending for too long)
    pub fn cleanupOrphanedEnhancements(self: *Self) !u32 {
        const query = 
            \\SELECT cleanup_orphaned_enhancements()
        ;

        var conn = try self.pool.acquire();
        defer self.pool.release(conn);

        var result = try conn.query(query, .{});
        defer result.deinit();
        
        if (try result.next()) |row| {
            const count: u32 = @intCast(row.get(i64, 0));
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

/// L2 API context for REST endpoints
pub const L2ApiContext = struct {
    allocator: std.mem.Allocator,
    l2_service: *L2Service,
};

/// Create transaction enhancement endpoint
/// POST /api/l2/enhancements
pub fn createEnhancementHandler(r: zap.Request) void {
    const self = @as(*L2ApiContext, @ptrCast(@alignCast(r.getUserContext())));
    
    r.parsebody() catch |err| {
        log.err("Failed to parse body: {}", .{err});
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid request body" }) catch return;
        return;
    };

    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Missing request body" }) catch return;
        return;
    };

    const parsed = std.json.parseFromSlice(struct {
        sender: []const u8,
        recipient: ?[]const u8 = null,
        message: ?[]const u8 = null,
        tags: [][]const u8 = &.{},
        category: ?[]const u8 = null,
        reference_id: ?[]const u8 = null,
        is_private: bool = false,
    }, self.allocator, body, .{}) catch |err| {
        log.err("Failed to parse JSON: {}", .{err});
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid JSON format" }) catch return;
        return;
    };
    defer parsed.deinit();

    const data = parsed.value;

    const temp_id = self.l2_service.createEnhancement(
        data.sender,
        data.recipient,
        data.message,
        data.tags,
        data.category,
        data.reference_id,
        data.is_private,
    ) catch |err| {
        log.err("Failed to create enhancement: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendJson(.{ .@"error" = "Failed to create enhancement" }) catch return;
        return;
    };
    defer self.allocator.free(temp_id);

    r.setStatus(.ok);
    r.sendJson(.{
        .success = true,
        .temp_id = temp_id,
        .status = "draft",
    }) catch return;
}

/// Update enhancement to pending status
/// PUT /api/l2/enhancements/{temp_id}/pending
pub fn setEnhancementPendingHandler(r: zap.Request) void {
    const self = @as(*L2ApiContext, @ptrCast(@alignCast(r.getUserContext())));
    
    const path = r.path orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid path" }) catch return;
        return;
    };

    const temp_id = extractTempIdFromPath(path) catch {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid temp_id in path" }) catch return;
        return;
    };

    self.l2_service.setEnhancementPending(temp_id) catch |err| {
        log.err("Failed to update enhancement: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendJson(.{ .@"error" = "Failed to update enhancement" }) catch return;
        return;
    };

    r.setStatus(.ok);
    r.sendJson(.{
        .success = true,
        .temp_id = temp_id,
        .status = "pending",
    }) catch return;
}

/// Confirm enhancement with transaction hash
/// PUT /api/l2/enhancements/{temp_id}/confirm
pub fn confirmEnhancementHandler(r: zap.Request) void {
    const self = @as(*L2ApiContext, @ptrCast(@alignCast(r.getUserContext())));
    
    r.parsebody() catch |err| {
        log.err("Failed to parse body: {}", .{err});
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid request body" }) catch return;
        return;
    };

    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Missing request body" }) catch return;
        return;
    };

    const path = r.path orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid path" }) catch return;
        return;
    };

    const temp_id = extractTempIdFromPath(path) catch {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid temp_id in path" }) catch return;
        return;
    };

    const parsed = std.json.parseFromSlice(struct {
        tx_hash: []const u8,
        block_height: u32,
    }, self.allocator, body, .{}) catch |err| {
        log.err("Failed to parse JSON: {}", .{err});
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Invalid JSON format" }) catch return;
        return;
    };
    defer parsed.deinit();

    const data = parsed.value;

    self.l2_service.confirmEnhancement(
        temp_id,
        data.tx_hash,
        data.block_height,
    ) catch |err| {
        log.err("Failed to confirm enhancement: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendJson(.{ .@"error" = "Failed to confirm enhancement" }) catch return;
        return;
    };

    r.setStatus(.ok);
    r.sendJson(.{
        .success = true,
        .temp_id = temp_id,
        .tx_hash = data.tx_hash,
        .status = "confirmed",
    }) catch return;
}

/// Get enhanced transactions for an address
/// GET /api/transactions/enhanced?address={address}&limit={limit}&offset={offset}
pub fn getEnhancedTransactionsHandler(r: zap.Request) void {
    const self = @as(*L2ApiContext, @ptrCast(@alignCast(r.getUserContext())));
    
    const address = r.getParamStr("address") catch {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Missing address parameter" }) catch return;
        return;
    };

    const limit = r.getParamInt("limit") catch 50;
    const offset = r.getParamInt("offset") catch 0;

    const transactions = self.l2_service.getEnhancedTransactionsForAddress(
        address,
        @intCast(limit),
        @intCast(offset),
    ) catch |err| {
        log.err("Failed to get enhanced transactions: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendJson(.{ .@"error" = "Failed to retrieve transactions" }) catch return;
        return;
    };
    defer self.allocator.free(transactions);

    var response = std.ArrayList(std.json.Value).init(self.allocator);
    defer response.deinit();

    for (transactions) |tx| {
        var tx_obj = std.StringHashMap(std.json.Value).init(self.allocator);
        defer tx_obj.deinit();
        
        if (tx.tx_hash) |hash| {
            try tx_obj.put("tx_hash", .{ .string = hash });
        }
        try tx_obj.put("temp_id", .{ .string = tx.temp_id });
        try tx_obj.put("sender", .{ .string = tx.sender_address });
        if (tx.recipient_address) |recipient| {
            try tx_obj.put("recipient", .{ .string = recipient });
        }
        if (tx.message) |msg| {
            try tx_obj.put("message", .{ .string = msg });
        }
        if (tx.category) |cat| {
            try tx_obj.put("category", .{ .string = cat });
        }
        try tx_obj.put("status", .{ .string = tx.status.toString() });
        try tx_obj.put("is_private", .{ .bool = tx.is_private });
        
        try response.append(.{ .object = tx_obj });
    }

    r.setStatus(.ok);
    r.sendJson(.{
        .transactions = response.items,
        .count = transactions.len,
        .offset = offset,
        .limit = limit,
    }) catch return;
}

/// Search enhanced transactions by message content
/// GET /api/l2/search?q={query}&address={address}&limit={limit}
pub fn searchEnhancedTransactionsHandler(r: zap.Request) void {
    const self = @as(*L2ApiContext, @ptrCast(@alignCast(r.getUserContext())));
    
    const query = r.getParamStr("q") catch {
        r.setStatus(.bad_request);
        r.sendJson(.{ .@"error" = "Missing search query" }) catch return;
        return;
    };

    const address = r.getParamStr("address") catch null;
    const limit = r.getParamInt("limit") catch 50;

    const results = self.l2_service.searchEnhancedTransactions(
        query,
        address,
        @intCast(limit),
    ) catch |err| {
        log.err("Failed to search transactions: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendJson(.{ .@"error" = "Search failed" }) catch return;
        return;
    };
    defer self.allocator.free(results);

    r.setStatus(.ok);
    r.sendJson(.{
        .results = results,
        .count = results.len,
        .query = query,
    }) catch return;
}

/// Helper function to extract temp_id from path
fn extractTempIdFromPath(path: []const u8) ![]const u8 {
    const parts = std.mem.tokenize(u8, path, "/");
    var iter = parts;
    
    while (iter.next()) |part| {
        if (part.len == 36 and std.mem.indexOf(u8, part, "-") != null) {
            return part;
        }
    }
    
    return error.TempIdNotFound;
}

/// Register L2 API endpoints
pub fn registerL2Endpoints(app: *zap.Listener, context: *L2ApiContext) !void {
    try app.post("/api/l2/enhancements", createEnhancementHandler);
    try app.put("/api/l2/enhancements/*/pending", setEnhancementPendingHandler);
    try app.put("/api/l2/enhancements/*/confirm", confirmEnhancementHandler);
    
    try app.get("/api/transactions/enhanced", getEnhancedTransactionsHandler);
    try app.get("/api/l2/search", searchEnhancedTransactionsHandler);
    
    app.setUserContext(context);
    
    log.info("L2 API endpoints registered", .{});
}

/// Initialize L2 service with configuration
pub fn initL2Service(allocator: std.mem.Allocator, pool: *pg.Pool) !L2Service {
    log.info("Initializing L2 Messaging Service", .{});
    
    const service = L2Service.init(allocator, pool);
    
    const conn = try pool.acquire();
    defer pool.release(conn);
    
    var result = try conn.query("SELECT 1", .{});
    defer result.deinit();
    if (result) |val| {
        if (val == 1) {
            log.info("L2 Service database connection verified", .{});
        }
    }
    
    return service;
}