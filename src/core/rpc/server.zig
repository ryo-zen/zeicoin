const std = @import("std");
const net = std.net;
const rpc_types = @import("types.zig");
const format = @import("format.zig");
const zen = @import("../node.zig");
const db = @import("../storage/db.zig");

const log = std.log.scoped(.rpc_server);

/// Minimal JSON-RPC 2.0 server for blockchain operations
/// Uses secondary RocksDB instance for concurrent reads during mining
pub const RPCServer = struct {
    allocator: std.mem.Allocator,
    blockchain: *zen.ZeiCoin,
    secondary_db: ?db.Database,
    blockchain_path: []const u8,
    secondary_path: []const u8,
    server: net.Server,
    port: u16,
    running: std.atomic.Value(bool),
    active_connections: std.atomic.Value(u32),

    /// Maximum concurrent connections to prevent DoS
    const MAX_CONNECTIONS: u32 = 100;

    pub fn init(
        allocator: std.mem.Allocator,
        blockchain: *zen.ZeiCoin,
        blockchain_path: []const u8,
        port: u16,
    ) !*RPCServer {
        const self = try allocator.create(RPCServer);
        errdefer allocator.destroy(self);

        // Reuse same secondary path as indexer for efficiency
        const secondary_path = try std.fmt.allocPrint(allocator, "{s}_indexer_secondary", .{blockchain_path});
        errdefer allocator.free(secondary_path);

        const address = try net.Address.parseIp4("0.0.0.0", port);
        const server = try address.listen(.{
            .reuse_address = true,
            .reuse_port = true,
        });

        self.* = RPCServer{
            .allocator = allocator,
            .blockchain = blockchain,
            .secondary_db = null,
            .blockchain_path = blockchain_path,
            .secondary_path = secondary_path,
            .server = server,
            .port = port,
            .running = std.atomic.Value(bool).init(false),
            .active_connections = std.atomic.Value(u32).init(0),
        };

        return self;
    }

    pub fn deinit(self: *RPCServer) void {
        self.stop();
        if (self.secondary_db) |*secondary| {
            secondary.deinit();
        }
        self.allocator.free(self.secondary_path);
        self.server.deinit();
        self.allocator.destroy(self);
    }

    /// Initialize secondary database for concurrent reads
    fn ensureSecondaryDb(self: *RPCServer) !*db.Database {
        if (self.secondary_db != null) {
            // Sync with primary before returning
            try self.secondary_db.?.catchUpWithPrimary();
            return &self.secondary_db.?;
        }

        // Try to initialize secondary instance
        self.secondary_db = db.Database.initSecondary(
            self.allocator,
            self.blockchain_path,
            self.secondary_path,
        ) catch |err| {
            log.warn("Secondary DB failed, falling back to primary: {}", .{err});
            // Fallback to primary if secondary fails (single-node testing)
            return self.blockchain.database;
        };

        log.info("✅ RPC using secondary database: {s}", .{self.secondary_path});
        return &self.secondary_db.?;
    }

    pub fn start(self: *RPCServer) !void {
        self.running.store(true, .release);
        log.info("🔌 RPC Server listening on 0.0.0.0:{d}", .{self.port});

        while (self.running.load(.acquire)) {
            // Accept connection with timeout
            const connection = self.acceptWithTimeout() catch |err| {
                if (err == error.Timeout) continue;
                log.err("Accept error: {}", .{err});
                continue;
            };

            // SECURITY: Check connection limit before spawning thread
            const current = self.active_connections.load(.acquire);
            if (current >= MAX_CONNECTIONS) {
                log.warn("⚠️ RPC connection limit reached ({}/{}), rejecting", .{ current, MAX_CONNECTIONS });
                connection.stream.close();
                continue;
            }

            // Increment active connections
            _ = self.active_connections.fetchAdd(1, .acq_rel);

            // Handle in new thread
            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, connection }) catch |err| {
                log.err("Failed to spawn thread: {}", .{err});
                _ = self.active_connections.fetchSub(1, .acq_rel);
                connection.stream.close();
                continue;
            };
            thread.detach();
        }

        log.info("RPC Server stopped", .{});
    }

    pub fn stop(self: *RPCServer) void {
        self.running.store(false, .release);
    }

    fn acceptWithTimeout(self: *RPCServer) !net.Server.Connection {
        const timeout_ns = 1 * std.time.ns_per_s;
        const start_time = std.time.nanoTimestamp();

        while (true) {
            if (std.time.nanoTimestamp() - start_time > timeout_ns) {
                return error.Timeout;
            }

            const connection = self.server.accept() catch |err| {
                if (err == error.WouldBlock) {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };

            return connection;
        }
    }

    fn handleConnection(self: *RPCServer, connection: net.Server.Connection) void {
        defer {
            connection.stream.close();
            _ = self.active_connections.fetchSub(1, .acq_rel);
        }

        var buffer: [8192]u8 = undefined;
        const bytes_read = connection.stream.read(&buffer) catch |err| {
            log.err("Read error: {}", .{err});
            return;
        };

        if (bytes_read == 0) return;

        // Extract JSON body from HTTP request if present
        const request_data = buffer[0..bytes_read];
        const json_body = self.extractJsonBody(request_data) orelse request_data;

        const response = self.handleRequest(json_body) catch |err| {
            log.err("Request handling error: {}", .{err});
            const error_response = format.formatError(
                self.allocator,
                rpc_types.ErrorCode.internal_error,
                null,
                null,
            ) catch return;
            defer self.allocator.free(error_response);

            // Send HTTP response
            const http_response = self.wrapHttpResponse(error_response) catch return;
            defer self.allocator.free(http_response);
            _ = connection.stream.writeAll(http_response) catch {};
            return;
        };
        defer self.allocator.free(response);

        // Skip response for notifications (empty response)
        if (response.len == 0) return;

        // Wrap response in HTTP
        const http_response = self.wrapHttpResponse(response) catch |err| {
            log.err("HTTP wrap error: {}", .{err});
            return;
        };
        defer self.allocator.free(http_response);

        _ = connection.stream.writeAll(http_response) catch |err| {
            log.err("Write error: {}", .{err});
        };
    }

    fn extractJsonBody(self: *RPCServer, data: []const u8) ?[]const u8 {
        _ = self;

        // Check if this is an HTTP request (starts with POST, GET, etc.)
        if (data.len < 4) return null;

        const is_http = std.mem.startsWith(u8, data, "POST") or
                       std.mem.startsWith(u8, data, "GET") or
                       std.mem.startsWith(u8, data, "PUT");

        if (!is_http) return null;

        // Find double CRLF that separates headers from body
        if (std.mem.indexOf(u8, data, "\r\n\r\n")) |idx| {
            const body = data[idx + 4 ..];
            return if (body.len > 0) body else null;
        }

        // Try single LF (some clients use \n\n)
        if (std.mem.indexOf(u8, data, "\n\n")) |idx| {
            const body = data[idx + 2 ..];
            return if (body.len > 0) body else null;
        }

        return null;
    }

    fn wrapHttpResponse(self: *RPCServer, json_body: []const u8) ![]const u8 {
        const header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ";

        // Calculate response size
        const content_len_str = try std.fmt.allocPrint(self.allocator, "{d}", .{json_body.len});
        defer self.allocator.free(content_len_str);

        const total_size = header.len + content_len_str.len + 4 + json_body.len; // 4 for \r\n\r\n

        var response = try self.allocator.alloc(u8, total_size);
        var pos: usize = 0;

        @memcpy(response[pos .. pos + header.len], header);
        pos += header.len;

        @memcpy(response[pos .. pos + content_len_str.len], content_len_str);
        pos += content_len_str.len;

        @memcpy(response[pos .. pos + 4], "\r\n\r\n");
        pos += 4;

        @memcpy(response[pos .. pos + json_body.len], json_body);

        return response;
    }

    fn handleRequest(self: *RPCServer, request: []const u8) ![]const u8 {
        // Trim whitespace
        const trimmed = std.mem.trim(u8, request, &std.ascii.whitespace);

        // Check if this is a batch request (starts with '[')
        if (trimmed.len > 0 and trimmed[0] == '[') {
            return try self.handleBatchRequest(trimmed);
        }

        // Handle single request
        return try self.handleSingleRequest(trimmed);
    }

    fn handleBatchRequest(self: *RPCServer, request: []const u8) ![]const u8 {
        // Parse batch request
        const parsed = std.json.parseFromSlice(
            []rpc_types.Request,
            self.allocator,
            request,
            .{},
        ) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.parse_error,
                null,
                null,
            );
        };
        defer parsed.deinit();

        const requests = parsed.value;

        // Empty batch is invalid
        if (requests.len == 0) {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_request,
                null,
                null,
            );
        }

        // Process each request
        var responses = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (responses.items) |resp| {
                self.allocator.free(resp);
            }
            responses.deinit();
        }

        for (requests) |req| {
            // Process request and collect response (skip notifications)
            const response = self.processSingleRequest(req) catch |err| blk: {
                log.err("Batch request processing error: {}", .{err});
                break :blk try format.formatError(
                    self.allocator,
                    rpc_types.ErrorCode.internal_error,
                    null,
                    req.id,
                );
            };

            // Only include response if not a notification
            if (req.id != null) {
                try responses.append(response);
            } else {
                self.allocator.free(response);
            }
        }

        // Build batch response
        // Per JSON-RPC 2.0 spec: If batch contains only notifications, return nothing
        if (responses.items.len == 0) {
            return try self.allocator.alloc(u8, 0);
        }

        var buf = std.ArrayList(u8).init(self.allocator);
        defer buf.deinit();

        try buf.append('[');
        for (responses.items, 0..) |resp, i| {
            if (i > 0) try buf.append(',');
            try buf.appendSlice(resp);
        }
        try buf.append(']');

        return buf.toOwnedSlice();
    }

    fn handleSingleRequest(self: *RPCServer, request: []const u8) ![]const u8 {
        // Parse JSON-RPC request
        const parsed = std.json.parseFromSlice(
            rpc_types.Request,
            self.allocator,
            request,
            .{},
        ) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.parse_error,
                null,
                null,
            );
        };
        defer parsed.deinit();

        const req = parsed.value;

        // Check if this is a notification (no id)
        if (req.id == null) {
            // Process the request but don't send response
            _ = self.processSingleRequest(req) catch |err| {
                log.err("Notification processing error: {}", .{err});
            };
            // Return empty string to signal no response should be sent
            return try self.allocator.alloc(u8, 0);
        }

        return try self.processSingleRequest(req);
    }

    fn processSingleRequest(self: *RPCServer, req: rpc_types.Request) ![]const u8 {
        // Validate JSON-RPC version
        if (!std.mem.eql(u8, req.jsonrpc, "2.0")) {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_request,
                null,
                req.id,
            );
        }

        // Route to method handler
        const result = if (std.mem.eql(u8, req.method, "ping"))
            try self.handlePing()
        else if (std.mem.eql(u8, req.method, "getHeight"))
            try self.handleGetHeight()
        else if (std.mem.eql(u8, req.method, "getMempoolSize"))
            try self.handleGetMempoolSize()
        else if (std.mem.eql(u8, req.method, "getInfo"))
            try self.handleGetInfo()
        else if (std.mem.eql(u8, req.method, "getNonce"))
            try self.handleGetNonce(req.params)
        else if (std.mem.eql(u8, req.method, "getBalance"))
            try self.handleGetBalance(req.params)
        else if (std.mem.eql(u8, req.method, "getTransaction"))
            try self.handleGetTransaction(req.params)
        else if (std.mem.eql(u8, req.method, "submitTransaction"))
            try self.handleSubmitTransaction(req.params)
        else
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.method_not_found,
                null,
                req.id,
            );

        defer self.allocator.free(result);

        // Format success response
        return try format.formatSuccess(self.allocator, result, req.id);
    }

    // ========== Method Handlers ==========

    fn handlePing(self: *RPCServer) ![]const u8 {
        const response = rpc_types.PingResponse{ .pong = "pong" };
        return try format.formatResult(self.allocator, rpc_types.PingResponse, response);
    }

    fn handleGetHeight(self: *RPCServer) ![]const u8 {
        const database = try self.ensureSecondaryDb();
        const height = try database.getHeight();
        const response = rpc_types.GetHeightResponse{ .height = height };
        return try format.formatResult(self.allocator, rpc_types.GetHeightResponse, response);
    }

    fn handleGetMempoolSize(self: *RPCServer) ![]const u8 {
        const size = self.blockchain.mempool_manager.getTransactionCount();
        const response = rpc_types.GetMempoolSizeResponse{ .size = @intCast(size) };
        return try format.formatResult(self.allocator, rpc_types.GetMempoolSizeResponse, response);
    }

    fn handleGetInfo(self: *RPCServer) ![]const u8 {
        const types = @import("../types/types.zig");
        const database = try self.ensureSecondaryDb();
        const height = try database.getHeight();
        const mempool_size = self.blockchain.mempool_manager.getTransactionCount();
        const is_mining = self.blockchain.mining_manager != null;
        const peer_count: u32 = 0; // TODO: Get from network manager

        const network_str = if (types.CURRENT_NETWORK == .testnet) "testnet" else "mainnet";

        const response = rpc_types.GetInfoResponse{
            .version = "0.1.0",
            .network = network_str,
            .height = height,
            .mempool_size = @intCast(mempool_size),
            .is_mining = is_mining,
            .peer_count = peer_count,
        };
        return try format.formatResult(self.allocator, rpc_types.GetInfoResponse, response);
    }

    fn handleGetNonce(self: *RPCServer, params: std.json.Value) ![]const u8 {
        const bech32 = @import("../crypto/bech32.zig");

        // Extract address from params
        const params_obj = params.object;
        const address_str = params_obj.get("address") orelse {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                null,
                null,
            );
        };

        // Parse bech32 address
        const addr = bech32.decodeAddress(self.allocator, address_str.string) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                null,
                null,
            );
        };

        const database = try self.ensureSecondaryDb();
        const account = try database.getAccount(addr);
        const response = rpc_types.GetNonceResponse{ .nonce = account.nonce };
        return try format.formatResult(self.allocator, rpc_types.GetNonceResponse, response);
    }

    fn handleGetBalance(self: *RPCServer, params: std.json.Value) ![]const u8 {
        const bech32 = @import("../crypto/bech32.zig");

        // Extract address from params
        const params_obj = params.object;
        const address_str = params_obj.get("address") orelse {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                null,
                null,
            );
        };

        // Parse bech32 address
        const addr = bech32.decodeAddress(self.allocator, address_str.string) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                null,
                null,
            );
        };

        const database = try self.ensureSecondaryDb();
        const account = try database.getAccount(addr);

        const response = rpc_types.GetBalanceResponse{
            .balance = account.balance,
            .nonce = account.nonce,
        };
        return try format.formatResult(self.allocator, rpc_types.GetBalanceResponse, response);
    }

    fn handleGetTransaction(self: *RPCServer, params: std.json.Value) ![]const u8 {
        // Extract tx_hash from params
        const params_obj = params.object;
        const hash_str = params_obj.get("hash") orelse {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Missing transaction hash",
                null,
            );
        };

        // Parse hex hash
        var tx_hash: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&tx_hash, hash_str.string) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Invalid transaction hash format",
                null,
            );
        };

        // Get transaction from secondary database
        const database = try self.ensureSecondaryDb();
        const tx = database.getTransactionByHash(tx_hash) catch {
            // Check mempool if not found in database
            const mempool_tx = self.blockchain.mempool_manager.getTransaction(tx_hash) orelse {
                return try format.formatError(
                    self.allocator,
                    rpc_types.ErrorCode.invalid_params,
                    "Transaction not found",
                    null,
                );
            };

            const types = @import("../types/types.zig");
            const sender_bech32 = try mempool_tx.sender.toBech32(self.allocator, types.CURRENT_NETWORK);
            defer self.allocator.free(sender_bech32);
            const recipient_bech32 = try mempool_tx.recipient.toBech32(self.allocator, types.CURRENT_NETWORK);
            defer self.allocator.free(recipient_bech32);

            const response = rpc_types.GetTransactionResponse{
                .sender = sender_bech32,
                .recipient = recipient_bech32,
                .amount = mempool_tx.amount,
                .fee = mempool_tx.fee,
                .nonce = mempool_tx.nonce,
                .timestamp = mempool_tx.timestamp,
                .expiry_height = mempool_tx.expiry_height,
                .status = "pending",
                .block_height = null,
            };
            return try format.formatResult(self.allocator, rpc_types.GetTransactionResponse, response);
        };

        const types = @import("../types/types.zig");

        // Convert addresses to bech32 (confirmed transaction from database)
        const sender_bech32 = try tx.sender.toBech32(self.allocator, types.CURRENT_NETWORK);
        defer self.allocator.free(sender_bech32);

        const recipient_bech32 = try tx.recipient.toBech32(self.allocator, types.CURRENT_NETWORK);
        defer self.allocator.free(recipient_bech32);

        const response = rpc_types.GetTransactionResponse{
            .sender = sender_bech32,
            .recipient = recipient_bech32,
            .amount = tx.amount,
            .fee = tx.fee,
            .nonce = tx.nonce,
            .timestamp = tx.timestamp,
            .expiry_height = tx.expiry_height,
            .status = "confirmed",
            .block_height = null, // TODO: Get block height from transaction metadata
        };
        return try format.formatResult(self.allocator, rpc_types.GetTransactionResponse, response);
    }

    fn handleSubmitTransaction(self: *RPCServer, params: std.json.Value) ![]const u8 {
        const types = @import("../types/types.zig");
        const bech32 = @import("../crypto/bech32.zig");

        // Extract transaction data from params
        const params_obj = params.object;

        // Parse sender and recipient addresses
        const sender_str = params_obj.get("sender") orelse {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Missing sender address",
                null,
            );
        };
        const recipient_str = params_obj.get("recipient") orelse {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Missing recipient address",
                null,
            );
        };

        const sender = bech32.decodeAddress(self.allocator, sender_str.string) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Invalid sender address",
                null,
            );
        };

        const recipient = bech32.decodeAddress(self.allocator, recipient_str.string) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Invalid recipient address",
                null,
            );
        };

        // Extract numeric fields
        const amount = @as(u64, @intCast(params_obj.get("amount").?.integer));
        const fee = @as(u64, @intCast(params_obj.get("fee").?.integer));
        const nonce = @as(u64, @intCast(params_obj.get("nonce").?.integer));
        const timestamp = @as(u64, @intCast(params_obj.get("timestamp").?.integer));
        const expiry_height = @as(u64, @intCast(params_obj.get("expiry_height").?.integer));

        // Parse signature (hex string to bytes)
        const signature_hex = params_obj.get("signature").?.string;
        var signature: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(&signature, signature_hex) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Invalid signature format",
                null,
            );
        };

        // Parse public key (hex string to bytes)
        const pubkey_hex = params_obj.get("sender_public_key").?.string;
        var sender_public_key: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&sender_public_key, pubkey_hex) catch {
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_params,
                "Invalid public key format",
                null,
            );
        };

        // Create transaction
        const transaction = types.Transaction{
            .version = 0,
            .flags = .{},
            .sender = sender,
            .recipient = recipient,
            .amount = amount,
            .fee = fee,
            .nonce = nonce,
            .timestamp = timestamp,
            .expiry_height = expiry_height,
            .sender_public_key = sender_public_key,
            .signature = signature,
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };

        // Submit to mempool
        self.blockchain.mempool_manager.addTransaction(transaction) catch |err| {
            const error_msg = @errorName(err);
            return try format.formatError(
                self.allocator,
                rpc_types.ErrorCode.invalid_transaction,
                error_msg,
                null,
            );
        };

        // Get transaction hash
        const tx_hash = transaction.hash();
        const tx_hash_hex = try std.fmt.allocPrint(
            self.allocator,
            "{s}",
            .{std.fmt.fmtSliceHexLower(&tx_hash)},
        );
        defer self.allocator.free(tx_hash_hex);

        const response = rpc_types.SubmitTransactionResponse{
            .success = true,
            .tx_hash = tx_hash_hex,
        };
        return try format.formatResult(self.allocator, rpc_types.SubmitTransactionResponse, response);
    }
};

// ========== Tests ==========
// Integration tests in build.zig
