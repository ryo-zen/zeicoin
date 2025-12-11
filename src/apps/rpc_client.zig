const std = @import("std");
const net = std.net;

/// Minimal JSON-RPC 2.0 client for blockchain queries
pub const RPCClient = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    request_id: u64,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) RPCClient {
        return RPCClient{
            .allocator = allocator,
            .host = host,
            .port = port,
            .request_id = 0,
        };
    }

    /// Ping the RPC server
    pub fn ping(self: *RPCClient) !void {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"params\":{{}},\"id\":{d}}}",
            .{self.request_id},
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        // Check for "pong" in response
        if (std.mem.indexOf(u8, response, "pong") == null) {
            return error.InvalidPong;
        }
    }

    /// Get blockchain height
    pub fn getHeight(self: *RPCClient) !u32 {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"getHeight\",\"params\":{{}},\"id\":{d}}}",
            .{self.request_id},
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        // Parse response
        const parsed = try std.json.parseFromSlice(
            struct {
                result: struct {
                    height: u32,
                },
            },
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        return parsed.value.result.height;
    }

    /// Get mempool size
    pub fn getMempoolSize(self: *RPCClient) !u32 {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"getMempoolSize\",\"params\":{{}},\"id\":{d}}}",
            .{self.request_id},
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        const parsed = try std.json.parseFromSlice(
            struct {
                result: struct {
                    size: u32,
                },
            },
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        return parsed.value.result.size;
    }

    /// Get account nonce
    pub fn getNonce(self: *RPCClient, address: []const u8) !u64 {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"getNonce\",\"params\":{{\"address\":\"{s}\"}},\"id\":{d}}}",
            .{ address, self.request_id },
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        const parsed = try std.json.parseFromSlice(
            struct {
                result: struct {
                    nonce: u64,
                },
            },
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        return parsed.value.result.nonce;
    }

    /// Get account balance and nonce
    pub fn getBalance(self: *RPCClient, address: []const u8) !struct { balance: u64, nonce: u64 } {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"getBalance\",\"params\":{{\"address\":\"{s}\"}},\"id\":{d}}}",
            .{ address, self.request_id },
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        const parsed = try std.json.parseFromSlice(
            struct {
                result: struct {
                    balance: u64,
                    nonce: u64,
                },
            },
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        return .{
            .balance = parsed.value.result.balance,
            .nonce = parsed.value.result.nonce,
        };
    }

    /// Get transaction by hash
    pub fn getTransaction(self: *RPCClient, tx_hash: []const u8) !struct {
        sender: []const u8,
        recipient: []const u8,
        amount: u64,
        fee: u64,
        nonce: u64,
        timestamp: u64,
        expiry_height: u64,
        status: []const u8,
        block_height: ?u32,
    } {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            "{{\"jsonrpc\":\"2.0\",\"method\":\"getTransaction\",\"params\":{{\"hash\":\"{s}\"}},\"id\":{d}}}",
            .{ tx_hash, self.request_id },
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        const parsed = try std.json.parseFromSlice(
            struct {
                result: struct {
                    sender: []const u8,
                    recipient: []const u8,
                    amount: u64,
                    fee: u64,
                    nonce: u64,
                    timestamp: u64,
                    expiry_height: u64,
                    status: []const u8,
                    block_height: ?u32,
                },
            },
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        return .{
            .sender = try self.allocator.dupe(u8, parsed.value.result.sender),
            .recipient = try self.allocator.dupe(u8, parsed.value.result.recipient),
            .amount = parsed.value.result.amount,
            .fee = parsed.value.result.fee,
            .nonce = parsed.value.result.nonce,
            .timestamp = parsed.value.result.timestamp,
            .expiry_height = parsed.value.result.expiry_height,
            .status = try self.allocator.dupe(u8, parsed.value.result.status),
            .block_height = parsed.value.result.block_height,
        };
    }

    /// Broadcast a signed transaction
    pub fn broadcastTransaction(
        self: *RPCClient,
        sender: []const u8,
        recipient: []const u8,
        amount: u64,
        fee: u64,
        nonce: u64,
        timestamp: u64,
        expiry_height: u64,
        signature: []const u8,
        sender_public_key: []const u8,
    ) ![]const u8 {
        self.request_id += 1;

        const request = try std.fmt.allocPrint(
            self.allocator,
            \\{{"jsonrpc":"2.0","method":"submitTransaction","params":{{"sender":"{s}","recipient":"{s}","amount":{d},"fee":{d},"nonce":{d},"timestamp":{d},"expiry_height":{d},"signature":"{s}","sender_public_key":"{s}"}},"id":{d}}}
        ,
            .{ sender, recipient, amount, fee, nonce, timestamp, expiry_height, signature, sender_public_key, self.request_id },
        );
        defer self.allocator.free(request);

        const response = try self.call(request);
        defer self.allocator.free(response);

        const parsed = try std.json.parseFromSlice(
            struct {
                result: struct {
                    success: bool,
                    tx_hash: ?[]const u8,
                },
            },
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true },
        );
        defer parsed.deinit();

        if (!parsed.value.result.success) {
            return error.TransactionFailed;
        }

        return try self.allocator.dupe(u8, parsed.value.result.tx_hash orelse "");
    }

    /// Low-level RPC call
    fn call(self: *RPCClient, request: []const u8) ![]const u8 {
        // Connect to RPC server
        const address = try net.Address.parseIp4(self.host, self.port);
        var stream = try net.tcpConnectToAddress(address);
        defer stream.close();

        // Send request
        try stream.writeAll(request);

        // Read response
        var buffer: [16384]u8 = undefined;
        const bytes_read = try stream.read(&buffer);

        if (bytes_read == 0) {
            return error.EmptyResponse;
        }

        // Strip HTTP headers if present (server returns HTTP/1.1 200 OK...)
        const response = buffer[0..bytes_read];

        // Look for HTTP header separator "\r\n\r\n"
        if (std.mem.indexOf(u8, response, "\r\n\r\n")) |header_end| {
            // JSON body starts after the headers
            const json_body = response[header_end + 4..];
            return try self.allocator.dupe(u8, json_body);
        }

        // No HTTP headers, return as-is
        return try self.allocator.dupe(u8, response);
    }
};

// ========== Tests ==========

test "RPC client creation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const client = RPCClient.init(allocator, "127.0.0.1", 10803);
    try testing.expect(client.port == 10803);
    try testing.expect(client.request_id == 0);
    try testing.expectEqualStrings("127.0.0.1", client.host);
}

test "request ID increments" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var client = RPCClient.init(allocator, "127.0.0.1", 10803);
    try testing.expect(client.request_id == 0);

    // Simulate ID increment
    client.request_id += 1;
    try testing.expect(client.request_id == 1);
}
