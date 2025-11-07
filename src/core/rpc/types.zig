const std = @import("std");

/// JSON-RPC 2.0 error codes
pub const ErrorCode = enum(i32) {
    parse_error = -32700,
    invalid_request = -32600,
    method_not_found = -32601,
    invalid_params = -32602,
    internal_error = -32603,

    // Application-specific errors
    mempool_full = -32001,
    duplicate_transaction = -32002,
    invalid_transaction = -32003,
    insufficient_balance = -32004,

    pub fn message(self: ErrorCode) []const u8 {
        return switch (self) {
            .parse_error => "Parse error",
            .invalid_request => "Invalid request",
            .method_not_found => "Method not found",
            .invalid_params => "Invalid params",
            .internal_error => "Internal error",
            .mempool_full => "Mempool full",
            .duplicate_transaction => "Duplicate transaction",
            .invalid_transaction => "Invalid transaction",
            .insufficient_balance => "Insufficient balance",
        };
    }
};

/// JSON-RPC 2.0 request
pub const Request = struct {
    jsonrpc: []const u8,
    method: []const u8,
    params: std.json.Value,
    id: ?std.json.Value = null, // Optional for notifications
};

/// JSON-RPC 2.0 error object
pub const ErrorObject = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value = null,
};

/// Submit transaction response
pub const SubmitTransactionResponse = struct {
    success: bool,
    tx_hash: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
};

/// Get balance response
pub const GetBalanceResponse = struct {
    balance: u64,
    nonce: u64,
};

/// Get nonce response
pub const GetNonceResponse = struct {
    nonce: u64,
};

/// Get height response
pub const GetHeightResponse = struct {
    height: u32,
};

/// Get mempool size response
pub const GetMempoolSizeResponse = struct {
    size: u32,
};

/// Get info response
pub const GetInfoResponse = struct {
    version: []const u8,
    network: []const u8,
    height: u32,
    mempool_size: u32,
    is_mining: bool,
    peer_count: u32,
};

/// Ping response
pub const PingResponse = struct {
    pong: []const u8,
};

/// Get transaction response
pub const GetTransactionResponse = struct {
    sender: []const u8,
    recipient: []const u8,
    amount: u64,
    fee: u64,
    nonce: u64,
    timestamp: u64,
    expiry_height: u64,
    status: []const u8, // "pending" or "confirmed"
    block_height: ?u32,
};

test "error code messages" {
    const testing = std.testing;
    try testing.expectEqualStrings("Parse error", ErrorCode.parse_error.message());
    try testing.expectEqualStrings("Mempool full", ErrorCode.mempool_full.message());
}
