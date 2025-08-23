// Client protocol helpers for ZeiCoin CLI
// Common request/response patterns and data structures

const std = @import("std");
const log = std.log.scoped(.cli);

const zeicoin = @import("zeicoin");
const types = zeicoin.types;
pub const connection = @import("connection.zig");

pub const BalanceInfo = struct {
    mature: u64,
    immature: u64,
};

/// Get balance for an address
pub fn getBalance(allocator: std.mem.Allocator, address: types.Address) !BalanceInfo {
    // Send balance request with bech32 address
    const bech32_addr = try address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(bech32_addr);

    const balance_request = try std.fmt.allocPrint(allocator, "CHECK_BALANCE:{s}", .{bech32_addr});
    defer allocator.free(balance_request);

    var buffer: [1024]u8 = undefined;
    const response = try connection.sendRequest(allocator, balance_request, &buffer);

    // Parse BALANCE:mature,immature response
    if (std.mem.startsWith(u8, response, "BALANCE:")) {
        const balance_str = response[8..];

        // Split by comma to get mature and immature
        var parts = std.mem.splitScalar(u8, balance_str, ',');
        const mature_str = std.mem.trim(u8, parts.next() orelse "0", " \n\r\t");
        const immature_str = std.mem.trim(u8, parts.next() orelse "0", " \n\r\t");

        return BalanceInfo{
            .mature = std.fmt.parseInt(u64, mature_str, 10) catch 0,
            .immature = std.fmt.parseInt(u64, immature_str, 10) catch 0,
        };
    }

    return BalanceInfo{ .mature = 0, .immature = 0 };
}

/// Get current nonce for an address
pub fn getNonce(allocator: std.mem.Allocator, address: types.Address) !u64 {
    // Send nonce request with bech32 address
    const bech32_addr = try address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(bech32_addr);

    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{bech32_addr});
    defer allocator.free(nonce_request);

    var buffer: [1024]u8 = undefined;
    const response = try connection.sendRequest(allocator, nonce_request, &buffer);

    // Parse NONCE:value response
    if (std.mem.startsWith(u8, response, "NONCE:")) {
        const nonce_str = std.mem.trim(u8, response[6..], " \n\r\t");
        return std.fmt.parseInt(u64, nonce_str, 10) catch 0;
    }

    return 0;
}

/// Get current blockchain height
pub fn getHeight(allocator: std.mem.Allocator) !u64 {
    var buffer: [1024]u8 = undefined;
    const response = try connection.sendRequest(allocator, "GET_HEIGHT", &buffer);

    // Parse HEIGHT:value response
    if (std.mem.startsWith(u8, response, "HEIGHT:")) {
        const height_str = std.mem.trim(u8, response[7..], " \n\r\t");
        return std.fmt.parseInt(u64, height_str, 10) catch 0;
    }

    return 0;
}

pub const TransactionInfo = struct {
    height: u64,
    hash: [32]u8,
    tx_type: []const u8,
    amount: u64,
    fee: u64,
    timestamp: u64,
    confirmations: u64,
    counterparty: types.Address,
};

/// Get transaction history for an address
pub fn getHistory(allocator: std.mem.Allocator, address: types.Address) ![]TransactionInfo {
    // Send history request with bech32 address
    const bech32_addr = try address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(bech32_addr);

    const history_request = try std.fmt.allocPrint(allocator, "GET_HISTORY:{s}", .{bech32_addr});
    defer allocator.free(history_request);

    var buffer: [65536]u8 = undefined;
    const response = try connection.sendRequest(allocator, history_request, &buffer);

    if (std.mem.startsWith(u8, response, "ERROR:")) {
        log.info("❌ {s}", .{response[7..]});
        return &[_]TransactionInfo{};
    }

    // Parse HISTORY:count\n format
    if (!std.mem.startsWith(u8, response, "HISTORY:")) {
        log.info("❌ Invalid server response", .{});
        return &[_]TransactionInfo{};
    }

    // Find the newline after count
    const first_newline = std.mem.indexOfScalar(u8, response[8..], '\n') orelse {
        log.info("❌ Invalid history response format", .{});
        return &[_]TransactionInfo{};
    };

    const count_str = response[8..8 + first_newline];
    const tx_count = std.fmt.parseInt(usize, count_str, 10) catch {
        log.info("❌ Invalid transaction count", .{});
        return &[_]TransactionInfo{};
    };

    if (tx_count == 0) {
        return &[_]TransactionInfo{};
    }

    // Parse transaction lines
    var transactions = std.ArrayList(TransactionInfo).init(allocator);
    var lines = std.mem.splitScalar(u8, response[8 + first_newline + 1..], '\n');
    
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        
        // Parse: height|hash|type|amount|fee|timestamp|confirmations|counterparty
        var parts = std.mem.splitScalar(u8, line, '|');
        
        const height_str = parts.next() orelse continue;
        const hash_str = parts.next() orelse continue;
        const type_str = parts.next() orelse continue;
        const amount_str = parts.next() orelse continue;
        const fee_str = parts.next() orelse continue;
        const timestamp_str = parts.next() orelse continue;
        const confirmations_str = parts.next() orelse continue;
        const counterparty_str = parts.next() orelse continue;
        
        const height = std.fmt.parseInt(u64, height_str, 10) catch continue;
        const amount = std.fmt.parseInt(u64, amount_str, 10) catch continue;
        const fee = std.fmt.parseInt(u64, fee_str, 10) catch continue;
        const timestamp = std.fmt.parseInt(u64, timestamp_str, 10) catch continue;
        const confirmations = std.fmt.parseInt(u64, confirmations_str, 10) catch continue;
        
        // Parse hash
        var hash: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&hash, hash_str) catch continue;
        
        // Parse counterparty address
        const counterparty = types.Address.fromString(allocator, counterparty_str) catch continue;
        
        try transactions.append(TransactionInfo{
            .height = height,
            .hash = hash,
            .tx_type = try allocator.dupe(u8, type_str),
            .amount = amount,
            .fee = fee,
            .timestamp = timestamp,
            .confirmations = confirmations,
            .counterparty = counterparty,
        });
    }
    
    return transactions.toOwnedSlice();
}

/// Send a transaction to the network
pub fn sendTransaction(allocator: std.mem.Allocator, transaction: *const types.Transaction) !void {
    // Convert addresses to bech32 for sending
    const sender_bech32 = try transaction.sender.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(sender_bech32);

    const recipient_bech32 = try transaction.recipient.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(recipient_bech32);

    // Format transaction message
    const tx_message = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{s}:{s}:{}:{}:{}:{}:{}:{s}:{s}", .{
        sender_bech32,
        recipient_bech32,
        transaction.amount,
        transaction.fee,
        transaction.nonce,
        transaction.timestamp,
        transaction.expiry_height,
        std.fmt.fmtSliceHexLower(&transaction.signature),
        std.fmt.fmtSliceHexLower(&transaction.sender_public_key),
    });
    defer allocator.free(tx_message);

    var buffer: [1024]u8 = undefined;
    const response = try connection.sendRequest(allocator, tx_message, &buffer);

    if (!std.mem.startsWith(u8, response, "OK:")) {
        // Provide helpful error messages based on server response
        if (std.mem.startsWith(u8, response, "ERROR: Insufficient balance")) {
            log.info("❌ Insufficient balance! You don't have enough ZEI for this transaction.", .{});
            log.info("💡 Check your balance with: zeicoin balance", .{});
            log.info("💡 Use genesis accounts (alice, bob, charlie, david, eve) which have pre-funded balances", .{});
        } else if (std.mem.startsWith(u8, response, "ERROR: Invalid nonce")) {
            log.info("❌ Invalid transaction nonce. This usually means another transaction is pending.", .{});
            log.info("💡 Wait a moment and try again after the current transaction is processed.", .{});
        } else if (std.mem.startsWith(u8, response, "ERROR: Sender account not found")) {
            log.info("❌ Wallet account not found on the network.", .{});
            log.info("💡 Use genesis accounts (alice, bob, charlie, david, eve) which have pre-funded balances", .{});
        } else {
            log.info("❌ Transaction failed: {s}", .{response});
        }
        return connection.ConnectionError.NetworkError;
    }
}