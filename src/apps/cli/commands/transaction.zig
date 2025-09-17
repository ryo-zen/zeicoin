// Transaction commands for ZeiCoin CLI
// Handles balance, send, and history commands

const std = @import("std");
const log = std.log.scoped(.cli);
const print = std.debug.print;

const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const wallet = zeicoin.wallet;
const password_util = zeicoin.password;
const util = zeicoin.util;
const NonceManager = zeicoin.nonce_manager.NonceManager;

const protocol = @import("../client/protocol.zig");
const display = @import("../utils/display.zig");

pub const CLIError = error{
    WalletNotFound,
    NetworkError,
    TransactionFailed,
};

/// Global nonce manager for high-throughput transaction sending
var global_nonce_manager: ?*NonceManager = null;
var nonce_manager_mutex: std.Thread.Mutex = std.Thread.Mutex{};
var global_allocator: ?std.mem.Allocator = null;

/// Transaction sequence counter for timestamp uniqueness
var tx_sequence: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Get unique timestamp for transactions to prevent hash collisions
fn getUniqueTimestamp() u64 {
    // Use millisecond precision for transaction timestamps
    const base_time = @as(u64, @intCast(std.time.milliTimestamp()));

    // Add atomic sequence number to ensure uniqueness even within same millisecond
    const seq = tx_sequence.fetchAdd(1, .monotonic);

    return base_time + seq;
}

/// Get or create the global nonce manager
fn getGlobalNonceManager(allocator: std.mem.Allocator) !*NonceManager {
    nonce_manager_mutex.lock();
    defer nonce_manager_mutex.unlock();
    
    if (global_nonce_manager == null) {
        global_nonce_manager = try allocator.create(NonceManager);
        global_nonce_manager.?.* = NonceManager.init(allocator);
        global_allocator = allocator;
    }
    
    return global_nonce_manager.?;
}

/// Cleanup global nonce manager resources
pub fn cleanupGlobalNonceManager() void {
    nonce_manager_mutex.lock();
    defer nonce_manager_mutex.unlock();
    
    if (global_nonce_manager) |nonce_manager| {
        if (global_allocator) |allocator| {
            nonce_manager.deinit();
            allocator.destroy(nonce_manager);
            global_nonce_manager = null;
            global_allocator = null;
        }
    }
}

/// Callback function for nonce manager to fetch nonce from server
fn fetchNonceFromServer(address: types.Address) !u64 {
    // Use page allocator for internal protocol operations
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    return protocol.getNonce(allocator, address) catch |err| {
        switch (err) {
            protocol.connection.ConnectionError.NetworkError,
            protocol.connection.ConnectionError.ConnectionFailed,
            protocol.connection.ConnectionError.ConnectionTimeout => {
                // Let nonce manager handle the error
                return err;
            },
            else => return err,
        }
    };
}

fn loadHDWalletForOperation(allocator: std.mem.Allocator, wallet_name: []const u8) !*wallet.Wallet {
    // Get wallet path directly without opening database
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    
    // Check wallet directly in filesystem
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);
    
    // Check if wallet file exists
    std.fs.cwd().access(wallet_path, .{}) catch {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        print("💡 Use 'zeicoin wallet create {s}' to create it\n", .{wallet_name});
        return CLIError.WalletNotFound;
    };

    // Create HD wallet
    const zen_wallet = try allocator.create(wallet.Wallet);
    zen_wallet.* = wallet.Wallet.init(allocator);
    errdefer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    // Get password for wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch |err| {
        print("❌ Failed to get password for wallet '{s}': {}\n", .{ wallet_name, err });
        return CLIError.WalletNotFound;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    // Load wallet using a fresh copy of the path
    const wallet_path_for_load = try allocator.dupe(u8, wallet_path);
    defer allocator.free(wallet_path_for_load);
    
    zen_wallet.loadFromFile(wallet_path_for_load, password) catch |err| {
        switch (err) {
            wallet.WalletError.InvalidPassword => {
                print("❌ Failed to load wallet '{s}': Invalid password\n", .{wallet_name});
                print("💡 Please check your password and try again\n", .{});
                return CLIError.WalletNotFound;
            },
            else => {
                print("❌ Failed to load wallet '{s}': {}\n", .{ wallet_name, err });
                return CLIError.WalletNotFound;
            },
        }
    };

    return zen_wallet;
}

/// Handle balance command
pub fn handleBalance(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    // Load HD wallet
    const zen_wallet = loadHDWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            CLIError.WalletNotFound => {
                // Error message already printed in loadHDWalletForOperation
                return CLIError.TransactionFailed;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const address = try zen_wallet.getAddress(0);

    // Get balance from server using protocol helper
    const balance_info = protocol.getBalance(allocator, address) catch |err| {
        switch (err) {
            protocol.connection.ConnectionError.NetworkError,
            protocol.connection.ConnectionError.ConnectionFailed,
            protocol.connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };

    // Format bech32 address for display
    const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        print("❌ Failed to encode address\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);

    // Display balance using display utility
    try display.displayBalance(allocator, wallet_name, balance_info, bech32_addr);
}

/// Handle send command
pub fn handleSend(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 2) {
        print("❌ Usage: zeicoin send <amount> <recipient> [wallet_name]\n", .{});
        print("💡 Recipient can be a bech32 address or wallet name\n", .{});
        print("💡 Example: zeicoin send 10 tzei1qr2qge3sdeq... alice\n", .{});
        print("💡 Example: zeicoin send 10 bob alice\n", .{});
        return CLIError.TransactionFailed;
    }

    const amount_str = args[0];
    const recipient_hex = args[1];
    const wallet_name = if (args.len > 2) args[2] else "default";

    // Parse amount (supports decimals)
    const amount = display.parseZeiAmount(amount_str) catch {
        print("❌ Invalid amount: {s}\n", .{amount_str});
        print("💡 Amount must be a positive number (supports up to 8 decimal places)\n", .{});
        return CLIError.TransactionFailed;
    };

    // Validate amount is not zero or negative
    if (amount == 0) {
        print("❌ Invalid amount: cannot send zero ZEI\n", .{});
        return CLIError.TransactionFailed;
    }

    // Try to parse recipient as bech32 address first, then as wallet name
    const recipient_address = types.Address.fromString(allocator, recipient_hex) catch blk: {
        // Check if this looks like a bech32 address but is invalid
        if (std.mem.startsWith(u8, recipient_hex, "tzei1") or std.mem.startsWith(u8, recipient_hex, "mzei1")) {
            print("❌ Invalid bech32 address: '{s}'\n", .{recipient_hex});
            print("💡 Address format is invalid or has wrong checksum\n", .{});
            return CLIError.TransactionFailed;
        }

        // If not a bech32 format, try to resolve as wallet name
        const recipient_wallet = loadHDWalletForOperation(allocator, recipient_hex) catch {
            print("❌ Invalid recipient: '{s}'\n", .{recipient_hex});
            print("💡 Recipient must be a valid bech32 address or wallet name\n", .{});
            print("💡 Example: zeicoin send 10 tzei1qr2q... alice\n", .{});
            print("💡 Example: zeicoin send 10 bob alice\n", .{});
            return CLIError.TransactionFailed;
        };
        defer {
            recipient_wallet.deinit();
            allocator.destroy(recipient_wallet);
        }

        const addr = recipient_wallet.getAddress(0) catch {
            print("❌ Could not get address from wallet '{s}'\n", .{recipient_hex});
            return;
        };

        print("💡 Resolved wallet '{s}' to address\n", .{recipient_hex});
        break :blk addr;
    };

    // Load sender wallet
    const zen_wallet = loadHDWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            CLIError.WalletNotFound => {
                // Error message already printed
                std.process.exit(1);
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const sender_address = try zen_wallet.getAddress(0);
    const key_pair = try zen_wallet.getKeyPair(0);
    const sender_public_key = key_pair.public_key;

    // Get next nonce using nonce manager with ultra-reliable retry logic
    const nonce_manager = try getGlobalNonceManager(allocator);
    const current_nonce = nonce_manager.getNextNonceWithRetry(sender_address, fetchNonceFromServer, 3) catch |err| {
        switch (err) {
            protocol.connection.ConnectionError.NetworkError,
            protocol.connection.ConnectionError.ConnectionFailed,
            protocol.connection.ConnectionError.ConnectionTimeout => {
                print("❌ Failed to get nonce from server\n", .{});
                return CLIError.NetworkError;
            },
            else => {
                print("❌ Nonce management error: {}\n", .{err});
                return CLIError.NetworkError;
            }
        }
    };

    const current_height = protocol.getHeight(allocator) catch {
        print("❌ Failed to get height from server\n", .{});
        return CLIError.NetworkError;
    };

    // Create transaction with expiry height (24 hours from now)
    const fee = types.ZenFees.STANDARD_FEE;
    const expiry_window = types.TransactionExpiry.getExpiryWindow();
    var transaction = types.Transaction{
        .version = 0, // Version 0 for initial protocol
        .flags = .{}, // Default flags
        .sender = sender_address,
        .sender_public_key = sender_public_key,
        .recipient = recipient_address,
        .amount = amount,
        .fee = fee,
        .nonce = current_nonce,
        .timestamp = @intCast(getUniqueTimestamp()),
        .expiry_height = current_height + expiry_window,
        .signature = std.mem.zeroes(types.Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Sign transaction
    const tx_hash = transaction.hashForSigning();
    transaction.signature = try key_pair.sign(&tx_hash);

    // Send transaction with smart retry on nonce errors
    var retry_count: u32 = 0;
    const max_retries = 2;
    
    while (retry_count <= max_retries) : (retry_count += 1) {
        const send_result = protocol.sendTransaction(allocator, &transaction);
        
        if (send_result) |_| {
            // Transaction succeeded!
            break;
        } else |err| switch (err) {
            protocol.connection.ConnectionError.NetworkError => {
                // Check if this was a nonce error that we can recover from
                // This is a simplification - in reality we'd need to examine the error message
                if (retry_count < max_retries) {
                    print("⚠️  Nonce error detected, attempting emergency recovery...\n", .{});
                    
                    // Use emergency nonce recovery to get a fresh, conservative nonce
                    const recovery_nonce = nonce_manager.emergencyNonceRecovery(sender_address, fetchNonceFromServer) catch {
                        print("❌ Emergency nonce recovery failed\n", .{});
                        return CLIError.NetworkError;
                    };
                    
                    // Update transaction with recovered nonce and new timestamp
                    transaction.nonce = recovery_nonce;
                    transaction.timestamp = @intCast(getUniqueTimestamp());
                    
                    // Re-sign transaction with new data
                    const new_tx_hash = transaction.hashForSigning();
                    transaction.signature = try key_pair.sign(&new_tx_hash);
                    
                    print("🔄 Retrying transaction with recovered nonce {}...\n", .{recovery_nonce});
                    continue; // Retry the transaction
                } else {
                    nonce_manager.markTransactionFailed(sender_address);
                    return CLIError.TransactionFailed;
                }
            },
            else => {
                nonce_manager.markTransactionFailed(sender_address);
                return err;
            },
        }
    }

    // Success message
    const tx_hash_final = transaction.hash();
    print("✅ Transaction sent successfully!\n", .{});
    print("🆔 Transaction hash: {}\n", .{std.fmt.fmtSliceHexLower(&tx_hash_final)});
    
    const amount_display = util.formatZEI(allocator, amount) catch "? ZEI";
    defer if (!std.mem.eql(u8, amount_display, "? ZEI")) allocator.free(amount_display);
    
    print("💰 Sent {s} from '{s}'\n", .{amount_display, wallet_name});
}

/// Handle history command
pub fn handleHistory(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";
    
    // Load HD wallet
    const zen_wallet = loadHDWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            CLIError.WalletNotFound => {
                // Error message already printed in loadHDWalletForOperation
                return CLIError.TransactionFailed;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }
    
    const address = try zen_wallet.getAddress(0);

    // Get transaction history using protocol helper
    const transactions = protocol.getHistory(allocator, address) catch |err| {
        switch (err) {
            protocol.connection.ConnectionError.NetworkError,
            protocol.connection.ConnectionError.ConnectionFailed,
            protocol.connection.ConnectionError.ConnectionTimeout => {
                // Error messages already printed by connection module
                return;
            },
            else => return err,
        }
    };
    defer {
        for (transactions) |tx_info| {
            allocator.free(tx_info.tx_type);
        }
        allocator.free(transactions);
    }

    // Format bech32 address for display
    const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        print("❌ Failed to encode address\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);

    // Display history using display utility
    try display.displayHistory(allocator, wallet_name, bech32_addr, transactions);
}