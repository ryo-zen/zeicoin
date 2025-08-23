// Display utilities for ZeiCoin CLI
// Formatting, banners, and user interface helpers

const std = @import("std");
const log = std.log.scoped(.cli);

const zeicoin = @import("zeicoin");
const util = zeicoin.util;
const protocol = @import("../client/protocol.zig");

/// Print the ZeiCoin banner
pub fn printZeiBanner() void {
    log.info("", .{});
    log.info("╔══════════════════════════════════════════════════════════════════════╗", .{});
    log.info("║                                                                      ║", .{});
    log.info("║            ███████╗███████╗██╗ ██████╗ ██████╗ ██╗███╗   ██╗         ║", .{});
    log.info("║            ╚══███╔╝██╔════╝██║██╔════╝██╔═══██╗██║████╗  ██║         ║", .{});
    log.info("║              ███╔╝ █████╗  ██║██║     ██║   ██║██║██╔██╗ ██║         ║", .{});
    log.info("║             ███╔╝  ██╔══╝  ██║██║     ██║   ██║██║██║╚██╗██║         ║", .{});
    log.info("║            ███████╗███████╗██║╚██████╗╚██████╔╝██║██║ ╚████║         ║", .{});
    log.info("║            ╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝         ║", .{});
    log.info("║                                                                      ║", .{});
    log.info("║                 🚀 Minimalist Cryptocurrency in Zig 🚀              ║", .{});
    log.info("║                                                                      ║", .{});
    log.info("╚══════════════════════════════════════════════════════════════════════╝", .{});
    log.info("", .{});
}

/// Print help information
pub fn printHelp() void {
    printZeiBanner();
    log.info("WALLET COMMANDS:", .{});
    log.info("  zeicoin wallet create [name]           # Create new HD wallet with mnemonic", .{});
    log.info("  zeicoin wallet list                    # List all wallets", .{});
    log.info("  zeicoin wallet restore <name> <words>  # Restore HD wallet from mnemonic", .{});
    log.info("  zeicoin wallet derive <name> [index]   # Derive new HD wallet address", .{});
    log.info("  zeicoin wallet import <genesis>        # Import genesis account (testnet)", .{});
    log.info("  zeicoin seed <wallet>                  # Display wallet's recovery seed phrase", .{});
    log.info("  zeicoin mnemonic <wallet>              # Display wallet's recovery seed phrase\n", .{});
    log.info("TRANSACTION COMMANDS:", .{});
    log.info("  zeicoin balance [wallet]               # Check wallet balance", .{});
    log.info("  zeicoin send <amount> <recipient>      # Send ZEI to address or wallet", .{});
    log.info("  zeicoin history [wallet]               # Show transaction history\n", .{});
    log.info("NETWORK COMMANDS:", .{});
    log.info("  zeicoin status                         # Show network status", .{});
    log.info("  zeicoin status --watch (-w)            # Monitor mining status with live blockchain animation", .{});
    log.info("  zeicoin sync                           # Trigger manual blockchain sync", .{});
    log.info("  zeicoin block <height>                 # Inspect block at specific height", .{});
    log.info("  zeicoin address [wallet] [--index N]   # Show wallet address at index N\n", .{});
    log.info("EXAMPLES:", .{});
    log.info("  zeicoin wallet create alice            # Create HD wallet named 'alice'", .{});
    log.info("  zeicoin wallet restore myhd word1...   # Restore from 24-word mnemonic", .{});
    log.info("  zeicoin wallet derive myhd             # Get next HD address", .{});
    log.info("  zeicoin balance alice                  # Check alice's balance (pre-funded)", .{});
    log.info("  zeicoin send 50 tzei1qr2q...           # Send 50 ZEI to address", .{});
    log.info("  zeicoin send 50 bob                    # Send 50 ZEI to wallet 'bob'", .{});
    log.info("  zeicoin status                         # Check network status", .{});
    log.info("  zeicoin block 6                        # Inspect block at height 6\n", .{});
    log.info("ENVIRONMENT:", .{});
    log.info("  ZEICOIN_SERVER=ip                      # Set server IP (default: 127.0.0.1)\n", .{});
    log.info("💡 Default wallet is 'default' if no name specified", .{});
}

/// Display balance information with proper formatting
pub fn displayBalance(allocator: std.mem.Allocator, wallet_name: []const u8, balance_info: protocol.BalanceInfo, address: []const u8) !void {
    // Format balances properly for display
    const mature_display = util.formatZEI(allocator, balance_info.mature) catch "? ZEI";
    defer if (!std.mem.eql(u8, mature_display, "? ZEI")) allocator.free(mature_display);

    const immature_display = util.formatZEI(allocator, balance_info.immature) catch "? ZEI";
    defer if (!std.mem.eql(u8, immature_display, "? ZEI")) allocator.free(immature_display);

    const total_display = util.formatZEI(allocator, balance_info.mature + balance_info.immature) catch "? ZEI";
    defer if (!std.mem.eql(u8, total_display, "? ZEI")) allocator.free(total_display);

    log.info("💰 Wallet '{s}' balance:", .{wallet_name});
    log.info("   ✅ Mature (spendable): {s}", .{mature_display});
    if (balance_info.immature > 0) {
        log.info("   ⏳ Immature (not spendable): {s}", .{immature_display});
        log.info("   📊 Total balance: {s}", .{total_display});
    }

    // Show bech32 address (truncated for display)
    if (address.len > 20) {
        log.info("🆔 Address: {s}...{s}", .{ address[0..16], address[address.len - 4 ..] });
    } else {
        log.info("🆔 Address: {s}", .{address});
    }
}

/// Display transaction history with proper formatting
pub fn displayHistory(allocator: std.mem.Allocator, wallet_name: []const u8, address: []const u8, transactions: []protocol.TransactionInfo) !void {
    log.info("📜 Transaction History for '{s}':", .{wallet_name});
    log.info("💼 Address: {s}", .{address});
    log.info("📊 Total transactions: {}\n", .{transactions.len});
    
    if (transactions.len == 0) {
        log.info("💡 No transactions found for this wallet", .{});
        return;
    }
    
    for (transactions, 1..) |tx_info, tx_num| {
        // Format amount for display
        const amount_display = util.formatZEI(allocator, tx_info.amount) catch "? ZEI";
        defer if (!std.mem.eql(u8, amount_display, "? ZEI")) allocator.free(amount_display);
        
        const fee_display = util.formatZEI(allocator, tx_info.fee) catch "? ZEI";
        defer if (!std.mem.eql(u8, fee_display, "? ZEI")) allocator.free(fee_display);
        
        // Format time
        const time_str = util.formatTime(tx_info.timestamp);
        
        // Format counterparty address
        const counterparty_bech32 = tx_info.counterparty.toBech32(allocator, zeicoin.types.CURRENT_NETWORK) catch "invalid";
        defer if (!std.mem.eql(u8, counterparty_bech32, "invalid")) allocator.free(counterparty_bech32);
        
        // Display transaction
        log.info("─────────────────────────────────────────────────────────────", .{});
        log.info("#{} ", .{tx_num});
        
        if (std.mem.eql(u8, tx_info.tx_type, "SENT")) {
            log.info("📤 SENT {s} to {s}", .{amount_display, counterparty_bech32});
        } else if (std.mem.eql(u8, tx_info.tx_type, "RECEIVED")) {
            log.info("📥 RECEIVED {s} from {s}", .{amount_display, counterparty_bech32});
        } else if (std.mem.eql(u8, tx_info.tx_type, "COINBASE")) {
            log.info("⛏️  MINED {s} (coinbase reward)", .{amount_display});
        }
        
        log.info("   🔗 Block: {} | ✅ Confirmations: {}", .{tx_info.height, tx_info.confirmations});
        log.info("   💰 Fee: {s} | ⏰ Time: {s}", .{fee_display, time_str});
        log.info("   🆔 Hash: {}", .{std.fmt.fmtSliceHexLower(&tx_info.hash)});
    }
    
    log.info("─────────────────────────────────────────────────────────────", .{});
}

/// Parse ZEI amount supporting decimals up to 8 places
pub fn parseZeiAmount(amount_str: []const u8) !u64 {
    if (amount_str.len == 0) return error.InvalidAmount;

    // Check for decimal point
    if (std.mem.indexOfScalar(u8, amount_str, '.')) |decimal_pos| {
        // Has decimal point
        const integer_part = amount_str[0..decimal_pos];
        const fractional_part = amount_str[decimal_pos + 1 ..];

        // Check decimal places limit (8 max)
        if (fractional_part.len > 8) return error.InvalidAmount;

        // Parse integer part
        const integer_zei = if (integer_part.len == 0) 0 else std.fmt.parseInt(u64, integer_part, 10) catch return error.InvalidAmount;

        // Parse fractional part and pad to 8 decimal places
        var fractional_str: [8]u8 = "00000000".*;
        if (fractional_part.len > 0) {
            @memcpy(fractional_str[0..fractional_part.len], fractional_part);
        }

        const fractional_units = std.fmt.parseInt(u64, &fractional_str, 10) catch return error.InvalidAmount;

        // Convert to base units
        const integer_units = std.math.mul(u64, integer_zei, zeicoin.types.ZEI_COIN) catch return error.InvalidAmount;
        const total_units = std.math.add(u64, integer_units, fractional_units) catch return error.InvalidAmount;

        return total_units;
    } else {
        // No decimal point - integer ZEI
        const zei_amount = std.fmt.parseInt(u64, amount_str, 10) catch return error.InvalidAmount;
        return std.math.mul(u64, zei_amount, zeicoin.types.ZEI_COIN) catch return error.InvalidAmount;
    }
}