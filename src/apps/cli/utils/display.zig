// Display utilities for ZeiCoin CLI
// Formatting, banners, and user interface helpers

const std = @import("std");
const log = std.log.scoped(.cli);
const print = std.debug.print;

const zeicoin = @import("zeicoin");
const util = zeicoin.util;
const protocol = @import("../client/protocol.zig");

/// Print the ZeiCoin banner
pub fn printZeiBanner() void {
    print("\n", .{});
    print("╔═════════════════════════════════════════════════════════════════════════╗\n", .{});
    print("║                                                                         ║\n", .{});
    print("║            ███████╗███████╗██╗ ██████╗ ██████╗ ██╗███╗   ██╗            ║\n", .{});
    print("║            ╚══███╔╝██╔════╝██║██╔════╝██╔═══██╗██║████╗  ██║            ║\n", .{});
    print("║              ███╔╝ █████╗  ██║██║     ██║   ██║██║██╔██╗ ██║            ║\n", .{});
    print("║             ███╔╝  ██╔══╝  ██║██║     ██║   ██║██║██║╚██╗██║            ║\n", .{});
    print("║            ███████╗███████╗██║╚██████╗╚██████╔╝██║██║ ╚████║            ║\n", .{});
    print("║            ╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝            ║\n", .{});
    print("║                                                                         ║\n", .{});
    print("║            🚀 A Minimalist Cryptocurrency written in Zig 🚀             ║\n", .{});
    print("║                                                                         ║\n", .{});
    print("╚═════════════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
}

/// Print help information
pub fn printHelp() void {
    printZeiBanner();
    print("WALLET COMMANDS:\n", .{});
    print("  zeicoin wallet create [name]           # Create new HD wallet with mnemonic\n", .{});
    print("  zeicoin wallet list                    # List all wallets\n", .{});
    print("  zeicoin wallet restore <name> <words>  # Restore HD wallet from mnemonic\n", .{});
    print("  zeicoin wallet derive <name> [index]   # Derive new HD wallet address\n", .{});
    print("  zeicoin wallet import <genesis>        # Import genesis account (testnet)\n", .{});
    print("  zeicoin seed <wallet>                  # Display wallet's recovery seed phrase\n", .{});
    print("  zeicoin mnemonic <wallet>              # Display wallet's recovery seed phrase\n\n", .{});
    print("TRANSACTION COMMANDS:\n", .{});
    print("  zeicoin balance [wallet]               # Check wallet balance\n", .{});
    print("  zeicoin send <amount> <recipient>      # Send ZEI to address or wallet\n", .{});
    print("  zeicoin history [wallet]               # Show transaction history\n\n", .{});
    print("NETWORK COMMANDS:\n", .{});
    print("  zeicoin status                         # Show network status\n", .{});
    print("  zeicoin status --watch (-w)            # Monitor mining status with live blockchain animation\n", .{});
    print("  zeicoin sync                           # Trigger manual blockchain sync\n", .{});
    print("  zeicoin block <height>                 # Inspect block at specific height\n", .{});
    print("  zeicoin address [wallet] [--index N]   # Show wallet address at index N\n\n", .{});
    print("EXAMPLES:\n", .{});
    print("  zeicoin wallet create alice            # Create HD wallet named 'alice'\n", .{});
    print("  zeicoin wallet restore myhd word1...   # Restore from 24-word mnemonic\n", .{});
    print("  zeicoin wallet derive myhd             # Get next HD address\n", .{});
    print("  zeicoin balance alice                  # Check alice's balance (pre-funded)\n", .{});
    print("  zeicoin send 50 tzei1qr2q...           # Send 50 ZEI to address\n", .{});
    print("  zeicoin send 50 bob                    # Send 50 ZEI to wallet 'bob'\n", .{});
    print("  zeicoin status                         # Check network status\n", .{});
    print("  zeicoin block 6                        # Inspect block at height 6\n\n", .{});
    print("ENVIRONMENT:\n", .{});
    print("  ZEICOIN_SERVER=ip                      # Set server IP (default: 127.0.0.1)\n\n", .{});
    print("💡 Default wallet is 'default' if no name specified\n", .{});
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

    print("💰 Wallet '{s}' balance:\n", .{wallet_name});
    print("   ✅ Mature (spendable): {s}\n", .{mature_display});
    if (balance_info.immature > 0) {
        print("   ⏳ Immature (not spendable): {s}\n", .{immature_display});
        print("   📊 Total balance: {s}\n", .{total_display});
    }

    // Show bech32 address (truncated for display)
    if (address.len > 20) {
        print("🆔 Address: {s}...{s}\n", .{ address[0..16], address[address.len - 4 ..] });
    } else {
        print("🆔 Address: {s}\n", .{address});
    }
}

/// Display transaction history with proper formatting
pub fn displayHistory(allocator: std.mem.Allocator, wallet_name: []const u8, address: []const u8, transactions: []protocol.TransactionInfo) !void {
    print("📜 Transaction History for '{s}':\n", .{wallet_name});
    print("💼 Address: {s}\n", .{address});
    print("📊 Total transactions: {}\n\n", .{transactions.len});

    if (transactions.len == 0) {
        print("💡 No transactions found for this wallet\n", .{});
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
        print("─────────────────────────────────────────────────────────────\n", .{});
        print("#{} ", .{tx_num});

        if (std.mem.eql(u8, tx_info.tx_type, "SENT")) {
            print("📤 SENT {s} to {s}\n", .{ amount_display, counterparty_bech32 });
        } else if (std.mem.eql(u8, tx_info.tx_type, "RECEIVED")) {
            print("📥 RECEIVED {s} from {s}\n", .{ amount_display, counterparty_bech32 });
        } else if (std.mem.eql(u8, tx_info.tx_type, "COINBASE")) {
            print("⛏️  MINED {s} (coinbase reward)\n", .{amount_display});
        }

        print("   🔗 Block: {} | ✅ Confirmations: {}\n", .{ tx_info.height, tx_info.confirmations });
        print("   💰 Fee: {s} | ⏰ Time: {s}\n", .{ fee_display, time_str });
        print("   🆔 Hash: {}\n", .{std.fmt.fmtSliceHexLower(&tx_info.hash)});
    }

    print("─────────────────────────────────────────────────────────────\n", .{});
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
