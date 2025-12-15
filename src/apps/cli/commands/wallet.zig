// Wallet commands for ZeiCoin CLI
// Handles wallet creation, restoration, listing, and address management

const std = @import("std");
const log = std.log.scoped(.cli);
const print = std.debug.print;

const zeicoin = @import("zeicoin");
const types = zeicoin.types;
const wallet = zeicoin.wallet;
const bip39 = zeicoin.bip39;
const password_util = zeicoin.password;
const db = zeicoin.db;

const WalletSubcommand = enum {
    create,
    list,
    restore,
    derive,
    import, // For genesis accounts
};

// Note: We avoid returning errors to prevent stack traces
// All error handling is done via print statements and early returns

/// Validate wallet name according to rules:
/// - Must be 1-64 characters long
/// - Must start with a letter (a-z, A-Z)
/// - Can contain letters, numbers, and underscores only
/// - No spaces, special characters, or unicode
fn validateWalletName(name: []const u8) bool {
    // Check empty name
    if (name.len == 0) {
        print("❌ Wallet name cannot be empty\n", .{});
        return false;
    }
    
    // Check length (max 64 chars for filesystem compatibility)
    if (name.len > 64) {
        print("❌ Wallet name too long (max 64 characters)\n", .{});
        return false;
    }
    
    // Check first character (must be a letter)
    if (!std.ascii.isAlphabetic(name[0])) {
        print("❌ Wallet name must start with a letter\n", .{});
        return false;
    }
    
    // Check all characters (letters, numbers, underscores only)
    for (name) |char| {
        if (!std.ascii.isAlphanumeric(char) and char != '_') {
            print("❌ Wallet name can only contain letters, numbers, and underscores\n", .{});
            print("💡 Invalid character found: '{c}'\n", .{char});
            return false;
        }
    }
    
    return true;
}

/// Handle wallet command with subcommands
pub fn handleWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Wallet subcommand required\n", .{});
        print("Usage: zeicoin wallet <create|list|restore|derive|import> [name]\n", .{});
        return;
    }
    
    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(WalletSubcommand, subcommand_str) orelse {
        print("❌ Unknown wallet subcommand: {s}\n", .{subcommand_str});
        print("💡 Available subcommands: create, list, restore, derive, import\n", .{});
        return;
    };

    switch (subcommand) {
        .create => try createWallet(allocator, args[1..]),
        .list => try listWallets(allocator, args[1..]),
        .restore => try restoreWallet(allocator, args[1..]),
        .derive => try deriveAddress(allocator, args[1..]),
        .import => try importGenesisWallet(allocator, args[1..]),
    }
}

/// Create a new HD wallet
fn createWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";
    
    // Validate wallet name
    if (!validateWalletName(wallet_name)) {
        return; // Error already printed by validateWalletName
    }

    // Get data directory path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };

    // Create data directory if it doesn't exist
    std.fs.cwd().makePath(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // This is fine
        else => {
            print("❌ Failed to create data directory: {}\n", .{err});
            return;
        },
    };

    // Create wallets subdirectory
    const wallets_dir = try std.fmt.allocPrint(allocator, "{s}/wallets", .{data_dir});
    defer allocator.free(wallets_dir);
    
    std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // This is fine
        else => {
            print("❌ Failed to create wallets directory: {}\n", .{err});
            return;
        },
    };

    // Check if wallet already exists
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);

    if (std.fs.cwd().access(wallet_path, .{})) {
        print("❌ Wallet '{s}' already exists at: {s}\n", .{wallet_name, wallet_path});
        print("💡 Use a different name or remove the existing wallet first\n", .{});
        print("💡 List existing wallets with: zeicoin wallet list\n", .{});
        return;
    } else |err| switch (err) {
        error.FileNotFound => {}, // This is what we want - wallet doesn't exist
        else => {
            print("❌ Error checking wallet file: {}\n", .{err});
            return;
        },
    }

    // Create new HD wallet
    var new_wallet = wallet.Wallet.init(allocator);
    defer new_wallet.deinit();

    // Generate new HD wallet with 12-word mnemonic
    const mnemonic = try new_wallet.createNew(bip39.WordCount.twelve);
    defer allocator.free(mnemonic);
    defer std.crypto.utils.secureZero(u8, @constCast(mnemonic));

    // Get password for wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, true) catch {
        print("❌ Password setup failed\n", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);

    // Save wallet to file
    new_wallet.saveToFile(wallet_path, password) catch |err| {
        print("❌ Failed to save wallet: {}\n", .{err});
        return;
    };

    // Success message
    print("✅ HD wallet '{s}' created successfully!\n", .{wallet_name});
    print("🔑 Mnemonic (12 words):\n", .{});
    print("{s}\n", .{mnemonic});
    print("\n⚠️  IMPORTANT: Save these 12 words in a secure place!\n", .{});
    print("💡 These words can restore your wallet if lost.\n", .{});
    
    // Show first address
    const first_address = new_wallet.getAddress(0) catch {
        print("❌ Failed to get address\n", .{});
        return;
    };
    const bech32_addr = first_address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        print("❌ Failed to encode address\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    print("🆔 First address: {s}\n", .{bech32_addr});
}


/// List all wallets in the data directory
fn listWallets(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    _ = args; // Unused parameter
    
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    
    const wallets_dir = try std.fmt.allocPrint(allocator, "{s}/wallets", .{data_dir});
    defer allocator.free(wallets_dir);
    
    var dir = std.fs.cwd().openDir(wallets_dir, .{ .iterate = true }) catch |err| {
        switch (err) {
            error.FileNotFound => {
                print("📁 No wallets directory found.\n", .{});
                print("💡 Create a wallet with: zeicoin wallet create\n", .{});
                return;
            },
            else => return err,
        }
    };
    defer dir.close();
    
    print("📁 Wallets in {s}:\n", .{wallets_dir});
    
    var iterator = dir.iterate();
    var wallet_count: usize = 0;
    
    while (try iterator.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".wallet")) {
            // Extract wallet name (remove .wallet extension)
            const wallet_name = entry.name[0..entry.name.len - 7];
            print("  💼 {s}\n", .{wallet_name});
            wallet_count += 1;
        }
    }
    
    if (wallet_count == 0) {
        print("  (No wallets found)\n", .{});
        print("💡 Create a wallet with: zeicoin wallet create\n", .{});
    } else {
        print("\n💡 Use 'zeicoin balance <name>' to check wallet balance\n", .{});
    }
}

/// Restore HD wallet from mnemonic
fn restoreWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 2) { // name + at least one word
        print("❌ Invalid usage: missing wallet name and mnemonic\n", .{});
        print("💡 Usage: zeicoin wallet restore <name> <12-or-24-word-mnemonic>\n", .{});
        print("💡 Example: zeicoin wallet restore mywallet word1 word2 ... word12\n", .{});
        return;
    }
    
    const wallet_name = args[0];
    
    // Validate wallet name
    if (!validateWalletName(wallet_name)) {
        return; // Error already printed by validateWalletName
    }
    
    // Check if we have any mnemonic words
    if (args.len < 2) {
        print("❌ Invalid mnemonic: no words provided\n", .{});
        print("💡 Provide 12 or 24 words for wallet restoration\n", .{});
        return;
    }
    
    // Validate word count (must be 12, 15, 18, 21, or 24)
    const word_count = args.len - 1; // subtract wallet name
    if (word_count != 12 and word_count != 15 and word_count != 18 and word_count != 21 and word_count != 24) {
        print("❌ Invalid mnemonic: wrong word count ({} words)\n", .{word_count});
        print("💡 Mnemonic must be 12, 15, 18, 21, or 24 words\n", .{});
        return;
    }
    
    // Join mnemonic words
    var mnemonic_list = std.ArrayList(u8).init(allocator);
    defer mnemonic_list.deinit();
    
    for (args[1..], 0..) |word, i| {
        if (i > 0) try mnemonic_list.append(' ');
        try mnemonic_list.appendSlice(word);
    }
    
    const mnemonic = try mnemonic_list.toOwnedSlice();
    defer allocator.free(mnemonic);
    defer std.crypto.utils.secureZero(u8, @constCast(mnemonic));
    
    // Validate mnemonic
    bip39.validateMnemonic(mnemonic) catch {
        print("❌ Invalid mnemonic phrase\n", .{});
        print("💡 Please check your mnemonic and try again\n", .{});
        return;
    };
    
    // Get data directory path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };

    // Create directories if needed
    std.fs.cwd().makePath(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const wallets_dir = try std.fmt.allocPrint(allocator, "{s}/wallets", .{data_dir});
    defer allocator.free(wallets_dir);
    
    std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Check if wallet already exists
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);

    if (std.fs.cwd().access(wallet_path, .{})) {
        print("❌ Wallet '{s}' already exists at: {s}\n", .{wallet_name, wallet_path});
        print("💡 Use a different name or remove the existing wallet first\n", .{});
        print("💡 List existing wallets with: zeicoin wallet list\n", .{});
        return;
    } else |err| switch (err) {
        error.FileNotFound => {}, // This is what we want - wallet doesn't exist
        else => {
            print("❌ Error checking wallet file: {}\n", .{err});
            return;
        },
    }
    
    // Create HD wallet from mnemonic
    var restored_wallet = wallet.Wallet.init(allocator);
    defer restored_wallet.deinit();
    
    restored_wallet.fromMnemonic(mnemonic, null) catch |err| {
        print("❌ Failed to restore from mnemonic: {}\n", .{err});
        return;
    };
    
    // Get password for wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, true) catch {
        print("❌ Password setup failed\n", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    // Save wallet to file
    restored_wallet.saveToFile(wallet_path, password) catch |err| {
        print("❌ Failed to save restored wallet: {}\n", .{err});
        return;
    };
    
    // Success message
    print("✅ HD wallet '{s}' restored successfully from mnemonic!\n", .{wallet_name});
    
    // Show first address
    const first_address = restored_wallet.getAddress(0) catch {
        print("❌ Failed to get address\n", .{});
        return;
    };
    const bech32_addr = first_address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        print("❌ Failed to encode address\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    print("🆔 First address: {s}\n", .{bech32_addr});
}

/// Derive new address from HD wallet
fn deriveAddress(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Wallet name required\n", .{});
        print("Usage: zeicoin wallet derive <wallet_name> [index]\n", .{});
        return;
    }
    
    const wallet_name = args[0];
    var index: ?u32 = null;
    
    if (args.len > 1) {
        index = std.fmt.parseInt(u32, args[1], 10) catch {
            print("❌ Invalid index: {s}\n", .{args[1]});
            return;
        };
    }
    
    // Get wallet path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);
    
    // Check if wallet exists
    std.fs.cwd().access(wallet_path, .{}) catch {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        print("💡 Create it with: zeicoin wallet create {s}\n", .{wallet_name});
        return;
    };
    
    // Check if this is an HD wallet
    if (!std.mem.endsWith(u8, wallet_path, ".wallet")) {
        print("❌ '{s}' is not an HD wallet\n", .{wallet_name});
        print("💡 Only HD wallets support address derivation\n", .{});
        return;
    }
    
    // Load HD wallet
    var hd_zen_wallet = wallet.Wallet.init(allocator);
    defer hd_zen_wallet.deinit();
    
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch {
        print("❌ Failed to get password\n", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    hd_zen_wallet.loadFromFile(wallet_path, password) catch |err| {
        switch (err) {
            wallet.WalletError.InvalidPassword => {
                print("❌ Failed to load wallet '{s}': Invalid password\n", .{wallet_name});
                print("💡 Please check your password and try again\n", .{});
                return;
            },
            else => {
                print("❌ Failed to load wallet '{s}': {}\n", .{ wallet_name, err });
                return;
            },
        }
    };
    
    if (index) |idx| {
        // Derive specific address
        const address = hd_zen_wallet.getAddress(idx) catch {
            print("❌ Failed to get address #{}\n", .{idx});
            return;
        };
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address #{}: <encoding error>\n", .{idx});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address #{}: {s}\n", .{ idx, bech32_addr });
    } else {
        // Get next address
        const address = hd_zen_wallet.getNextAddress() catch {
            print("❌ Failed to get next address\n", .{});
            return;
        };
        const new_index = hd_zen_wallet.highest_index;
        
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address #{}: <encoding error>\n", .{new_index});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("✅ New address derived!\n", .{});
        print("🆔 Address #{}: {s}\n", .{ new_index, bech32_addr });
        
        // Save updated wallet with new highest index
        try hd_zen_wallet.saveToFile(wallet_path, password);
    }
}

/// Import genesis wallet
fn importGenesisWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Genesis account name required\n", .{});
        print("Usage: zeicoin wallet import <alice|bob|charlie|david|eve>\n", .{});
        return;
    }

    const wallet_name = args[0];

    // Check if it's a valid genesis account
    const genesis_names = [_][]const u8{ "alice", "bob", "charlie", "david", "eve" };
    var is_genesis = false;
    for (genesis_names) |name| {
        if (std.mem.eql(u8, wallet_name, name)) {
            is_genesis = true;
            break;
        }
    }

    if (!is_genesis) {
        print("❌ '{s}' is not a valid genesis account name\n", .{wallet_name});
        print("💡 Valid genesis accounts: alice, bob, charlie, david, eve\n", .{});
        return;
    }

    if (types.CURRENT_NETWORK != .testnet) {
        print("❌ Genesis accounts are only available on TestNet\n", .{});
        return;
    }

    // Read genesis mnemonic from keys.config
    const config_path = "config/keys.config";
    const config_file = std.fs.cwd().openFile(config_path, .{}) catch |err| {
        print("❌ Cannot open genesis keys config: {}\n", .{err});
        print("💡 Make sure config/keys.config exists\n", .{});
        return;
    };
    defer config_file.close();

    const config_content = config_file.readToEndAlloc(allocator, 4096) catch |err| {
        print("❌ Cannot read genesis keys config: {}\n", .{err});
        return;
    };
    defer allocator.free(config_content);
    defer std.crypto.utils.secureZero(u8, @constCast(config_content));

    // Parse config file for the genesis account mnemonic
    var genesis_mnemonic_slice: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, config_content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        
        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const value = std.mem.trim(u8, trimmed[eq_pos + 1..], " \t");
            
            if (std.mem.eql(u8, key, wallet_name)) {
                genesis_mnemonic_slice = value;
                break;
            }
        }
    }

    if (genesis_mnemonic_slice == null) {
        print("❌ Genesis mnemonic for '{s}' not found in config\n", .{wallet_name});
        return;
    }

    // Make a secure copy of the genesis mnemonic
    const genesis_mnemonic = try allocator.dupe(u8, genesis_mnemonic_slice.?);
    defer allocator.free(genesis_mnemonic);
    defer std.crypto.utils.secureZero(u8, @constCast(genesis_mnemonic));

    // Get data directory path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };

    // Create directories if needed
    std.fs.cwd().makePath(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const wallets_dir = try std.fmt.allocPrint(allocator, "{s}/wallets", .{data_dir});
    defer allocator.free(wallets_dir);
    
    std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Check if wallet already exists
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);

    std.fs.cwd().access(wallet_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {}, // This is what we want
        else => {
            print("✅ Genesis wallet '{s}' already exists\n", .{wallet_name});
            return; // Don't error on existing genesis wallets
        },
    };
    
    // Create HD wallet from genesis mnemonic (24 words)
    var genesis_wallet = wallet.Wallet.init(allocator);
    defer genesis_wallet.deinit();
    
    try genesis_wallet.fromMnemonic(genesis_mnemonic, null);
    
    // Get password for wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, true) catch |err| {
        switch (err) {
            error.EndOfStream => {
                print("❌ Password input cancelled\n", .{});
                return;
            },
            error.PasswordMismatch => {
                print("❌ Passwords do not match\n", .{});
                return;
            },
            else => {
                print("❌ Failed to get password: {}\n", .{err});
                return;
            },
        }
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    // Save wallet to file
    try genesis_wallet.saveToFile(wallet_path, password);
    
    // Success message
    print("✅ Genesis wallet '{s}' imported successfully!\n", .{wallet_name});
    
    // Show first address
    const first_address = try genesis_wallet.getAddress(0);
    const bech32_addr = first_address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        print("❌ Failed to encode address\n", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    print("🆔 First address: {s}\n", .{bech32_addr});
}

/// Handle address command (moved from main CLI)
pub fn handleAddress(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0 and !std.mem.eql(u8, args[0], "--index")) args[0] else "default";
    
    var index: ?u32 = null;
    var i: usize = if (std.mem.eql(u8, wallet_name, "default")) 0 else 1;
    
    // Parse --index flag
    while (i < args.len) {
        if (std.mem.eql(u8, args[i], "--index") and i + 1 < args.len) {
            index = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                print("❌ Invalid index: {s}\n", .{args[i + 1]});
                return;
            };
            break;
        }
        i += 1;
    }
    
    // Get wallet path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);
    
    // Check if wallet exists
    std.fs.cwd().access(wallet_path, .{}) catch {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        log.info("💡 Create it with: zeicoin wallet create {s}", .{wallet_name});
        return;
    };
    
    // Load HD wallet
    var hd_zen_wallet = wallet.Wallet.init(allocator);
    defer hd_zen_wallet.deinit();
    
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch {
        print("❌ Failed to get password\n", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    hd_zen_wallet.loadFromFile(wallet_path, password) catch |err| {
        switch (err) {
            wallet.WalletError.InvalidPassword => {
                print("❌ Failed to load wallet '{s}': Invalid password\n", .{wallet_name});
                print("💡 Please check your password and try again\n", .{});
                return;
            },
            else => {
                print("❌ Failed to load wallet '{s}': {}\n", .{ wallet_name, err });
                return;
            },
        }
    };
    
    if (index) |idx| {
        // Show specific address
        const address = hd_zen_wallet.getAddress(idx) catch {
            print("❌ Failed to get address #{}\n", .{idx});
            return;
        };
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address #{}: <encoding error>\n", .{idx});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address #{}: {s}\n", .{ idx, bech32_addr });
    } else {
        // Show current/first address
        const address = hd_zen_wallet.getAddress(0) catch {
            print("❌ Failed to get address\n", .{});
            return;
        };
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            print("🆔 Address: <encoding error>\n", .{});
            return;
        };
        defer allocator.free(bech32_addr);
        
        print("🆔 Address: {s}\n", .{bech32_addr});
    }
}

/// Handle seed/mnemonic command - display wallet's recovery phrase
pub fn handleSeed(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("❌ Wallet name required\n", .{});
        print("Usage: zeicoin seed <wallet_name>\n", .{});
        return;
    }
    
    const wallet_name = args[0];
    
    // Get wallet path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };
    
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);
    
    // Check if wallet exists
    const file = std.fs.cwd().openFile(wallet_path, .{}) catch {
        print("❌ Wallet '{s}' not found\n", .{wallet_name});
        log.info("💡 Create it with: zeicoin wallet create {s}", .{wallet_name});
        return;
    };
    defer file.close();
    
    // Load wallet file
    const wallet_file = wallet.WalletFile.load(wallet_path) catch {
        print("❌ Invalid or corrupted wallet file\n", .{});
        return;
    };
    
    // Show security warning
    print("\n⚠️  WARNING: You are about to display your wallet's recovery seed phrase!\n", .{});
    print("⚠️  Anyone with these words can access your funds!\n", .{});
    print("⚠️  Make sure no one is watching your screen!\n\n", .{});
    
    // Get password to decrypt mnemonic
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch {
        print("❌ Failed to get password\n", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    
    // Decrypt mnemonic
    const mnemonic = wallet_file.decrypt(password, allocator) catch {
        print("❌ Invalid password or corrupted wallet\n", .{});
        return;
    };
    defer allocator.free(mnemonic);
    defer std.crypto.utils.secureZero(u8, mnemonic);
    
    // Display mnemonic
    print("🔑 Recovery Seed Phrase (12 words):\n", .{});
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
    print("{s}\n", .{mnemonic});
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n", .{});
    
    // Final security reminder
    print("⚠️  IMPORTANT SECURITY REMINDERS:\n", .{});
    print("   • Write these words down on paper and store in a secure location\n", .{});
    print("   • Never share these words with anyone\n", .{});
    print("   • Never store these words digitally (email, photos, cloud storage)\n", .{});
    print("   • These words can restore your wallet on any device\n", .{});
    print("   • If you lose these words, your funds cannot be recovered\n", .{});
}