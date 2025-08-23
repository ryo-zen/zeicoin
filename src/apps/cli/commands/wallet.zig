// Wallet commands for ZeiCoin CLI
// Handles wallet creation, restoration, listing, and address management

const std = @import("std");
const log = std.log.scoped(.cli);

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

/// Handle wallet command with subcommands
pub fn handleWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        log.info("❌ Wallet subcommand required", .{});
        log.info("Usage: zeicoin wallet <create|list|restore|derive|import> [name]", .{});
        return;
    }
    
    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(WalletSubcommand, subcommand_str) orelse {
        log.info("❌ Unknown wallet subcommand: {s}", .{subcommand_str});
        log.info("💡 Available subcommands: create, list, restore, derive, import", .{});
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

    // Get data directory path
    const data_dir = switch (types.CURRENT_NETWORK) {
        .testnet => "zeicoin_data_testnet",
        .mainnet => "zeicoin_data_mainnet",
    };

    // Create data directory if it doesn't exist
    std.fs.cwd().makePath(data_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // This is fine
        else => {
            log.info("❌ Failed to create data directory: {}", .{err});
            return;
        },
    };

    // Create wallets subdirectory
    const wallets_dir = try std.fmt.allocPrint(allocator, "{s}/wallets", .{data_dir});
    defer allocator.free(wallets_dir);
    
    std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {}, // This is fine
        else => {
            log.info("❌ Failed to create wallets directory: {}", .{err});
            return;
        },
    };

    // Check if wallet already exists
    const wallet_path = try std.fmt.allocPrint(allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name });
    defer allocator.free(wallet_path);

    std.fs.cwd().access(wallet_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {}, // This is what we want
        else => {
            log.info("❌ Wallet '{s}' already exists", .{wallet_name});
            log.info("💡 Use a different name or 'zeicoin wallet load {s}'", .{wallet_name});
            return;
        },
    };

    // Create new HD wallet
    var new_wallet = wallet.Wallet.init(allocator);
    defer new_wallet.deinit();

    // Generate new HD wallet with 12-word mnemonic
    const mnemonic = try new_wallet.createNew(bip39.WordCount.twelve);
    defer allocator.free(mnemonic);

    // Get password for wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, true) catch {
        log.info("❌ Password setup failed", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);

    // Save wallet to file
    new_wallet.saveToFile(wallet_path, password) catch |err| {
        log.info("❌ Failed to save wallet: {}", .{err});
        return;
    };

    // Success message
    log.info("✅ HD wallet '{s}' created successfully!", .{wallet_name});
    log.info("🔑 Mnemonic (12 words):", .{});
    log.info("{s}", .{mnemonic});
    log.info("\n⚠️  IMPORTANT: Save these 12 words in a secure place!", .{});
    log.info("💡 These words can restore your wallet if lost.", .{});
    
    // Show first address
    const first_address = new_wallet.getAddress(0) catch {
        log.info("❌ Failed to get address", .{});
        return;
    };
    const bech32_addr = first_address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        log.info("❌ Failed to encode address", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    log.info("🆔 First address: {s}", .{bech32_addr});
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
                log.info("📁 No wallets directory found.", .{});
                log.info("💡 Create a wallet with: zeicoin wallet create", .{});
                return;
            },
            else => return err,
        }
    };
    defer dir.close();
    
    log.info("📁 Wallets in {s}:", .{wallets_dir});
    
    var iterator = dir.iterate();
    var wallet_count: usize = 0;
    
    while (try iterator.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".wallet")) {
            // Extract wallet name (remove .wallet extension)
            const wallet_name = entry.name[0..entry.name.len - 7];
            log.info("  💼 {s}", .{wallet_name});
            wallet_count += 1;
        }
    }
    
    if (wallet_count == 0) {
        log.info("  (No wallets found)", .{});
        log.info("💡 Create a wallet with: zeicoin wallet create", .{});
    } else {
        log.info("\n💡 Use 'zeicoin balance <name>' to check wallet balance", .{});
    }
}

/// Restore HD wallet from mnemonic
fn restoreWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 25) { // name + 24 words
        log.info("❌ Usage: zeicoin wallet restore <name> <24-word-mnemonic>", .{});
        log.info("💡 Example: zeicoin wallet restore mywallet word1 word2 ... word24", .{});
        return;
    }
    
    const wallet_name = args[0];
    
    // Join mnemonic words
    var mnemonic_list = std.ArrayList(u8).init(allocator);
    defer mnemonic_list.deinit();
    
    for (args[1..], 0..) |word, i| {
        if (i > 0) try mnemonic_list.append(' ');
        try mnemonic_list.appendSlice(word);
    }
    
    const mnemonic = try mnemonic_list.toOwnedSlice();
    defer allocator.free(mnemonic);
    
    // Validate mnemonic
    bip39.validateMnemonic(mnemonic) catch {
        log.info("❌ Invalid mnemonic phrase", .{});
        log.info("💡 Please check your mnemonic and try again", .{});
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

    std.fs.cwd().access(wallet_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {}, // This is what we want
        else => {
            log.info("❌ Wallet '{s}' already exists", .{wallet_name});
            log.info("💡 Use a different name or remove the existing wallet", .{});
            return;
        },
    };
    
    // Create HD wallet from mnemonic
    var restored_wallet = wallet.Wallet.init(allocator);
    defer restored_wallet.deinit();
    
    restored_wallet.fromMnemonic(mnemonic, null) catch |err| {
        log.info("❌ Failed to restore from mnemonic: {}", .{err});
        return;
    };
    
    // Get password for wallet
    const password = password_util.getPasswordForWallet(allocator, wallet_name, true) catch {
        log.info("❌ Password setup failed", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    // Save wallet to file
    restored_wallet.saveToFile(wallet_path, password) catch |err| {
        log.info("❌ Failed to save restored wallet: {}", .{err});
        return;
    };
    
    // Success message
    log.info("✅ HD wallet '{s}' restored successfully from mnemonic!", .{wallet_name});
    
    // Show first address
    const first_address = restored_wallet.getAddress(0) catch {
        log.info("❌ Failed to get address", .{});
        return;
    };
    const bech32_addr = first_address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        log.info("❌ Failed to encode address", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    log.info("🆔 First address: {s}", .{bech32_addr});
}

/// Derive new address from HD wallet
fn deriveAddress(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        log.info("❌ Wallet name required", .{});
        log.info("Usage: zeicoin wallet derive <wallet_name> [index]", .{});
        return;
    }
    
    const wallet_name = args[0];
    var index: ?u32 = null;
    
    if (args.len > 1) {
        index = std.fmt.parseInt(u32, args[1], 10) catch {
            log.info("❌ Invalid index: {s}", .{args[1]});
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
        log.info("❌ Wallet '{s}' not found", .{wallet_name});
        log.info("💡 Create it with: zeicoin wallet create {s}", .{wallet_name});
        return;
    };
    
    // Check if this is an HD wallet
    if (!std.mem.endsWith(u8, wallet_path, ".wallet")) {
        log.info("❌ '{s}' is not an HD wallet", .{wallet_name});
        log.info("💡 Only HD wallets support address derivation", .{});
        return;
    }
    
    // Load HD wallet
    var hd_zen_wallet = wallet.Wallet.init(allocator);
    defer hd_zen_wallet.deinit();
    
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch {
        log.info("❌ Failed to get password", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    hd_zen_wallet.loadFromFile(wallet_path, password) catch |err| {
        switch (err) {
            wallet.WalletError.InvalidPassword => {
                log.info("❌ Failed to load wallet '{s}': Invalid password", .{wallet_name});
                log.info("💡 Please check your password and try again", .{});
                return;
            },
            else => {
                log.info("❌ Failed to load wallet '{s}': {}", .{ wallet_name, err });
                return;
            },
        }
    };
    
    if (index) |idx| {
        // Derive specific address
        const address = hd_zen_wallet.getAddress(idx) catch {
            log.info("❌ Failed to get address #{}", .{idx});
            return;
        };
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            log.info("🆔 Address #{}: <encoding error>", .{idx});
            return;
        };
        defer allocator.free(bech32_addr);
        
        log.info("🆔 Address #{}: {s}", .{ idx, bech32_addr });
    } else {
        // Get next address
        const address = hd_zen_wallet.getNextAddress() catch {
            log.info("❌ Failed to get next address", .{});
            return;
        };
        const new_index = hd_zen_wallet.highest_index;
        
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            log.info("🆔 Address #{}: <encoding error>", .{new_index});
            return;
        };
        defer allocator.free(bech32_addr);
        
        log.info("✅ New address derived!", .{});
        log.info("🆔 Address #{}: {s}", .{ new_index, bech32_addr });
        
        // Save updated wallet with new highest index
        try hd_zen_wallet.saveToFile(wallet_path, password);
    }
}

/// Import genesis wallet
fn importGenesisWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        log.info("❌ Genesis account name required", .{});
        log.info("Usage: zeicoin wallet import <alice|bob|charlie|david|eve>", .{});
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
        log.info("❌ '{s}' is not a valid genesis account name", .{wallet_name});
        log.info("💡 Valid genesis accounts: alice, bob, charlie, david, eve", .{});
        return;
    }

    if (types.CURRENT_NETWORK != .testnet) {
        log.info("❌ Genesis accounts are only available on TestNet", .{});
        return;
    }

    // Read genesis mnemonic from keys.config
    const config_path = "config/keys.config";
    const config_file = std.fs.cwd().openFile(config_path, .{}) catch |err| {
        log.info("❌ Cannot open genesis keys config: {}", .{err});
        log.info("💡 Make sure config/keys.config exists", .{});
        return;
    };
    defer config_file.close();

    const config_content = config_file.readToEndAlloc(allocator, 4096) catch |err| {
        log.info("❌ Cannot read genesis keys config: {}", .{err});
        return;
    };
    defer allocator.free(config_content);

    // Parse config file for the genesis account mnemonic
    var genesis_mnemonic: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, config_content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        
        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const value = std.mem.trim(u8, trimmed[eq_pos + 1..], " \t");
            
            if (std.mem.eql(u8, key, wallet_name)) {
                genesis_mnemonic = value;
                break;
            }
        }
    }

    if (genesis_mnemonic == null) {
        log.info("❌ Genesis mnemonic for '{s}' not found in config", .{wallet_name});
        return;
    }

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
            log.info("✅ Genesis wallet '{s}' already exists", .{wallet_name});
            return; // Don't error on existing genesis wallets
        },
    };
    
    // Create HD wallet from genesis mnemonic (24 words)
    var genesis_wallet = wallet.Wallet.init(allocator);
    defer genesis_wallet.deinit();
    
    try genesis_wallet.fromMnemonic(genesis_mnemonic.?, null);
    
    // Get password for wallet
    const password = try password_util.getPasswordForWallet(allocator, wallet_name, true);
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    // Save wallet to file
    try genesis_wallet.saveToFile(wallet_path, password);
    
    // Success message
    log.info("✅ Genesis wallet '{s}' imported successfully!", .{wallet_name});
    
    // Show first address
    const first_address = try genesis_wallet.getAddress(0);
    const bech32_addr = first_address.toBech32(allocator, types.CURRENT_NETWORK) catch {
        log.info("❌ Failed to encode address", .{});
        return;
    };
    defer allocator.free(bech32_addr);
    
    log.info("🆔 First address: {s}", .{bech32_addr});
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
                log.info("❌ Invalid index: {s}", .{args[i + 1]});
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
        log.info("❌ Wallet '{s}' not found", .{wallet_name});
        log.info("💡 Create it with: zeicoin wallet create {s}", .{wallet_name});
        return;
    };
    
    // Load HD wallet
    var hd_zen_wallet = wallet.Wallet.init(allocator);
    defer hd_zen_wallet.deinit();
    
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch {
        log.info("❌ Failed to get password", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    hd_zen_wallet.loadFromFile(wallet_path, password) catch |err| {
        switch (err) {
            wallet.WalletError.InvalidPassword => {
                log.info("❌ Failed to load wallet '{s}': Invalid password", .{wallet_name});
                log.info("💡 Please check your password and try again", .{});
                return;
            },
            else => {
                log.info("❌ Failed to load wallet '{s}': {}", .{ wallet_name, err });
                return;
            },
        }
    };
    
    if (index) |idx| {
        // Show specific address
        const address = hd_zen_wallet.getAddress(idx) catch {
            log.info("❌ Failed to get address #{}", .{idx});
            return;
        };
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            log.info("🆔 Address #{}: <encoding error>", .{idx});
            return;
        };
        defer allocator.free(bech32_addr);
        
        log.info("🆔 Address #{}: {s}", .{ idx, bech32_addr });
    } else {
        // Show current/first address
        const address = hd_zen_wallet.getAddress(0) catch {
            log.info("❌ Failed to get address", .{});
            return;
        };
        const bech32_addr = address.toBech32(allocator, types.CURRENT_NETWORK) catch {
            log.info("🆔 Address: <encoding error>", .{});
            return;
        };
        defer allocator.free(bech32_addr);
        
        log.info("🆔 Address: {s}", .{bech32_addr});
    }
}

/// Handle seed/mnemonic command - display wallet's recovery phrase
pub fn handleSeed(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        log.info("❌ Wallet name required", .{});
        log.info("Usage: zeicoin seed <wallet_name>", .{});
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
        log.info("❌ Wallet '{s}' not found", .{wallet_name});
        log.info("💡 Create it with: zeicoin wallet create {s}", .{wallet_name});
        return;
    };
    defer file.close();
    
    // Load wallet file
    const wallet_file = wallet.WalletFile.load(wallet_path) catch {
        log.info("❌ Invalid or corrupted wallet file", .{});
        return;
    };
    
    // Show security warning
    log.info("\n⚠️  WARNING: You are about to display your wallet's recovery seed phrase!", .{});
    log.info("⚠️  Anyone with these words can access your funds!", .{});
    log.info("⚠️  Make sure no one is watching your screen!\n", .{});
    
    // Get password to decrypt mnemonic
    const password = password_util.getPasswordForWallet(allocator, wallet_name, false) catch {
        log.info("❌ Failed to get password", .{});
        return;
    };
    defer allocator.free(password);
    defer password_util.clearPassword(password);
    
    
    // Decrypt mnemonic
    const mnemonic = wallet_file.decrypt(password, allocator) catch {
        log.info("❌ Invalid password or corrupted wallet", .{});
        return;
    };
    defer allocator.free(mnemonic);
    defer std.crypto.utils.secureZero(u8, mnemonic);
    
    // Display mnemonic
    log.info("🔑 Recovery Seed Phrase (12 words):", .{});
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", .{});
    log.info("{s}", .{mnemonic});
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", .{});
    
    // Final security reminder
    log.info("⚠️  IMPORTANT SECURITY REMINDERS:", .{});
    log.info("   • Write these words down on paper and store in a secure location", .{});
    log.info("   • Never share these words with anyone", .{});
    log.info("   • Never store these words digitally (email, photos, cloud storage)", .{});
    log.info("   • These words can restore your wallet on any device", .{});
    log.info("   • If you lose these words, your funds cannot be recovered", .{});
}