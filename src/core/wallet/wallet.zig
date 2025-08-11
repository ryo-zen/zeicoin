// wallet.zig - ZeiCoin HD-Only Wallet
// Hierarchical Deterministic wallet implementation

const std = @import("std");
const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");
const bip39 = @import("../crypto/bip39.zig");
const hd = @import("../crypto/hd.zig");

/// 💰 ZeiCoin wallet errors
pub const WalletError = error{
    NoWalletLoaded,
    WalletFileNotFound,
    InvalidPassword,
    CorruptedWallet,
    InvalidWalletFile,
    DecryptionFailed,
    InvalidMnemonic,
    DerivationFailed,
};

/// HD Wallet file format (version 3)
pub const WalletFile = struct {
    version: u32 = 3, // Version 3 = HD wallet
    encrypted_mnemonic: [512]u8, // Encrypted mnemonic phrase
    salt: [16]u8,
    checksum: [32]u8,
    highest_index: u32 = 0, // Highest derived address index
    account: u32 = 0, // Account number (default 0)

    /// Create wallet file from mnemonic
    pub fn fromMnemonic(mnemonic: []const u8, password: []const u8) !WalletFile {
        // Generate salt
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        
        // Encrypt mnemonic
        var encrypted: [512]u8 = [_]u8{0} ** 512;
        const mnemonic_bytes = mnemonic;
        if (mnemonic_bytes.len > 500) return WalletError.InvalidWalletFile;
        
        // Use PBKDF2 + XOR encryption for mnemonic
        var key_bytes: [32]u8 = undefined;
        try std.crypto.pwhash.pbkdf2(&key_bytes, password, &salt, 100_000, std.crypto.auth.hmac.sha2.HmacSha256);
        
        for (mnemonic_bytes, 0..) |byte, i| {
            encrypted[i] = byte ^ key_bytes[i % 32];
        }
        encrypted[511] = @intCast(mnemonic_bytes.len); // Store length
        
        // Calculate checksum
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&encrypted);
        hasher.update(&salt);
        const checksum = hasher.finalResult();
        
        return WalletFile{
            .encrypted_mnemonic = encrypted,
            .salt = salt,
            .checksum = checksum,
        };
    }

    /// Decrypt mnemonic from wallet file
    pub fn decryptMnemonic(self: *const WalletFile, password: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Verify checksum first
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.encrypted_mnemonic);
        hasher.update(&self.salt);
        const computed_checksum = hasher.finalResult();

        if (!std.mem.eql(u8, &computed_checksum, &self.checksum)) {
            return WalletError.CorruptedWallet;
        }

        // Decrypt mnemonic
        var key_bytes: [32]u8 = undefined;
        std.crypto.pwhash.pbkdf2(&key_bytes, password, &self.salt, 100_000, std.crypto.auth.hmac.sha2.HmacSha256) catch {
            return WalletError.InvalidPassword;
        };
        
        var decrypted: [512]u8 = undefined;
        for (self.encrypted_mnemonic, 0..) |byte, i| {
            decrypted[i] = byte ^ key_bytes[i % 32];
        }
        
        // Get length from last byte
        const mnemonic_len = self.encrypted_mnemonic[511];
        if (mnemonic_len == 0 or mnemonic_len > 500) {
            return WalletError.InvalidWalletFile;
        }
        
        // Return copy of mnemonic
        return try allocator.dupe(u8, decrypted[0..mnemonic_len]);
    }
};

/// ZeiCoin HD Wallet Manager
pub const Wallet = struct {
    allocator: std.mem.Allocator,
    mnemonic: ?[]u8, // Only in memory when unlocked
    master_key: ?hd.HDKey,
    current_account: u32 = 0,
    current_index: u32 = 0, // Current address index
    highest_index: u32 = 0,

    /// Create new HD wallet
    pub fn init(allocator: std.mem.Allocator) Wallet {
        return Wallet{
            .allocator = allocator,
            .mnemonic = null,
            .master_key = null,
        };
    }

    /// Clean HD wallet (secure memory clearing)
    pub fn deinit(self: *Wallet) void {
        // Securely clear mnemonic
        if (self.mnemonic) |m| {
            std.crypto.utils.secureZero(u8, m);
            self.allocator.free(m);
        }
        // Clear master key
        if (self.master_key) |*mk| {
            std.crypto.utils.secureZero(u8, &mk.key);
            std.crypto.utils.secureZero(u8, &mk.chain_code);
        }
    }

    /// Generate new HD wallet with mnemonic
    pub fn createNew(self: *Wallet, word_count: bip39.WordCount) ![]const u8 {
        // Generate mnemonic
        const mnemonic = try bip39.generateMnemonic(self.allocator, word_count);
        errdefer self.allocator.free(mnemonic);
        
        // Store mnemonic
        self.mnemonic = mnemonic;
        
        // Generate seed and master key
        const seed = bip39.mnemonicToSeed(mnemonic, null);
        self.master_key = hd.HDKey.fromSeed(seed);
        
        // Return copy of mnemonic for display
        return try self.allocator.dupe(u8, mnemonic);
    }
    
    /// Restore wallet from mnemonic
    pub fn fromMnemonic(self: *Wallet, mnemonic: []const u8, passphrase: ?[]const u8) !void {
        // Validate mnemonic
        try bip39.validateMnemonic(mnemonic);
        
        // Store copy of mnemonic
        self.mnemonic = try self.allocator.dupe(u8, mnemonic);
        
        // Generate seed and master key
        const seed = bip39.mnemonicToSeed(mnemonic, passphrase);
        self.master_key = hd.HDKey.fromSeed(seed);
    }


    /// Import a genesis test account (TestNet only)
    pub fn importGenesisAccount(self: *Wallet, name: []const u8) !void {
        if (types.CURRENT_NETWORK != .testnet) {
            return error.GenesisAccountsTestNetOnly;
        }
        
        const genesis_wallet = @import("genesis_wallet.zig");
        // Get genesis mnemonic for the account name
        const genesis_mnemonic = try genesis_wallet.getGenesisAccountMnemonic(self.allocator, name);
        defer self.allocator.free(genesis_mnemonic);
        
        // Load from mnemonic (now with proper BIP39 validation)
        try self.fromMnemonic(genesis_mnemonic, null);
    }

    /// Save wallet to encrypted file
    pub fn saveToFile(self: *Wallet, file_path: []const u8, password: []const u8) !void {
        if (self.mnemonic == null) return WalletError.NoWalletLoaded;
        
        const wallet_file = try WalletFile.fromMnemonic(self.mnemonic.?, password);
        
        // Update state in file
        var updated_file = wallet_file;
        updated_file.highest_index = self.highest_index;
        updated_file.account = self.current_account;
        
        // Write to file
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        try file.writeAll(std.mem.asBytes(&updated_file));
    }

    /// Load wallet from encrypted file
    pub fn loadFromFile(self: *Wallet, file_path: []const u8, password: []const u8) !void {
        // Read file
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return WalletError.WalletFileNotFound,
            else => return err,
        };
        defer file.close();

        var wallet_file: WalletFile = undefined;
        const bytes_read = try file.readAll(std.mem.asBytes(&wallet_file));
        if (bytes_read != @sizeOf(WalletFile)) {
            return WalletError.InvalidWalletFile;
        }

        // Verify version
        if (wallet_file.version != 3) {
            return WalletError.InvalidWalletFile;
        }

        // Decrypt mnemonic
        const mnemonic = wallet_file.decryptMnemonic(password, self.allocator) catch |err| switch (err) {
            WalletError.InvalidPassword => return WalletError.InvalidPassword,
            WalletError.CorruptedWallet => return WalletError.CorruptedWallet,
            else => return err,
        };

        // Restore wallet from mnemonic (now with proper BIP39 validation for all)
        try self.fromMnemonic(mnemonic, null);
        self.allocator.free(mnemonic); // fromMnemonic makes its own copy

        // Restore state
        self.highest_index = wallet_file.highest_index;
        self.current_account = wallet_file.account;
    }

    /// Sign a transaction using current address index
    pub fn signTransaction(self: *Wallet, tx_hash: *const types.Hash) !types.Signature {
        return self.signTransactionAtIndex(tx_hash, self.current_index);
    }
    
    /// Sign a transaction at specific HD index
    pub fn signTransactionAtIndex(self: *Wallet, tx_hash: *const types.Hash, index: u32) !types.Signature {
        if (self.master_key == null) return WalletError.NoWalletLoaded;
        
        const keypair = try self.getKeyPairAtIndex(index);
        return keypair.signTransaction(tx_hash.*);
    }

    /// Get wallet address at current index
    pub fn getAddress(self: *Wallet) ?types.Address {
        return self.getAddressAtIndex(self.current_index) catch null;
    }
    
    /// Get address at specific HD index
    pub fn getAddressAtIndex(self: *Wallet, index: u32) !types.Address {
        if (self.master_key == null) return WalletError.NoWalletLoaded;
        
        const path = hd.getAddressPath(self.current_account, 0, index);
        const derived_key = try hd.derivePath(&self.master_key.?, &path);
        
        // Update highest index
        if (index > self.highest_index) {
            self.highest_index = index;
        }
        
        return derived_key.getAddress();
    }
    
    /// Get next unused address
    pub fn getNextAddress(self: *Wallet) !types.Address {
        return self.getAddressAtIndex(self.highest_index + 1);
    }

    /// Get public key for current address
    pub fn getPublicKey(self: *Wallet) ?[32]u8 {
        const keypair = self.getKeyPairAtIndex(self.current_index) catch return null;
        return keypair.public_key;
    }

    /// Check if wallet is loaded
    pub fn isLoaded(self: *Wallet) bool {
        return self.master_key != null;
    }
    
    /// Get key pair for signing at current index
    pub fn getKeyPair(self: *Wallet) !key.KeyPair {
        return self.getKeyPairAtIndex(self.current_index);
    }

    /// Get key pair at specific HD index
    pub fn getKeyPairAtIndex(self: *Wallet, index: u32) !key.KeyPair {
        if (self.master_key == null) return WalletError.NoWalletLoaded;
        
        const path = hd.getAddressPath(self.current_account, 0, index);
        const derived_key = try hd.derivePath(&self.master_key.?, &path);
        
        return try derived_key.toKeyPair();
    }

    /// Get ZeiCoin KeyPair for compatibility (current index)
    pub fn getZeiCoinKeyPair(self: *Wallet) ?key.KeyPair {
        return self.getKeyPair() catch null;
    }

    /// Get address as hex string for display
    pub fn getAddressHex(self: *Wallet, allocator: std.mem.Allocator) !?[]u8 {
        const address = self.getAddress() orelse return null;
        const addr_bytes = address.toBytes();
        return try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&addr_bytes)});
    }

    /// Get short address for UI display (first 16 chars)
    pub fn getShortAddressHex(self: *Wallet) ?[16]u8 {
        const address = self.getAddress() orelse return null;
        
        var short_addr: [16]u8 = undefined;
        const addr_bytes = address.toBytes();
        const hex_slice = std.fmt.fmtSliceHexLower(addr_bytes[0..8]);
        _ = std.fmt.bufPrint(&short_addr, "{s}", .{hex_slice}) catch return null;
        return short_addr;
    }
    
    /// Set current address index
    pub fn setCurrentIndex(self: *Wallet, index: u32) void {
        self.current_index = index;
        if (index > self.highest_index) {
            self.highest_index = index;
        }
    }
    
    /// Get mnemonic (for display/backup)
    pub fn getMnemonic(self: *Wallet) ?[]const u8 {
        return self.mnemonic;
    }

    /// Check if wallet file exists
    pub fn fileExists(file_path: []const u8) bool {
        const file = std.fs.cwd().openFile(file_path, .{}) catch return false;
        file.close();
        return true;
    }
    
    /// Check if this is an HD wallet file
    pub fn isHDWallet(file_path: []const u8) bool {
        const file = std.fs.cwd().openFile(file_path, .{}) catch return false;
        defer file.close();
        
        var version: u32 = undefined;
        _ = file.read(std.mem.asBytes(&version)) catch return false;
        
        return version == 3;
    }
};

