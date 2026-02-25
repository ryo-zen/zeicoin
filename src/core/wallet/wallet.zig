// wallet.zig - ZeiCoin HD-Only Wallet with Modern Security
// Hierarchical Deterministic wallet implementation with ChaCha20-Poly1305 AEAD

const std = @import("std");
const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");
const bip39 = @import("../crypto/bip39.zig");
const hd = @import("../crypto/hd.zig");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

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
    UnsupportedVersion,
};

/// Modern wallet file format with AEAD encryption
pub const WalletFile = struct {
    /// File format version
    pub const VERSION: u32 = 4; // Version 4 = ChaCha20-Poly1305 + Argon2
    pub const MAGIC: [4]u8 = .{ 'Z', 'E', 'I', 0x04 };
    
    /// Argon2 parameters - balanced for security and speed
    pub const KDF_PARAMS = std.crypto.pwhash.argon2.Params{
        .t = 3,           // iterations
        .m = 64 * 1024,   // 64 MB memory
        .p = 1,           // parallelism
    };
    
    // File structure (compact, fixed size)
    magic: [4]u8 = MAGIC,
    version: u32 = VERSION,
    salt: [32]u8,
    nonce: [ChaCha20Poly1305.nonce_length]u8,
    encrypted_data: [512]u8, // Encrypted mnemonic + padding
    auth_tag: [ChaCha20Poly1305.tag_length]u8,
    data_len: u16, // Actual length of encrypted data
    
    /// Create a new secure wallet file
    pub fn create(mnemonic: []const u8, password: []const u8) !WalletFile {
        if (mnemonic.len > 500) return WalletError.InvalidMnemonic;
        
        // Validate mnemonic before encrypting
        bip39.validateMnemonic(mnemonic) catch {
            return WalletError.InvalidMnemonic;
        };
        
        var wallet = WalletFile{
            .encrypted_data = [_]u8{0} ** 512,
            .data_len = @intCast(mnemonic.len),
            .salt = undefined,
            .nonce = undefined,
            .auth_tag = undefined,
        };
        
        // Generate random salt and nonce
        const io = std.Io.Threaded.global_single_threaded.ioBasic();
        std.Io.randomSecure(io, &wallet.salt) catch unreachable;
        std.Io.randomSecure(io, &wallet.nonce) catch unreachable;
        
        // Derive key using Argon2id
        var encryption_key: [ChaCha20Poly1305.key_length]u8 = undefined;
        try std.crypto.pwhash.argon2.kdf(
            std.heap.page_allocator,
            &encryption_key,
            password,
            &wallet.salt,
            KDF_PARAMS,
            .argon2id,
            io
        );
        defer std.crypto.secureZero(u8, &encryption_key);
        
        // Create associated data (binds version and salt to ciphertext)
        var ad: [40]u8 = undefined;
        @memcpy(ad[0..4], &wallet.magic);
        std.mem.writeInt(u32, ad[4..8], wallet.version, .little);
        @memcpy(ad[8..40], &wallet.salt);
        
        // Encrypt mnemonic with ChaCha20-Poly1305
        ChaCha20Poly1305.encrypt(
            wallet.encrypted_data[0..mnemonic.len],
            &wallet.auth_tag,
            mnemonic,
            &ad,
            wallet.nonce,
            encryption_key
        );
        
        return wallet;
    }
    
    /// Decrypt the wallet file
    pub fn decrypt(self: *const WalletFile, password: []const u8, allocator: std.mem.Allocator) ![]u8 {
        // Verify magic and version
        if (!std.mem.eql(u8, &self.magic, &MAGIC)) {
            return WalletError.InvalidWalletFile;
        }
        if (self.version != VERSION) {
            return WalletError.UnsupportedVersion;
        }
        
        // Validate data length
        if (self.data_len == 0 or self.data_len > 500) {
            return WalletError.InvalidWalletFile;
        }
        
        // Derive key from password
        var encryption_key: [ChaCha20Poly1305.key_length]u8 = undefined;
        const io = std.Io.Threaded.global_single_threaded.ioBasic();
        std.crypto.pwhash.argon2.kdf(
            std.heap.page_allocator,
            &encryption_key,
            password,
            &self.salt,
            KDF_PARAMS,
            .argon2id,
            io
        ) catch {
            return WalletError.InvalidPassword;
        };
        defer std.crypto.secureZero(u8, &encryption_key);
        
        // Recreate associated data
        var ad: [40]u8 = undefined;
        @memcpy(ad[0..4], &self.magic);
        std.mem.writeInt(u32, ad[4..8], self.version, .little);
        @memcpy(ad[8..40], &self.salt);
        
        // Decrypt mnemonic
        const plaintext = try allocator.alloc(u8, self.data_len);
        
        ChaCha20Poly1305.decrypt(
            plaintext,
            self.encrypted_data[0..self.data_len],
            self.auth_tag,
            &ad,
            self.nonce,
            encryption_key
        ) catch {
            allocator.free(plaintext);
            // Authentication failed = wrong password or corrupted file
            return WalletError.InvalidPassword;
        };
        
        // Validate decrypted mnemonic (belt-and-suspenders)
        bip39.validateMnemonic(plaintext) catch {
            allocator.free(plaintext);
            return WalletError.InvalidPassword;
        };
        
        return plaintext;
    }
    
    /// Save to file
    pub fn save(self: *const WalletFile, io: std.Io, path: []const u8) !void {
        const dir = std.Io.Dir.cwd();
        const file = try dir.createFile(io, path, .{});
        defer file.close(io);
        _ = try file.writeStreamingAll(io, std.mem.asBytes(self));
    }
    
    /// Load from file
    pub fn load(io: std.Io, path: []const u8) !WalletFile {
        const dir = std.Io.Dir.cwd();
        const file = try dir.openFile(io, path, .{});
        defer file.close(io);
        
        var wallet: WalletFile = undefined;
        var buf: [@sizeOf(WalletFile)]u8 = undefined;
        const bytes_read = try file.readStreaming(io, &[_][]u8{&buf});
        
        if (bytes_read != @sizeOf(WalletFile)) {
            return WalletError.InvalidWalletFile;
        }
        
        @memcpy(std.mem.asBytes(&wallet), buf[0..bytes_read]);
        return wallet;
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
            std.crypto.secureZero(u8, m);
            self.allocator.free(m);
        }
        // Clear master key
        if (self.master_key) |*mk| {
            std.crypto.secureZero(u8, &mk.key);
            std.crypto.secureZero(u8, &mk.chain_code);
        }
    }

    /// Generate new HD wallet with mnemonic
    pub fn createNew(self: *Wallet, io: std.Io, word_count: bip39.WordCount) ![]const u8 {
        // Generate mnemonic
        const mnemonic = try bip39.generateMnemonic(self.allocator, io, word_count);
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
    pub fn importGenesisAccount(self: *Wallet, io: std.Io, name: []const u8) !void {
        if (types.CURRENT_NETWORK != .testnet) {
            return error.GenesisAccountsTestNetOnly;
        }
        
        // Get genesis mnemonic for the account name
        const genesis_mnemonic = try getGenesisAccountMnemonic(self.allocator, io, name);
        defer self.allocator.free(genesis_mnemonic);
        
        // Load from mnemonic (now with proper BIP39 validation)
        try self.fromMnemonic(genesis_mnemonic, null);
    }

    /// Save wallet to encrypted file
    pub fn saveToFile(self: *Wallet, io: std.Io, file_path: []const u8, password: []const u8) !void {
        if (self.mnemonic == null) return WalletError.NoWalletLoaded;
        
        // Create secure wallet file
        const wallet_file = try WalletFile.create(self.mnemonic.?, password);
        
        // Note: highest_index and account are stored separately in the Wallet struct
        // They are not part of the encrypted data for security
        
        // Save to file
        try wallet_file.save(io, file_path);
    }

    /// Load wallet from encrypted file
    pub fn loadFromFile(self: *Wallet, io: std.Io, file_path: []const u8, password: []const u8) !void {
        // Load wallet file
        const wallet_file = WalletFile.load(io, file_path) catch |err| switch (err) {
            WalletError.InvalidWalletFile => return WalletError.WalletFileNotFound,
            else => return err,
        };

        // Decrypt mnemonic
        const mnemonic = wallet_file.decrypt(password, self.allocator) catch |err| switch (err) {
            WalletError.InvalidPassword => return WalletError.InvalidPassword,
            WalletError.CorruptedWallet => return WalletError.CorruptedWallet,
            WalletError.UnsupportedVersion => return WalletError.UnsupportedVersion,
            else => return err,
        };

        // Restore wallet from mnemonic
        try self.fromMnemonic(mnemonic, null);
        self.allocator.free(mnemonic); // fromMnemonic makes its own copy

        // Note: highest_index and current_account default to 0
        // They are managed separately from the encrypted file
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

    /// Get wallet address at specific index (primary function)
    pub fn getAddress(self: *Wallet, index: u32) !types.Address {
        return self.getAddressAtIndex(index);
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
    
    /// Get key pair for signing at specific index (primary function)
    pub fn getKeyPair(self: *Wallet, index: u32) !key.KeyPair {
        return self.getKeyPairAtIndex(index);
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
        return self.getKeyPair(self.current_index) catch null;
    }

    /// Get address as hex string for display
    pub fn getAddressHex(self: *Wallet, allocator: std.mem.Allocator) ![]u8 {
        const address = try self.getAddress(0);
        const addr_bytes = address.toBytes();
        return try std.fmt.allocPrint(allocator, "{x}", .{&addr_bytes});
    }

    /// Get short address for UI display (first 16 chars)
    pub fn getShortAddressHex(self: *Wallet) ?[16]u8 {
        const address = self.getAddress(0) catch return null;
        
        var short_addr: [16]u8 = undefined;
        const addr_bytes = address.toBytes();
        _ = std.fmt.bufPrint(&short_addr, "{x}", .{addr_bytes[0..8]}) catch return null;
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
    pub fn fileExists(io: std.Io, file_path: []const u8) bool {
        const dir = std.Io.Dir.cwd();
        dir.access(io, file_path, .{}) catch return false;
        return true;
    }
    
    /// Check if this is an HD wallet file
    pub fn isHDWallet(io: std.Io, file_path: []const u8) bool {
        const dir = std.Io.Dir.cwd();
        const file = dir.openFile(io, file_path, .{}) catch return false;
        defer file.close(io);
        
        var version: u32 = undefined;
        var buf: [4]u8 = undefined;
        const bytes_read = file.readStreaming(io, &[_][]u8{&buf}) catch return false;
        if (bytes_read < 4) return false;
        version = std.mem.readInt(u32, buf[0..4], .little);
        
        return version == 3;
    }
};

/// Get genesis account mnemonic from keys.config file
fn getGenesisAccountMnemonic(allocator: std.mem.Allocator, io: std.Io, name: []const u8) ![]const u8 {
    // Read from keys.config file - fail gracefully if not found
    const dir = std.Io.Dir.cwd();
    const file = dir.openFile(io, "config/keys.config", .{}) catch |err| switch (err) {
        error.FileNotFound => {
            return error.KeysConfigNotFound;
        },
        else => return err,
    };
    defer file.close(io);
    
    var buf: [4096]u8 = undefined;
    const bytes_read = try file.readStreaming(io, &[_][]u8{&buf});
    const content = buf[0..bytes_read];
    
    // Parse config file line by line
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        
        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        
        // Parse "name=mnemonic" format
        if (std.mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const config_key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const value = std.mem.trim(u8, trimmed[eq_pos + 1..], " \t");
            
            if (std.mem.eql(u8, config_key, name)) {
                return try allocator.dupe(u8, value); // Return allocated copy
            }
        }
    }
    
    return error.UnknownGenesisAccount;
}

