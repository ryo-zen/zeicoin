// wallet.zig - ZeiCoin Minimal Wallet

const std = @import("std");
const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");

/// 💰 Zeicoin wallet errors - simple and clear
pub const WalletError = error{
    NoWalletLoaded,
    WalletFileNotFound,
    InvalidPassword,
    CorruptedWallet,
    InvalidWalletFile,
    DecryptionFailed,
};

/// ℹ️ Zeicoin wallet file format - encrypted and secure
pub const WalletFile = struct {
    version: u32,
    encrypted_data: [128]u8, // AES-GCM encrypted private key (64 bytes) + auth tag (16 bytes) + padding
    public_key: [32]u8, // Ed25519 public key
    address: types.Address, // Derived address
    salt: [16]u8, // Salt for key derivation
    checksum: [32]u8, // SHA256 checksum for integrity

    /// 👌 Create wallet file from private key (64-byte Ed25519 secret key)
    pub fn fromPrivateKey(private_key_64: [64]u8, password: []const u8) !WalletFile {

        // Generate salt
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);

        // Create ZeiCoin keypair from the 64-byte Ed25519 secret key
        const zeicoin_keypair = key.KeyPair.fromPrivateKey(private_key_64);

        // Derive address from public key
        const address = deriveAddress(zeicoin_keypair.public_key);

        // Encrypt the full 64-byte private key with password and salt
        var encrypted_data: [128]u8 = undefined;
        try encryptKey64(private_key_64, password, salt, &encrypted_data);

        // Calculate checksum
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&encrypted_data);
        hasher.update(&zeicoin_keypair.public_key);
        hasher.update(std.mem.asBytes(&address));
        hasher.update(&salt);
        const checksum = hasher.finalResult();

        return WalletFile{
            .version = 2, // AES-GCM format
            .encrypted_data = encrypted_data,
            .public_key = zeicoin_keypair.public_key,
            .address = address,
            .salt = salt,
            .checksum = checksum,
        };
    }

    /// 🔓 Decrypt private key from wallet file
    pub fn decryptPrivateKey(self: *const WalletFile, password: []const u8) ![64]u8 {
        // Verify checksum first
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.encrypted_data);
        hasher.update(&self.public_key);
        hasher.update(std.mem.asBytes(&self.address));
        hasher.update(&self.salt);
        const computed_checksum = hasher.finalResult();

        if (!std.mem.eql(u8, &computed_checksum, &self.checksum)) {
            return error.CorruptedWallet;
        }

        // Decrypt private key using AES-GCM
        var private_key: [64]u8 = undefined;
        decryptKey64(self.encrypted_data, password, self.salt, &private_key) catch |err| {
            if (err == error.DecryptionFailed) {
                return error.InvalidPassword; // Map decryption failure to invalid password
            }
            return err; // Propagate other potential errors
        };

        return private_key;
    }
};

/// Zeicoin Wallet Manager - one struct
pub const Wallet = struct {
    allocator: std.mem.Allocator,
    private_key: ?[64]u8, // Use full Ed25519 key format for zen compatibility
    public_key: ?[32]u8,
    address: ?types.Address,

    /// 🌱 Create new zen wallet
    pub fn init(allocator: std.mem.Allocator) Wallet {
        return Wallet{
            .allocator = allocator,
            .private_key = null,
            .public_key = null,
            .address = null,
        };
    }

    /// 🧹 Clean Zeicoin wallet (secure memory clearing)
    pub fn deinit(self: *Wallet) void {
        // Clear sensitive data
        if (self.private_key) |*priv_key| {
            @memset(priv_key, 0);
        }
    }

    /// 🆕 Create a new wallet with random private key
    pub fn createNew(self: *Wallet) !void {
        // Generate new Ed25519 keypair using ZeiCoin key format
        const zeicoin_keypair = try key.KeyPair.generateNew();

        // Derive address from public key (same as ZeiCoin)
        const address = types.Address.fromPublicKey(zeicoin_keypair.public_key);

        self.private_key = zeicoin_keypair.private_key;
        self.public_key = zeicoin_keypair.public_key;
        self.address = address;
    }
    
    /// 🔑 Import a genesis test account (TestNet only)
    pub fn importGenesisAccount(self: *Wallet, name: []const u8) !void {
        if (types.CURRENT_NETWORK != .testnet) {
            return error.GenesisAccountsTestNetOnly;
        }
        
        const genesis_wallet = @import("genesis_wallet.zig");
        const keypair = (try genesis_wallet.getTestAccountKeyPair(name)) orelse {
            return error.UnknownGenesisAccount;
        };
        
        // Verify the keypair generates the expected address
        if (!try genesis_wallet.verifyGenesisKeyPair(name, keypair)) {
            return error.InvalidGenesisKeyPair;
        }
        
        const address = types.Address.fromPublicKey(keypair.public_key);
        
        self.private_key = keypair.private_key;
        self.public_key = keypair.public_key;
        self.address = address;
    }

    /// 💾 Save wallet to encrypted file
    pub fn saveToFile(self: *Wallet, file_path: []const u8, password: []const u8) !void {
        if (self.private_key == null) return error.NoWalletLoaded;

        // Use the full 64-byte Ed25519 private key
        const private_key_64 = self.private_key.?;
        const wallet_file = try WalletFile.fromPrivateKey(private_key_64, password);

        // Write to file
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();

        try file.writeAll(std.mem.asBytes(&wallet_file));
    }

    /// 🔓 Load wallet from encrypted file
    pub fn loadFromFile(self: *Wallet, file_path: []const u8, password: []const u8) !void {
        // Read file
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.WalletFileNotFound,
            else => return err,
        };
        defer file.close();

        var wallet_file: WalletFile = undefined;
        const bytes_read = try file.readAll(std.mem.asBytes(&wallet_file));
        if (bytes_read != @sizeOf(WalletFile)) {
            return error.InvalidWalletFile;
        }

        // Decrypt private key (64 bytes)
        const private_key_64 = wallet_file.decryptPrivateKey(password) catch |err| switch (err) {
            error.InvalidPassword => return error.InvalidPassword,
            error.CorruptedWallet => return error.CorruptedWallet,
            else => return err,
        };

        // Create ZeiCoin keypair from the 64-byte Ed25519 private key
        const zeicoin_keypair = key.KeyPair.fromPrivateKey(private_key_64);

        self.private_key = zeicoin_keypair.private_key;
        self.public_key = zeicoin_keypair.public_key;
        // Always derive address from public key to ensure consistency
        self.address = deriveAddress(zeicoin_keypair.public_key);
    }

    /// ✍️ Sign a transaction
    pub fn signTransaction(self: *Wallet, tx_hash: *const types.Hash) !types.Signature {
        if (self.private_key == null) return error.NoWalletLoaded;

        // Use ZeiCoin KeyPair for signing consistency
        const zeicoin_keypair = self.getZeiCoinKeyPair() orelse return error.NoWalletLoaded;

        // Sign the transaction hash using ZeiCoin KeyPair
        return zeicoin_keypair.signTransaction(tx_hash.*) catch return error.NoWalletLoaded;
    }

    /// 🆔 Get wallet address for display
    pub fn getAddress(self: *Wallet) ?types.Address {
        return self.address;
    }

    /// 🗝️ Get public key for transactions
    pub fn getPublicKey(self: *Wallet) ?[32]u8 {
        return self.public_key;
    }

    /// ✅ Check if wallet is loaded
    pub fn isLoaded(self: *Wallet) bool {
        return self.private_key != null;
    }

    /// 🔗 Get Zeicoin KeyPair for compatibility
    pub fn getZeiCoinKeyPair(self: *Wallet) ?key.KeyPair {
        if (self.private_key == null or self.public_key == null) return null;

        return key.KeyPair{
            .private_key = self.private_key.?,
            .public_key = self.public_key.?,
        };
    }

    /// 📋 Get address as hex string for display
    pub fn getAddressHex(self: *Wallet, allocator: std.mem.Allocator) !?[]u8 {
        if (self.address == null) return null;

        const addr_bytes = self.address.?.toLegacyBytes();
        return try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&addr_bytes)});
    }

    /// 📝 Get short address for UI display (first 16 chars)
    pub fn getShortAddressHex(self: *Wallet) ?[16]u8 {
        if (self.address == null) return null;

        var short_addr: [16]u8 = undefined;
        const addr_bytes = self.address.?.toLegacyBytes();
        const hex_slice = std.fmt.fmtSliceHexLower(addr_bytes[0..8]);
        _ = std.fmt.bufPrint(&short_addr, "{s}", .{hex_slice}) catch return null;
        return short_addr;
    }

    /// 📁 Check if wallet file exists
    pub fn fileExists(file_path: []const u8) bool {
        const file = std.fs.cwd().openFile(file_path, .{}) catch return false;
        file.close();
        return true;
    }
};

// === INTERNAL FUNCTIONS ===

/// Expand 32-byte seed to 64-byte Ed25519 private key
fn expandPrivateKey(seed: [32]u8) [64]u8 {
    var expanded_key: [64]u8 = undefined;
    // Use Ed25519 key expansion (compatible with Zeicoin KeyPair)
    std.crypto.hash.sha2.Sha512.hash(seed[0..], &expanded_key, .{});
    return expanded_key;
}

/// 🏠 Derive ZeiCoin address from public key
fn deriveAddress(public_key: [32]u8) types.Address {
    return types.Address.fromPublicKey(public_key);
}

/// 🔒 Encrypt 64-byte private key using PBKDF2 + AES256-GCM
fn encryptKey64(private_key: [64]u8, password: []const u8, salt: [16]u8, output: *[128]u8) !void {
    // Derive 32-byte key using PBKDF2 with 100,000 iterations
    var derived_key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&derived_key, password, &salt, 100_000, std.crypto.auth.hmac.sha2.HmacSha256);
    defer std.crypto.utils.secureZero(u8, &derived_key);

    // Use AES256-GCM for authenticated encryption
    const aes = std.crypto.aead.aes_gcm.Aes256Gcm;
    
    // Generate nonce from salt (first 12 bytes)
    var nonce: [aes.nonce_length]u8 = undefined;
    @memcpy(&nonce, salt[0..aes.nonce_length]);
    
    // Encrypt with authentication tag
    var ciphertext: [64]u8 = undefined;
    var tag: [aes.tag_length]u8 = undefined;
    aes.encrypt(&ciphertext, &tag, &private_key, &.{}, nonce, derived_key);
    
    // Store ciphertext and tag in output
    @memcpy(output[0..64], &ciphertext);
    @memcpy(output[64..80], &tag);
    // Remaining bytes (80-128) are zero-padded
    @memset(output[80..128], 0);
}

/// 🔓 Decrypt 64-byte private key using PBKDF2 + AES256-GCM
fn decryptKey64(encrypted_data: [128]u8, password: []const u8, salt: [16]u8, output: *[64]u8) !void {
    // Derive 32-byte key using PBKDF2 with 100,000 iterations
    var derived_key: [32]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&derived_key, password, &salt, 100_000, std.crypto.auth.hmac.sha2.HmacSha256);
    defer std.crypto.utils.secureZero(u8, &derived_key);

    // Use AES256-GCM for authenticated decryption
    const aes = std.crypto.aead.aes_gcm.Aes256Gcm;
    
    // Generate nonce from salt (first 12 bytes)
    var nonce: [aes.nonce_length]u8 = undefined;
    @memcpy(&nonce, salt[0..aes.nonce_length]);
    
    // Extract ciphertext and tag
    const ciphertext = encrypted_data[0..64];
    const tag = encrypted_data[64..80];
    
    // Decrypt and verify authentication tag
    aes.decrypt(output, ciphertext, tag.*, &.{}, nonce, derived_key) catch {
        return error.DecryptionFailed;
    };
}

