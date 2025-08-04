// hd_wallet.zig - Hierarchical Deterministic wallet for ZeiCoin
// Combines BIP39 mnemonics with HD key derivation

const std = @import("std");
const bip39 = @import("../crypto/bip39.zig");
const hd = @import("../crypto/hd.zig");
const wallet = @import("wallet.zig");
const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");

pub const HDWalletError = error{
    InvalidMnemonic,
    InvalidPath,
    DerivationFailed,
    WalletNotLoaded,
    SerializationFailed,
};

/// HD Wallet file format
pub const HDWalletFile = struct {
    version: u32 = 3, // Version 3 = HD wallet
    encrypted_mnemonic: [512]u8, // Encrypted mnemonic phrase
    salt: [16]u8,
    checksum: [32]u8,
    // Cached data for performance
    highest_index: u32 = 0, // Highest derived address index
    account: u32 = 0, // Account number (default 0)
};

/// Hierarchical Deterministic Wallet
pub const HDWallet = struct {
    allocator: std.mem.Allocator,
    mnemonic: ?[]u8, // Only in memory when unlocked
    master_key: ?hd.HDKey,
    current_account: u32 = 0,
    highest_index: u32 = 0,
    
    pub fn init(allocator: std.mem.Allocator) HDWallet {
        return HDWallet{
            .allocator = allocator,
            .mnemonic = null,
            .master_key = null,
        };
    }
    
    pub fn deinit(self: *HDWallet) void {
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
    pub fn generateNew(self: *HDWallet, word_count: bip39.WordCount) ![]const u8 {
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
    pub fn fromMnemonic(self: *HDWallet, mnemonic: []const u8, passphrase: ?[]const u8) !void {
        // Validate mnemonic
        try bip39.validateMnemonic(mnemonic);
        
        // Store copy of mnemonic
        self.mnemonic = try self.allocator.dupe(u8, mnemonic);
        
        // Generate seed and master key
        const seed = bip39.mnemonicToSeed(mnemonic, passphrase);
        self.master_key = hd.HDKey.fromSeed(seed);
    }
    
    /// Get address at specific index
    pub fn getAddress(self: *HDWallet, index: u32) !types.Address {
        if (self.master_key == null) return HDWalletError.WalletNotLoaded;
        
        // Derive address using BIP44 path: m/44'/501'/account'/0/index
        const path = hd.getAddressPath(self.current_account, 0, index);
        const derived_key = try hd.derivePath(&self.master_key.?, &path);
        
        // Update highest index
        if (index > self.highest_index) {
            self.highest_index = index;
        }
        
        return derived_key.getAddress();
    }
    
    /// Get next unused address
    pub fn getNextAddress(self: *HDWallet) !types.Address {
        return self.getAddress(self.highest_index + 1);
    }
    
    /// Get key pair for signing at specific index
    pub fn getKeyPair(self: *HDWallet, index: u32) !key.KeyPair {
        if (self.master_key == null) return HDWalletError.WalletNotLoaded;
        
        const path = hd.getAddressPath(self.current_account, 0, index);
        const derived_key = try hd.derivePath(&self.master_key.?, &path);
        
        return try derived_key.toKeyPair();
    }
    
    /// Save to encrypted file
    pub fn saveToFile(self: *HDWallet, file_path: []const u8, password: []const u8) !void {
        if (self.mnemonic == null) return HDWalletError.WalletNotLoaded;
        
        // Generate salt
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        
        // Encrypt mnemonic (simplified - should use proper encryption)
        var encrypted: [512]u8 = [_]u8{0} ** 512;
        const mnemonic_bytes = self.mnemonic.?;
        if (mnemonic_bytes.len > 500) return HDWalletError.SerializationFailed;
        
        // Simple XOR encryption for demo (should use AES-GCM in production)
        var key_bytes: [32]u8 = undefined;
        try std.crypto.pwhash.pbkdf2(&key_bytes, password, &salt, 10000, std.crypto.auth.hmac.sha2.HmacSha256);
        
        for (mnemonic_bytes, 0..) |byte, i| {
            encrypted[i] = byte ^ key_bytes[i % 32];
        }
        encrypted[511] = @intCast(mnemonic_bytes.len); // Store length at fixed position
        
        // Calculate checksum
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&encrypted);
        hasher.update(&salt);
        const checksum = hasher.finalResult();
        
        const wallet_file = HDWalletFile{
            .encrypted_mnemonic = encrypted,
            .salt = salt,
            .checksum = checksum,
            .highest_index = self.highest_index,
            .account = self.current_account,
        };
        
        // Write to file
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        try file.writeAll(std.mem.asBytes(&wallet_file));
    }
    
    /// Load from encrypted file
    pub fn loadFromFile(self: *HDWallet, file_path: []const u8, password: []const u8) !void {
        const file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();
        
        var wallet_file: HDWalletFile = undefined;
        const bytes_read = try file.readAll(std.mem.asBytes(&wallet_file));
        if (bytes_read != @sizeOf(HDWalletFile)) {
            return wallet.WalletError.InvalidWalletFile;
        }
        
        // Verify version
        if (wallet_file.version != 3) {
            return wallet.WalletError.InvalidWalletFile;
        }
        
        // Verify checksum
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&wallet_file.encrypted_mnemonic);
        hasher.update(&wallet_file.salt);
        const checksum = hasher.finalResult();
        
        if (!std.mem.eql(u8, &checksum, &wallet_file.checksum)) {
            return wallet.WalletError.CorruptedWallet;
        }
        
        // Decrypt mnemonic
        var key_bytes: [32]u8 = undefined;
        try std.crypto.pwhash.pbkdf2(&key_bytes, password, &wallet_file.salt, 10000, std.crypto.auth.hmac.sha2.HmacSha256);
        
        var decrypted: [512]u8 = undefined;
        for (wallet_file.encrypted_mnemonic, 0..) |byte, i| {
            decrypted[i] = byte ^ key_bytes[i % 32];
        }
        
        // Get length from last byte
        const mnemonic_len = wallet_file.encrypted_mnemonic[511];
        if (mnemonic_len == 0 or mnemonic_len > 500) {
            return wallet.WalletError.InvalidWalletFile;
        }
        
        // Restore wallet from mnemonic
        const mnemonic = decrypted[0..mnemonic_len];
        try self.fromMnemonic(mnemonic, null);
        
        // Restore state
        self.highest_index = wallet_file.highest_index;
        self.current_account = wallet_file.account;
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