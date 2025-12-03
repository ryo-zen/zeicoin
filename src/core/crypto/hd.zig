// hd.zig - Hierarchical Deterministic key derivation for ZeiCoin
// Ed25519-based HD wallet using BLAKE3 instead of HMAC-SHA512

const std = @import("std");
const testing = std.testing;

// When testing standalone, we define minimal types
const key = if (@import("builtin").is_test) struct {
    pub const KeyPair = struct {
        private_key: [64]u8,
        public_key: [32]u8,
    };
} else @import("key.zig");

const types = if (@import("builtin").is_test) struct {
    pub const Address = struct {
        bytes: [32]u8,
        
        pub fn fromPublicKey(pubkey: [32]u8) Address {
            var hasher = std.crypto.hash.Blake3.init(.{});
            hasher.update(&pubkey);
            var hash: [32]u8 = undefined;
            hasher.final(&hash);
            return Address{ .bytes = hash };
        }
    };
} else @import("../types/types.zig");

pub const HDError = error{
    InvalidPath,
    InvalidIndex,
    InvalidDepth,
    DerivationFailed,
    InvalidSeed,
};

/// BIP32-style path levels
pub const PathLevel = enum {
    purpose,     // 44' for BIP44
    coin_type,   // 882' for ZeiCoin
    account,     // Account number
    change,      // 0 = external, 1 = internal
    address,     // Address index
};

/// HD key with chain code for derivation
pub const HDKey = struct {
    /// Key material (32 bytes for Ed25519)
    key: [32]u8,
    /// Chain code for child derivation
    chain_code: [32]u8,
    /// Depth in hierarchy (0 for master)
    depth: u8,
    /// Child number (index at this depth)
    child_number: u32,
    /// Parent fingerprint (first 4 bytes of parent pubkey hash)
    parent_fingerprint: [4]u8,
    
    /// Create master key from seed
    pub fn fromSeed(seed: [64]u8) HDKey {
        // Make mutable copy of seed for secure clearing
        var mutable_seed = seed;
        defer std.crypto.utils.secureZero(u8, &mutable_seed); // Clear seed copy from stack

        // Use BLAKE3 with domain separation
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update("zeicoin-hd-master");
        hasher.update(&mutable_seed);

        var output: [64]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &output); // Clear intermediate key material
        hasher.final(output[0..32]);

        // Second round for chain code
        var hasher2 = std.crypto.hash.Blake3.init(.{});
        hasher2.update("zeicoin-hd-chain");
        hasher2.update(&mutable_seed);
        hasher2.final(output[32..64]);

        return HDKey{
            .key = output[0..32].*,
            .chain_code = output[32..64].*,
            .depth = 0,
            .child_number = 0,
            .parent_fingerprint = [_]u8{0} ** 4,
        };
    }
    
    /// Derive child key at index
    /// Note: For Ed25519, we support all indices but treat them as hardened
    pub fn deriveChild(self: *const HDKey, index: u32) !HDKey {
        // For Ed25519, we'll treat all derivation as hardened-style
        // This is a design choice for ZeiCoin HD wallets

        // Check depth limit
        if (self.depth >= 255) {
            return HDError.InvalidDepth;
        }

        // Prepare data for derivation (contains private key material)
        var data: [37]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &data); // Clear derivation data containing key
        data[0] = 0x00; // Hardened derivation marker
        @memcpy(data[1..33], &self.key);
        std.mem.writeInt(u32, data[33..37], index, .big);

        // Derive using BLAKE3
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(&self.chain_code);
        hasher.update(&data);

        var output: [64]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &output); // Clear intermediate key material
        hasher.final(output[0..32]);

        // Second round for new chain code
        var hasher2 = std.crypto.hash.Blake3.init(.{});
        hasher2.update("zeicoin-hd-child-chain");
        hasher2.update(&self.chain_code);
        hasher2.update(&data);
        hasher2.final(output[32..64]);

        // Calculate parent fingerprint
        const parent_pubkey = self.getPublicKey();
        var fp_hasher = std.crypto.hash.Blake3.init(.{});
        fp_hasher.update(&parent_pubkey);
        var fp_hash: [32]u8 = undefined;
        fp_hasher.final(&fp_hash);

        return HDKey{
            .key = output[0..32].*,
            .chain_code = output[32..64].*,
            .depth = self.depth + 1,
            .child_number = index,
            .parent_fingerprint = fp_hash[0..4].*,
        };
    }
    
    /// Get Ed25519 public key from this HD key
    pub fn getPublicKey(self: *const HDKey) [32]u8 {
        // For deterministic key generation, we need to convert our key material
        // into a proper Ed25519 seed format
        var seed: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &seed); // Clear private key material from stack
        @memcpy(&seed, &self.key);

        // Use the standard Ed25519 key generation from seed
        const Ed25519 = std.crypto.sign.Ed25519;
        const kp = Ed25519.KeyPair.generateDeterministic(seed) catch {
            return [_]u8{0} ** 32;
        };

        return kp.public_key.bytes;
    }
    
    /// Convert to ZeiCoin KeyPair for signing
    pub fn toKeyPair(self: *const HDKey) !key.KeyPair {
        // Use the same seed-based generation
        var seed: [32]u8 = undefined;
        defer std.crypto.utils.secureZero(u8, &seed); // Clear private key material from stack
        @memcpy(&seed, &self.key);

        const Ed25519 = std.crypto.sign.Ed25519;
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);

        return key.KeyPair{
            .private_key = kp.secret_key.bytes,
            .public_key = kp.public_key.bytes,
        };
    }
    
    /// Get ZeiCoin address for this key
    pub fn getAddress(self: *const HDKey) types.Address {
        const pubkey = self.getPublicKey();
        return types.Address.fromPublicKey(pubkey);
    }
};

/// Parse HD derivation path like "m/44'/882'/0'/0/0"
pub fn parsePath(path: []const u8) ![]u32 {
    var parts = std.ArrayList(u32).init(std.heap.page_allocator);
    defer parts.deinit();
    
    var iter = std.mem.tokenizeScalar(u8, path, '/');
    
    // First part should be 'm' for master
    const first = iter.next() orelse return HDError.InvalidPath;
    if (!std.mem.eql(u8, first, "m")) {
        return HDError.InvalidPath;
    }
    
    // Parse remaining parts
    while (iter.next()) |part| {
        var index: u32 = 0;
        var hardened = false;
        
        // Check for hardened marker (' or h)
        if (part[part.len - 1] == '\'' or part[part.len - 1] == 'h') {
            hardened = true;
            const num_part = part[0..part.len - 1];
            index = std.fmt.parseInt(u32, num_part, 10) catch return HDError.InvalidPath;
        } else {
            index = std.fmt.parseInt(u32, part, 10) catch return HDError.InvalidPath;
        }
        
        // Apply hardened bit if needed
        if (hardened) {
            index |= 0x80000000;
        }
        
        try parts.append(index);
    }
    
    return parts.toOwnedSlice();
}

/// Derive key from path
pub fn derivePath(master: *const HDKey, path: []const u32) !HDKey {
    var current = master.*;
    
    for (path) |index| {
        current = try current.deriveChild(index);
    }
    
    return current;
}

/// Common derivation paths
pub const COIN_TYPE_ZEICOIN: u32 = 882; // ZeiCoin coin type (single type for both testnet and mainnet)

pub fn getAccountPath(account: u32) [3]u32 {
    return [3]u32{
        44 | 0x80000000,                    // purpose: BIP44
        COIN_TYPE_ZEICOIN | 0x80000000,     // coin_type: 882
        account | 0x80000000,               // account (hardened)
    };
}

pub fn getAddressPath(account: u32, change: u32, index: u32) [5]u32 {
    return [5]u32{
        44 | 0x80000000,                    // purpose: BIP44
        COIN_TYPE_ZEICOIN | 0x80000000,     // coin_type: 882
        account | 0x80000000,               // account (hardened)
        change,                             // change (0 or 1)
        index,                              // address index
    };
}

// Tests
test "master key generation" {
    const seed = [_]u8{0x42} ** 64;
    const master = HDKey.fromSeed(seed);
    
    try testing.expectEqual(@as(u8, 0), master.depth);
    try testing.expectEqual(@as(u32, 0), master.child_number);
    try testing.expect(master.key[0] != 0 or master.key[1] != 0);
}

test "child key derivation" {
    const seed = [_]u8{0x42} ** 64;
    const master = HDKey.fromSeed(seed);
    
    // Derive first hardened child
    const child = try master.deriveChild(0x80000000);
    
    try testing.expectEqual(@as(u8, 1), child.depth);
    try testing.expectEqual(@as(u32, 0x80000000), child.child_number);
    try testing.expect(!std.mem.eql(u8, &master.key, &child.key));
}

test "path parsing" {
    const path_str = "m/44'/882'/0'/0/0";
    const path = try parsePath(path_str);
    defer std.heap.page_allocator.free(path);

    try testing.expectEqual(@as(usize, 5), path.len);
    try testing.expectEqual(@as(u32, 44 | 0x80000000), path[0]);
    try testing.expectEqual(@as(u32, 882 | 0x80000000), path[1]);
    try testing.expectEqual(@as(u32, 0 | 0x80000000), path[2]);
    try testing.expectEqual(@as(u32, 0), path[3]);
    try testing.expectEqual(@as(u32, 0), path[4]);
}

test "full derivation" {
    const seed = [_]u8{0x42} ** 64;
    const master = HDKey.fromSeed(seed);
    
    // Derive first address
    const path = getAddressPath(0, 0, 0);
    const derived = try derivePath(&master, &path);
    
    try testing.expectEqual(@as(u8, 5), derived.depth);
    
    // Should produce valid address
    const addr = derived.getAddress();
    try testing.expect(addr.bytes[0] != 0);
}

test "deterministic derivation" {
    const seed = [_]u8{0x42} ** 64;
    const master = HDKey.fromSeed(seed);
    
    // Same path should give same key
    const path = getAddressPath(0, 0, 0);
    const key1 = try derivePath(&master, &path);
    const key2 = try derivePath(&master, &path);
    
    try testing.expectEqualSlices(u8, &key1.key, &key2.key);
    try testing.expectEqualSlices(u8, &key1.chain_code, &key2.chain_code);
}