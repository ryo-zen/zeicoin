// Genesis wallet utilities for TestNet
// Provides deterministic wallet generation for pre-funded test accounts

const std = @import("std");
const types = @import("../types/types.zig");
const key = @import("../crypto/key.zig");
const genesis = @import("../chain/genesis.zig");

/// Create deterministic key pair for a genesis test account
pub fn createGenesisKeyPair(seed: []const u8) !key.KeyPair {
    // Use same approach as genesis public key but derive full key pair
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(seed);
    hasher.update("_ZEICOIN_GENESIS_KEY");
    
    var seed_bytes: [32]u8 = undefined;
    hasher.final(&seed_bytes);
    
    // Create Ed25519 keypair using the seed as private key
    // This follows RFC 8032 - the seed IS the private key
    const Ed25519 = std.crypto.sign.Ed25519;
    
    // Create keypair directly from seed
    const seed_keypair = try Ed25519.KeyPair.generateDeterministic(seed_bytes);
    
    return key.KeyPair{
        .public_key = seed_keypair.public_key.bytes,
        .private_key = seed_keypair.secret_key.bytes,
    };
}

/// Get key pair for a named test account (deprecated - use HD wallets instead)
pub fn getTestAccountKeyPair(name: []const u8) !?key.KeyPair {
    // Since we're using HD wallets now, this function is deprecated
    // But we keep it for backward compatibility in tests
    const seed = try std.fmt.allocPrint(std.heap.page_allocator, "GENESIS_{s}", .{name});
    defer std.heap.page_allocator.free(seed);
    return try createGenesisKeyPair(seed);
}

/// Verify that a key pair matches the expected genesis address
pub fn verifyGenesisKeyPair(name: []const u8, keypair: key.KeyPair) !bool {
    const expected_addr = genesis.getTestAccountAddress(name) orelse return false;
    const actual_addr = types.Address.fromPublicKey(keypair.public_key);
    
    return std.mem.eql(u8, &expected_addr.hash, &actual_addr.hash);
}

/// Generate deterministic mnemonic for genesis account from config file
pub fn getGenesisAccountMnemonic(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    // Read from keys.config file - fail gracefully if not found
    const file = std.fs.cwd().openFile("config/keys.config", .{}) catch |err| switch (err) {
        error.FileNotFound => {
            return error.KeysConfigNotFound;
        },
        else => return err,
    };
    defer file.close();
    
    const content = try file.readToEndAlloc(allocator, 4096);
    defer allocator.free(content);
    
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

/// Generate deterministic mnemonic from genesis seed that produces compatible addresses
fn generateGenesisHDMnemonic(allocator: std.mem.Allocator, seed: []const u8) ![]u8 {
    const bip39 = @import("../crypto/bip39.zig");
    
    // Create deterministic entropy from the seed
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(seed);
    hasher.update("_ZEICOIN_HD_GENESIS"); // Different suffix for HD wallets
    var full_hash: [32]u8 = undefined;
    hasher.final(&full_hash);
    
    // Use first 16 bytes as entropy for 12-word mnemonic
    const entropy = full_hash[0..16];
    
    // Generate mnemonic from entropy
    return try bip39.entropyToMnemonic(allocator, entropy);
}


test "Genesis key pair generation" {
    // Test alice key pair
    const alice_kp = (try getTestAccountKeyPair("alice")).?;
    try std.testing.expect(try verifyGenesisKeyPair("alice", alice_kp));
    
    // Test all accounts
    for (genesis.TESTNET_DISTRIBUTION) |account| {
        const kp = (try getTestAccountKeyPair(account.name)).?;
        try std.testing.expect(try verifyGenesisKeyPair(account.name, kp));
        
        // Verify address matches
        const addr = types.Address.fromPublicKey(kp.public_key);
        const expected = genesis.getTestAccountAddress(account.name).?;
        try std.testing.expectEqualSlices(u8, &expected.hash, &addr.hash);
    }
}