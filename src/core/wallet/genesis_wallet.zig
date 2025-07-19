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

/// Get key pair for a named test account
pub fn getTestAccountKeyPair(name: []const u8) !?key.KeyPair {
    for (genesis.TESTNET_DISTRIBUTION) |account| {
        if (std.mem.eql(u8, account.name, name)) {
            return try createGenesisKeyPair(account.seed);
        }
    }
    return null;
}

/// Verify that a key pair matches the expected genesis address
pub fn verifyGenesisKeyPair(name: []const u8, keypair: key.KeyPair) !bool {
    const expected_addr = genesis.getTestAccountAddress(name) orelse return false;
    const actual_addr = types.Address.fromPublicKey(keypair.public_key);
    
    return std.mem.eql(u8, &expected_addr.hash, &actual_addr.hash);
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