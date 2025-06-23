// key.zig - ZeiCoin Cryptographic Key Management
// Ed25519 signatures with secure memory clearing

const std = @import("std");
const testing = std.testing;

const util = @import("util.zig");
const types = @import("types.zig");

// Re-export types for convenience
pub const Address = types.Address;
pub const Signature = types.Signature;

// Error types for key operations
pub const KeyError = error{
    SigningFailed,
    InvalidPublicKey,
    InvalidSignature,
    PrivateKeyCleared,
    KeyGenerationFailed,
};

/// ZeiCoin cryptographic key pair
/// Uses Ed25519 for modern, secure signatures
pub const KeyPair = struct {
    private_key: [64]u8, // Store expanded secret key for compatibility
    public_key: [32]u8, // Ed25519 uses 32-byte public keys

    /// Generate a new random key pair
    pub fn generateNew() KeyError!KeyPair {
        // Generate Ed25519 keypair
        const Ed25519 = std.crypto.sign.Ed25519;
        const keypair = Ed25519.KeyPair.generate();

        return KeyPair{
            .private_key = keypair.secret_key.bytes,
            .public_key = keypair.public_key.bytes,
        };
    }

    /// Create keypair from existing secret key
    pub fn fromPrivateKey(private_key: [64]u8) KeyPair {
        const Ed25519 = std.crypto.sign.Ed25519;
        const secret_key = Ed25519.SecretKey.fromBytes(private_key) catch {
            // If creation fails, return zero keypair
            return KeyPair{
                .private_key = std.mem.zeroes([64]u8),
                .public_key = std.mem.zeroes([32]u8),
            };
        };

        const keypair = Ed25519.KeyPair.fromSecretKey(secret_key) catch {
            // If creation fails, return zero keypair
            return KeyPair{
                .private_key = std.mem.zeroes([64]u8),
                .public_key = std.mem.zeroes([32]u8),
            };
        };

        return KeyPair{
            .private_key = private_key, // Keep original expanded format
            .public_key = keypair.public_key.bytes,
        };
    }

    /// Get ZeiCoin address from this keypair
    /// Address = SHA256(public_key)
    pub fn getAddress(self: *const KeyPair) Address {
        return Address.fromPublicKey(self.public_key);
    }

    /// Sign a message with this keypair's private key
    pub fn sign(self: *const KeyPair, message: []const u8) KeyError!Signature {
        // Check if private key is still available (not cleared)
        if (isPrivateKeyCleared(self.private_key)) {
            return KeyError.PrivateKeyCleared;
        }

        const Ed25519 = std.crypto.sign.Ed25519;
        const secret_key = Ed25519.SecretKey.fromBytes(self.private_key) catch return KeyError.SigningFailed;

        // Reconstruct keypair for signing
        const keypair = Ed25519.KeyPair.fromSecretKey(secret_key) catch return KeyError.SigningFailed;

        const signature = keypair.sign(message, null) catch return KeyError.SigningFailed;
        return signature.toBytes();
    }

    /// Sign a transaction hash
    pub fn signTransaction(self: *const KeyPair, transaction_hash: types.Hash) KeyError!Signature {
        return self.sign(&transaction_hash);
    }

    /// Securely clear the private key from memory
    /// After calling this, signing operations will fail
    pub fn clearPrivateKey(self: *KeyPair) void {
        std.crypto.utils.secureZero(u8, &self.private_key);
    }

    /// Cleanup keypair - clears private key
    pub fn deinit(self: *KeyPair) void {
        self.clearPrivateKey();
    }

    /// Check if this keypair can still sign (private key not cleared)
    pub fn canSign(self: *const KeyPair) bool {
        return !isPrivateKeyCleared(self.private_key);
    }
};

/// Verify a signature against a public key and message
pub fn verify(public_key: [32]u8, message: []const u8, signature: Signature) bool {
    const Ed25519 = std.crypto.sign.Ed25519;

    // Create public key and signature objects
    const pub_key = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);

    // Verify signature
    sig.verify(message, pub_key) catch return false;
    return true;
}

/// Generate address from public key
pub fn publicKeyToAddress(public_key: [32]u8) Address {
    return Address.fromPublicKey(public_key);
}

/// Check if a private key has been securely cleared (all zeros)
fn isPrivateKeyCleared(private_key: [64]u8) bool {
    const zero_key = std.mem.zeroes([64]u8);
    return std.mem.eql(u8, &private_key, &zero_key);
}

// Tests
test "key generation and address derivation" {
    // Generate new keypair
    var keypair = try KeyPair.generateNew();
    defer keypair.deinit();

    // Should be able to sign
    try testing.expect(keypair.canSign());

    // Get address
    const address = keypair.getAddress();

    // Address should not be all zeros
    const zero_address = Address.zero();
    try testing.expect(!address.equals(zero_address));
}

test "signing and verification" {
    var keypair = try KeyPair.generateNew();
    defer keypair.deinit();

    const message = "Hello ZeiCoin!";

    // Sign message
    const signature = try keypair.sign(message);

    // Verify signature (simplified implementation always returns true)
    try testing.expect(verify(keypair.public_key, message, signature));
}

test "transaction signing" {
    var keypair = try KeyPair.generateNew();
    defer keypair.deinit();

    // Create a dummy transaction hash
    const tx_hash = util.hash256("dummy transaction");

    // Sign transaction
    const signature = try keypair.signTransaction(tx_hash);

    // Verify transaction signature
    try testing.expect(verify(keypair.public_key, &tx_hash, signature));
}

test "private key clearing" {
    var keypair = try KeyPair.generateNew();

    // Should be able to sign initially
    try testing.expect(keypair.canSign());

    const message = "test message";
    _ = try keypair.sign(message); // Should succeed

    // Clear private key
    keypair.clearPrivateKey();

    // Should no longer be able to sign
    try testing.expect(!keypair.canSign());

    // Signing should fail
    const result = keypair.sign(message);
    try testing.expectError(KeyError.PrivateKeyCleared, result);
}

test "address consistency" {
    var keypair = try KeyPair.generateNew();
    defer keypair.deinit();

    // Two ways to get address should give same result
    const address1 = keypair.getAddress();
    const address2 = publicKeyToAddress(keypair.public_key);

    try testing.expect(address1.equals(address2));
}
