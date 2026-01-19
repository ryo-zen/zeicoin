const std = @import("std");
const mldsa = std.crypto.sign.mldsa;
const print = std.debug.print;

pub fn main() !void {
    print("=== ML-DSA (Dilithium) Test - Zig 0.16.0 Nightly ===\n\n", .{});

    // Test ML-DSA-44 (128-bit security, smallest signatures)
    print("Testing ML-DSA-44...\n", .{});
    try testMLDSA44();

    print("\n✅ All ML-DSA tests passed!\n", .{});
    print("\n=== Conclusion ===\n", .{});
    print("ML-DSA is fully functional in Zig 0.16.0 nightly.\n", .{});
    print("Ready for ZeiCoin integration when 0.16.0 stable releases.\n", .{});
}

fn testMLDSA44() !void {
    const MLDSA44 = mldsa.MLDSA44;

    // Generate keypair using deterministic seed for testing
    const seed: [32]u8 = [_]u8{0x42} ** 32; // Fixed seed for reproducible testing
    const kp = try MLDSA44.KeyPair.generateDeterministic(seed);

    print("  ✓ Key pair generated\n", .{});
    print("    - Public key size:  {} bytes\n", .{MLDSA44.PublicKey.encoded_length});
    print("    - Secret key size:  {} bytes\n", .{MLDSA44.SecretKey.encoded_length});

    // Sign a message
    const message = "ZeiCoin post-quantum test transaction";
    const sig = try kp.sign(message, null);

    print("  ✓ Message signed\n", .{});
    print("    - Signature size:   {} bytes\n", .{MLDSA44.Signature.encoded_length});
    print("    - Message: \"{s}\"\n", .{message});

    // Verify signature
    try sig.verify(message, kp.public_key);
    print("  ✓ Signature verified successfully\n", .{});

    // Test with context (domain separation)
    const context = "ZeiCoin-TestNet-v1";
    const sig_ctx = try kp.signWithContext(message, null, context);
    try sig_ctx.verifyWithContext(message, kp.public_key, context);
    print("  ✓ Context-based signature verified\n", .{});
    print("    - Context: \"{s}\"\n", .{context});

    // Test signature verification failure on wrong message
    if (sig.verify("wrong message", kp.public_key)) {
        print("  ✗ ERROR: Signature verified for wrong message!\n", .{});
        return error.SignatureVerificationFailed;
    } else |_| {
        print("  ✓ Correctly rejected invalid signature\n", .{});
    }

    // Size comparison with Ed25519
    print("\n  Comparison to Ed25519:\n", .{});
    print("    ML-DSA-44 signature: {} bytes\n", .{MLDSA44.Signature.encoded_length});
    print("    Ed25519 signature:   64 bytes\n", .{});
    print("    Size ratio:          {d:.1}x larger\n", .{@as(f64, @floatFromInt(MLDSA44.Signature.encoded_length)) / 64.0});
}
