// bip39.zig - Modern mnemonic implementation using BLAKE3
// Clean design with no legacy SHA256/SHA512 baggage

const std = @import("std");
const testing = std.testing;

pub const MnemonicError = error{
    InvalidWordCount,
    InvalidChecksum,
    WordNotInList,
    InvalidEntropy,
    AllocationFailed,
};

/// Supported mnemonic lengths
pub const WordCount = enum(u8) {
    twelve = 12,      // 128 bits entropy + 4 bits checksum = 132 bits
    fifteen = 15,     // 160 bits entropy + 5 bits checksum = 165 bits
    eighteen = 18,    // 192 bits entropy + 6 bits checksum = 198 bits
    twentyone = 21,   // 224 bits entropy + 7 bits checksum = 231 bits
    twentyfour = 24,  // 256 bits entropy + 8 bits checksum = 264 bits

    pub fn entropyBits(self: WordCount) u16 {
        return switch (self) {
            .twelve => 128,
            .fifteen => 160,
            .eighteen => 192,
            .twentyone => 224,
            .twentyfour => 256,
        };
    }

    pub fn checksumBits(self: WordCount) u8 {
        return @intCast(@as(u16, @intFromEnum(self)) / 3);
    }
};

/// Import the BIP39 English wordlist
const wordlist = @import("bip39_wordlist.zig");
pub const WORDLIST = wordlist.WORDLIST;

/// Generate a new mnemonic phrase
pub fn generateMnemonic(allocator: std.mem.Allocator, word_count: WordCount) ![]u8 {
    const entropy_bytes = word_count.entropyBits() / 8;
    
    // Generate random entropy
    var entropy: [32]u8 = undefined; // Max 256 bits
    std.crypto.random.bytes(entropy[0..entropy_bytes]);
    
    // Generate mnemonic from entropy
    return entropyToMnemonic(allocator, entropy[0..entropy_bytes]);
}

/// Convert entropy to mnemonic words
pub fn entropyToMnemonic(allocator: std.mem.Allocator, entropy: []const u8) ![]u8 {
    if (entropy.len < 16 or entropy.len > 32 or entropy.len % 4 != 0) {
        return MnemonicError.InvalidEntropy;
    }
    
    // Calculate checksum using BLAKE3 (not SHA256!)
    var blake3_out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(entropy, &blake3_out, .{});
    const checksum_byte = blake3_out[0];
    const checksum_bits: u8 = @intCast(entropy.len / 4);
    
    // Combine entropy + checksum
    var bits = std.ArrayList(u8).init(allocator);
    defer bits.deinit();
    
    // Add entropy bits
    for (entropy) |byte| {
        try bits.append(byte);
    }
    
    // Add checksum bits (only the required number of bits)
    try bits.append(checksum_byte >> @as(u3, @intCast(8 - checksum_bits)));
    
    // Convert to word indices
    const word_count = (entropy.len * 8 + checksum_bits) / 11;
    var words = std.ArrayList([]const u8).init(allocator);
    defer words.deinit();
    
    var bit_index: usize = 0;
    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        const word_index = extractBits(bits.items, bit_index, 11);
        try words.append(WORDLIST[word_index]);
        bit_index += 11;
    }
    
    // Join words with spaces
    return std.mem.join(allocator, " ", words.items);
}

/// Extract n bits from a byte array starting at bit_offset
fn extractBits(data: []const u8, bit_offset: usize, n_bits: u8) u16 {
    var result: u16 = 0;
    var bits_read: u8 = 0;
    
    var byte_index = bit_offset / 8;
    var bit_index: u3 = @intCast(bit_offset % 8);
    
    while (bits_read < n_bits) {
        if (byte_index >= data.len) break;
        
        const bits_available = @as(u8, 8) - bit_index;
        const bits_to_read = if (bits_available < n_bits - bits_read) bits_available else n_bits - bits_read;
        
        const mask = if (bits_to_read >= 8) 0xFF else (@as(u8, 1) << @as(u3, @intCast(bits_to_read))) - 1;
        // Safely calculate shift amount
        const shift_amount: u8 = 8 - @as(u8, bit_index) - bits_to_read;
        const bits = if (shift_amount >= 8) 0 else (data[byte_index] >> @as(u3, @intCast(shift_amount & 0x7))) & mask;
        
        result = (result << @as(u4, @intCast(bits_to_read))) | bits;
        bits_read += bits_to_read;
        
        bit_index = 0;
        byte_index += 1;
    }
    
    return result;
}

/// Convert mnemonic to seed using BLAKE3-based KDF
/// This replaces PBKDF2-SHA512 with a modern approach
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8) [64]u8 {
    var kdf = std.crypto.hash.Blake3.init(.{});
    
    // Domain separation
    kdf.update("zeicoin-mnemonic-v1");
    
    // Add mnemonic
    kdf.update(mnemonic);
    
    // Add passphrase (or empty string)
    if (passphrase) |p| {
        if (p.len > 0) {
            kdf.update(p);
        }
    }
    
    // For key stretching (replaces PBKDF2's 2048 iterations)
    // We'll use BLAKE3's built-in key derivation
    var derived: [32]u8 = undefined;
    kdf.final(&derived);
    
    // Additional rounds for computational cost
    var seed: [64]u8 = undefined;
    var i: u32 = 0;
    while (i < 2048) : (i += 1) {
        var round_kdf = std.crypto.hash.Blake3.init(.{});
        round_kdf.update(&derived);
        round_kdf.update(std.mem.asBytes(&i));
        round_kdf.final(&derived);
    }
    
    // Expand to 64 bytes
    var final_kdf = std.crypto.hash.Blake3.init(.{});
    final_kdf.update("zeicoin-seed-expansion");
    final_kdf.update(&derived);
    var expanded: [32]u8 = undefined;
    final_kdf.final(&expanded);
    
    @memcpy(seed[0..32], expanded[0..32]);
    
    // Second round for last 32 bytes
    var second_kdf = std.crypto.hash.Blake3.init(.{});
    second_kdf.update("zeicoin-seed-expansion-2");
    second_kdf.update(&derived);
    var expanded2: [32]u8 = undefined;
    second_kdf.final(&expanded2);
    
    @memcpy(seed[32..64], expanded2[0..32]);
    
    return seed;
}

/// Validate a mnemonic phrase
pub fn validateMnemonic(mnemonic: []const u8) !void {
    var words_iter = std.mem.tokenizeScalar(u8, mnemonic, ' ');
    var word_count: usize = 0;
    
    // Count and validate each word
    while (words_iter.next()) |word| {
        var found = false;
        for (WORDLIST) |valid_word| {
            if (std.mem.eql(u8, word, valid_word)) {
                found = true;
                break;
            }
        }
        if (!found) return MnemonicError.WordNotInList;
        word_count += 1;
    }
    
    // Validate word count
    const valid_counts = [_]usize{12, 15, 18, 21, 24};
    var valid_count = false;
    for (valid_counts) |count| {
        if (word_count == count) {
            valid_count = true;
            break;
        }
    }
    if (!valid_count) return MnemonicError.InvalidWordCount;
    
    // TODO: Validate checksum once we have mnemonic to entropy conversion
}

// Tests
test "extract bits" {
    const data = [_]u8{ 0b10101010, 0b11001100 };
    
    // Extract 11 bits starting at bit 0
    const result = extractBits(&data, 0, 11);
    try testing.expectEqual(@as(u16, 0b10101010110), result);
}

test "entropy to mnemonic - all zeros" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // All zeros entropy should produce "abandon" repeated
    const entropy = [_]u8{0x00} ** 16;
    const mnemonic = try entropyToMnemonic(allocator, &entropy);
    
    // Should be 12 "abandon" words
    try testing.expectEqualStrings("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", mnemonic);
}

test "entropy to mnemonic - all ones" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // All ones entropy
    const entropy = [_]u8{0xFF} ** 16;
    const mnemonic = try entropyToMnemonic(allocator, &entropy);
    
    // Should end with "zoo" words
    try testing.expectEqualStrings("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrap", mnemonic);
}

test "mnemonic to seed - deterministic" {
    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const seed1 = mnemonicToSeed(mnemonic, null);
    const seed2 = mnemonicToSeed(mnemonic, null);
    
    // Same mnemonic should produce same seed
    try testing.expectEqualSlices(u8, &seed1, &seed2);
    
    // With passphrase
    const seed_with_pass = mnemonicToSeed(mnemonic, "TREZOR");
    try testing.expect(!std.mem.eql(u8, &seed1, &seed_with_pass));
    
    // Empty passphrase should equal null passphrase
    const seed_empty = mnemonicToSeed(mnemonic, "");
    try testing.expectEqualSlices(u8, &seed1, &seed_empty);
}

test "invalid entropy sizes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // Test invalid sizes
    const invalid_sizes = [_]usize{ 0, 15, 17, 31, 33 };
    
    for (invalid_sizes) |size| {
        const entropy = try allocator.alloc(u8, size);
        defer allocator.free(entropy);
        @memset(entropy, 0);
        
        const result = entropyToMnemonic(allocator, entropy);
        try testing.expectError(MnemonicError.InvalidEntropy, result);
    }
}

test "word count calculations" {
    try testing.expectEqual(@as(u16, 128), WordCount.twelve.entropyBits());
    try testing.expectEqual(@as(u16, 256), WordCount.twentyfour.entropyBits());
    
    try testing.expectEqual(@as(u8, 4), WordCount.twelve.checksumBits());
    try testing.expectEqual(@as(u8, 8), WordCount.twentyfour.checksumBits());
}