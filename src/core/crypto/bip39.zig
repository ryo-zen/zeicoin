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
    defer std.crypto.utils.secureZero(u8, &entropy); // Clear entropy from stack
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
    
    // Create combined entropy + checksum bytes
    const total_bits = entropy.len * 8 + checksum_bits;
    const total_bytes = (total_bits + 7) / 8; // Round up
    
    var combined = try allocator.alloc(u8, total_bytes);
    defer allocator.free(combined);
    @memset(combined, 0);
    
    // Copy entropy bytes
    @memcpy(combined[0..entropy.len], entropy);
    
    // Add checksum bits to the end
    const checksum_shift: u3 = @intCast(8 - checksum_bits);
    const checksum_masked = checksum_byte >> checksum_shift;
    
    // Place checksum bits after entropy
    const entropy_bits = entropy.len * 8;
    var checksum_bit_count: u8 = 0;
    while (checksum_bit_count < checksum_bits) : (checksum_bit_count += 1) {
        const bit_pos: u3 = @intCast(checksum_bits - 1 - checksum_bit_count);
        const bit = (checksum_masked >> bit_pos) & 1;
        
        const total_bit_index = entropy_bits + checksum_bit_count;
        const byte_index = total_bit_index / 8;
        const bit_offset: u3 = @intCast(7 - (total_bit_index % 8));
        
        if (bit == 1) {
            combined[byte_index] |= (@as(u8, 1) << bit_offset);
        }
    }
    
    // Convert to word indices
    const word_count = total_bits / 11;
    var words = std.ArrayList([]const u8).init(allocator);
    defer words.deinit();
    
    var bit_index: usize = 0;
    var i: usize = 0;
    while (i < word_count) : (i += 1) {
        const word_index = extractBits(combined, bit_index, 11);
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
    defer std.crypto.utils.secureZero(u8, &derived); // Clear intermediate key material
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
    defer std.crypto.utils.secureZero(u8, &expanded); // Clear intermediate expansion
    final_kdf.final(&expanded);

    @memcpy(seed[0..32], expanded[0..32]);

    // Second round for last 32 bytes
    var second_kdf = std.crypto.hash.Blake3.init(.{});
    second_kdf.update("zeicoin-seed-expansion-2");
    second_kdf.update(&derived);
    var expanded2: [32]u8 = undefined;
    defer std.crypto.utils.secureZero(u8, &expanded2); // Clear intermediate expansion
    second_kdf.final(&expanded2);

    @memcpy(seed[32..64], expanded2[0..32]);

    return seed;
}

/// Convert mnemonic back to entropy (needed for checksum validation)
pub fn mnemonicToEntropy(allocator: std.mem.Allocator, mnemonic: []const u8) ![]u8 {
    var words_iter = std.mem.tokenizeScalar(u8, mnemonic, ' ');
    var words = std.ArrayList([]const u8).init(allocator);
    defer words.deinit();
    
    // Split into words
    while (words_iter.next()) |word| {
        try words.append(word);
    }
    
    const word_count = words.items.len;
    if (word_count < 12 or word_count > 24 or word_count % 3 != 0) {
        return MnemonicError.InvalidWordCount;
    }
    
    // Convert words to indices
    var indices = std.ArrayList(u16).init(allocator);
    defer indices.deinit();
    
    for (words.items) |word| {
        var found_index: ?u16 = null;
        for (WORDLIST, 0..) |valid_word, idx| {
            if (std.mem.eql(u8, word, valid_word)) {
                found_index = @intCast(idx);
                break;
            }
        }
        if (found_index == null) return MnemonicError.WordNotInList;
        try indices.append(found_index.?);
    }
    
    // Pack indices into bits
    const total_bits = word_count * 11;
    const checksum_bits = word_count / 3;
    const entropy_bits = total_bits - checksum_bits;
    const entropy_bytes = entropy_bits / 8;
    
    var bit_string = std.ArrayList(u8).init(allocator);
    defer bit_string.deinit();
    
    // Convert indices to bit string
    for (indices.items) |index| {
        const bits: u16 = index;
        var bit_count: u8 = 11;
        while (bit_count > 0) : (bit_count -= 1) {
            const shift_amount: u4 = @intCast(bit_count - 1);
            const bit = (bits >> shift_amount) & 1;
            try bit_string.append(@intCast(bit));
        }
    }
    
    // Extract entropy bytes
    var entropy = try allocator.alloc(u8, entropy_bytes);
    var byte_index: usize = 0;
    var bit_index: usize = 0;
    
    while (byte_index < entropy_bytes) : (byte_index += 1) {
        var byte_val: u8 = 0;
        var i: u8 = 0;
        while (i < 8) : (i += 1) {
            if (bit_index < bit_string.items.len) {
                byte_val = (byte_val << 1) | bit_string.items[bit_index];
                bit_index += 1;
            }
        }
        entropy[byte_index] = byte_val;
    }
    
    // Extract checksum bits
    var checksum_val: u8 = 0;
    var i: u8 = 0;
    while (i < checksum_bits) : (i += 1) {
        if (bit_index < bit_string.items.len) {
            checksum_val = (checksum_val << 1) | bit_string.items[bit_index];
            bit_index += 1;
        }
    }
    
    // Validate checksum using BLAKE3
    var blake3_out: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(entropy, &blake3_out, .{});
    const expected_checksum = blake3_out[0] >> @as(u3, @intCast(8 - checksum_bits));
    
    if (checksum_val != expected_checksum) {
        allocator.free(entropy);
        return MnemonicError.InvalidChecksum;
    }
    
    return entropy;
}

/// Validate a mnemonic phrase
pub fn validateMnemonic(mnemonic: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // Use mnemonicToEntropy for validation (includes checksum validation)
    const entropy = mnemonicToEntropy(allocator, mnemonic) catch |err| switch (err) {
        MnemonicError.InvalidWordCount => return MnemonicError.InvalidWordCount,
        MnemonicError.WordNotInList => return MnemonicError.WordNotInList,
        MnemonicError.InvalidChecksum => return MnemonicError.InvalidChecksum,
        else => return err,
    };
    _ = entropy; // entropy automatically freed by arena
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
    
    // All zeros entropy with BLAKE3 checksum
    const entropy = [_]u8{0x00} ** 16;
    const mnemonic = try entropyToMnemonic(allocator, &entropy);
    
    // ZeiCoin uses BLAKE3, so checksum differs from standard BIP39
    try testing.expectEqualStrings("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon achieve", mnemonic);
}

test "entropy to mnemonic - all ones" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // All ones entropy with BLAKE3 checksum
    const entropy = [_]u8{0xFF} ** 16;
    const mnemonic = try entropyToMnemonic(allocator, &entropy);
    
    // ZeiCoin uses BLAKE3, so checksum differs from standard BIP39
    try testing.expectEqualStrings("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zebra", mnemonic);
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

test "mnemonic to entropy roundtrip" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // Test with known entropy
    const original_entropy = [_]u8{ 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
    
    // Convert to mnemonic
    const mnemonic = try entropyToMnemonic(allocator, &original_entropy);
    
    // Convert back to entropy
    const recovered_entropy = try mnemonicToEntropy(allocator, mnemonic);
    
    // Should match original
    try testing.expectEqualSlices(u8, &original_entropy, recovered_entropy);
}

test "validate mnemonic - valid checksum" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    // Generate valid mnemonic
    const entropy = [_]u8{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    const mnemonic = try entropyToMnemonic(allocator, &entropy);
    
    // Should validate successfully
    try validateMnemonic(mnemonic);
}

test "validate mnemonic - invalid checksum" {
    // Manually construct mnemonic with wrong checksum
    const invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    
    // Should fail checksum validation
    try testing.expectError(MnemonicError.InvalidChecksum, validateMnemonic(invalid_mnemonic));
}

test "validate mnemonic - word not in list" {
    const invalid_mnemonic = "abandon abandon abandon notaword abandon abandon abandon abandon abandon abandon abandon abandon";
    
    try testing.expectError(MnemonicError.WordNotInList, validateMnemonic(invalid_mnemonic));
}

test "validate mnemonic - invalid word count" {
    const invalid_mnemonic = "abandon abandon abandon abandon abandon";
    
    try testing.expectError(MnemonicError.InvalidWordCount, validateMnemonic(invalid_mnemonic));
}

test "mnemonic to entropy - different word counts" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    
    const test_cases = [_]struct { bytes: usize, words: usize }{
        .{ .bytes = 16, .words = 12 },
        .{ .bytes = 20, .words = 15 },
        .{ .bytes = 24, .words = 18 },
        .{ .bytes = 28, .words = 21 },
        .{ .bytes = 32, .words = 24 },
    };
    
    for (test_cases) |case| {
        const entropy = try allocator.alloc(u8, case.bytes);
        defer allocator.free(entropy);
        @memset(entropy, 0x42);
        
        const mnemonic = try entropyToMnemonic(allocator, entropy);
        const recovered = try mnemonicToEntropy(allocator, mnemonic);
        
        try testing.expectEqual(case.bytes, recovered.len);
        try testing.expectEqualSlices(u8, entropy, recovered);
        
        allocator.free(recovered);
    }
}