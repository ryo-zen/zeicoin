// bech32.zig - Bech32 address encoding for ZeiCoin
// Implements BIP 173 with allocator-based memory management

const std = @import("std");
const types = @import("../types/types.zig");

// Bech32 character set (no 1, b, i, o)
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Generator for Bech32 checksum
const BECH32_GEN = [_]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

// Convert between bit groups (e.g., 8-bit bytes to 5-bit values)
fn convertBits(allocator: std.mem.Allocator, data: []const u8, from_bits: u8, to_bits: u8, pad: bool) ![]u8 {
    var acc: u32 = 0;
    var bits: u5 = 0;
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    const maxv = (@as(u32, 1) << @as(u5, @intCast(to_bits))) - 1;
    const max_acc = (@as(u32, 1) << @as(u5, @intCast(from_bits + to_bits - 1))) - 1;

    for (data) |value| {
        if (@as(u32, value) >> @as(u5, @intCast(from_bits)) != 0) return error.InvalidData;
        acc = ((acc << @as(u5, @intCast(from_bits))) | value) & max_acc;
        bits += @as(u5, @intCast(from_bits));
        while (bits >= to_bits) {
            bits -= @as(u5, @intCast(to_bits));
            try result.append(@as(u8, @intCast((acc >> bits) & maxv)));
        }
    }

    if (pad) {
        if (bits > 0) try result.append(@as(u8, @intCast((acc << @as(u5, @intCast(to_bits - bits))) & maxv)));
    } else if (bits >= from_bits or ((acc << @as(u5, @intCast(to_bits - bits))) & maxv) != 0) {
        return error.InvalidPadding;
    }

    return result.toOwnedSlice();
}

// Compute Bech32 checksum
fn bech32Polymod(values: []const u8) u32 {
    var chk: u32 = 1;
    for (values) |value| {
        const b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ value;
        for (0..5) |i| {
            if ((b >> @as(u5, @intCast(i))) & 1 != 0) {
                chk ^= BECH32_GEN[i];
            }
        }
    }
    return chk;
}

// Create checksum for Bech32
fn bech32CreateChecksum(allocator: std.mem.Allocator, hrp: []const u8, data: []const u8) ![6]u8 {
    var values = std.ArrayList(u8).init(allocator);
    defer values.deinit();

    // Expand human-readable part
    for (hrp) |c| {
        try values.append(@as(u8, @intCast(c >> 5)));
    }
    try values.append(0);
    for (hrp) |c| {
        try values.append(@as(u8, @intCast(c & 31)));
    }
    for (data) |d| {
        try values.append(d);
    }
    for (0..6) |_| {
        try values.append(0);
    }

    const polymod = bech32Polymod(values.items) ^ 1;
    var checksum: [6]u8 = undefined;
    for (0..6) |i| {
        checksum[i] = @as(u8, @intCast((polymod >> @as(u5, @intCast(5 * (5 - i)))) & 31));
    }
    return checksum;
}

// Encode data as Bech32 with human-readable part (hrp)
pub fn encodeBech32(allocator: std.mem.Allocator, hrp: []const u8, data: []const u8) ![]u8 {
    // Convert 8-bit data to 5-bit
    const data5bit = try convertBits(allocator, data, 8, 5, true);
    defer allocator.free(data5bit);

    // Calculate checksum
    const checksum = try bech32CreateChecksum(allocator, hrp, data5bit);

    // Build the final string
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    try result.appendSlice(hrp);
    try result.append('1');
    for (data5bit) |d| {
        try result.append(BECH32_CHARSET[d]);
    }
    for (checksum) |c| {
        try result.append(BECH32_CHARSET[c]);
    }

    return result.toOwnedSlice();
}

// Encode with checksum, similar to EncodeBase58Check
pub fn encodeBech32Check(allocator: std.mem.Allocator, hrp: []const u8, data: []const u8) ![]u8 {
    // In Bech32, the checksum is inherent, so we directly encode
    // If additional checksum is needed (like Base58Check's 4-byte hash),
    // append a hash here before encoding (omitted for pure Bech32)
    return encodeBech32(allocator, hrp, data);
}

// Create a Bech32 address from a BLAKE3 hash (modern, fast address generation)
pub fn hash160ToAddress(allocator: std.mem.Allocator, hash160: []const u8, hrp: []const u8) ![]u8 {
    // Add version byte (similar to ADDRESSVERSION in original)
    var data = std.ArrayList(u8).init(allocator);
    defer data.deinit();

    try data.append(0); // Version byte, e.g., 0 for P2WPKH
    try data.appendSlice(hash160); // Append the 20-byte BLAKE3 hash

    return encodeBech32(allocator, hrp, data.items);
}

/// Verifies a Bech32 checksum. This is a private helper that does not allocate.
/// It constructs the checksum data on the stack and checks if the polymod is 1.
fn bech32VerifyChecksum(hrp: []const u8, data_5bit_with_checksum: []const u8) bool {
    // A bech32 string is at most 90 chars. The buffer for polymod calculation
    // needs space for expanded HRP and data. Max size is ~173 for a valid string.
    // A 200-byte buffer is safe and avoids heap allocation for this check.
    var values_buf: [200]u8 = undefined;
    var values_len: usize = 0;

    // These appends cannot fail given the 90-char limit checked by callers.
    for (hrp) |c| {
        values_buf[values_len] = @as(u8, @intCast(c >> 5));
        values_len += 1;
    }
    values_buf[values_len] = 0;
    values_len += 1;
    for (hrp) |c| {
        values_buf[values_len] = @as(u8, @intCast(c & 31));
        values_len += 1;
    }
    for (data_5bit_with_checksum) |d| {
        values_buf[values_len] = d;
        values_len += 1;
    }

    return bech32Polymod(values_buf[0..values_len]) == 1;
}

// Decode Bech32 string (simplified, returns hrp and data without full validation)
pub fn decodeBech32(allocator: std.mem.Allocator, bech: []const u8) !struct { hrp: []const u8, data: []u8 } {
    // Find separator
    const sepIndex = std.mem.indexOfScalar(u8, bech, '1') orelse return error.InvalidFormat;
    if (sepIndex == 0 or sepIndex + 7 > bech.len or bech.len > 90) return error.InvalidFormat;

    const hrp = bech[0..sepIndex];
    const dataPart = bech[sepIndex + 1 ..];

    // Convert characters to 5-bit values
    var data5bit = std.ArrayList(u8).init(allocator);
    defer data5bit.deinit();

    for (dataPart) |c| {
        const idx = std.mem.indexOfScalar(u8, BECH32_CHARSET, c) orelse return error.InvalidCharacter;
        try data5bit.append(@as(u8, @intCast(idx)));
    }

    if (!bech32VerifyChecksum(hrp, data5bit.items)) return error.InvalidChecksum;

    // Convert 5-bit back to 8-bit
    const data8bit = try convertBits(allocator, data5bit.items[0 .. data5bit.items.len - 6], 5, 8, false);
    return .{ .hrp = hrp, .data = data8bit };
}

// Decode with checksum validation, similar to DecodeBase58Check
pub fn decodeBech32Check(allocator: std.mem.Allocator, bech: []const u8) !struct { hrp: []const u8, data: []u8 } {
    // For Bech32, standard decoding includes checksum validation.
    return decodeBech32(allocator, bech);
}

// ===== ZeiCoin-specific address encoding/decoding =====

/// Encode a ZeiCoin address to bech32 string
pub fn encodeAddress(allocator: std.mem.Allocator, address: types.Address, network: types.NetworkType) ![]u8 {
    // Select HRP based on network
    const hrp = switch (network) {
        .testnet => "tzei",
        .mainnet => "zei",
    };
    
    // Combine version and hash into 32-byte payload
    var payload: [32]u8 = undefined;
    payload[0] = address.version;
    @memcpy(payload[1..], &address.hash);
    
    return encodeBech32(allocator, hrp, &payload);
}

/// Decode a bech32 address string to a ZeiCoin address
pub fn decodeAddress(allocator: std.mem.Allocator, bech32_str: []const u8) !types.Address {
    // Find separator
    const sep_pos = std.mem.indexOfScalar(u8, bech32_str, '1') orelse return error.InvalidFormat;
    if (sep_pos == 0 or sep_pos + 7 > bech32_str.len or bech32_str.len > 90) return error.InvalidFormat;

    const hrp = bech32_str[0..sep_pos];
    const data_part = bech32_str[sep_pos + 1 ..];
    
    // Verify HRP matches current network
    const expected_hrp = switch (types.CURRENT_NETWORK) {
        .testnet => "tzei",
        .mainnet => "zei",
    };
    if (!std.mem.eql(u8, hrp, expected_hrp)) {
        return error.InvalidHRP;
    }
    
    // Convert from bech32 charset to 5-bit values
    var data5bit = std.ArrayList(u8).init(allocator);
    defer data5bit.deinit();
    for (data_part) |c| {
        const idx = std.mem.indexOfScalar(u8, BECH32_CHARSET, c) orelse return error.InvalidCharacter;
        try data5bit.append(@intCast(idx));
    }
    
    // Verify checksum
    if (!bech32VerifyChecksum(hrp, data5bit.items)) return error.InvalidChecksum;
    
    // Remove checksum (last 6 5-bit values)
    const data5bit_no_checksum = data5bit.items[0 .. data5bit.items.len - 6];
    
    // Convert back to 8-bit
    const data8bit = try convertBits(allocator, data5bit_no_checksum, 5, 8, false);
    defer allocator.free(data8bit);
    
    // Extract version and hash
    if (data8bit.len != 32) return error.InvalidLength;
    
    var address = types.Address{
        .version = data8bit[0],
        .hash = undefined,
    };
    @memcpy(&address.hash, data8bit[1..]);
    
    return address;
}

/// Parse an address from string (either bech32 or legacy hex)
pub fn parseAddress(allocator: std.mem.Allocator, str: []const u8) !types.Address {
    // Try bech32 first by checking for the separator '1'
    if (std.mem.indexOf(u8, str, "1")) |_| {
        return decodeAddress(allocator, str) catch {
            // Fall back to hex parsing
            return parseHexAddress(str);
        };
    }
    return parseHexAddress(str);
}

/// Parse legacy hex address format.
/// A hex address is expected to be 64 characters, representing a 32-byte payload
/// consisting of a 1-byte version and a 31-byte hash.
fn parseHexAddress(hex_str: []const u8) !types.Address {
    // Handle "0x" prefix if present
    const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x"))
        hex_str[2..]
    else
        hex_str;

    if (clean_hex.len != 64) return error.InvalidLength;

    var payload: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&payload, clean_hex) catch return error.InvalidHex;

    var address = types.Address{
        .version = payload[0],
        .hash = undefined,
    };
    @memcpy(&address.hash, payload[1..]);
    return address;
}

// ===== Tests =====

test "bech32 encoding and decoding" {
    const allocator = std.testing.allocator;
    
    // Test address
    const address = types.Address{
        .version = 0,
        .hash = [_]u8{0x14} ** 31,
    };
    
    // Encode
    const encoded = try encodeAddress(allocator, address, .testnet);
    defer allocator.free(encoded);
    
    // Should start with "tzei1"
    try std.testing.expect(std.mem.startsWith(u8, encoded, "tzei1"));
    
    // Decode
    const decoded = try decodeAddress(allocator, encoded);
    
    // Should match
    try std.testing.expectEqual(address.version, decoded.version);
    try std.testing.expectEqualSlices(u8, &address.hash, &decoded.hash);
}

test "hex address parsing" {
    const allocator = std.testing.allocator;
    
    // Test hex address (version 0 + 31 bytes of 0x14)
    const hex = "00" ++ "14" ** 31;
    
    const address = try parseAddress(allocator, hex);
    try std.testing.expectEqual(@as(u8, 0), address.version);
    try std.testing.expectEqual(@as(u8, 0x14), address.hash[0]);
}

test "bech32 checksum validation" {
    const allocator = std.testing.allocator;
    
    // Valid TestNet address
    const valid = "tzei1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfx6kfn";
    const addr = try decodeAddress(allocator, valid);
    try std.testing.expectEqual(@as(u8, 0), addr.version);
    
    // Invalid checksum
    const invalid = "tzei1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsd5c0a8";
    try std.testing.expectError(error.InvalidChecksum, decodeAddress(allocator, invalid));
}

test "network HRP validation" {
    const allocator = std.testing.allocator;
    
    // MainNet address on TestNet should fail
    const mainnet_addr = "zei1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqscamelc";
    try std.testing.expectError(error.InvalidHRP, decodeAddress(allocator, mainnet_addr));
}

test "bech32 edge cases" {
    const allocator = std.testing.allocator;
    
    // Test maximum length (90 characters)
    const too_long = "tzei1" ++ ("q" ** 85);
    try std.testing.expectError(error.InvalidChecksum, decodeAddress(allocator, too_long));
    
    // Test empty HRP
    try std.testing.expectError(error.InvalidFormat, decodeAddress(allocator, "1qqqqqqq"));
    
    // Test missing separator
    try std.testing.expectError(error.InvalidFormat, decodeAddress(allocator, "tzeiqqqqqqq"));
    
    // Test invalid characters
    try std.testing.expectError(error.InvalidCharacter, decodeAddress(allocator, "tzei1qqqqbbbbb"));
    
    // Test too short (no checksum)
    try std.testing.expectError(error.InvalidFormat, decodeAddress(allocator, "tzei1qq"));
}

test "hex address edge cases" {
    const allocator = std.testing.allocator;
    
    // Test with 0x prefix
    const with_prefix = "0x00" ++ "14" ** 31;
    const addr1 = try parseAddress(allocator, with_prefix);
    try std.testing.expectEqual(@as(u8, 0), addr1.version);
    
    // Test invalid hex length
    try std.testing.expectError(error.InvalidLength, parseAddress(allocator, "00112233"));
    try std.testing.expectError(error.InvalidLength, parseAddress(allocator, "00" ++ "11" ** 32));
    
    // Test invalid hex characters
    try std.testing.expectError(error.InvalidHex, parseAddress(allocator, "00" ++ "ZZ" ** 31));
}

test "address round-trip encoding" {
    const allocator = std.testing.allocator;
    
    // Test various address versions
    const versions = [_]u8{0, 1, 5, 127, 255};
    
    for (versions) |version| {
        var address = types.Address{
            .version = version,
            .hash = undefined,
        };
        // Fill hash with pattern
        for (&address.hash, 0..) |*byte, i| {
            byte.* = @as(u8, @intCast(i % 256));
        }
        
        // Encode to bech32
        const encoded = try encodeAddress(allocator, address, .testnet);
        defer allocator.free(encoded);
        
        // Decode back
        const decoded = try decodeAddress(allocator, encoded);
        
        // Should match exactly
        try std.testing.expectEqual(address.version, decoded.version);
        try std.testing.expectEqualSlices(u8, &address.hash, &decoded.hash);
    }
}

test "bech32 case sensitivity" {
    const allocator = std.testing.allocator;
    
    // Bech32 addresses should be case-insensitive for the HRP
    // but the data part uses lowercase only
    const valid_lower = "tzei1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfx6kfn";
    
    // This should work (lowercase)
    _ = try decodeAddress(allocator, valid_lower);
    
    // Mixed case in data part should fail
    const mixed_case = "tzei1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqFX6KFN";
    try std.testing.expectError(error.InvalidCharacter, decodeAddress(allocator, mixed_case));
}