// bech32.zig - Bech32 address encoding for ZeiCoin
// Implements BIP 173 Bech32 encoding for human-readable cryptocurrency addresses

const std = @import("std");
const types = @import("types.zig");

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Helper function to convert 8-bit bytes to 5-bit values for Bech32
fn convertBits(allocator: std.mem.Allocator, data: []const u8, fromBits: u8, toBits: u8, pad: bool) ![]u8 {
    var acc: u32 = 0;
    var bits: u8 = 0;
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();
    const maxv = (@as(u32, 1) << @intCast(toBits)) - 1;

    for (data) |value| {
        acc = (acc << @intCast(fromBits)) | @as(u32, value);
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            try result.append(@as(u8, @truncate((acc >> @intCast(bits)) & maxv)));
        }
    }

    if (pad and bits > 0) {
        try result.append(@as(u8, @truncate((acc << @intCast(toBits - bits)) & maxv)));
    } else if (bits >= fromBits or ((acc << @intCast(toBits - bits)) & maxv) != 0) {
        return error.InvalidPadding;
    }

    return result.toOwnedSlice();
}

// Bech32 checksum calculation (simplified BCH code from BIP 173)
fn bech32Polymod(values: []const u8) u32 {
    const GEN = [_]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    for (values) |v| {
        const top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ @as(u32, v);
        for (0..5) |i| {
            if ((top >> @as(u5, @intCast(i))) & 1 != 0) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

// Create checksum for Bech32
fn bech32CreateChecksum(hrp: []const u8, data: []const u8) [6]u8 {
    var values = std.ArrayList(u8).init(std.heap.page_allocator);
    defer values.deinit();

    // Expand human-readable part
    for (hrp) |c| {
        values.append(@as(u8, @intCast(c >> 5))) catch unreachable;
    }
    values.append(0) catch unreachable;
    for (hrp) |c| {
        values.append(@as(u8, @intCast(c & 31))) catch unreachable;
    }
    for (data) |d| {
        values.append(d) catch unreachable;
    }
    for (0..6) |_| {
        values.append(0) catch unreachable;
    }

    const polymod = bech32Polymod(values.items) ^ 1;
    var result: [6]u8 = undefined;
    for (0..6) |i| {
        result[i] = @as(u8, @truncate((polymod >> @as(u5, @intCast(5 * (5 - i)))) & 31));
    }
    return result;
}

// Encode data as Bech32 with human-readable part (hrp)
pub fn encodeBech32(hrp: []const u8, data: []const u8) ![]u8 {
    // Convert 8-bit data to 5-bit
    const data5bit = try convertBits(std.heap.page_allocator, data, 8, 5, true);
    defer std.heap.page_allocator.free(data5bit);

    // Calculate checksum
    const checksum = bech32CreateChecksum(hrp, data5bit);

    // Build the final string
    var result = std.ArrayList(u8).init(std.heap.page_allocator);
    defer result.deinit();

    try result.appendSlice(hrp);
    try result.append('1'); // Separator
    for (data5bit) |d| {
        try result.append(BECH32_CHARSET[d]);
    }
    for (checksum) |c| {
        try result.append(BECH32_CHARSET[c]);
    }

    return result.toOwnedSlice();
}

// Encode with checksum, similar to EncodeBase58Check
pub fn encodeBech32Check(hrp: []const u8, data: []const u8) ![]u8 {
    // In Bech32, the checksum is inherent, so we directly encode
    // If additional checksum is needed (like Base58Check's 4-byte hash),
    // append a hash here before encoding (omitted for pure Bech32)
    return encodeBech32(hrp, data);
}

// Equivalent to Hash160ToAddress, creating a Bech32 address from a hash
pub fn hash160ToAddress(hash160: []const u8, hrp: []const u8) ![]u8 {
    // Add version byte (similar to ADDRESSVERSION in original)
    var data = std.ArrayList(u8).init(std.heap.page_allocator);
    defer data.deinit();

    try data.append(0); // Version byte, e.g., 0 for P2WPKH
    try data.appendSlice(hash160); // Append the 20-byte hash160

    return encodeBech32(hrp, data.items);
}

// Decode Bech32 string (simplified, returns hrp and data without full validation)
pub fn decodeBech32(bech: []const u8) !struct { hrp: []const u8, data: []u8 } {
    // Find separator
    const sepIndex = std.mem.indexOfScalar(u8, bech, '1') orelse return error.InvalidFormat;
    if (sepIndex == 0 or sepIndex + 7 > bech.len) return error.InvalidFormat;

    const hrp = bech[0..sepIndex];
    const dataPart = bech[sepIndex + 1 ..];

    // Convert characters to 5-bit values
    var data5bit = std.ArrayList(u8).init(std.heap.page_allocator);
    defer data5bit.deinit();

    for (dataPart) |c| {
        const idx = std.mem.indexOfScalar(u8, BECH32_CHARSET, c) orelse return error.InvalidCharacter;
        try data5bit.append(@as(u8, @intCast(idx)));
    }

    // TODO: Validate checksum here (omitted for brevity, should check polymod)

    // Convert 5-bit back to 8-bit
    const data8bit = try convertBits(std.heap.page_allocator, data5bit.items[0 .. data5bit.items.len - 6], 5, 8, false);
    return .{ .hrp = hrp, .data = data8bit };
}

// Decode with checksum validation, similar to DecodeBase58Check
pub fn decodeBech32Check(bech: []const u8) !struct { hrp: []const u8, data: []u8 } {
    const result = try decodeBech32(bech);
    // TODO: Add full checksum validation using bech32Polymod
    // For now, assume basic decoding; in practice, verify the last 6 characters as checksum
    return result;
}

// ===== ZeiCoin-specific address encoding/decoding =====

/// Encode a ZeiCoin address to bech32 format
pub fn encodeAddress(allocator: std.mem.Allocator, address: types.Address, network: types.NetworkType) ![]u8 {
    // Choose HRP based on network
    const hrp = switch (network) {
        .testnet => "tzei",
        .mainnet => "zei",
    };
    
    // Prepare data: version byte + 31-byte hash
    var data: [32]u8 = undefined;
    data[0] = address.version;
    @memcpy(data[1..], &address.hash);
    
    // Convert to 5-bit encoding
    const data5bit = try convertBits(allocator, &data, 8, 5, true);
    defer allocator.free(data5bit);
    
    // Calculate checksum
    const checksum = bech32CreateChecksum(hrp, data5bit);
    
    // Build result string
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    
    try result.appendSlice(hrp);
    try result.append('1'); // Separator
    
    for (data5bit) |d| {
        try result.append(BECH32_CHARSET[d]);
    }
    
    for (checksum) |c| {
        try result.append(BECH32_CHARSET[c]);
    }
    
    return result.toOwnedSlice();
}

/// Decode a bech32 address string to a ZeiCoin address
pub fn decodeAddress(allocator: std.mem.Allocator, bech32_str: []const u8) !types.Address {
    _ = allocator; // Will use for intermediate allocations
    
    // Find separator
    const sep_pos = std.mem.indexOfScalar(u8, bech32_str, '1') orelse return error.InvalidFormat;
    if (sep_pos == 0 or sep_pos + 7 > bech32_str.len) return error.InvalidFormat;
    
    const hrp = bech32_str[0..sep_pos];
    const data_part = bech32_str[sep_pos + 1 ..];
    
    // Verify HRP
    const network = if (std.mem.eql(u8, hrp, "zei"))
        types.NetworkType.mainnet
    else if (std.mem.eql(u8, hrp, "tzei"))
        types.NetworkType.testnet
    else
        return error.InvalidHRP;
    
    // Convert from bech32 charset to 5-bit values
    var data5bit: [256]u8 = undefined; // Max reasonable address length
    var data5bit_len: usize = 0;
    
    for (data_part) |c| {
        const idx = std.mem.indexOfScalar(u8, BECH32_CHARSET, c) orelse return error.InvalidCharacter;
        data5bit[data5bit_len] = @intCast(idx);
        data5bit_len += 1;
    }
    
    // Verify checksum
    var values: [512]u8 = undefined; // Temporary buffer for checksum validation
    var values_len: usize = 0;
    
    // Expand HRP
    for (hrp) |c| {
        values[values_len] = @intCast(c >> 5);
        values_len += 1;
    }
    values[values_len] = 0;
    values_len += 1;
    for (hrp) |c| {
        values[values_len] = @intCast(c & 31);
        values_len += 1;
    }
    
    // Add data
    @memcpy(values[values_len..values_len + data5bit_len], data5bit[0..data5bit_len]);
    values_len += data5bit_len;
    
    if (bech32Polymod(values[0..values_len]) != 1) {
        return error.InvalidChecksum;
    }
    
    // Remove checksum (last 6 5-bit values)
    const data5bit_no_checksum = data5bit[0 .. data5bit_len - 6];
    
    // Convert back to 8-bit
    const data8bit = try convertBits(std.heap.page_allocator, data5bit_no_checksum, 5, 8, false);
    defer std.heap.page_allocator.free(data8bit);
    
    // Extract version and hash
    if (data8bit.len != 32) return error.InvalidLength;
    
    const address = types.Address{
        .version = data8bit[0],
        .hash = data8bit[1..32].*,
    };
    
    // Verify we're on the right network
    _ = network; // Could add network validation if needed
    
    return address;
}

/// Get the string representation of an address for display
pub fn addressToString(allocator: std.mem.Allocator, address: types.Address, network: types.NetworkType) ![]u8 {
    return encodeAddress(allocator, address, network);
}

/// Parse an address from string (either bech32 or legacy hex)
pub fn parseAddress(allocator: std.mem.Allocator, str: []const u8) !types.Address {
    // Try bech32 first
    if (std.mem.indexOfScalar(u8, str, '1')) |_| {
        return decodeAddress(allocator, str) catch {
            // Fall back to hex parsing
            return parseHexAddress(str);
        };
    }
    
    // Try hex format
    return parseHexAddress(str);
}

/// Parse legacy hex address format
fn parseHexAddress(hex_str: []const u8) !types.Address {
    var bytes: [32]u8 = undefined;
    
    // Handle "0x" prefix if present
    const clean_hex = if (std.mem.startsWith(u8, hex_str, "0x"))
        hex_str[2..]
    else
        hex_str;
    
    // Convert hex to bytes
    if (clean_hex.len != 64) return error.InvalidLength;
    
    _ = std.fmt.hexToBytes(&bytes, clean_hex) catch return error.InvalidHex;
    
    // For legacy hex addresses, check if it starts with version byte (00)
    if (bytes[0] == 0x00) {
        // This is a versioned address in hex format
        return types.Address{
            .version = bytes[0],
            .hash = bytes[1..32].*,
        };
    } else {
        // This is a true legacy address - use the full hash
        return types.Address{
            .version = 0,
            .hash = bytes[0..31].*,
        };
    }
}
