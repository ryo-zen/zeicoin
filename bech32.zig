const std = @import("std");

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const ADDRESSVERSION = 0; // Placeholder for version byte, adjust as needed

// Helper function to convert 8-bit bytes to 5-bit values for Bech32
fn convertBits(data: []const u8, fromBits: u8, toBits: u8, pad: bool) ![]u8 {
    var acc: u32 = 0;
    var bits: u8 = 0;
    var result = std.ArrayList(u8).init(std.heap.page_allocator);
    defer result.deinit();
    const maxv = (@as(u32, 1) << toBits) - 1;

    for (data) |value| {
        acc = (acc << fromBits) | @as(u32, value);
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            try result.append(@as(u8, @truncate((acc >> bits) & maxv)));
        }
    }

    if (pad and bits > 0) {
        try result.append(@as(u8, @truncate((acc << (toBits - bits)) & maxv)));
    } else if (bits >= fromBits or ((acc << (toBits - bits)) & maxv) != 0) {
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
    const data5bit = try convertBits(data, 8, 5, true);
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

    try data.append(ADDRESSVERSION); // Version byte, e.g., 0 for P2WPKH
    try data.appendSlice(hash160);   // Append the 20-byte hash160

    return encodeBech32(hrp, data.items);
}

// Decode Bech32 string (simplified, returns hrp and data without full validation)
pub fn decodeBech32(bech: []const u8) !struct { hrp: []const u8, data: []u8 } {
    // Find separator
    const sepIndex = std.mem.indexOfScalar(u8, bech, '1') orelse return error.InvalidFormat;
    if (sepIndex == 0 or sepIndex + 7 > bech.len) return error.InvalidFormat;

    const hrp = bech[0..sepIndex];
    const dataPart = bech[sepIndex + 1..];

    // Convert characters to 5-bit values
    var data5bit = std.ArrayList(u8).init(std.heap.page_allocator);
    defer data5bit.deinit();

    for (dataPart) |c| {
        const idx = std.mem.indexOfScalar(u8, BECH32_CHARSET, c) orelse return error.InvalidCharacter;
        try data5bit.append(@as(u8, @intCast(idx)));
    }

    // TODO: Validate checksum here (omitted for brevity, should check polymod)

    // Convert 5-bit back to 8-bit
    const data8bit = try convertBits(data5bit.items[0..data5bit.items.len - 6], 5, 8, false);
    return .{ .hrp = hrp, .data = data8bit };
}

// Decode with checksum validation, similar to DecodeBase58Check
pub fn decodeBech32Check(bech: []const u8) !struct { hrp: []const u8, data: []u8 } {
    const result = try decodeBech32(bech);
    // TODO: Add full checksum validation using bech32Polymod
    // For now, assume basic decoding; in practice, verify the last 6 characters as checksum
    return result;
}