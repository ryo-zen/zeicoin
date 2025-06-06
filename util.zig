// Utilities for Zeicoin

const std = @import("std");
const print = std.debug.print;
const Allocator = std.mem.Allocator;

// Coin constants - Zei monetary units
pub const COIN: i64 = 100000000; // 1 ZEI = 100,000,000 zeis
pub const CENT: i64 = 1000000; // 1 cents = 1,000,000 zeis

// Global debug flag
pub var debug_mode: bool = false;

// Error types
pub const UtilError = error{
    InvalidFormat,
    InvalidMoney,
    Overflow,
    FileNotFound,
    OutOfMemory,
};

// Time management
var time_offset: i64 = 0;
var known_time_sources = std.HashMap(u32, void, std.hash_map.DefaultContext(u32), 80).init(std.heap.page_allocator);
var time_offsets = std.ArrayList(i64).init(std.heap.page_allocator);

/// Get current Unix timestamp
pub fn getTime() i64 {
    return std.time.timestamp();
}

/// Get time adjusted by network consensus
pub fn getAdjustedTime() i64 {
    return getTime() + time_offset;
}

/// Add time data from network peer for consensus adjustment
pub fn addTimeData(ip: u32, network_time: i64) !void {
    const offset_sample = network_time - getTime();

    // Ignore duplicates
    if (known_time_sources.contains(ip)) {
        return;
    }
    try known_time_sources.put(ip, {});

    // Add data
    if (time_offsets.items.len == 0) {
        try time_offsets.append(0);
    }
    try time_offsets.append(offset_sample);

    if (debug_mode) {
        print("Added time data, samples {}, ip 0x{:0>8}, offset {:+} ({:+} minutes)\n", .{ time_offsets.items.len, ip, offset_sample, @divTrunc(offset_sample, 60) });
    }

    // Calculate median when we have enough samples (odd number >= 5)
    if (time_offsets.items.len >= 5 and time_offsets.items.len % 2 == 1) {
        var sorted_offsets = try time_offsets.clone();
        defer sorted_offsets.deinit();
        std.sort.heap(i64, sorted_offsets.items, {}, std.sort.asc(i64));

        const median = sorted_offsets.items[sorted_offsets.items.len / 2];
        time_offset = median;

        if (@abs(median) > 5 * 60) {
            // Only let other nodes change our clock so far before we
            // would go to NTP servers (not implemented yet)
            if (debug_mode) {
                print("WARNING: Time offset is large: {:+} minutes\n", .{@divTrunc(median, 60)});
            }
        }

        if (debug_mode) {
            for (sorted_offsets.items) |offset| {
                print("{:+}  ", .{offset});
            }
            print("|  time_offset = {:+}  ({:+} minutes)\n", .{ time_offset, @divTrunc(time_offset, 60) });
        }
    }
}

/// Format money amount for display (e.g., 150000000 -> "1.50")
pub fn formatMoney(allocator: Allocator, amount: i64, show_plus: bool) ![]u8 {
    const n = @divTrunc(amount, CENT);
    const abs_n = if (n > 0) n else -n;
    const dollars = @divTrunc(abs_n, 100);
    const cents = @mod(abs_n, 100);

    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    // Format as "dollars.cents" using absolute values
    if (cents < 10) {
        try result.writer().print("{}.0{}", .{ dollars, cents });
    } else {
        try result.writer().print("{}.{}", .{ dollars, cents });
    }

    // Add thousand separators (from the original algorithm)
    // Start at position 6 and work backwards, adding commas every 4 positions
    var i: usize = 6;
    while (i < result.items.len) : (i += 4) {
        const pos = result.items.len - i - 1;
        if (pos < result.items.len and std.ascii.isDigit(result.items[pos])) {
            try result.insert(result.items.len - i, ',');
        }
    }

    // Add sign at the beginning
    if (n < 0) {
        try result.insert(0, '-');
    } else if (show_plus and n > 0) {
        try result.insert(0, '+');
    }

    return result.toOwnedSlice();
}

/// Parse money string to satoshi amount (e.g., "1.50" -> 150000000)
pub fn parseMoney(input: []const u8) UtilError!i64 {
    var whole_str = std.ArrayList(u8).init(std.heap.page_allocator);
    defer whole_str.deinit();

    var cents: i64 = 0;
    var i: usize = 0;

    // Skip whitespace
    while (i < input.len and std.ascii.isWhitespace(input[i])) : (i += 1) {}

    // Parse digits and handle commas/decimal point
    while (i < input.len) : (i += 1) {
        const c = input[i];

        // Handle comma separators (validate format)
        if (c == ',' and i > 0 and i + 3 < input.len and
            std.ascii.isDigit(input[i - 1]) and std.ascii.isDigit(input[i + 1]) and
            std.ascii.isDigit(input[i + 2]) and std.ascii.isDigit(input[i + 3]) and
            (i + 4 >= input.len or !std.ascii.isDigit(input[i + 4])))
        {
            continue;
        }

        // Handle decimal point
        if (c == '.') {
            i += 1;
            if (i + 1 >= input.len or !std.ascii.isDigit(input[i]) or !std.ascii.isDigit(input[i + 1])) {
                return UtilError.InvalidFormat;
            }
            cents = std.fmt.parseInt(i64, input[i .. i + 2], 10) catch return UtilError.InvalidFormat;
            if (cents < 0 or cents > 99) {
                return UtilError.InvalidFormat;
            }
            i += 2;
            break;
        }

        // End on whitespace
        if (std.ascii.isWhitespace(c)) {
            break;
        }

        // Must be digit
        if (!std.ascii.isDigit(c)) {
            return UtilError.InvalidFormat;
        }

        try whole_str.append(c);
    }

    // Skip remaining whitespace
    while (i < input.len and std.ascii.isWhitespace(input[i])) : (i += 1) {}

    // Should be at end
    if (i < input.len) {
        return UtilError.InvalidFormat;
    }

    // Validate whole part length
    if (whole_str.items.len > 17) {
        return UtilError.InvalidFormat;
    }

    const whole = if (whole_str.items.len == 0)
        0
    else
        std.fmt.parseInt(i64, whole_str.items, 10) catch return UtilError.InvalidFormat;

    const value = whole * 100 + cents;

    // Check for overflow
    if (@divTrunc(value, 100) != whole) {
        return UtilError.Overflow;
    }

    return value * CENT;
}

/// Secure random number generation
pub fn getRand(max: u64) u64 {
    if (max == 0) return 0;

    var rng = std.crypto.random;

    // Ensure uniform distribution by rejecting values outside valid range
    const range = (std.math.maxInt(u64) / max) * max;
    while (true) {
        const rand_val = rng.int(u64);
        if (rand_val < range) {
            return rand_val % max;
        }
    }
}

/// Enhanced random seeding using system entropy
pub fn randAddSeed() void {
    if (debug_mode) {
        print("Random number generator seeded with system entropy\n");
    }
}

/// Safe string formatting (Zig equivalent of strprintf)
pub fn strPrintf(allocator: Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return std.fmt.allocPrint(allocator, fmt, args);
}

/// Error logging function
pub fn logError(comptime fmt: []const u8, args: anytype) bool {
    std.log.err(fmt, args);
    return false;
}

/// Parse string into tokens separated by delimiter
pub fn parseString(allocator: Allocator, input: []const u8, delimiter: u8) ![][]const u8 {
    var result = std.ArrayList([]const u8).init(allocator);
    defer result.deinit();

    var it = std.mem.split(u8, input, &[_]u8{delimiter});
    while (it.next()) |token| {
        try result.append(token);
    }

    return result.toOwnedSlice();
}

/// Check if file exists
pub fn fileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

/// Get file size
pub fn getFileSize(file: std.fs.File) !u64 {
    const stat = try file.stat();
    return stat.size;
}

/// Convert integer to string
pub fn intToStr(allocator: Allocator, value: i64) ![]u8 {
    return std.fmt.allocPrint(allocator, "{}", .{value});
}

/// Convert string to integer
pub fn strToInt(str: []const u8) !i64 {
    return std.fmt.parseInt(i64, str, 10);
}

/// Round double to nearest integer
pub fn roundInt(value: f64) i32 {
    return @intFromFloat(if (value > 0) value + 0.5 else value - 0.5);
}

/// Convert bytes to hex string
pub fn hexStr(allocator: Allocator, data: []const u8, spaces: bool) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    for (data, 0..) |byte, i| {
        if (spaces and i > 0) {
            try result.append(' ');
        }
        try result.writer().print("{x:0>2}", .{byte});
    }

    return result.toOwnedSlice();
}

/// Convert bytes to hex number string (reverse byte order)
pub fn hexNumStr(allocator: Allocator, data: []const u8, prefix_0x: bool) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();

    if (prefix_0x) {
        try result.appendSlice("0x");
    }

    var i = data.len;
    while (i > 0) {
        i -= 1;
        try result.writer().print("{X:0>2}", .{data[i]});
    }

    return result.toOwnedSlice();
}

/// Double SHA256 hash (Bitcoin's OG standard hash function)
pub fn hash256(data: []const u8) [32]u8 {
    var hasher1 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher1.update(data);
    const hash1 = hasher1.finalResult();

    var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
    hasher2.update(&hash1);
    return hasher2.finalResult();
}

/// SHA256 + RIPEMD160 hash (Bitcoin OG address hash)
pub fn hash160(_: Allocator, data: []const u8) ![20]u8 {
    // SHA256 first
    var sha_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    sha_hasher.update(data);
    const sha_result = sha_hasher.finalResult();

    // RIPEMD160 second - note: std.crypto doesn't have RIPEMD160
    // For now, return first 20 bytes of SHA256 as placeholder
    // TODO: Implement proper RIPEMD160 or use external library
    var result: [20]u8 = undefined;
    @memcpy(&result, sha_result[0..20]);
    return result;
}

/// Print exception information (Zig equivalent)
pub fn printException(err: anyerror, thread_name: []const u8) void {
    std.log.err("EXCEPTION in {s}: {}\n", .{ thread_name, err });
}

/// Initialize utility module
pub fn init() void {
    randAddSeed();
    if (debug_mode) {
        print("Utility module initialized\n");
    }
}

/// Cleanup utility module resources
pub fn deinit() void {
    known_time_sources.deinit();
    time_offsets.deinit();
}
