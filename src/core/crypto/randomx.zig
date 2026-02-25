// randomx.zig - RandomX integration for ZeiCoin proof-of-work
const std = @import("std");
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.crypto);

pub const RandomXError = error{
    InitFailed,
    HashFailed,
    InvalidMode,
    ProcessFailed,
    InvalidInput,
    ProcessTimeout,
};

pub const RandomXMode = enum {
    light, // 256MB memory - used for TestNet
    fast, // 2GB memory - used for MainNet
};

// RandomX context using keep-alive subprocess
pub const RandomXContext = struct {
    allocator: Allocator,
    io: std.Io,
    key: []u8,
    mode: RandomXMode,

    // Keep-alive subprocess state
    helper_process: ?std.process.Child,
    stdin_writer: ?std.Io.File,
    stdout_reader: ?std.Io.File,

    pub fn init(allocator: Allocator, io: std.Io, key: []const u8, mode: RandomXMode) !RandomXContext {
        const key_copy = try allocator.dupe(u8, key);
        errdefer allocator.free(key_copy);

        // Resolve helper path
        const exe_path = std.Io.Dir.realPathFileAlloc(std.Io.Dir.cwd(), io, "./randomx/randomx_helper", allocator) catch |err| {
            log.info("Failed to resolve RandomX helper path: {}", .{err});
            return RandomXError.ProcessFailed;
        };
        defer allocator.free(exe_path);

        // Spawn helper in server mode (no args = server mode)
        const argv = &[_][]const u8{exe_path};
        var child = std.process.spawn(io, .{
            .argv = argv,
            .stdin = .pipe,   // We write to this
            .stdout = .pipe,  // We read from this
            .stderr = .ignore,
        }) catch |err| {
            log.info("Failed to spawn RandomX helper: {}", .{err});
            return RandomXError.ProcessFailed;
        };

        return RandomXContext{
            .allocator = allocator,
            .io = io,
            .key = key_copy,
            .mode = mode,
            .helper_process = child,
            .stdin_writer = if (child.stdin) |s| s else null,
            .stdout_reader = if (child.stdout) |s| s else null,
        };
    }

    pub fn deinit(self: *RandomXContext) void {
        self.allocator.free(self.key);

        if (self.helper_process) |*process| {
            // Send exit command
            if (self.stdin_writer) |file| {
                var write_buf: [8]u8 = undefined;
                var writer = file.writer(self.io, &write_buf);
                const exit_cmd = "exit\n";
                writer.interface.writeAll(exit_cmd) catch {};
                writer.flush() catch {};
            }

            // Wait for graceful exit (with short timeout)
            _ = process.wait(self.io) catch {
                // Force kill if timeout
                process.kill(self.io);
            };
        }
    }

    pub fn hash(self: *RandomXContext, input: []const u8, output: *[32]u8) !void {
        return self.hashWithDifficulty(input, output, 1);
    }

    pub fn hashWithDifficulty(self: *RandomXContext, input: []const u8, output: *[32]u8, difficulty_bytes: u8) !void {
        // Validate subprocess is alive
        if (self.helper_process == null or self.stdin_writer == null or self.stdout_reader == null) {
            return RandomXError.ProcessFailed;
        }

        // Convert input to hex string
        var hex_input = try self.allocator.alloc(u8, input.len * 2);
        defer self.allocator.free(hex_input);

        for (input, 0..) |byte, i| {
            _ = std.fmt.bufPrint(hex_input[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
        }

        // Get mode string
        const mode_str = if (self.mode == .light) "light" else "fast";

        // Format request: hex_input:hex_key:difficulty:mode\n
        var request_buf: [16384]u8 = undefined;
        const request = std.fmt.bufPrint(&request_buf, "{s}:{s}:{d}:{s}\n", .{ hex_input, self.key, difficulty_bytes, mode_str }) catch {
            return RandomXError.InvalidInput;
        };

        // Write request to stdin
        const stdin_file = self.stdin_writer.?;
        var write_buf: [16384]u8 = undefined;
        var writer = stdin_file.writer(self.io, &write_buf);
        writer.interface.writeAll(request) catch |err| {
            log.info("Failed to write to RandomX helper: {}", .{err});
            return RandomXError.ProcessFailed;
        };
        writer.flush() catch |err| {
            log.info("Failed to flush RandomX helper stdin: {}", .{err});
            return RandomXError.ProcessFailed;
        };

        // Read response from stdout
        const stdout_file = self.stdout_reader.?;
        var read_buf: [256]u8 = undefined;
        var reader = stdout_file.reader(self.io, &read_buf);
        const response = reader.interface.takeDelimiterExclusive('\n') catch |err| {
            log.info("Failed to read from RandomX helper: {}", .{err});
            return RandomXError.ProcessFailed;
        };

        // Check for error response
        if (std.mem.startsWith(u8, response, "ERROR:")) {
            log.info("RandomX helper error: {s}", .{response});
            return RandomXError.HashFailed;
        }

        // Parse response: hash_hex:meets_difficulty
        const colon_pos = std.mem.indexOf(u8, response, ":") orelse {
            log.info("Failed to find colon in RandomX output: {s}", .{response});
            return RandomXError.HashFailed;
        };
        const hash_hex = response[0..colon_pos];

        if (hash_hex.len != 64) {
            log.info("Invalid hash length: {} (expected 64)", .{hash_hex.len});
            return RandomXError.HashFailed;
        }

        // Convert hex hash to bytes
        for (0..32) |i| {
            const hex_byte = hash_hex[i * 2 .. i * 2 + 2];
            output[i] = std.fmt.parseInt(u8, hex_byte, 16) catch return RandomXError.HashFailed;
        }
    }
};

// Check if hash meets difficulty target (configurable leading zeros) - Legacy function
pub fn hashMeetsDifficulty(hash: [32]u8, difficulty_bytes: u8) bool {
    if (difficulty_bytes == 0 or difficulty_bytes > 32) return false;

    // Check if first N bytes are zero
    for (0..difficulty_bytes) |i| {
        if (hash[i] != 0) return false;
    }

    return true;
}

// Check if hash meets new dynamic difficulty target
pub fn hashMeetsDifficultyTarget(hash: [32]u8, target: @import("../types/types.zig").DifficultyTarget) bool {
    return target.meetsDifficulty(hash);
}

// Helper to create blockchain-specific RandomX key
pub fn createRandomXKey(chain_id: []const u8) [32]u8 {
    var key: [32]u8 = undefined;
    const key_string = std.fmt.allocPrint(
        std.heap.page_allocator,
        "ZeiCoin-{s}-RandomX",
        .{chain_id},
    ) catch "ZeiCoin-MainNet-RandomX";
    defer std.heap.page_allocator.free(key_string);

    // Hash the key string to get fixed-size key
    std.crypto.hash.sha2.Sha256.hash(key_string, &key, .{});
    return key;
}

test "RandomX integration" {
    // Test key generation
    const key = createRandomXKey("TestNet");
    try std.testing.expect(key.len == 32);

    // Test difficulty checking
    var easy_hash: [32]u8 = .{0} ** 32;
    easy_hash[0] = 0x00;
    easy_hash[1] = 0xFF;
    try std.testing.expect(hashMeetsDifficulty(easy_hash, 1));
    try std.testing.expect(!hashMeetsDifficulty(easy_hash, 2));

    const hard_hash: [32]u8 = .{0xFF} ** 32;
    try std.testing.expect(!hashMeetsDifficulty(hard_hash, 1));
}

test "RandomX keep-alive subprocess performance" {
    const allocator = std.testing.allocator;
    const io = std.Io.default();

    // Create RandomX key
    const key = createRandomXKey("TestNet");
    var hex_key: [64]u8 = undefined;
    for (key, 0..) |byte, i| {
        _ = std.fmt.bufPrint(hex_key[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
    }

    // Initialize context (spawns helper once)
    var ctx = try RandomXContext.init(allocator, io, &hex_key, .light);
    defer ctx.deinit();

    std.debug.print("\n🧪 Testing keep-alive subprocess with 50 hashes...\n", .{});

    var timer = try std.time.Timer.start();

    // Hash 50 inputs using same subprocess
    for (0..50) |i| {
        var input: [32]u8 = undefined;
        std.mem.writeInt(u64, input[0..8], i, .little);

        var output: [32]u8 = undefined;
        try ctx.hashWithDifficulty(&input, &output, 0);

        // Verify hash is valid (not all zeros, not all 0xFF)
        var all_zero = true;
        var all_ff = true;
        for (output) |byte| {
            if (byte != 0) all_zero = false;
            if (byte != 0xFF) all_ff = false;
        }
        try std.testing.expect(!all_zero);
        try std.testing.expect(!all_ff);
    }

    const elapsed_ms = timer.read() / std.time.ns_per_ms;
    const per_hash = @as(f64, @floatFromInt(elapsed_ms)) / 50.0;

    std.debug.print("✅ Completed 50 hashes in {}ms (~{d:.1}ms per hash)\n", .{ elapsed_ms, per_hash });
    std.debug.print("   Old way (spawn per hash): ~25 seconds (500ms per hash)\n", .{});
    std.debug.print("   New way (keep-alive): {}ms total\n", .{elapsed_ms});

    // Performance check: should complete in < 5 seconds
    // Old way: 50 * 500ms = 25 seconds
    // New way: 500ms init + 50 * 5ms = ~750ms
    if (elapsed_ms < 5000) {
        std.debug.print("🎉 SUCCESS! Keep-alive subprocess is working ({d:.0}x faster)!\n", .{@as(f64, 25000.0) / @as(f64, @floatFromInt(elapsed_ms))});
    } else {
        std.debug.print("⚠️  WARNING: Slower than expected, may still be spawning per hash\n", .{});
    }

    try std.testing.expect(elapsed_ms < 10000); // Should complete in < 10 seconds
}
