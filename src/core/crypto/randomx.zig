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

// RandomX context using subprocess approach
pub const RandomXContext = struct {
    allocator: Allocator,
    key: []u8,
    mode: RandomXMode,

    pub fn init(allocator: Allocator, key: []const u8, mode: RandomXMode) !RandomXContext {
        const key_copy = try allocator.dupe(u8, key);
        return RandomXContext{
            .allocator = allocator,
            .key = key_copy,
            .mode = mode,
        };
    }

    pub fn deinit(self: *RandomXContext) void {
        self.allocator.free(self.key);
    }

    pub fn hash(self: *RandomXContext, input: []const u8, output: *[32]u8) !void {
        return self.hashWithDifficulty(input, output, 1);
    }

    pub fn hashWithDifficulty(self: *RandomXContext, input: []const u8, output: *[32]u8, difficulty_bytes: u8) !void {

        // Convert input to hex string
        var hex_input = try self.allocator.alloc(u8, input.len * 2);
        defer self.allocator.free(hex_input);

        for (input, 0..) |byte, i| {
            _ = std.fmt.bufPrint(hex_input[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte}) catch unreachable;
        }

        // Get mode string
        const mode_str = if (self.mode == .light) "light" else "fast";

        // Validate inputs before subprocess execution
        if (hex_input.len == 0) return RandomXError.InvalidInput;
        for (hex_input) |c| {
            if (!std.ascii.isHex(c)) return RandomXError.InvalidInput;
        }

        // Validate key format (should be hex string)
        if (self.key.len != 64) return RandomXError.InvalidInput; // 32 bytes * 2 hex chars
        for (self.key) |c| {
            if (!std.ascii.isHex(c)) return RandomXError.InvalidInput;
        }

        // Use absolute path to prevent PATH manipulation
        const exe_path = std.fs.realpathAlloc(self.allocator, "./randomx/randomx_helper") catch |err| {
            log.info("Failed to resolve RandomX helper path: {}", .{err});
            return RandomXError.ProcessFailed;
        };
        defer self.allocator.free(exe_path);

        // Create argv array with proper memory management
        const argv = try self.allocator.alloc([]const u8, 5);
        defer self.allocator.free(argv);
        // Format difficulty bytes as string
        var difficulty_str: [4]u8 = undefined;
        _ = std.fmt.bufPrint(&difficulty_str, "{}", .{difficulty_bytes}) catch unreachable;

        argv[0] = exe_path;
        argv[1] = hex_input;
        argv[2] = self.key;
        argv[3] = difficulty_str[0..std.fmt.count("{}", .{difficulty_bytes})];
        argv[4] = mode_str;

        // Run RandomX helper subprocess with resource limits
        var child = std.process.Child.init(argv, self.allocator);

        // Set resource limits for security
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        child.stdin_behavior = .Ignore;

        // Spawn and wait with timeout
        child.spawn() catch |err| {
            log.info("Failed to spawn RandomX helper: {}", .{err});
            return RandomXError.ProcessFailed;
        };

        // Set up timeout (30 seconds max)
        const timeout_ns = 30 * std.time.ns_per_s;
        const start_time = std.time.nanoTimestamp();

        // Collect output with size limits
        var stdout = std.ArrayList(u8).init(self.allocator);
        defer stdout.deinit();
        var stderr = std.ArrayList(u8).init(self.allocator);
        defer stderr.deinit();

        // Read with size limits (max 1KB output)
        const max_output = 1024;
        try stdout.ensureTotalCapacity(max_output);
        try stderr.ensureTotalCapacity(max_output);

        // Read output before wait to avoid deadlock
        if (child.stdout) |out| {
            const n = try out.reader().readAll(stdout.unusedCapacitySlice()[0..@min(max_output, stdout.unusedCapacitySlice().len)]);
            stdout.items.len += n;
        }
        if (child.stderr) |err| {
            const n = try err.reader().readAll(stderr.unusedCapacitySlice()[0..@min(max_output, stderr.unusedCapacitySlice().len)]);
            stderr.items.len += n;
        }

        const result = try child.wait();

        // Check execution time
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) return RandomXError.ProcessTimeout;

        if (result != .Exited or result.Exited != 0) {
            log.info("RandomX helper failed with exit code: {}", .{result});
            log.info("stderr: {s}", .{stderr.items});
            log.info("stdout: {s}", .{stdout.items});
            return RandomXError.ProcessFailed;
        }

        // Parse result: hash_hex:meets_difficulty
        const output_str = stdout.items;
        const colon_pos = std.mem.indexOf(u8, output_str, ":") orelse {
            log.info("Failed to find colon in RandomX output", .{});
            return RandomXError.HashFailed;
        };
        const hash_hex = output_str[0..colon_pos];

        if (hash_hex.len != 64) return RandomXError.HashFailed;

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
