// password.zig - Secure password handling for ZeiCoin wallets
// Provides three modes: test (default passwords), environment (from env var), and interactive (secure prompt)
// Handles password input with terminal echo disabled and memory clearing after use

const std = @import("std");
const builtin = @import("builtin");

pub const PasswordError = error{
    PasswordTooShort,
    PasswordTooLong,
    ReadFailed,
    NoPassword,
};

pub const PasswordOptions = struct {
    min_length: usize = 8,
    max_length: usize = 256,
    allow_env: bool = true,
    prompt: []const u8 = "Enter wallet password: ",
};

pub fn getPassword(allocator: std.mem.Allocator, wallet_name: []const u8, options: PasswordOptions) ![]u8 {
    _ = wallet_name; // No longer needed without test mode
    
    // Check for environment variable password first
    if (options.allow_env) {
        if (std.process.getEnvVarOwned(allocator, "ZEICOIN_WALLET_PASSWORD")) |env_password| {
            if (env_password.len < options.min_length) {
                allocator.free(env_password);
                return PasswordError.PasswordTooShort;
            }
            if (env_password.len > options.max_length) {
                allocator.free(env_password);
                return PasswordError.PasswordTooLong;
            }
            return env_password;
        } else |_| {}
    }

    // No environment password, prompt user
    return readPasswordFromStdin(allocator, options);
}

pub fn readPasswordFromStdin(allocator: std.mem.Allocator, options: PasswordOptions) ![]u8 {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn();
    
    try stdout.print("{s}", .{options.prompt});

    const original_termios = if (builtin.os.tag != .windows) blk: {
        const termios = std.posix.tcgetattr(stdin.handle) catch |err| switch (err) {
            error.NotATerminal => break :blk null,
            else => return err,
        };
        
        var new_termios = termios;
        new_termios.lflag.ECHO = false;
        new_termios.lflag.ICANON = true;
        
        try std.posix.tcsetattr(stdin.handle, .NOW, new_termios);
        break :blk termios;
    } else null;
    
    defer if (original_termios) |termios| {
        std.posix.tcsetattr(stdin.handle, .NOW, termios) catch {};
        stdout.print("\n", .{}) catch {};
    };

    const reader = stdin.reader();
    const password = reader.readUntilDelimiterAlloc(allocator, '\n', options.max_length) catch |err| {
        return err;
    };
    errdefer allocator.free(password);
    
    const trimmed = std.mem.trim(u8, password, " \r\n\t");
    if (trimmed.len < options.min_length) {
        return PasswordError.PasswordTooShort;
    }
    
    if (trimmed.len != password.len) {
        const result = try allocator.dupe(u8, trimmed);
        allocator.free(password);
        return result;
    }
    
    return password;
}

pub fn confirmPassword(allocator: std.mem.Allocator, options: PasswordOptions) ![]u8 {
    const stdout = std.io.getStdOut().writer();
    
    const first_password = try readPasswordFromStdin(allocator, .{
        .min_length = options.min_length,
        .max_length = options.max_length,
        .prompt = "Enter new password: ",
    });
    defer allocator.free(first_password);
    defer clearPassword(first_password);
    
    const second_password = try readPasswordFromStdin(allocator, .{
        .min_length = options.min_length,
        .max_length = options.max_length,
        .prompt = "Confirm password: ",
    });
    defer allocator.free(second_password);
    defer clearPassword(second_password);
    
    if (!std.mem.eql(u8, first_password, second_password)) {
        try stdout.print("❌ Passwords do not match\n", .{});
        return error.PasswordMismatch;
    }
    
    return allocator.dupe(u8, first_password);
}

pub fn clearPassword(password: []u8) void {
    @memset(password, 0);
}

pub fn getPasswordForWallet(allocator: std.mem.Allocator, wallet_name: []const u8, creating: bool) ![]u8 {
    // Check if password is provided via environment variable
    const has_env_password = if (std.process.getEnvVarOwned(allocator, "ZEICOIN_WALLET_PASSWORD")) |env_pw| blk: {
        allocator.free(env_pw);
        break :blk true;
    } else |_| false;
    
    // If creating a new wallet and no env password, confirm password
    if (creating and !has_env_password) {
        return confirmPassword(allocator, .{
            .min_length = 8,
            .max_length = 256,
        });
    }
    
    // Otherwise get password (from env or prompt)
    return getPassword(allocator, wallet_name, .{
        .min_length = 8,
        .max_length = 256,
        .allow_env = true,
        .prompt = if (creating) "Enter new wallet password: " else "Enter wallet password: ",
    });
}