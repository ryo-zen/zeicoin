// dotenv.zig - Environment file loader for ZeiCoin
// Loads .env files and applies variables to the environment using setenv()
// Supports multiple .env files with proper precedence and memory management

const std = @import("std");
const builtin = @import("builtin");

// Import C functions we need
const c = @cImport({
    @cInclude("stdlib.h");
});

pub const DotEnvError = error{
    FileNotFound,
    ParseError,
    InvalidLine,
};

pub const DotEnv = struct {
    allocator: std.mem.Allocator,
    vars: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) DotEnv {
        return .{
            .allocator = allocator,
            .vars = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *DotEnv) void {
        var it = self.vars.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.vars.deinit();
    }

    /// Load environment variables from a .env file
    pub fn loadFromFile(self: *DotEnv, path: []const u8) !void {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) {
                // .env file is optional, so we don't error if it doesn't exist
                return;
            }
            return err;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024); // Max 1MB
        defer self.allocator.free(content);

        try self.parseContent(content);
    }

    /// Parse .env content and store variables
    fn parseContent(self: *DotEnv, content: []const u8) !void {
        var lines = std.mem.tokenizeAny(u8, content, "\n\r");
        
        while (lines.next()) |line| {
            // Skip empty lines and comments
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0 or trimmed[0] == '#') {
                continue;
            }

            // Find the = separator
            const eq_pos = std.mem.indexOf(u8, trimmed, "=");
            if (eq_pos == null) {
                continue; // Skip invalid lines
            }

            const key = std.mem.trim(u8, trimmed[0..eq_pos.?], " \t");
            var value = std.mem.trim(u8, trimmed[eq_pos.? + 1..], " \t");

            // Remove quotes if present
            if (value.len >= 2) {
                if ((value[0] == '"' and value[value.len - 1] == '"') or
                    (value[0] == '\'' and value[value.len - 1] == '\'')) {
                    value = value[1..value.len - 1];
                }
            }

            // Store the key-value pair (check for existing to avoid leaks)
            if (self.vars.fetchRemove(key)) |existing| {
                // Free the old key and value before inserting new ones
                self.allocator.free(existing.key);
                self.allocator.free(existing.value);
            }
            
            const key_copy = try self.allocator.dupe(u8, key);
            errdefer self.allocator.free(key_copy);
            const value_copy = try self.allocator.dupe(u8, value);
            errdefer self.allocator.free(value_copy);

            try self.vars.put(key_copy, value_copy);
        }
    }

    /// Apply loaded variables to the environment (pure Zig implementation)
    pub fn applyToEnvironment(self: *DotEnv) !void {
        // On Windows, we'd use SetEnvironmentVariable
        // On Unix, we manipulate environ directly
        
        if (builtin.os.tag == .windows) {
            // Windows implementation would go here
            @compileError("Windows not yet supported for .env loading");
        } else {
            // Unix/Linux implementation
            var it = self.vars.iterator();
            while (it.next()) |entry| {
                // Only set if not already in environment (env vars take precedence)
                if (std.process.getEnvVarOwned(self.allocator, entry.key_ptr.*)) |existing| {
                    self.allocator.free(existing);
                    continue; // Skip, already set
                } else |_| {
                    // Use setenv which copies the strings, so we can free them
                    const key_cstr = try self.allocator.dupeZ(u8, entry.key_ptr.*);
                    defer self.allocator.free(key_cstr);
                    const value_cstr = try self.allocator.dupeZ(u8, entry.value_ptr.*);
                    defer self.allocator.free(value_cstr);
                    
                    // setenv copies the strings internally, so we can free ours
                    const result = c.setenv(key_cstr, value_cstr, 1); // 1 = overwrite if exists
                    if (result != 0) {
                        return error.SetEnvFailed;
                    }
                }
            }
        }
    }

    /// Get a variable value
    pub fn get(self: *DotEnv, key: []const u8) ?[]const u8 {
        return self.vars.get(key);
    }
};

// Track if we've already loaded .env files
var env_loaded = false;

/// Load .env files and apply to environment
pub fn load(allocator: std.mem.Allocator) !void {
    if (env_loaded) {
        return; // Already loaded
    }
    
    var dotenv = DotEnv.init(allocator);
    defer dotenv.deinit(); // Clean up after applying to environment
    
    // Try to load multiple .env files in order of precedence
    const files = [_][]const u8{
        ".env",          // Default environment
        ".env.local",    // Local overrides (git-ignored)
    };

    for (files) |file| {
        dotenv.loadFromFile(file) catch |err| {
            if (err != error.FileNotFound) {
                return err;
            }
            // Continue if file not found
        };
    }
    
    // Apply to environment (setenv copies, so we can free after)
    try dotenv.applyToEnvironment();
    
    env_loaded = true;
}

/// Auto-detect and load appropriate .env file based on network
pub fn loadForNetwork(allocator: std.mem.Allocator) !void {
    if (env_loaded) {
        return; // Already loaded
    }
    
    var dotenv = DotEnv.init(allocator);
    defer dotenv.deinit(); // Clean up after applying to environment
    
    // First, load base configuration to get ZEICOIN_NETWORK
    dotenv.loadFromFile(".env") catch |err| {
        if (err != error.FileNotFound) {
            return err;
        }
    };
    
    // Determine which network-specific file to load based on ZEICOIN_NETWORK
    const network = dotenv.get("ZEICOIN_NETWORK") orelse "testnet"; // Default to testnet
    
    // Load network-specific configuration
    const network_file = if (std.mem.eql(u8, network, "mainnet")) 
        ".env.mainnet" 
    else 
        ".env.testnet";
        
    dotenv.loadFromFile(network_file) catch |err| {
        if (err != error.FileNotFound) {
            return err;
        }
    };
    
    // Load local overrides (git-ignored)
    dotenv.loadFromFile(".env.local") catch |err| {
        if (err != error.FileNotFound) {
            return err;
        }
    };
    
    // Apply to environment (setenv copies, so we can free after)
    try dotenv.applyToEnvironment();
    
    env_loaded = true;
}


// Tests
test "parse simple .env file" {
    const allocator = std.testing.allocator;
    var dotenv = DotEnv.init(allocator);
    defer dotenv.deinit();

    const content =
        \\# This is a comment
        \\KEY1=value1
        \\KEY2="value with spaces"
        \\KEY3='single quotes'
        \\  KEY4  =  value4  
        \\
        \\# Another comment
        \\KEY5=value5
    ;

    try dotenv.parseContent(content);

    try std.testing.expectEqualStrings("value1", dotenv.get("KEY1").?);
    try std.testing.expectEqualStrings("value with spaces", dotenv.get("KEY2").?);
    try std.testing.expectEqualStrings("single quotes", dotenv.get("KEY3").?);
    try std.testing.expectEqualStrings("value4", dotenv.get("KEY4").?);
    try std.testing.expectEqualStrings("value5", dotenv.get("KEY5").?);
    try std.testing.expect(dotenv.get("NONEXISTENT") == null);
}