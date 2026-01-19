// error_monitor.zig - Error monitoring agent for ZeiCoin mining nodes
// Reads systemd journal for zen_server errors and stores them in PostgreSQL
const std = @import("std");
const pg = @import("pg");
const zeicoin = @import("zeicoin");
const types = zeicoin.types;

const Pool = pg.Pool;
const print = std.debug.print;

/// PostgreSQL connection config
pub const PgConfig = struct {
    host: []const u8,
    port: u16,
    database: []const u8,
    user: []const u8,
    password: []const u8,
    pool_size: u32,
    node_address: []const u8,
    min_severity: ErrorSeverity,
    service_name: []const u8,
};

const ErrorSeverity = enum {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,

    fn toString(self: ErrorSeverity) []const u8 {
        return @tagName(self);
    }

    fn fromString(s: []const u8) ErrorSeverity {
        if (std.mem.eql(u8, s, "CRITICAL")) return .CRITICAL;
        if (std.mem.eql(u8, s, "HIGH")) return .HIGH;
        if (std.mem.eql(u8, s, "LOW")) return .LOW;
        return .MEDIUM;
    }
};

const ErrorData = struct {
    timestamp: []const u8,
    node_address: []const u8,
    severity: ErrorSeverity,
    scope: ?[]const u8,
    error_type: ?[]const u8,
    message: []const u8,
    source_location: ?[]const u8,
    context: ?[]const u8, // JSON string
};

/// Extract source location from message (e.g. "/path/to/file.zig:123:45")
fn extractSourceLocation(allocator: std.mem.Allocator, message: []const u8) !?[]const u8 {
    // Look for Zig source location pattern: /path/to/file.zig:line:col
    // Simple heuristic: look for ".zig:" followed by digits
    if (std.mem.indexOf(u8, message, ".zig:")) |zig_ext_pos| {
        // Find start of file path (search backwards for first space or start of line)
        var start: usize = zig_ext_pos;
        while (start > 0) : (start -= 1) {
            if (message[start] == ' ' or message[start] == '\n' or message[start] == '\t') {
                start += 1;
                break;
            }
        }
        
        // Find end of location (search forward for second colon after .zig)
        // Format: .zig:LINE:COL
        var colons_found: u8 = 0;
        var end: usize = zig_ext_pos + 4; // Skip ".zig"
        
        while (end < message.len) : (end += 1) {
            if (message[end] == ':') {
                colons_found += 1;
                if (colons_found == 2) {
                    // Include the column number digits after the second colon
                    end += 1;
                    while (end < message.len and std.ascii.isDigit(message[end])) : (end += 1) {}
                    break;
                }
            } else if (!std.ascii.isDigit(message[end])) {
                // If we hit a non-digit between colons, abort (it's not a line number)
                break;
            }
        }
        
        if (colons_found >= 1) {
            return try allocator.dupe(u8, message[start..end]);
        }
    }
    return null;
}

/// Detect node address from network interfaces or environment
fn detectNodeAddress(allocator: std.mem.Allocator) ![]const u8 {
    // Try to read from hostname -I or fallback to localhost
    var child = std.process.Child.init(&[_][]const u8{ "hostname", "-I" }, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    child.spawn() catch {
        return try allocator.dupe(u8, "127.0.0.1");
    };

    const stdout = child.stdout.?;
    var buf: [256]u8 = undefined;
    const bytes_read = stdout.read(&buf) catch 0;
    _ = child.wait() catch {};

    if (bytes_read > 0) {
        const output = std.mem.trim(u8, buf[0..bytes_read], &std.ascii.whitespace);
        if (output.len > 0) {
            // Take first IP address
            var iter = std.mem.splitScalar(u8, output, ' ');
            if (iter.next()) |first_ip| {
                return try allocator.dupe(u8, first_ip);
            }
        }
    }

    return try allocator.dupe(u8, "127.0.0.1");
}

/// Load configuration from environment variables
fn loadConfig(allocator: std.mem.Allocator) !PgConfig {
    const database = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_NAME") catch
        try allocator.dupe(u8, "zeicoin_testnet");
    errdefer allocator.free(database);

    const host = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_HOST") catch
        try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(host);

    const port_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PORT") catch null;
    const port = if (port_str) |p| blk: {
        defer allocator.free(p);
        break :blk std.fmt.parseInt(u16, p, 10) catch 5432;
    } else 5432;

    const user = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_USER") catch
        try allocator.dupe(u8, "zeicoin");
    errdefer allocator.free(user);

    const password = std.process.getEnvVarOwned(allocator, "ZEICOIN_DB_PASSWORD") catch |err| {
        print("❌ ZEICOIN_DB_PASSWORD environment variable is required\n", .{});
        return err;
    };
    errdefer allocator.free(password);

    const node_address = std.process.getEnvVarOwned(allocator, "ZEICOIN_MONITOR_NODE_ADDRESS") catch
        try detectNodeAddress(allocator);
    errdefer allocator.free(node_address);

    const severity_str = std.process.getEnvVarOwned(allocator, "ZEICOIN_MONITOR_MIN_SEVERITY") catch null;
    const min_severity = if (severity_str) |s| blk: {
        defer allocator.free(s);
        break :blk ErrorSeverity.fromString(s);
    } else ErrorSeverity.MEDIUM;

    const service_name = std.process.getEnvVarOwned(allocator, "ZEICOIN_MONITOR_SERVICE") catch
        try allocator.dupe(u8, "zeicoin-mining.service");
    errdefer allocator.free(service_name);

    return PgConfig{
        .host = host,
        .port = port,
        .database = database,
        .user = user,
        .password = password,
        .pool_size = 3,
        .node_address = node_address,
        .min_severity = min_severity,
        .service_name = service_name,
    };
}

/// Classify error severity based on message content
fn classifyError(message: []const u8) ErrorSeverity {
    // Critical errors - node cannot operate
    if (std.mem.indexOf(u8, message, "[CHAIN INCOMPATIBLE]") != null) return .CRITICAL;
    if (std.mem.indexOf(u8, message, "Failed to open RocksDB") != null) return .CRITICAL;
    if (std.mem.indexOf(u8, message, "[CONSENSUS ERROR]") != null) return .CRITICAL;
    if (std.mem.indexOf(u8, message, "Database is locked") != null) return .CRITICAL;
    if (std.mem.indexOf(u8, message, "Failed with result 'core-dump'") != null) return .CRITICAL;
    if (std.mem.indexOf(u8, message, "code=dumped") != null) return .CRITICAL;

    // High priority errors - major functionality impaired
    if (std.mem.indexOf(u8, message, "[SYNC POLL] Error") != null) return .HIGH;
    if (std.mem.indexOf(u8, message, "[FORK DETECT] Failed") != null) return .HIGH;
    if (std.mem.indexOf(u8, message, "Block validation failed") != null) return .HIGH;
    if (std.mem.indexOf(u8, message, "[REORG] Failed") != null) return .HIGH;
    if (std.mem.indexOf(u8, message, "Failed with result 'timeout'") != null) return .HIGH;
    if (std.mem.indexOf(u8, message, "State 'stop-sigterm' timed out") != null) return .HIGH;

    // Medium priority - degraded performance
    if (std.mem.indexOf(u8, message, "[MINING ERROR]") != null) return .MEDIUM;
    if (std.mem.indexOf(u8, message, "OutOfMemory") != null) return .MEDIUM;
    if (std.mem.indexOf(u8, message, "Failed to allocate") != null) return .MEDIUM;
    if (std.mem.indexOf(u8, message, "error(gpa):") != null) return .MEDIUM;
    if (std.mem.indexOf(u8, message, "memory address") != null and std.mem.indexOf(u8, message, "leaked") != null) return .MEDIUM;

    return .LOW;
}

/// Extract scope from log message (e.g., "info(sync):" -> "sync")
fn extractScope(allocator: std.mem.Allocator, message: []const u8) !?[]const u8 {
    // Look for pattern: "level(scope):"
    if (std.mem.indexOf(u8, message, "(")) |start| {
        if (std.mem.indexOf(u8, message[start..], ")")) |end_offset| {
            const scope = message[start + 1 .. start + end_offset];
            if (scope.len > 0 and scope.len < 50) {
                return try allocator.dupe(u8, scope);
            }
        }
    }
    return null;
}

/// Extract error type from message (use tags like [SYNC POLL], [MINING ERROR], etc.)
fn extractErrorType(allocator: std.mem.Allocator, message: []const u8) !?[]const u8 {
    // Look for [ERROR_TYPE] pattern
    if (std.mem.indexOf(u8, message, "[")) |start| {
        if (std.mem.indexOf(u8, message[start..], "]")) |end_offset| {
            const error_type = message[start + 1 .. start + end_offset];
            if (error_type.len > 0 and error_type.len < 100) {
                return try allocator.dupe(u8, error_type);
            }
        }
    }
    return null;
}

/// Extract structured context from message (height, hash, peer, etc.)
fn extractContext(allocator: std.mem.Allocator, message: []const u8) !?[]const u8 {
    var context = std.ArrayList(u8).init(allocator);
    defer context.deinit();

    try context.appendSlice("{");
    var has_fields = false;

    // Extract height: pattern "height \d+"
    if (std.mem.indexOf(u8, message, "height ")) |pos| {
        var i = pos + 7;
        while (i < message.len and std.ascii.isDigit(message[i])) : (i += 1) {}
        if (i > pos + 7) {
            const height = message[pos + 7 .. i];
            if (has_fields) try context.appendSlice(",");
            try context.appendSlice("\"height\":");
            try context.appendSlice(height);
            has_fields = true;
        }
    }

    // Extract peer: pattern "peer \d+.\d+.\d+.\d+:\d+"
    if (std.mem.indexOf(u8, message, "peer ")) |pos| {
        var i = pos + 5;
        while (i < message.len and (std.ascii.isDigit(message[i]) or message[i] == '.' or message[i] == ':')) : (i += 1) {}
        if (i > pos + 5) {
            const peer = message[pos + 5 .. i];
            if (has_fields) try context.appendSlice(",");
            try context.appendSlice("\"peer\":\"");
            try context.appendSlice(peer);
            try context.appendSlice("\"");
            has_fields = true;
        }
    }

    try context.appendSlice("}");

    if (has_fields) {
        return try context.toOwnedSlice();
    }

    return null;
}

/// Parse journal JSON entry and extract error data
fn parseJournalEntry(allocator: std.mem.Allocator, line: []const u8, node_address: []const u8) !?ErrorData {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, line, .{}) catch return null;
    defer parsed.deinit();

    const root = parsed.value.object;

    // Get message
    const message_value = root.get("MESSAGE") orelse return null;
    const message = message_value.string;

    // Filter: only process error and warning messages
    const priority_value = root.get("PRIORITY") orelse return null;
    const priority_str = priority_value.string;
    const priority = std.fmt.parseInt(u8, priority_str, 10) catch return null;

    // systemd priorities: 3=err, 4=warning, 6=info
    // Process errors (3), warnings (4), and info (6) if it contains error patterns
    const has_error_pattern = std.mem.indexOf(u8, message, "error(gpa):") != null or
        std.mem.indexOf(u8, message, "memory address") != null and std.mem.indexOf(u8, message, "leaked") != null or
        std.mem.indexOf(u8, message, "Failed") != null or
        std.mem.indexOf(u8, message, "[ERROR]") != null or
        std.mem.indexOf(u8, message, ".zig:") != null; // Capture stack trace lines

    if (priority > 4 and !has_error_pattern) return null;

    // Get timestamp
    const timestamp_value = root.get("__REALTIME_TIMESTAMP") orelse return null;
    const timestamp_us = timestamp_value.string;

    // Convert microseconds to ISO timestamp
    const timestamp_us_int = std.fmt.parseInt(u64, timestamp_us, 10) catch return null;
    const timestamp_ms = timestamp_us_int / 1000;
    const timestamp = try std.fmt.allocPrint(allocator, "{}", .{timestamp_ms});
    errdefer allocator.free(timestamp);

    // Classify severity
    const severity = classifyError(message);

    // Extract scope
    const scope = try extractScope(allocator, message);
    errdefer if (scope) |s| allocator.free(s);

    // Extract error type
    const error_type = try extractErrorType(allocator, message);
    errdefer if (error_type) |et| allocator.free(et);

    // Extract context
    const context = try extractContext(allocator, message);
    errdefer if (context) |ctx| allocator.free(ctx);

    // Extract source location
    const source_location = try extractSourceLocation(allocator, message);
    errdefer if (source_location) |sl| allocator.free(sl);

    // Duplicate message
    const message_copy = try allocator.dupe(u8, message);
    errdefer allocator.free(message_copy);

    return ErrorData{
        .timestamp = timestamp,
        .node_address = node_address,
        .severity = severity,
        .scope = scope,
        .error_type = error_type,
        .message = message_copy,
        .source_location = source_location,
        .context = context,
    };
}

/// Insert error into PostgreSQL
fn insertError(pool: *Pool, error_data: ErrorData) !void {
    const severity_str = error_data.severity.toString();

    _ = try pool.exec(
        \\INSERT INTO error_logs (timestamp, node_address, severity, scope, error_type, error_message, source_location, context)
        \\VALUES (to_timestamp($1/1000.0), $2, $3, $4, $5, $6, $7, $8::jsonb)
    , .{
        error_data.timestamp,
        error_data.node_address,
        severity_str,
        error_data.scope,
        error_data.error_type,
        error_data.message,
        error_data.source_location,
        error_data.context,
    });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("🔍 ZeiCoin Error Monitor Starting...\n", .{});

    // Load .env files
    zeicoin.dotenv.loadForNetwork(std.heap.page_allocator) catch |err| {
        if (err != error.FileNotFound) {
            print("⚠️  Failed to load .env file: {}\n", .{err});
        }
    };

    // Load config
    const config = try loadConfig(allocator);
    defer {
        allocator.free(config.database);
        allocator.free(config.host);
        allocator.free(config.user);
        allocator.free(config.password);
        allocator.free(config.node_address);
        allocator.free(config.service_name);
    }

    print("📊 Node: {s}\n", .{config.node_address});
    print("💾 Database: {s}@{s}:{}\n", .{ config.user, config.host, config.port });
    print("🎚️  Min Severity: {s}\n", .{config.min_severity.toString()});
    print("🔧 Service: {s}\n", .{config.service_name});

    // Connect to PostgreSQL
    var pool = try Pool.init(allocator, .{
        .size = @intCast(config.pool_size),
        .connect = .{
            .host = config.host,
            .port = config.port,
        },
        .auth = .{
            .username = config.user,
            .password = config.password,
            .database = config.database,
            .timeout = 10_000,
        },
    });
    defer pool.deinit();

    print("✅ Connected to PostgreSQL\n", .{});

    // Spawn journalctl subprocess
    const argv = [_][]const u8{
        "journalctl",
        "-u",
        config.service_name,
        "-f",
        "--output=json",
        "--since=now",
    };

    var child = std.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;

    try child.spawn();
    defer _ = child.kill() catch {};

    print("🔄 Monitoring logs from {s}...\n\n", .{config.service_name});

    // Read journal lines
    const stdout = child.stdout.?;
    var buf_reader = std.io.bufferedReader(stdout.reader());
    var reader = buf_reader.reader();

    var line_buffer: [8192]u8 = undefined;

    while (true) {
        const line = reader.readUntilDelimiter(&line_buffer, '\n') catch |err| {
            if (err == error.EndOfStream) break;
            continue;
        };

        // Parse journal JSON entry
        const maybe_error_data = parseJournalEntry(allocator, line, config.node_address) catch continue;

        if (maybe_error_data) |error_data| {
            defer allocator.free(error_data.timestamp);
            defer allocator.free(error_data.message);
            defer if (error_data.context) |ctx| allocator.free(ctx);
            defer if (error_data.scope) |s| allocator.free(s);
            defer if (error_data.error_type) |et| allocator.free(et);
            defer if (error_data.source_location) |sl| allocator.free(sl);

            // Filter by severity
            if (@intFromEnum(error_data.severity) < @intFromEnum(config.min_severity)) {
                continue;
            }

            // Insert to PostgreSQL
            insertError(pool, error_data) catch |err| {
                print("❌ Failed to insert error: {}\n", .{err});
                continue;
            };

            // Log to console
            print("[{s}] {s}: {s}\n", .{
                error_data.severity.toString(),
                error_data.error_type orelse "UNKNOWN",
                error_data.message,
            });
        }
    }
}
