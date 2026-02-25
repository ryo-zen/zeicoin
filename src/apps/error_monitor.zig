// error_monitor.zig - Journal monitoring for ZeiCoin
const std = @import("std");
const zeicoin = @import("zeicoin");
const util = zeicoin.util;
const postgres = util.postgres;
const Allocator = std.mem.Allocator;

// Helper to format strings and ensure they are null-terminated for PostgreSQL C API
fn fmtz(a: Allocator, comptime f: []const u8, args: anytype) ![:0]const u8 {
    return try a.dupeZ(u8, try std.fmt.allocPrint(a, f, args));
}

// Extract tags like [SYNC] or (scope) from log messages
fn getTag(a: Allocator, m: []const u8, open: u8, close: u8) ![:0]const u8 {
    const s = std.mem.indexOfScalar(u8, m, open) orelse return try a.dupeZ(u8, "");
    const e = std.mem.indexOfScalar(u8, m[s..], close) orelse return try a.dupeZ(u8, "");
    return try a.dupeZ(u8, m[s + 1 .. s + e]);
}

// Extract source location (file.zig:line:col) from log messages
fn getLoc(a: Allocator, m: []const u8) ![:0]const u8 {
    const p = std.mem.indexOf(u8, m, ".zig:") orelse return try a.dupeZ(u8, "");
    var s = p; while (s > 0 and !std.ascii.isWhitespace(m[s-1])) : (s -= 1) {}
    var e = p + 5; var colons: u8 = 0;
    while (e < m.len) : (e += 1) {
        if (m[e] == ':') {
            colons += 1;
            if (colons == 2) {
                e += 1;
                while (e < m.len and std.ascii.isDigit(m[e])) : (e += 1) {}
                break;
            }
        } else if (!std.ascii.isDigit(m[e])) break;
    }
    return try a.dupeZ(u8, m[s..e]);
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Global arena for configuration
    var arena_s = std.heap.ArenaAllocator.init(allocator);
    defer arena_s.deinit();
    const arena = arena_s.allocator();

    // Load environment variables
    zeicoin.dotenv.loadForNetwork(allocator) catch {};
    
    const host = util.getEnvVarOwned(arena, "ZEICOIN_DB_HOST") catch try arena.dupe(u8, "127.0.0.1");
    const port = if (util.getEnvVarOwned(arena, "ZEICOIN_DB_PORT")) |p| std.fmt.parseInt(u16, p, 10) catch 5432 else |_| 5432;
    const db_name = util.getEnvVarOwned(arena, "ZEICOIN_DB_NAME") catch try arena.dupe(u8, "zeicoin_testnet");
    const user = util.getEnvVarOwned(arena, "ZEICOIN_DB_USER") catch try arena.dupe(u8, "zeicoin");
    const pass = try util.getEnvVarOwned(arena, "ZEICOIN_DB_PASSWORD");
    const node = util.getEnvVarOwned(arena, "ZEICOIN_MONITOR_NODE_ADDRESS") catch try arena.dupe(u8, "127.0.0.1");
    const svc = util.getEnvVarOwned(arena, "ZEICOIN_MONITOR_SERVICE") catch try arena.dupe(u8, "zeicoin-server.service");

    // Initialize PostgreSQL connection
    const conninfo = try postgres.buildConnString(arena, host, port, db_name, user, pass);
    var conn = try postgres.Connection.init(allocator, conninfo);
    defer conn.deinit();

    std.log.info("🔍 Monitoring {s} -> {s}", .{svc, db_name});

    // Spawn journalctl to follow logs in JSON format
    const argv = &[_][]const u8{ "journalctl", "-u", svc, "-f", "--output=json", "--since=now" };
    var child = try std.process.spawn(init.io, .{
        .argv = argv,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer _ = child.kill(init.io);

    // Set up buffered reader for stdout
    const stdout = child.stdout.?;
    var read_buf: [16384]u8 = undefined;
    var reader = stdout.reader(init.io, &read_buf);

    // Process logs line by line
    while (true) {
        // Read next line from journalctl
        const line = reader.interface.takeDelimiterExclusive('\n') catch |err| {
            if (err == error.EndOfStream) break;
            continue;
        };
        
        // Use a per-line arena to prevent memory leaks in the long-running monitor
        var la_s = std.heap.ArenaAllocator.init(allocator);
        defer la_s.deinit();
        const la = la_s.allocator();

        // Parse JSON log entry
        const parsed = std.json.parseFromSlice(std.json.Value, la, line, .{}) catch continue;
        const obj = parsed.value.object;
        const msg = if (obj.get("MESSAGE")) |m| m.string else continue;
        const prio = if (obj.get("PRIORITY")) |p| std.fmt.parseInt(u8, p.string, 10) catch 6 else 6;
        
        // Filter for errors and warnings
        if (prio > 4 and std.mem.indexOf(u8, msg, "error") == null) continue;

        // Extract timestamp and metadata
        const ts_us = if (obj.get("__REALTIME_TIMESTAMP")) |t| t.string else continue;
        const ts_ms = (std.fmt.parseInt(u64, ts_us, 10) catch continue) / 1000;
        
        // Classify severity
        const sev = if (std.mem.indexOf(u8, msg, "RocksDB") != null or prio <= 3) "CRITICAL" else if (prio == 4) "HIGH" else "MEDIUM";

        // Insert into PostgreSQL
        var res = try conn.queryParams(
            \\INSERT INTO error_logs (timestamp, node_address, severity, scope, error_type, error_message, source_location, context)
            \\VALUES (to_timestamp($1/1000.0), $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, NULLIF($7, ''), $8::jsonb)
        , &.{
            try fmtz(la, "{}", .{ts_ms}), try la.dupeZ(u8, node), try la.dupeZ(u8, sev),
            try getTag(la, msg, '(', ')'), try getTag(la, msg, '[', ']'), try la.dupeZ(u8, msg),
            try getLoc(la, msg), "{}"
        });
        res.deinit();
        
        std.log.info("⚠️ [{s}] {s}", .{sev, msg});
    }
}
