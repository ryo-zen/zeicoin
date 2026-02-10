// postgres.zig - Minimal libpq wrapper for ZeiCoin
// Provides simple PostgreSQL query interface using libpq C library

const std = @import("std");
const c = @cImport({
    @cInclude("libpq-fe.h");
});

pub const PostgresError = error{
    ConnectionFailed,
    QueryFailed,
    NoResult,
    OutOfMemory,
};

/// PostgreSQL connection
pub const Connection = struct {
    conn: ?*c.PGconn,
    allocator: std.mem.Allocator,

    /// Connect to PostgreSQL
    pub fn init(allocator: std.mem.Allocator, conninfo: [:0]const u8) PostgresError!Connection {
        const conn = c.PQconnectdb(conninfo.ptr);
        if (c.PQstatus(conn) != c.CONNECTION_OK) {
            const err_msg = c.PQerrorMessage(conn);
            std.log.err("PostgreSQL connection failed: {s}", .{err_msg});
            c.PQfinish(conn);
            return PostgresError.ConnectionFailed;
        }

        return Connection{
            .conn = conn,
            .allocator = allocator,
        };
    }

    /// Close connection
    pub fn deinit(self: *Connection) void {
        if (self.conn) |conn| {
            c.PQfinish(conn);
            self.conn = null;
        }
    }

    /// Execute query and return result
    pub fn query(self: *Connection, sql: [:0]const u8) PostgresError!QueryResult {
        const conn = self.conn orelse return PostgresError.ConnectionFailed;

        const res = c.PQexec(conn, sql.ptr);
        const status = c.PQresultStatus(res);

        if (status != c.PGRES_TUPLES_OK and status != c.PGRES_COMMAND_OK) {
            const err_msg = c.PQerrorMessage(conn);
            std.log.err("Query failed: {s}", .{err_msg});
            c.PQclear(res);
            return PostgresError.QueryFailed;
        }

        return QueryResult{
            .result = res,
            .allocator = self.allocator,
        };
    }

    /// Execute parameterized query
    pub fn queryParams(
        self: *Connection,
        sql: [:0]const u8,
        params: []const [:0]const u8,
    ) PostgresError!QueryResult {
        const conn = self.conn orelse return PostgresError.ConnectionFailed;

        // Convert params to C array
        var param_values = try self.allocator.alloc([*c]const u8, params.len);
        defer self.allocator.free(param_values);

        for (params, 0..) |param, i| {
            param_values[i] = param.ptr;
        }

        const res = c.PQexecParams(
            conn,
            sql.ptr,
            @intCast(params.len),
            null, // paramTypes
            param_values.ptr,
            null, // paramLengths
            null, // paramFormats
            0,    // resultFormat (text)
        );

        const status = c.PQresultStatus(res);

        if (status != c.PGRES_TUPLES_OK and status != c.PGRES_COMMAND_OK) {
            const err_msg = c.PQerrorMessage(conn);
            std.log.err("Parameterized query failed: {s}", .{err_msg});
            c.PQclear(res);
            return PostgresError.QueryFailed;
        }

        return QueryResult{
            .result = res,
            .allocator = self.allocator,
        };
    }
};

/// Query result
pub const QueryResult = struct {
    result: ?*c.PGresult,
    allocator: std.mem.Allocator,

    /// Free result
    pub fn deinit(self: *QueryResult) void {
        if (self.result) |res| {
            c.PQclear(res);
            self.result = null;
        }
    }

    /// Get number of rows
    pub fn rowCount(self: *QueryResult) usize {
        const res = self.result orelse return 0;
        return @intCast(c.PQntuples(res));
    }

    /// Get number of columns
    pub fn columnCount(self: *QueryResult) usize {
        const res = self.result orelse return 0;
        return @intCast(c.PQnfields(res));
    }

    /// Get column name
    pub fn columnName(self: *QueryResult, col: usize) ?[]const u8 {
        const res = self.result orelse return null;
        const name = c.PQfname(res, @intCast(col));
        if (name == null) return null;
        return std.mem.span(name);
    }

    /// Get value as string (returns null if NULL)
    pub fn getValue(self: *QueryResult, row: usize, col: usize) ?[]const u8 {
        const res = self.result orelse return null;

        if (c.PQgetisnull(res, @intCast(row), @intCast(col)) == 1) {
            return null;
        }

        const value = c.PQgetvalue(res, @intCast(row), @intCast(col));
        return std.mem.span(value);
    }

    /// Get value as owned string (caller must free)
    pub fn getValueOwned(self: *QueryResult, row: usize, col: usize) PostgresError!?[]u8 {
        const value = self.getValue(row, col) orelse return null;
        return self.allocator.dupe(u8, value) catch return PostgresError.OutOfMemory;
    }
};

/// Build connection string from config
pub fn buildConnString(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    dbname: []const u8,
    user: []const u8,
    password: []const u8,
) ![:0]u8 {
    const str = try std.fmt.allocPrint(
        allocator,
        "host={s} port={d} dbname={s} user={s} password={s}",
        .{ host, port, dbname, user, password },
    );
    defer allocator.free(str);
    return allocator.dupeZ(u8, str);
}
