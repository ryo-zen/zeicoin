// cli_bridge.zig - Simple HTTP CLI Bridge for ZeiCoin
// Allows web interface to execute CLI commands via HTTP API

const std = @import("std");
const zap = @import("zap");

const log = std.log.scoped(.cli_bridge);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    
    var listener = zap.HttpListener.init(.{
        .port = 8081,
        .on_request = onRequest,
        .log = true,
        .max_clients = 100,
    });
    
    log.info("🌐 CLI Bridge starting on port 8081", .{});
    log.info("🔗 HTTP endpoint: http://127.0.0.1:8081/ws", .{});
    
    try listener.listen();
    
    log.info("🚀 CLI Bridge ready! Press Ctrl+C to stop", .{});
    
    // Start the event loop
    zap.start(.{
        .threads = 1,
        .workers = 1,
    });
}

fn onRequest(r: zap.Request) void {
    // Enable CORS
    r.setHeader("Access-Control-Allow-Origin", "*") catch {};
    r.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS") catch {};
    r.setHeader("Access-Control-Allow-Headers", "Content-Type") catch {};
    
    if (r.method) |method| {
        if (std.mem.eql(u8, method, "OPTIONS")) {
            r.setStatus(.ok);
            r.sendBody("") catch {};
            return;
        }
    }
    
    if (r.path) |path| {
        if (std.mem.eql(u8, path, "/ws")) {
            handleCLIRequest(r) catch |err| {
                log.err("CLI request error: {}", .{err});
                r.setStatus(.internal_server_error);
                r.sendBody("{\"error\":\"Internal server error\"}") catch {};
            };
            return;
        }
        
        if (std.mem.eql(u8, path, "/health")) {
            r.setStatus(.ok);
            r.sendBody("{\"status\":\"healthy\",\"service\":\"cli-bridge\"}") catch {};
            return;
        }
    }
    
    r.setStatus(.not_found);
    r.sendBody("CLI Bridge - Use POST /ws for commands") catch {};
}

fn handleCLIRequest(r: zap.Request) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){}; 
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    if (r.method == null or !std.mem.eql(u8, r.method.?, "POST")) {
        r.setStatus(.method_not_allowed);
        r.sendBody("{\"error\":\"Use POST method\"}") catch {};
        return;
    }
    
    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Request body required\"}") catch {};
        return;
    };
    
    // Parse JSON request
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Invalid JSON\"}") catch {};
        return;
    };
    defer parsed.deinit();
    
    const json = parsed.value;
    const command_type = json.object.get("command").?.string;
    
    if (std.mem.eql(u8, command_type, "send")) {
        try handleSendTransaction(r, json, allocator);
    } else if (std.mem.eql(u8, command_type, "balance")) {
        try handleGetBalance(r, json, allocator);
    } else if (std.mem.eql(u8, command_type, "status")) {
        try handleGetStatus(r, allocator);
    } else if (std.mem.eql(u8, command_type, "address")) {
        try handleGetAddress(r, json, allocator);
    } else {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Unknown command\"}") catch {};
    }
}

fn handleSendTransaction(r: zap.Request, json: std.json.Value, allocator: std.mem.Allocator) !void {
    const obj = json.object;
    
    const wallet = obj.get("wallet").?.string;
    const password = obj.get("password").?.string;
    const recipient = obj.get("recipient").?.string;
    const amount = obj.get("amount").?.string;
    
    // Build CLI command
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("send");
    try cmd_args.append(amount);
    try cmd_args.append(recipient);
    try cmd_args.append(wallet);
    
    // Set up environment with server and password
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    try env_map.put("ZEICOIN_WALLET_PASSWORD", password);
    
    // Execute command
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = cmd_args.items,
        .env_map = &env_map,
    }) catch |err| {
        log.err("Failed to execute CLI command: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Command execution failed\"}") catch {};
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    
    if (result.term.Exited == 0) {
        // Success - extract transaction hash if present
        var tx_hash: ?[]const u8 = null;
        if (std.mem.indexOf(u8, result.stdout, "Transaction hash: ")) |hash_start_pos| {
            const hash_line_start = hash_start_pos + "Transaction hash: ".len;
            if (std.mem.indexOf(u8, result.stdout[hash_line_start..], "\n")) |end| {
                tx_hash = result.stdout[hash_line_start..hash_line_start + end];
            }
        }
        
        const response = if (tx_hash) |hash|
            try std.fmt.allocPrint(allocator, 
                "{{\"success\":true,\"output\":\"{s}\",\"transaction_hash\":\"{s}\"}}", 
                .{ escapedJsonString(allocator, result.stdout), hash })
        else
            try std.fmt.allocPrint(allocator, 
                "{{\"success\":true,\"output\":\"{s}\"}}", 
                .{escapedJsonString(allocator, result.stdout)});
                
        defer allocator.free(response);
        
        r.setStatus(.ok);
        r.sendBody(response) catch {};
        
        log.info("✅ Transaction sent successfully from wallet: {s}", .{wallet});
    } else {
        // Error
        const response = try std.fmt.allocPrint(allocator, 
            "{{\"success\":false,\"error\":\"{s}\"}}", 
            .{escapedJsonString(allocator, result.stderr)});
        defer allocator.free(response);
        
        r.setStatus(.bad_request);
        r.sendBody(response) catch {};
        
        log.warn("❌ Transaction failed for wallet: {s}, error: {s}", .{ wallet, result.stderr });
    }
}

fn handleGetBalance(r: zap.Request, json: std.json.Value, allocator: std.mem.Allocator) !void {
    const obj = json.object;
    const wallet = obj.get("wallet").?.string;
    const password = obj.get("password").?.string;
    
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("balance");
    try cmd_args.append(wallet);
    
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    try env_map.put("ZEICOIN_WALLET_PASSWORD", password);
    
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = cmd_args.items,
        .env_map = &env_map,
    }) catch |err| {
        log.err("Failed to get balance: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Balance check failed\"}") catch {};
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    
    log.info("CLI Command Exit Code: {}", .{result.term.Exited});
    log.info("CLI Balance Output: '{s}'", .{result.stdout});
    log.info("CLI Balance Error: '{s}'", .{result.stderr});
    
    if (result.term.Exited == 0) {
        
        // Extract balance from CLI stderr (where the formatted output goes)
        var balance_str: []const u8 = "0.00000";
        const output_to_parse = result.stderr; // Use stderr instead of stdout
        
        if (std.mem.indexOf(u8, output_to_parse, "spendable): ")) |start| {
            const balance_start = start + "spendable): ".len;
            if (std.mem.indexOf(u8, output_to_parse[balance_start..], " ZEI")) |end| {
                balance_str = output_to_parse[balance_start..balance_start + end];
                log.info("Extracted balance: {s}", .{balance_str});
            } else {
                log.warn("Could not find ' ZEI' in stderr", .{});
            }
        } else {
            log.warn("Could not find 'spendable): ' in stderr", .{});
        }
        
        const response = try std.fmt.allocPrint(allocator, 
            "{{\"success\":true,\"balance\":\"{s}\"}}", 
            .{balance_str});
        defer allocator.free(response);
        
        r.setStatus(.ok);
        r.sendBody(response) catch {};
    } else {
        // Check if it's a password error for better user messaging
        const error_msg = if (std.mem.indexOf(u8, result.stderr, "Invalid password") != null)
            "❌ Invalid password. Please check your wallet password and try again."
        else
            result.stderr;
            
        const escaped_error = escapedJsonString(allocator, error_msg);
        defer if (escaped_error.ptr != error_msg.ptr) allocator.free(escaped_error);
        
        const response = try std.fmt.allocPrint(allocator, 
            "{{\"success\":false,\"error\":\"{s}\"}}", 
            .{escaped_error});
        defer allocator.free(response);
        
        r.setStatus(.bad_request);
        r.sendBody(response) catch {};
    }
}

fn handleGetAddress(r: zap.Request, json: std.json.Value, allocator: std.mem.Allocator) !void {
    const obj = json.object;
    const wallet = obj.get("wallet").?.string;
    const password = obj.get("password").?.string;
    
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("address");
    try cmd_args.append(wallet);
    
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    try env_map.put("ZEICOIN_WALLET_PASSWORD", password);
    
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = cmd_args.items,
        .env_map = &env_map,
    }) catch |err| {
        log.err("Failed to get address: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Address check failed\"}") catch {};
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    
    if (result.term.Exited == 0) {
        // Extract address from CLI stderr output
        var address_str: []const u8 = "";
        const output_to_parse = result.stderr;
        
        if (std.mem.indexOf(u8, output_to_parse, "Address: ")) |start| {
            const addr_start = start + "Address: ".len;
            if (std.mem.indexOf(u8, output_to_parse[addr_start..], "\n")) |end| {
                address_str = output_to_parse[addr_start..addr_start + end];
            }
        }
        
        const response = try std.fmt.allocPrint(allocator, 
            "{{\"success\":true,\"address\":\"{s}\"}}", 
            .{address_str});
        defer allocator.free(response);
        
        r.setStatus(.ok);
        r.sendBody(response) catch {};
    } else {
        // Check if it's a password error for better user messaging
        const error_msg = if (std.mem.indexOf(u8, result.stderr, "Invalid password") != null)
            "❌ Invalid password. Please check your wallet password and try again."
        else
            result.stderr;
            
        const escaped_error = escapedJsonString(allocator, error_msg);
        defer if (escaped_error.ptr != error_msg.ptr) allocator.free(escaped_error);
        
        const response = try std.fmt.allocPrint(allocator, 
            "{{\"success\":false,\"error\":\"{s}\"}}", 
            .{escaped_error});
        defer allocator.free(response);
        
        r.setStatus(.bad_request);
        r.sendBody(response) catch {};
    }
}

fn handleGetStatus(r: zap.Request, allocator: std.mem.Allocator) !void {
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("status");
    
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = cmd_args.items,
        .env_map = &env_map,
    }) catch |err| {
        log.err("Failed to get status: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Status check failed\"}") catch {};
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    
    const response = try std.fmt.allocPrint(allocator, 
        "{{\"success\":true,\"status\":\"{s}\"}}", 
        .{escapedJsonString(allocator, std.mem.trim(u8, result.stdout, " \n\r\t"))});
    defer allocator.free(response);
    
    r.setStatus(.ok);
    r.sendBody(response) catch {};
}

fn escapedJsonString(allocator: std.mem.Allocator, input: []const u8) []const u8 {
    // Simple JSON string escaping - replace newlines and quotes
    var result = std.ArrayList(u8).init(allocator);
    
    for (input) |char| {
        switch (char) {
            '\n' => result.appendSlice("\\n") catch {
                result.deinit();
                return input;
            },
            '\r' => result.appendSlice("\\r") catch {
                result.deinit();
                return input;
            },
            '"' => result.appendSlice("\\\"") catch {
                result.deinit();
                return input;
            },
            '\\' => result.appendSlice("\\\\") catch {
                result.deinit();
                return input;
            },
            else => result.append(char) catch {
                result.deinit();
                return input;
            },
        }
    }
    
    return result.toOwnedSlice() catch {
        result.deinit();
        return input;
    };
}