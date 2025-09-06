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
    } else if (std.mem.eql(u8, command_type, "wallet_create")) {
        try handleWalletCreate(r, json, allocator);
    } else if (std.mem.eql(u8, command_type, "wallet_list")) {
        try handleWalletList(r, allocator);
    } else if (std.mem.eql(u8, command_type, "wallet_restore")) {
        try handleWalletRestore(r, json, allocator);
    } else {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Unknown command\"}") catch {};
    }
}

fn handleSendTransaction(r: zap.Request, json: std.json.Value, allocator: std.mem.Allocator) !void {
    const obj = json.object;
    
    // Validate required fields
    const wallet_value = obj.get("wallet") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'wallet'\"}") catch {};
        return;
    };
    const password_value = obj.get("password") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'password'\"}") catch {};
        return;
    };
    const recipient_value = obj.get("recipient") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'recipient'\"}") catch {};
        return;
    };
    
    const wallet = wallet_value.string;
    const password = password_value.string;
    const recipient = recipient_value.string;
    
    // Handle amount as either number or string
    const amount_value = obj.get("amount") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"error\":\"Missing amount field\"}") catch {};
        return;
    };
    
    const amount = switch (amount_value) {
        .string => |s| s,
        .integer => |i| try std.fmt.allocPrint(allocator, "{}", .{i}),
        .float => |f| try std.fmt.allocPrint(allocator, "{d}", .{f}),
        else => {
            r.setStatus(.bad_request);
            r.sendBody("{\"error\":\"Amount must be a number or string\"}") catch {};
            return;
        },
    };
    defer if (amount_value != .string) allocator.free(amount);
    
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
    
    // Validate required fields
    const wallet_value = obj.get("wallet") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'wallet'\"}") catch {};
        return;
    };
    const password_value = obj.get("password") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'password'\"}") catch {};
        return;
    };
    
    const wallet = wallet_value.string;
    const password = password_value.string;
    
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
    
    // Validate required fields
    const wallet_value = obj.get("wallet") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'wallet'\"}") catch {};
        return;
    };
    const password_value = obj.get("password") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'password'\"}") catch {};
        return;
    };
    
    const wallet = wallet_value.string;
    const password = password_value.string;
    
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

fn handleWalletCreate(r: zap.Request, json: std.json.Value, allocator: std.mem.Allocator) !void {
    const obj = json.object;
    
    // Validate required fields
    const wallet_name_value = obj.get("wallet_name") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'wallet_name'\"}") catch {};
        return;
    };
    const password_value = obj.get("password") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'password'\"}") catch {};
        return;
    };
    
    const wallet_name = wallet_name_value.string;
    const password = password_value.string;
    
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("wallet");
    try cmd_args.append("create");
    try cmd_args.append(wallet_name);
    
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    try env_map.put("ZEICOIN_WALLET_PASSWORD", password);
    
    // Create child process (no stdin pipe needed with env var)
    var child = std.process.Child.init(cmd_args.items, allocator);
    child.env_map = &env_map;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    
    try child.spawn();
    
    // Read outputs BEFORE waiting (to avoid pipe deadlock)
    const stdout = if (child.stdout) |pipe| 
        pipe.readToEndAlloc(allocator, 1024 * 1024) catch ""
    else "";
    const stderr = if (child.stderr) |pipe| 
        pipe.readToEndAlloc(allocator, 1024 * 1024) catch ""
    else "";
    
    // Wait for completion with timeout
    const term = child.wait() catch |err| {
        _ = child.kill() catch {};
        log.err("Failed to wait for wallet creation: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Wallet creation failed\"}") catch {};
        return;
    };
    
    defer if (stdout.len > 0) allocator.free(stdout);
    defer if (stderr.len > 0) allocator.free(stderr);
    
    const result = std.process.Child.RunResult{
        .term = term,
        .stdout = @constCast(stdout),
        .stderr = @constCast(stderr),
    };
    
    // Clear password from memory immediately
    @memset(@as([*]u8, @ptrCast(@constCast(password.ptr)))[0..password.len], 0);
    
    if (result.term.Exited == 0) {
        // Extract mnemonic and first address from CLI output
        var mnemonic: ?[]const u8 = null;
        var first_address: ?[]const u8 = null;
        
        var lines = std.mem.splitScalar(u8, result.stderr, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            
            // Look for mnemonic pattern with emoji
            if (std.mem.indexOf(u8, trimmed, "🔑 Mnemonic (12 words):")) |_| {
                if (lines.next()) |mnemonic_line| {
                    mnemonic = std.mem.trim(u8, mnemonic_line, " \t\r\n");
                }
            }
            
            // Look for first address pattern with emoji
            if (std.mem.indexOf(u8, trimmed, "🆔 First address: ")) |pos| {
                const prefix = "🆔 First address: ";
                first_address = std.mem.trim(u8, trimmed[pos + prefix.len..], " \t\r\n");
            }
        }
        
        const response = if (mnemonic != null and first_address != null)
            try std.fmt.allocPrint(allocator,
                "{{\"success\":true,\"wallet_name\":\"{s}\",\"mnemonic\":\"{s}\",\"first_address\":\"{s}\"}}",
                .{ wallet_name, mnemonic.?, first_address.? })
        else
            try std.fmt.allocPrint(allocator,
                "{{\"success\":true,\"wallet_name\":\"{s}\",\"output\":\"{s}\"}}",
                .{ wallet_name, escapedJsonString(allocator, result.stderr) });
                
        defer allocator.free(response);
        
        r.setStatus(.ok);
        r.sendBody(response) catch {};
        
        log.info("✅ Wallet created successfully: {s}", .{wallet_name});
    } else {
        const response = try std.fmt.allocPrint(allocator,
            "{{\"success\":false,\"error\":\"Wallet creation failed\"}}", .{});
        defer allocator.free(response);
        
        r.setStatus(.bad_request);
        r.sendBody(response) catch {};
        
        log.warn("❌ Wallet creation failed for: {s}", .{wallet_name});
    }
}

fn handleWalletList(r: zap.Request, allocator: std.mem.Allocator) !void {
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("wallet");
    try cmd_args.append("list");
    
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = cmd_args.items,
        .env_map = &env_map,
    }) catch |err| {
        log.err("Failed to list wallets: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Failed to list wallets\"}") catch {};
        return;
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    
    if (result.term.Exited == 0) {
        // Parse wallet list from CLI output - extract wallet names
        var wallet_list = std.ArrayList([]const u8).init(allocator);
        defer wallet_list.deinit();
        
        // Try both stdout and stderr for wallet list output
        const output = if (result.stdout.len > 0) result.stdout else result.stderr;
        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r\n");
            // Look for lines with wallet emoji indicator
            if (std.mem.indexOf(u8, trimmed, "💼 ")) |pos| {
                const emoji_and_space = "💼 ";
                const wallet_name = std.mem.trim(u8, trimmed[pos + emoji_and_space.len..], " \t\r\n");
                if (wallet_name.len > 0) {
                    try wallet_list.append(wallet_name);
                }
            }
        }
        
        // Build JSON array of wallet names
        var json_builder = std.ArrayList(u8).init(allocator);
        defer json_builder.deinit();
        
        try json_builder.appendSlice("{\"success\":true,\"wallets\":[");
        for (wallet_list.items, 0..) |wallet, i| {
            if (i > 0) try json_builder.appendSlice(",");
            try json_builder.append('"');
            try json_builder.appendSlice(wallet);
            try json_builder.append('"');
        }
        try json_builder.appendSlice("]}");
        
        const response = try json_builder.toOwnedSlice();
        defer allocator.free(response);
        
        r.setStatus(.ok);
        r.sendBody(response) catch {};
        
        log.info("✅ Wallet list retrieved successfully", .{});
    } else {
        const response = try std.fmt.allocPrint(allocator, 
            "{{\"success\":false,\"error\":\"{s}\"}}", 
            .{escapedJsonString(allocator, result.stderr)});
        defer allocator.free(response);
        
        r.setStatus(.bad_request);
        r.sendBody(response) catch {};
        
        log.warn("❌ Failed to list wallets: {s}", .{result.stderr});
    }
}

fn handleWalletRestore(r: zap.Request, json: std.json.Value, allocator: std.mem.Allocator) !void {
    const obj = json.object;
    
    // Validate required fields
    const wallet_name_value = obj.get("wallet_name") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'wallet_name'\"}") catch {};
        return;
    };
    const mnemonic_value = obj.get("mnemonic") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'mnemonic'\"}") catch {};
        return;
    };
    const password_value = obj.get("password") orelse {
        r.setStatus(.bad_request);
        r.sendBody("{\"success\":false,\"error\":\"❌ Missing required field: 'password'\"}") catch {};
        return;
    };
    
    const wallet_name = wallet_name_value.string;
    const mnemonic = mnemonic_value.string;
    const password = password_value.string;
    
    // Build CLI command: zeicoin wallet restore <name> <word1> <word2> ... <wordN>
    var cmd_args = std.ArrayList([]const u8).init(allocator);
    defer cmd_args.deinit();
    
    try cmd_args.append("./zig-out/bin/zeicoin");
    try cmd_args.append("wallet");
    try cmd_args.append("restore");
    try cmd_args.append(wallet_name);
    
    // Split mnemonic into individual words
    var word_iterator = std.mem.splitSequence(u8, mnemonic, " ");
    while (word_iterator.next()) |word| {
        const trimmed_word = std.mem.trim(u8, word, " \t\r\n");
        if (trimmed_word.len > 0) {
            try cmd_args.append(trimmed_word);
        }
    }
    
    var env_map = std.process.EnvMap.init(allocator);
    defer env_map.deinit();
    
    try env_map.put("ZEICOIN_SERVER", "127.0.0.1");
    try env_map.put("ZEICOIN_WALLET_PASSWORD", password);
    
    // Create child process similar to wallet creation
    var child = std.process.Child.init(cmd_args.items, allocator);
    child.env_map = &env_map;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    
    try child.spawn();
    
    // Read outputs BEFORE waiting (to avoid pipe deadlock)
    const stdout = if (child.stdout) |pipe| 
        pipe.readToEndAlloc(allocator, 1024 * 1024) catch ""
    else "";
    const stderr = if (child.stderr) |pipe| 
        pipe.readToEndAlloc(allocator, 1024 * 1024) catch ""
    else "";
    
    // Wait for completion
    const term = child.wait() catch |err| {
        _ = child.kill() catch {};
        log.err("Failed to wait for wallet restoration: {}", .{err});
        r.setStatus(.internal_server_error);
        r.sendBody("{\"error\":\"Wallet restoration failed\"}") catch {};
        return;
    };
    
    defer if (stdout.len > 0) allocator.free(stdout);
    defer if (stderr.len > 0) allocator.free(stderr);
    
    // Clear mnemonic from memory immediately
    @memset(@as([*]u8, @ptrCast(@constCast(mnemonic.ptr)))[0..mnemonic.len], 0);
    
    if (term.Exited == 0) {
        const response = try std.fmt.allocPrint(allocator,
            "{{\"success\":true,\"wallet_name\":\"{s}\",\"message\":\"Wallet restored successfully\"}}",
            .{ wallet_name });
        defer allocator.free(response);
        
        r.setStatus(.ok);
        r.sendBody(response) catch {};
        
        log.info("✅ Wallet restored successfully: {s}", .{wallet_name});
    } else {
        const error_msg = if (std.mem.indexOf(u8, stderr, "Invalid mnemonic") != null)
            "❌ Invalid mnemonic seed phrase. Please check your 12 words and try again."
        else if (std.mem.indexOf(u8, stderr, "already exists") != null)
            "❌ Wallet name already exists. Please choose a different name."
        else if (std.mem.indexOf(u8, stderr, "Invalid password") != null)
            "❌ Invalid password. Please check your password and try again."
        else
            stderr;
            
        const escaped_error = escapedJsonString(allocator, error_msg);
        defer if (escaped_error.ptr != error_msg.ptr) allocator.free(escaped_error);
        
        const response = try std.fmt.allocPrint(allocator,
            "{{\"success\":false,\"error\":\"{s}\"}}", 
            .{escaped_error});
        defer allocator.free(response);
        
        r.setStatus(.bad_request);
        r.sendBody(response) catch {};
        
        log.warn("❌ Wallet restoration failed for: {s}, error: {s}", .{ wallet_name, stderr });
    }
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