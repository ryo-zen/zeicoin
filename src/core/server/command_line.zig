// command_line.zig - Command line argument parsing for ZeiCoin server
// Handles all CLI options and configuration

const std = @import("std");
const log = std.log.scoped(.server);
const network = @import("../network/peer.zig");

pub const Config = struct {
    port: u16 = network.DEFAULT_PORT,
    bootstrap_nodes: []const BootstrapNode = &[_]BootstrapNode{},
    enable_mining: bool = false,
    miner_wallet: ?[]const u8 = null,
    client_api_disabled: bool = false,
    bind_address: []const u8 = "127.0.0.1",
    bind_address_allocated: bool = false, // Track if bind_address was allocated
    allocator: std.mem.Allocator,
    
    pub fn deinit(self: *Config) void {
        if (self.bootstrap_nodes.len > 0) {
            // Free each IP string
            for (self.bootstrap_nodes) |node| {
                self.allocator.free(node.ip);
            }
            self.allocator.free(self.bootstrap_nodes);
        }
        // Free miner_wallet if owned
        if (self.miner_wallet) |wallet_name| {
            self.allocator.free(wallet_name);
        }
        // Free bind_address if it was allocated
        if (self.bind_address_allocated) {
            self.allocator.free(self.bind_address);
        }
    }
};

pub const BootstrapNode = struct {
    ip: []const u8,
    port: u16,
};

pub fn parseArgs(allocator: std.mem.Allocator) !Config {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    
    var config = Config{ .allocator = allocator };
    var bootstrap_list = std.ArrayList(BootstrapNode).init(allocator);
    defer bootstrap_list.deinit();
    
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "help")) {
            printHelp();
            return error.HelpRequested;
        } else if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            config.port = try std.fmt.parseInt(u16, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--bootstrap") and i + 1 < args.len) {
            try parseBootstrapNodes(&bootstrap_list, args[i + 1]);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--mine")) {
            // Check if wallet name follows (REQUIRED)
            if (i + 1 < args.len and !std.mem.startsWith(u8, args[i + 1], "--")) {
                config.enable_mining = true;
                // Create owned copy of wallet name to avoid dangling pointer
                config.miner_wallet = try allocator.dupe(u8, args[i + 1]);
                i += 1;
            } else {
                log.info("❌ Error: --mine requires a wallet name", .{});
                log.info("💡 Usage: zen_server --mine <wallet_name>", .{});
                log.info("💡 Example: zen_server --mine miner", .{});
                return error.MissingMinerWallet;
            }
        } else if (std.mem.eql(u8, args[i], "--no-client-api")) {
            config.client_api_disabled = true;
        } else {
            log.info("Unknown argument: {s}", .{args[i]});
            printHelp();
            return error.UnknownArgument;
        }
    }
    
    // Handle environment variable for bind address
    if (std.process.getEnvVarOwned(allocator, "ZEICOIN_BIND_IP")) |bind_ip| {
        config.bind_address = bind_ip; // Transfer ownership to config
        config.bind_address_allocated = true;
    } else |_| {}
    
    // Handle environment variable for bootstrap nodes
    if (bootstrap_list.items.len == 0) {
        if (std.process.getEnvVarOwned(allocator, "ZEICOIN_BOOTSTRAP")) |env_bootstrap| {
            defer allocator.free(env_bootstrap);
            try parseBootstrapNodes(&bootstrap_list, env_bootstrap);
        } else |_| {}
    }
    
    // No default bootstrap nodes - nodes without bootstrap config act as bootstrap nodes themselves
    
    config.bootstrap_nodes = try bootstrap_list.toOwnedSlice();
    return config;
}

fn parseBootstrapNodes(list: *std.ArrayList(BootstrapNode), input: []const u8) !void {
    var iter = std.mem.tokenizeScalar(u8, input, ',');
    while (iter.next()) |node| {
        var parts = std.mem.tokenizeScalar(u8, node, ':');
        const ip = parts.next() orelse continue;
        const port = if (parts.next()) |p| 
            try std.fmt.parseInt(u16, p, 10) 
        else 
            network.DEFAULT_PORT;
        
        // Duplicate the IP string to ensure it's owned by the list
        const ip_copy = try list.allocator.dupe(u8, ip);
        try list.append(.{ .ip = ip_copy, .port = port });
    }
}

fn printHelp() void {
    const print = std.debug.print;
    print(
        \\ZeiCoin Server
        \\
        \\Usage: zen_server [options]
        \\
        \\Options:
        \\  --port <port>           Listen on specified port (default: 10801)
        \\  --bootstrap <nodes>     Bootstrap nodes (ip:port,ip:port,...)
        \\  --mine <wallet>         Enable mining to specified wallet (REQUIRED)
        \\  --no-client-api         Disable client API on port 10802
        \\  --help, -h, help        Show this help message
        \\
        \\Environment variables:
        \\  ZEICOIN_P2P_PORT        P2P listen port (default: 10801)
        \\  ZEICOIN_BIND_IP         Bind IP address (default: 127.0.0.1)
        \\  ZEICOIN_BOOTSTRAP       Comma-separated list of bootstrap nodes
        \\  ZEICOIN_MINE_ENABLED    Enable mining (true/false)
        \\  ZEICOIN_MINER_WALLET    Wallet name for mining rewards
        \\  ZEICOIN_CLIENT_API_ENABLED  Enable client API (true/false, default: true)
        \\
        \\Examples:
        \\  zen_server --port 10801
        \\  zen_server --bootstrap 192.168.1.10:10801,192.168.1.11:10801
        \\  zen_server --mine miner
        \\
    , .{});
}