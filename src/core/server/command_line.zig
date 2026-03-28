// command_line.zig - Command line argument parsing for ZeiCoin server
// Handles all CLI options and configuration

const std = @import("std");
const log = std.log.scoped(.server);
const network = @import("../network/peer.zig");
const util = @import("../util/util.zig");
const bootstrap = @import("../network/bootstrap.zig");

pub const Config = struct {
    port: u16 = network.DEFAULT_PORT,
    api_port: u16 = 10802,
    rpc_port: u16 = 10803,
    bootstrap_nodes: []const bootstrap.BootstrapAddr = &[_]bootstrap.BootstrapAddr{},
    enable_mining: bool = false,
    miner_wallet: ?[]const u8 = null,
    client_api_disabled: bool = false,
    bind_address: []const u8 = "127.0.0.1",
    bind_address_allocated: bool = false, // Track if bind_address was allocated
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Config) void {
        if (self.bootstrap_nodes.len > 0) {
            bootstrap.freeList(self.allocator, self.bootstrap_nodes);
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

pub fn parseArgs(allocator: std.mem.Allocator, args: []const [:0]const u8) !Config {
    var config = Config{ .allocator = allocator };
    var bootstrap_list = std.array_list.Managed(bootstrap.BootstrapAddr).init(allocator);
    defer {
        for (bootstrap_list.items) |*n| n.deinit();
        bootstrap_list.deinit();
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h") or std.mem.eql(u8, args[i], "help")) {
            printHelp();
            return error.HelpRequested;
        } else if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            config.port = try std.fmt.parseInt(u16, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--bootstrap") and i + 1 < args.len) {
            try appendBootstrapNodes(allocator, &bootstrap_list, args[i + 1]);
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
    if (util.getEnvVarOwned(allocator, "ZEICOIN_BIND_IP")) |bind_ip| {
        config.bind_address = bind_ip; // Transfer ownership to config
        config.bind_address_allocated = true;
    } else |_| {}
    
    // Handle environment variable for bootstrap nodes
    if (bootstrap_list.items.len == 0) {
        if (util.getEnvVarOwned(allocator, "ZEICOIN_BOOTSTRAP")) |env_bootstrap| {
            defer allocator.free(env_bootstrap);
            try appendBootstrapNodes(allocator, &bootstrap_list, env_bootstrap);
        } else |_| {}
    }

    // Handle environment variables for ports
    const p2p_port_env = util.getEnvVarOwned(allocator, "ZEICOIN_P2P_PORT") catch 
                         util.getEnvVarOwned(allocator, "ZEICOIN_PORT") catch 
                         null;
    if (p2p_port_env) |p2p_port_str| {
        defer allocator.free(p2p_port_str);
        config.port = std.fmt.parseInt(u16, p2p_port_str, 10) catch config.port;
    }

    const api_port_env = util.getEnvVarOwned(allocator, "ZEICOIN_CLIENT_PORT") catch 
                         util.getEnvVarOwned(allocator, "ZEICOIN_API_PORT") catch 
                         null;
    if (api_port_env) |api_port_str| {
        defer allocator.free(api_port_str);
        config.api_port = std.fmt.parseInt(u16, api_port_str, 10) catch config.api_port;
    }

    if (util.getEnvVarOwned(allocator, "ZEICOIN_RPC_PORT")) |rpc_port_str| {
        defer allocator.free(rpc_port_str);
        config.rpc_port = std.fmt.parseInt(u16, rpc_port_str, 10) catch config.rpc_port;
    } else |_| {}
    
    // Handle mining environment variables
    if (util.getEnvVarOwned(allocator, "ZEICOIN_MINE_ENABLED")) |mine_enabled_str| {
        defer allocator.free(mine_enabled_str);
        config.enable_mining = std.mem.eql(u8, mine_enabled_str, "true");
    } else |_| {}
    
    if (config.miner_wallet == null) {
        if (util.getEnvVarOwned(allocator, "ZEICOIN_MINER_WALLET")) |miner_wallet| {
            config.miner_wallet = miner_wallet; // Transfer ownership
        } else |_| {}
    }

    // Handle client API environment variable
    if (util.getEnvVarOwned(allocator, "ZEICOIN_CLIENT_API_ENABLED")) |api_enabled_str| {
        defer allocator.free(api_enabled_str);
        config.client_api_disabled = std.mem.eql(u8, api_enabled_str, "false");
    } else |_| {}
    
    // No default bootstrap nodes - nodes without bootstrap config act as bootstrap nodes themselves
    
    config.bootstrap_nodes = try bootstrap_list.toOwnedSlice();
    return config;
}

fn appendBootstrapNodes(
    allocator: std.mem.Allocator,
    list: *std.array_list.Managed(bootstrap.BootstrapAddr),
    input: []const u8,
) !void {
    const parsed = try bootstrap.parseList(allocator, input);
    var transferred: usize = 0;
    errdefer {
        // Free elements that were not yet transferred into the list.
        for (parsed[transferred..]) |*n| n.deinit();
        allocator.free(parsed);
    }
    for (parsed) |node| {
        try list.append(node);
        transferred += 1;
    }
    allocator.free(parsed); // Slice header only; elements now owned by list.
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
        \\  --bootstrap <nodes>     Bootstrap nodes (multiaddr, comma-separated)
        \\  --mine <wallet>         Enable mining to specified wallet (REQUIRED)
        \\  --no-client-api         Disable client API on port 10802
        \\  --help, -h, help        Show this help message
        \\
        \\Environment variables:
        \\  ZEICOIN_P2P_PORT        P2P listen port (default: 10801)
        \\  ZEICOIN_BIND_IP         Bind IP address (default: 127.0.0.1)
        \\  ZEICOIN_BOOTSTRAP       Comma-separated bootstrap multiaddrs
        \\  ZEICOIN_MINE_ENABLED    Enable mining (true/false)
        \\  ZEICOIN_MINER_WALLET    Wallet name for mining rewards
        \\  ZEICOIN_CLIENT_API_ENABLED  Enable client API (true/false, default: true)
        \\
        \\Examples:
        \\  zen_server --port 10801
        \\  zen_server --bootstrap /ip4/192.168.1.10/tcp/10801,/ip4/192.168.1.11/tcp/10801
        \\  zen_server --mine miner
        \\
    , .{});
}