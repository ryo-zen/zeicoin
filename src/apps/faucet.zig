const std = @import("std");
const zeicoin = @import("zeicoin");
const wallet_mod = zeicoin.wallet;
const types = zeicoin.types;
const util = zeicoin.util;
const password_util = zeicoin.password;
const postgres = util.postgres;
const RPCClient = @import("rpc_client.zig").RPCClient;

const log = std.log.scoped(.faucet);

const ZEI_COIN = types.ZEI_COIN;
const FAUCET_MAX_SCORE: u32 = 200; // score cap -> 2.00 ZEI max
const FAUCET_RATE_LIMIT_MS: u64 = 24 * 60 * 60 * 1000; // 24 hours

pub const FaucetService = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    rpc: *RPCClient,

    wallet: ?*wallet_mod.Wallet = null,
    address: types.Address = types.Address.zero(),
    address_bech32: []u8 = &[_]u8{},
    enabled: bool = false,
    mutex: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io: std.Io, rpc: *RPCClient) Self {
        return .{
            .allocator = allocator,
            .io = io,
            .rpc = rpc,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.wallet) |w| {
            w.deinit();
            self.allocator.destroy(w);
            self.wallet = null;
        }
        if (self.address_bech32.len > 0) {
            self.allocator.free(self.address_bech32);
            self.address_bech32 = &[_]u8{};
        }
        self.enabled = false;
    }

    pub fn loadFromEnv(self: *Self) void {
        const wallet_name = util.getEnvVarOwned(self.allocator, "FAUCET_WALLET_NAME") catch {
            log.info("FAUCET_WALLET_NAME not set, faucet disabled", .{});
            return;
        };
        defer self.allocator.free(wallet_name);

        const wallet_password = util.getEnvVarOwned(self.allocator, "FAUCET_WALLET_PASSWORD") catch {
            log.warn("FAUCET_WALLET_PASSWORD not set, faucet disabled", .{});
            return;
        };
        defer {
            password_util.clearPassword(wallet_password);
            self.allocator.free(wallet_password);
        }

        const data_dir = switch (types.CURRENT_NETWORK) {
            .testnet => "zeicoin_data_testnet",
            .mainnet => "zeicoin_data_mainnet",
        };

        const wallet_path = std.fmt.allocPrint(self.allocator, "{s}/wallets/{s}.wallet", .{ data_dir, wallet_name }) catch return;
        defer self.allocator.free(wallet_path);

        const w = self.allocator.create(wallet_mod.Wallet) catch return;
        w.* = wallet_mod.Wallet.init(self.allocator);

        w.loadFromFile(self.io, wallet_path, wallet_password) catch |err| {
            log.err("Failed to load faucet wallet '{s}': {}", .{ wallet_name, err });
            w.deinit();
            self.allocator.destroy(w);
            return;
        };

        const addr = w.getAddress(0) catch |err| {
            log.err("Failed to get faucet address: {}", .{err});
            w.deinit();
            self.allocator.destroy(w);
            return;
        };

        const addr_str = addr.toBech32(self.allocator, types.CURRENT_NETWORK) catch |err| {
            log.err("Failed to encode faucet address: {}", .{err});
            w.deinit();
            self.allocator.destroy(w);
            return;
        };

        self.wallet = w;
        self.address = addr;
        self.address_bech32 = addr_str;
        self.enabled = true;

        log.info("faucet wallet loaded: {s}", .{addr_str});
    }

    pub fn handleRequest(self: *Self, allocator: std.mem.Allocator, db_pool: anytype, body: []const u8) ![]const u8 {
        if (!self.enabled) {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_disabled\"}");
        }

        const trimmed = std.mem.trim(u8, body, &std.ascii.whitespace);
        const parsed = std.json.parseFromSlice(
            struct {
                address: []const u8,
                score: u32,
            },
            allocator,
            trimmed,
            .{},
        ) catch return try allocator.dupe(u8, "{\"success\":false,\"error\":\"invalid_json\"}");
        defer parsed.deinit();

        const recipient_str = parsed.value.address;
        const score = parsed.value.score;

        const recipient_address = types.Address.fromString(allocator, recipient_str) catch {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"invalid_address\"}");
        };
        if (recipient_address.equals(self.address)) {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"self_transfer_not_allowed\"}");
        }

        const score_capped = @min(score, FAUCET_MAX_SCORE);
        if (score_capped == 0) {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"score_too_low\"}");
        }

        const amount: u64 = @as(u64, score_capped) * (ZEI_COIN / 100);
        const fee = types.ZenFees.STANDARD_FEE;
        const display_whole = score_capped / 100;
        const display_frac = score_capped % 100;
        const amount_display = try std.fmt.allocPrint(allocator, "{d}.{d:0>2}", .{ display_whole, display_frac });
        defer allocator.free(amount_display);

        {
            var conn: postgres.Connection = try db_pool.acquire();
            defer db_pool.release(conn);

            const now_ms: u64 = @as(u64, @intCast(util.getTime())) * 1000;
            const cutoff_ms = now_ms -| FAUCET_RATE_LIMIT_MS;

            const cutoff_str = try std.fmt.allocPrint(allocator, "{d}", .{cutoff_ms});
            defer allocator.free(cutoff_str);
            const address_z = try allocator.dupeZ(u8, recipient_str);
            defer allocator.free(address_z);
            const cutoff_z = try allocator.dupeZ(u8, cutoff_str);
            defer allocator.free(cutoff_z);

            const rate_sql =
                \\SELECT claimed_at FROM faucet_claims
                \\WHERE address = $1 AND claimed_at > $2
                \\ORDER BY claimed_at DESC LIMIT 1
            ;
            const rate_sql_z = try allocator.dupeZ(u8, rate_sql);
            defer allocator.free(rate_sql_z);

            const rate_params = [_][:0]const u8{ address_z, cutoff_z };
            var rate_result = try conn.queryParams(rate_sql_z, &rate_params);
            defer rate_result.deinit();

            if (rate_result.rowCount() > 0) {
                const last_claim_str = rate_result.getValue(0, 0) orelse "0";
                const last_claim_ms = std.fmt.parseInt(u64, last_claim_str, 10) catch 0;
                const retry_after_s = (last_claim_ms + FAUCET_RATE_LIMIT_MS -| now_ms) / 1000;
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"success\":false,\"error\":\"rate_limited\",\"retry_after_seconds\":{d}}}",
                    .{retry_after_s},
                );
            }
        }

        const faucet_str = self.address_bech32;
        const balance_result = self.rpc.getBalance(faucet_str) catch {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_unavailable\"}");
        };

        if (balance_result.balance < amount + fee) {
            log.warn("faucet balance too low: have {d}, need {d}", .{ balance_result.balance, amount + fee });
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_empty\"}");
        }

        if (balance_result.balance < 100 * ZEI_COIN) {
            log.warn("faucet balance below 100 ZEI: {d} satoshis remaining", .{balance_result.balance});
        }

        const current_height = self.rpc.getHeight() catch {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_unavailable\"}");
        };

        const timestamp: u64 = @as(u64, @intCast(util.getTime())) * 1000;
        const expiry_height: u64 = @as(u64, current_height) + types.TransactionExpiry.getExpiryWindow();

        var transaction = types.Transaction{
            .version = 0,
            .flags = .{},
            .sender = self.address,
            .sender_public_key = std.mem.zeroes([32]u8),
            .recipient = recipient_address,
            .amount = amount,
            .fee = fee,
            .nonce = balance_result.nonce,
            .timestamp = timestamp,
            .expiry_height = expiry_height,
            .signature = std.mem.zeroes(types.Signature),
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };

        {
            self.mutex.lock();
            defer self.mutex.unlock();

            const w = self.wallet orelse return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_disabled\"}");
            const key_pair = w.getKeyPair(0) catch {
                return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_signing_failed\"}");
            };
            transaction.sender_public_key = key_pair.public_key;
            const tx_hash = transaction.hashForSigning();
            transaction.signature = w.signTransaction(&tx_hash) catch {
                return try allocator.dupe(u8, "{\"success\":false,\"error\":\"faucet_signing_failed\"}");
            };
        }

        const sig_bytes = std.fmt.bytesToHex(transaction.signature, .lower);
        const pk_bytes = std.fmt.bytesToHex(transaction.sender_public_key, .lower);
        const sig_hex: []const u8 = &sig_bytes;
        const pk_hex: []const u8 = &pk_bytes;

        const tx_hash_str = self.rpc.broadcastTransaction(
            faucet_str,
            recipient_str,
            transaction.amount,
            transaction.fee,
            transaction.nonce,
            transaction.timestamp,
            transaction.expiry_height,
            sig_hex,
            pk_hex,
        ) catch {
            return try allocator.dupe(u8, "{\"success\":false,\"error\":\"broadcast_failed\"}");
        };
        defer allocator.free(tx_hash_str);

        {
            var conn: postgres.Connection = try db_pool.acquire();
            defer db_pool.release(conn);

            const now_ms_str = try std.fmt.allocPrint(allocator, "{d}", .{timestamp});
            defer allocator.free(now_ms_str);
            const amount_str = try std.fmt.allocPrint(allocator, "{d}", .{amount});
            defer allocator.free(amount_str);
            const score_str = try std.fmt.allocPrint(allocator, "{d}", .{score_capped});
            defer allocator.free(score_str);

            const address_z = try allocator.dupeZ(u8, recipient_str);
            defer allocator.free(address_z);
            const amount_z = try allocator.dupeZ(u8, amount_str);
            defer allocator.free(amount_z);
            const score_z = try allocator.dupeZ(u8, score_str);
            defer allocator.free(score_z);
            const txid_z = try allocator.dupeZ(u8, tx_hash_str);
            defer allocator.free(txid_z);
            const claimed_at_z = try allocator.dupeZ(u8, now_ms_str);
            defer allocator.free(claimed_at_z);

            const insert_sql =
                \\INSERT INTO faucet_claims (address, amount, score, txid, claimed_at)
                \\VALUES ($1, $2, $3, $4, $5)
            ;
            const insert_sql_z = try allocator.dupeZ(u8, insert_sql);
            defer allocator.free(insert_sql_z);

            const insert_params = [_][:0]const u8{ address_z, amount_z, score_z, txid_z, claimed_at_z };
            var insert_result = conn.queryParams(insert_sql_z, &insert_params) catch {
                return try std.fmt.allocPrint(
                    allocator,
                    "{{\"success\":true,\"amount\":\"{s}\",\"txid\":\"{s}\"}}",
                    .{ amount_display, tx_hash_str },
                );
            };
            insert_result.deinit();
        }

        return try std.fmt.allocPrint(
            allocator,
            "{{\"success\":true,\"amount\":\"{s}\",\"txid\":\"{s}\"}}",
            .{ amount_display, tx_hash_str },
        );
    }
};

const DummyPool = struct {
    pub fn acquire(_: *DummyPool) !postgres.Connection {
        return error.ShouldNotBeCalled;
    }

    pub fn release(_: *DummyPool, _: postgres.Connection) void {}
};

test "handleRequest returns faucet_disabled when service disabled" {
    const allocator = std.testing.allocator;
    var rpc_client = RPCClient.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), "127.0.0.1", 10803);
    var service = FaucetService.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), &rpc_client);
    defer service.deinit();

    var dummy_pool = DummyPool{};
    const response = try service.handleRequest(allocator, &dummy_pool, "{\"address\":\"x\",\"score\":1}");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("{\"success\":false,\"error\":\"faucet_disabled\"}", response);
}

test "handleRequest returns invalid_json for malformed payload" {
    const allocator = std.testing.allocator;
    var rpc_client = RPCClient.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), "127.0.0.1", 10803);
    var service = FaucetService.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), &rpc_client);
    defer service.deinit();

    service.enabled = true;
    service.address = types.Address.zero();

    var dummy_pool = DummyPool{};
    const response = try service.handleRequest(allocator, &dummy_pool, "{");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("{\"success\":false,\"error\":\"invalid_json\"}", response);
}

test "handleRequest returns invalid_address for bad bech32 address" {
    const allocator = std.testing.allocator;
    var rpc_client = RPCClient.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), "127.0.0.1", 10803);
    var service = FaucetService.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), &rpc_client);
    defer service.deinit();

    service.enabled = true;
    service.address = types.Address.zero();

    var dummy_pool = DummyPool{};
    const response = try service.handleRequest(
        allocator,
        &dummy_pool,
        "{\"address\":\"not-a-valid-address\",\"score\":42}",
    );
    defer allocator.free(response);

    try std.testing.expectEqualStrings("{\"success\":false,\"error\":\"invalid_address\"}", response);
}

test "handleRequest returns self_transfer_not_allowed for faucet self-send" {
    const allocator = std.testing.allocator;
    var rpc_client = RPCClient.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), "127.0.0.1", 10803);
    var service = FaucetService.init(allocator, std.Io.Threaded.global_single_threaded.ioBasic(), &rpc_client);
    defer service.deinit();

    service.enabled = true;
    service.address = types.Address.zero();

    const self_addr = try service.address.toBech32(allocator, types.CURRENT_NETWORK);
    defer allocator.free(self_addr);

    const body = try std.fmt.allocPrint(allocator, "{{\"address\":\"{s}\",\"score\":10}}", .{self_addr});
    defer allocator.free(body);

    var dummy_pool = DummyPool{};
    const response = try service.handleRequest(allocator, &dummy_pool, body);
    defer allocator.free(response);

    try std.testing.expectEqualStrings("{\"success\":false,\"error\":\"self_transfer_not_allowed\"}", response);
}
