// client_api.zig - Client API server for ZeiCoin
// Handles transaction submission, balance queries, and other client operations

const std = @import("std");
const log = std.log.scoped(.server);
const net = std.Io.net;
const types = @import("../types/types.zig");
const zen = @import("../node.zig");
const wallet = @import("../wallet/wallet.zig");
const serialize = @import("../storage/serialize.zig");
const key = @import("../crypto/key.zig");
const bech32 = @import("../crypto/bech32.zig");
const util = @import("../util/util.zig");

pub const CLIENT_API_PORT: u16 = 10802;
const MAX_TRANSACTIONS_PER_SESSION = 100;

pub const ClientApiServer = struct {
    allocator: std.mem.Allocator,
    blockchain: *zen.ZeiCoin,
    server: ?net.Server,
    running: std.atomic.Value(bool),
    bind_address: []const u8,
    port: u16,
    
    const Self = @This();

    fn sendResponse(io: std.Io, connection: net.Stream, data: []const u8) !void {
        // Use a tiny 1-byte buffer to ensure std.Io.net.Writer 
        // doesn't trap small responses in a larger default buffer.
        var tiny_buf: [1]u8 = undefined;
        var writer = connection.writer(io, &tiny_buf);
        try writer.interface.writeAll(data);
    }

    pub fn init(allocator: std.mem.Allocator, blockchain: *zen.ZeiCoin, bind_address: []const u8, port: u16) Self {
        return .{ 
            .allocator = allocator,
            .blockchain = blockchain,
            .server = null,
            .running = std.atomic.Value(bool).init(false),
            .bind_address = bind_address,
            .port = port,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stop();
        if (self.server) |*server| {
            const io = self.blockchain.io;
            server.deinit(io);
        }
    }

    /// Initialize the listener socket. 
    /// Should be called from the main thread before starting the background loop.
    pub fn setup(self: *Self) !void {
        const address = try net.IpAddress.parse(self.bind_address, self.port);
        const io = self.blockchain.io;
        self.server = try address.listen(io, .{ .reuse_address = true });
        log.info("Client API listening on {s}:{}", .{self.bind_address, self.port});
    }
    
    pub fn start(self: *Self) !void {
        if (self.server == null) try self.setup();
        
        self.running.store(true, .release);
        const io = self.blockchain.io;

        while (self.running.load(.acquire)) {
            const connection = self.server.?.accept(io) catch |err| switch (err) {
                error.WouldBlock => {
                    io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
                    continue;
                },
                else => {
                    if (self.running.load(.acquire)) {
                        log.err("Client API accept error: {}", .{err});
                        io.sleep(std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake) catch {};
                    }
                    continue;
                },
            };
            
            // Handle connection in a new thread
            const thread = std.Thread.spawn(.{}, handleConnection, .{ 
                self, connection
            }) catch |err| {
                log.err("Failed to spawn connection thread: {}", .{err});
                connection.close(io);
                continue;
            };
            thread.detach();
        }
    }
    
    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
    }
    
    fn handleConnection(self: *Self, connection: net.Stream) void {
        const io = self.blockchain.io;
        defer connection.close(io);

        var transaction_count: u32 = 0;

        // Connection handler loop
        var buffer: [65536]u8 = undefined;
        while (self.running.load(.acquire)) {
            const msg = connection.socket.receive(io, &buffer) catch |err| {
                if (err != error.Canceled) {
                    log.debug("Client connection closed/error: {}", .{err});
                }
                break;
            };
            const bytes_read = msg.data.len;
            
            if (bytes_read == 0) break;
            
            const message = buffer[0..bytes_read];
            
            // Parse command
            if (std.mem.startsWith(u8, message, "BLOCKCHAIN_STATUS_ENHANCED")) {
                self.handleEnhancedStatus(io, connection) catch |err| {
                    std.log.err("Failed to send enhanced status: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "BLOCKCHAIN_STATUS")) {
                self.handleStatus(io, connection) catch |err| {
                    std.log.err("Failed to send status: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "CHECK_BALANCE:")) {
                self.handleCheckBalance(io, connection, message) catch |err| {
                    std.log.err("Failed to check balance: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "BALANCE:")) {
                self.handleBalance(io, connection, message) catch |err| {
                    std.log.err("Failed to check balance: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_HEIGHT")) {
                self.handleGetHeight(io, connection) catch |err| {
                    std.log.err("Failed to send height: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "HEIGHT")) {
                self.handleHeight(io, connection) catch |err| {
                    std.log.err("Failed to send height: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_NONCE:")) {
                self.handleGetNonce(io, connection, message) catch |err| {
                    std.log.err("Failed to check nonce: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "NONCE:")) {
                self.handleNonce(io, connection, message) catch |err| {
                    std.log.err("Failed to check nonce: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "CLIENT_TRANSACTION:")) {
                self.handleClientTransaction(io, connection, message, &transaction_count) catch |err| {
                    std.log.err("Failed to process transaction: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "TX:")) {
                self.handleTransaction(io, connection, message, &transaction_count) catch |err| {
                    std.log.err("Failed to process transaction: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "BATCH_TX:")) {
                self.handleBatchTransactions(io, connection, message, &transaction_count) catch |err| {
                    std.log.err("Failed to process batch transactions: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "TRIGGER_SYNC")) {
                self.handleTriggerSync(io, connection) catch |err| {
                    log.err("Failed to trigger sync: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_BLOCK:")) {
                self.handleGetBlock(io, connection, message) catch |err| {
                    log.err("Failed to get block: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_HISTORY:")) {
                self.handleGetHistory(io, connection, message) catch |err| {
                    log.err("Failed to get transaction history: {}", .{err});
                };
            } else {
                sendResponse(io, connection, "ERROR: Unknown command\n") catch {};
            }
        }
    }
    
    fn handleStatus(self: *Self, io: std.Io, connection: net.Stream) !void {
        const height = try self.blockchain.getHeight();
        const pending_count = self.blockchain.mempool_manager.getTransactionCount();
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HEIGHT={} PENDING={}\n",
            .{height, pending_count}
        );
        defer self.allocator.free(response);
        
        try sendResponse(io, connection, response);
    }
    
    fn handleEnhancedStatus(self: *Self, io: std.Io, connection: net.Stream) !void {
        const height = try self.blockchain.getHeight();
        const pending_count = self.blockchain.mempool_manager.getTransactionCount();
        
        // Get peer count from network manager
        var connected_peers: usize = 0;
        if (self.blockchain.network_coordinator.getNetworkManager()) |network_manager| {
            const peer_stats = network_manager.getPeerStats();
            connected_peers = peer_stats.connected;
        }
        
        // Check if mining is active AND there are transactions to mine
        const mining_manager_active = if (self.blockchain.mining_manager) |_|
            self.blockchain.mining_state.active.load(.acquire)
        else
            false;
        const has_transactions = pending_count > 0;
        const is_mining = mining_manager_active and has_transactions;
        
        // Calculate hash rate
        var hash_rate: f64 = 0.0;
        if (is_mining) {
            hash_rate = 150.5; // Placeholder hash rate
        }

        // If mining, we are working on the NEXT block (height + 1)
        const display_height = if (is_mining) height + 1 else height;
        
        // Format: "STATUS:height:peers:mempool:mining:hashrate"
        const response = try std.fmt.allocPrint(
            self.allocator,
            "STATUS:{}:{}:{}:{}:{d:.1}\n",
            .{display_height, connected_peers, pending_count, is_mining, hash_rate}
        );
        defer self.allocator.free(response);
        
        try sendResponse(io, connection, response);
    }
    
    fn handleTriggerSync(self: *Self, io: std.Io, connection: net.Stream) !void {
        std.log.info("Manual sync triggered via client API", .{});
        
        // Check if sync manager is available
        if (self.blockchain.sync_manager == null) {
            try sendResponse(io, connection, "ERROR: Sync manager not initialized\n");
            return;
        }
        
        const sync_manager = self.blockchain.sync_manager.?;
        sync_manager.checkTimeout();
        
        if (!sync_manager.getSyncState().canStart()) {
            const response = try std.fmt.allocPrint(
                self.allocator,
                "SYNC_STATUS: Already syncing (state: {}\n",
                .{sync_manager.getSyncState()}
            );
            defer self.allocator.free(response);
            try sendResponse(io, connection, response);
            return;
        }
        
        const current_height = self.blockchain.getHeight() catch |err| {
            std.log.err("Failed to get blockchain height: {}", .{err});
            try sendResponse(io, connection, "ERROR: Failed to get blockchain height\n");
            return;
        };
        
        if (self.blockchain.network_coordinator.getNetworkManager()) |network_manager| {
            const peer_stats = network_manager.getPeerStats();
            if (peer_stats.connected == 0) {
                try sendResponse(io, connection, "ERROR: No connected peers available for sync\n");
                return;
            }
            
            var connected_peers = std.array_list.Managed(*@import("../network/peer.zig").Peer).init(self.allocator);
            defer connected_peers.deinit();
            try network_manager.peer_manager.getConnectedPeers(&connected_peers);
            
            var best_peer: ?*@import("../network/peer.zig").Peer = null;
            var max_height: u32 = current_height;
            for (connected_peers.items) |peer| {
                if (peer.height > max_height) {
                    best_peer = peer;
                    max_height = peer.height;
                }
            }
            
            if (best_peer) |peer| {
                sync_manager.startSync(io, peer, peer.height, false) catch |err| {
                    std.log.err("Failed to start sync: {}", .{err});
                    try sendResponse(io, connection, "ERROR: Failed to start synchronization\n");
                    return;
                };
                
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "SYNC_STARTED: Syncing from height {} to {} with peer\n",
                    .{current_height, peer.height}
                );
                defer self.allocator.free(response);
                try sendResponse(io, connection, response);
            } else {
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "SYNC_STATUS: Already up to date (height: {}, {} peers)\n",
                    .{current_height, peer_stats.connected}
                );
                defer self.allocator.free(response);
                try sendResponse(io, connection, response);
            }
        } else {
            try sendResponse(io, connection, "ERROR: Network manager not available\n");
        }
    }
    
    fn handleGetBlock(self: *Self, io: std.Io, connection: net.Stream, message: []const u8) !void {
        const height_str = std.mem.trim(u8, message[10..], " \n\r"); 
        const height = std.fmt.parseUnsigned(u32, height_str, 10) catch {
            try sendResponse(io, connection, "ERROR: Invalid height format\n");
            return;
        };
        
        const block = self.blockchain.getBlockByHeight(height) catch |err| switch (err) {
            error.NotFound => {
                try sendResponse(io, connection, "ERROR: Block not found\n");
                return;
            },
            else => {
                const error_msg = try std.fmt.allocPrint(self.allocator, "ERROR: Failed to get block: {}\n", .{err});
                defer self.allocator.free(error_msg);
                try sendResponse(io, connection, error_msg);
                return;
            },
        };
        
        const block_hash = block.hash();
        var hash_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&hash_hex, "{x}", .{&block_hash});
        
        var prev_hash_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&prev_hash_hex, "{x}", .{&block.header.previous_hash});
        
        const response = try std.fmt.allocPrint(
            self.allocator,
            "BLOCK:{{\n  \"height\": {},\n  \"hash\": \"{s}\",\n  \"version\": {},\n  \"previous_hash\": \"{s}\",\n  \"timestamp\": {},\n  \"difficulty\": {},\n  \"nonce\": {},\n  \"tx_count\": {}\n}}\n",
            .{
                height,
                &hash_hex,
                block.header.version,
                &prev_hash_hex,
                block.header.timestamp,
                block.header.difficulty,
                block.header.nonce,
                block.transactions.len,
            }
        );
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleBalance(self: *Self, io: std.Io, connection: net.Stream, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[8..], " \n\r");
        const address = bech32.decodeAddress(self.allocator, address_str) catch {
            try sendResponse(io, connection, "ERROR: Invalid bech32 address format\n");
            return;
        };
        const balance = self.blockchain.chain_query.getBalance(self.blockchain.io, address) catch |err| {
            const error_msg = try std.fmt.allocPrint(self.allocator, "ERROR: Failed to get balance: {}\n", .{err});
            defer self.allocator.free(error_msg);
            try sendResponse(io, connection, error_msg);
            return;
        };
        
        const response = try std.fmt.allocPrint(self.allocator, "BALANCE:{}\n", .{balance});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleCheckBalance(self: *Self, io: std.Io, connection: net.Stream, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[14..], " \n\r"); 
        const decoded_address = bech32.decodeAddress(self.allocator, address_str) catch {
            try sendResponse(io, connection, "ERROR: Invalid address format\n");
            return;
        };
        const address = types.Address{ .version = decoded_address.version, .hash = decoded_address.hash };
        
        const account = self.blockchain.chain_query.getAccount(self.blockchain.io, address) catch |err| {
            if (err == error.AccountNotFound) {
                try sendResponse(io, connection, "BALANCE:0,0\n");
                return;
            }
            const error_msg = try std.fmt.allocPrint(self.allocator, "ERROR: Failed to get balance: {}\n", .{err});
            defer self.allocator.free(error_msg);
            try sendResponse(io, connection, error_msg);
            return;
        };
        
        const response = try std.fmt.allocPrint(self.allocator, "BALANCE:{},{}\n", .{account.balance, account.immature_balance});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleHeight(self: *Self, io: std.Io, connection: net.Stream) !void {
        const height = try self.blockchain.getHeight();
        const response = try std.fmt.allocPrint(self.allocator, "HEIGHT:{}\n", .{height});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleGetHeight(self: *Self, io: std.Io, connection: net.Stream) !void {
        const height = try self.blockchain.getHeight();
        const response = try std.fmt.allocPrint(self.allocator, "HEIGHT:{}\n", .{height});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleNonce(self: *Self, io: std.Io, connection: net.Stream, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[6..], " \n\r");
        const address = bech32.decodeAddress(self.allocator, address_str) catch {
            try sendResponse(io, connection, "ERROR: Invalid bech32 address format\n");
            return;
        };
        const account = self.blockchain.chain_query.getAccount(self.blockchain.io, address) catch types.Account{ .address = address, .balance = 0, .nonce = 0 };
        const response = try std.fmt.allocPrint(self.allocator, "NONCE:{}\n", .{account.nonce});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleGetNonce(self: *Self, io: std.Io, connection: net.Stream, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[10..], " \n\r"); 
        const decoded_address = bech32.decodeAddress(self.allocator, address_str) catch {
            try sendResponse(io, connection, "ERROR: Invalid bech32 address format\n");
            return;
        };
        const address = types.Address{ .version = decoded_address.version, .hash = decoded_address.hash };
        const account = self.blockchain.chain_query.getAccount(self.blockchain.io, address) catch |err| {
            if (err == error.AccountNotFound) {
                try sendResponse(io, connection, "NONCE:0");
                return;
            }
            try sendResponse(io, connection, "ERROR: Failed to get nonce");
            return;
        };
        const next_nonce = self.blockchain.getNextAvailableNonce(address) catch account.nonce;
        const response = try std.fmt.allocPrint(self.allocator, "NONCE:{}", .{next_nonce});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleTransaction(self: *Self, io: std.Io, connection: net.Stream, message: []const u8, transaction_count: *u32) !void {
        if (transaction_count.* >= MAX_TRANSACTIONS_PER_SESSION) {
            try sendResponse(io, connection, "ERROR: Transaction limit reached\n");
            return;
        }
        const tx_data = message[3..];
        var reader = std.Io.Reader.fixed(tx_data);
        var tx = serialize.deserialize(&reader, types.Transaction, self.allocator) catch |err| {
            const error_msg = try std.fmt.allocPrint(self.allocator, "ERROR: Failed to deserialize: {}\n", .{err});
            defer self.allocator.free(error_msg);
            try sendResponse(io, connection, error_msg);
            return;
        };
        defer tx.deinit(self.allocator);
        self.blockchain.addTransaction(tx) catch |err| {
            const error_msg = try std.fmt.allocPrint(self.allocator, "ERROR: {}\n", .{err});
            defer self.allocator.free(error_msg);
            try sendResponse(io, connection, error_msg);
            return;
        };
        transaction_count.* += 1;
        const tx_hash = tx.hash();
        const response = try std.fmt.allocPrint(self.allocator, "OK:{x}\n", .{tx_hash});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleBatchTransactions(self: *Self, io: std.Io, connection: net.Stream, message: []const u8, transaction_count: *u32) !void {
        const batch_data = message[9..]; 
        const count_end = std.mem.indexOf(u8, batch_data, ":") orelse {
            try sendResponse(io, connection, "ERROR: Invalid batch format\n");
            return;
        };
        const batch_count = std.fmt.parseInt(u32, batch_data[0..count_end], 10) catch {
            try sendResponse(io, connection, "ERROR: Invalid batch count\n");
            return;
        };
        if (batch_count == 0 or batch_count > 100 or transaction_count.* + batch_count > MAX_TRANSACTIONS_PER_SESSION) {
            try sendResponse(io, connection, "ERROR: Invalid batch count or limit reached\n");
            return;
        }
        var tx_data = batch_data[count_end + 1..];
        var results = std.array_list.Managed(u8).init(self.allocator);
        defer results.deinit();
        var success_count: u32 = 0;
        var i: u32 = 0;
        while (i < batch_count) : (i += 1) {
            if (tx_data.len < 4) break;
            const tx_size = std.mem.readInt(u32, tx_data[0..4], .little);
            tx_data = tx_data[4..];
            if (tx_data.len < tx_size) break;
            var reader = std.Io.Reader.fixed(tx_data[0..tx_size]);
            var tx = serialize.deserialize(&reader, types.Transaction, self.allocator) catch |err| {
                try results.print("ERROR:Failed: {}\n", .{err});
                tx_data = tx_data[tx_size..];
                continue;
            };
            defer tx.deinit(self.allocator);
            self.blockchain.addTransaction(tx) catch |err| {
                try results.print("ERROR:{}\n", .{err});
                tx_data = tx_data[tx_size..];
                continue;
            };
            try results.print("OK:{x}\n", .{tx.hash()});
            success_count += 1;
            tx_data = tx_data[tx_size..];
        }
        transaction_count.* += success_count;
        const response = try std.fmt.allocPrint(self.allocator, "BATCH_RESULT:{}:{}\\n{s}", .{ batch_count, success_count, results.items });
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleClientTransaction(self: *Self, io: std.Io, connection: net.Stream, message: []const u8, transaction_count: *u32) !void {
        if (transaction_count.* >= MAX_TRANSACTIONS_PER_SESSION) {
            try sendResponse(io, connection, "ERROR: Transaction limit reached\n");
            return;
        }
        const parts_str = message[19..];
        var parts = std.mem.splitScalar(u8, parts_str, ':');
        const s_b32 = parts.next() orelse return;
        const r_b32 = parts.next() orelse return;
        const amt_s = parts.next() orelse return;
        const fee_s = parts.next() orelse return;
        const nce_s = parts.next() orelse return;
        const tms_s = parts.next() orelse return;
        const exp_s = parts.next() orelse return;
        const sig_h = parts.next() orelse return;
        const pk_h = parts.next() orelse return;
        
        const amt = std.fmt.parseInt(u64, std.mem.trim(u8, amt_s, " \n\r\t"), 10) catch return;
        const fee = std.fmt.parseInt(u64, std.mem.trim(u8, fee_s, " \n\r\t"), 10) catch return;
        const nce = std.fmt.parseInt(u64, std.mem.trim(u8, nce_s, " \n\r\t"), 10) catch return;
        const tms = std.fmt.parseInt(u64, std.mem.trim(u8, tms_s, " \n\r\t"), 10) catch return;
        const exp = std.fmt.parseInt(u64, std.mem.trim(u8, exp_s, " \n\r\t"), 10) catch return;
        
        const s_addr = bech32.decodeAddress(self.allocator, std.mem.trim(u8, s_b32, " \n\r\t")) catch return;
        const r_addr = bech32.decodeAddress(self.allocator, std.mem.trim(u8, r_b32, " \n\r\t")) catch return;
        
        var sig: [64]u8 = undefined; _ = std.fmt.hexToBytes(&sig, std.mem.trim(u8, sig_h, " \n\r\t")) catch return;
        var pk: [32]u8 = undefined; _ = std.fmt.hexToBytes(&pk, std.mem.trim(u8, pk_h, " \n\r\t")) catch return;
        
        var tx = types.Transaction{
            .version = 0, .flags = . {},
            .sender = types.Address{ .version = s_addr.version, .hash = s_addr.hash },
            .recipient = types.Address{ .version = r_addr.version, .hash = r_addr.hash },
            .amount = amt, .fee = fee, .nonce = nce, .timestamp = tms, .expiry_height = exp,
            .sender_public_key = pk, .signature = sig, .script_version = 0,
            .witness_data = &[_]u8{}, .extra_data = &[_]u8{},
        };
        
        self.blockchain.addTransaction(tx) catch |err| {
            const error_msg = try std.fmt.allocPrint(self.allocator, "ERROR: {}\n", .{err});
            defer self.allocator.free(error_msg);
            try sendResponse(io, connection, error_msg);
            return;
        };
        transaction_count.* += 1;
        const response = try std.fmt.allocPrint(self.allocator, "OK:{x}\n", .{tx.hash()});
        defer self.allocator.free(response);
        try sendResponse(io, connection, response);
    }
    
    fn handleGetHistory(self: *Self, io: std.Io, connection: net.Stream, message: []const u8) !void {
        // TODO: This implementation is O(N) where N is blockchain height.
        // It iterates through EVERY block to find transactions for an address.
        // For production use, this MUST be replaced with:
        // 1. A secondary index in RocksDB (Address -> [TxHash])
        // 2. Or integration with the PostgreSQL Indexer
        const address_str = std.mem.trim(u8, message[12..], " \n\r"); 
        const address = types.Address.fromString(self.allocator, address_str) catch return;
        const chain_height = try self.blockchain.getHeight();
        var transactions = std.array_list.Managed(struct {
            height: u64,
            hash: [32]u8,
            tx_type: []const u8,
            amount: u64,
            fee: u64,
            timestamp: u64,
            confirmations: u64,
            counterparty: types.Address,
        }).init(self.allocator);
        defer transactions.deinit();
        
        var height: u64 = 0;
        while (height <= chain_height) : (height += 1) {
            const block = self.blockchain.database.getBlock(io, @intCast(height)) catch continue;
            for (block.transactions) |tx| {
                var involves = false; var t_type: []const u8 = ""; var cp: types.Address = undefined;
                if (tx.sender.isZero()) {
                    if (tx.recipient.equals(address)) { involves = true; t_type = "COINBASE"; cp = types.Address.zero(); }
                } else if (tx.sender.equals(address)) { involves = true; t_type = "SENT"; cp = tx.recipient; }
                else if (tx.recipient.equals(address)) { involves = true; t_type = "RECEIVED"; cp = tx.sender; }
                if (involves) {
                    try transactions.append(.{ .height = height, .hash = tx.hash(), .tx_type = t_type, .amount = tx.amount, .fee = tx.fee, .timestamp = tx.timestamp, .confirmations = chain_height - height + 1, .counterparty = cp });
                }
            }
        }
        var response = std.array_list.Managed(u8).init(self.allocator);
        defer response.deinit();
        try response.print("HISTORY:{}\n", .{transactions.items.len});
        for (transactions.items) |tx| {
            const cp_b32 = try tx.counterparty.toBech32(self.allocator, types.CURRENT_NETWORK);
            defer self.allocator.free(cp_b32);
            try response.print("{}|{x}|{s}|{}|{}|{}|{}|{s}\n", .{tx.height, tx.hash, tx.tx_type, tx.amount, tx.fee, tx.timestamp, tx.confirmations, cp_b32});
        }
        try sendResponse(io, connection, response.items);
    }
};