// client_api.zig - Client API server for ZeiCoin
// Handles transaction submission, balance queries, and other client operations

const std = @import("std");
const log = std.log.scoped(.server);
const net = std.net;
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
    running: bool,
    bind_address: []const u8,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, blockchain: *zen.ZeiCoin, bind_address: []const u8) Self {
        return .{
            .allocator = allocator,
            .blockchain = blockchain,
            .server = null,
            .running = false,
            .bind_address = bind_address,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.stop();
        if (self.server) |*server| {
            server.deinit();
        }
    }
    
    pub fn start(self: *Self) !void {
        const address = try net.Address.parseIp(self.bind_address, CLIENT_API_PORT);
        self.server = try address.listen(.{ .reuse_address = true });
        
        log.info("Client API listening on {s}:{}", .{self.bind_address, CLIENT_API_PORT});
        
        self.running = true;
        while (self.running) {
            const connection = self.server.?.accept() catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(100 * std.time.ns_per_ms);
                    continue;
                },
                else => return err,
            };
            
            // Handle connection in thread
            const thread = try std.Thread.spawn(.{}, handleConnection, .{
                self, connection
            });
            thread.detach();
        }
    }
    
    pub fn stop(self: *Self) void {
        self.running = false;
    }
    
    fn handleConnection(self: *Self, connection: net.Server.Connection) void {
        defer connection.stream.close();
        
        var transaction_count: u32 = 0;
        
        // Connection handler loop
        var buffer: [65536]u8 = undefined;
        while (true) {
            const bytes_read = connection.stream.read(&buffer) catch |err| {
                std.log.warn("Client connection error: {}", .{err});
                break;
            };
            
            if (bytes_read == 0) break;
            
            const message = buffer[0..bytes_read];
            
            // Parse command
            if (std.mem.startsWith(u8, message, "BLOCKCHAIN_STATUS_ENHANCED")) {
                self.handleEnhancedStatus(connection) catch |err| {
                    std.log.err("Failed to send enhanced status: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "BLOCKCHAIN_STATUS")) {
                self.handleStatus(connection) catch |err| {
                    std.log.err("Failed to send status: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "CHECK_BALANCE:")) {
                self.handleCheckBalance(connection, message) catch |err| {
                    std.log.err("Failed to check balance: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "BALANCE:")) {
                self.handleBalance(connection, message) catch |err| {
                    std.log.err("Failed to check balance: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_HEIGHT")) {
                self.handleGetHeight(connection) catch |err| {
                    std.log.err("Failed to send height: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "HEIGHT")) {
                self.handleHeight(connection) catch |err| {
                    std.log.err("Failed to send height: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_NONCE:")) {
                self.handleGetNonce(connection, message) catch |err| {
                    std.log.err("Failed to check nonce: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "NONCE:")) {
                self.handleNonce(connection, message) catch |err| {
                    std.log.err("Failed to check nonce: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "CLIENT_TRANSACTION:")) {
                self.handleClientTransaction(connection, message, &transaction_count) catch |err| {
                    std.log.err("Failed to process transaction: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "TX:")) {
                self.handleTransaction(connection, message, &transaction_count) catch |err| {
                    std.log.err("Failed to process transaction: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "BATCH_TX:")) {
                self.handleBatchTransactions(connection, message, &transaction_count) catch |err| {
                    std.log.err("Failed to process batch transactions: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "TRIGGER_SYNC")) {
                self.handleTriggerSync(connection) catch |err| {
                    std.log.err("Failed to trigger sync: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_BLOCK:")) {
                self.handleGetBlock(connection, message) catch |err| {
                    std.log.err("Failed to get block: {}", .{err});
                };
            } else if (std.mem.startsWith(u8, message, "GET_HISTORY:")) {
                self.handleGetHistory(connection, message) catch |err| {
                    std.log.err("Failed to get transaction history: {}", .{err});
                };
            } else {
                _ = connection.stream.write("ERROR: Unknown command\n") catch {};
            }
        }
    }
    
    fn handleStatus(self: *Self, connection: net.Server.Connection) !void {
        const height = try self.blockchain.getHeight();
        const pending_count = self.blockchain.mempool_manager.getTransactionCount();
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HEIGHT={} PENDING={}\n",
            .{height, pending_count}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleEnhancedStatus(self: *Self, connection: net.Server.Connection) !void {
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
        
        // Calculate hash rate (simplified - you may want to implement proper tracking)
        var hash_rate: f64 = 0.0;
        if (is_mining) {
            // For now, use a placeholder hash rate calculation
            // In a real implementation, you'd track actual hash attempts over time
            hash_rate = if (self.blockchain.mining_manager) |manager| blk: {
                // This is a simplified approach - you might want to add actual hash rate tracking
                _ = manager;
                break :blk 150.5; // Placeholder hash rate
            } else 0.0;
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
        
        _ = try connection.stream.write(response);
    }
    
    fn handleTriggerSync(self: *Self, connection: net.Server.Connection) !void {
        std.log.info("Manual sync triggered via client API", .{});
        
        // Check if sync manager is available
        if (self.blockchain.sync_manager == null) {
            _ = try connection.stream.write("ERROR: Sync manager not initialized\n");
            return;
        }
        
        const sync_manager = self.blockchain.sync_manager.?;
        
        // Check for sync timeout before checking state
        sync_manager.checkTimeout();
        
        // Check if sync can start
        if (!sync_manager.getSyncState().canStart()) {
            const response = try std.fmt.allocPrint(
                self.allocator,
                "SYNC_STATUS: Already syncing (state: {})\n",
                .{sync_manager.getSyncState()}
            );
            defer self.allocator.free(response);
            _ = try connection.stream.write(response);
            return;
        }
        
        // Get current blockchain height
        const current_height = self.blockchain.getHeight() catch |err| {
            std.log.err("Failed to get blockchain height: {}", .{err});
            _ = try connection.stream.write("ERROR: Failed to get blockchain height\n");
            return;
        };
        
        // Try to find peers to sync with
        if (self.blockchain.network_coordinator.getNetworkManager()) |network_manager| {
            const peer_stats = network_manager.getPeerStats();
            
            if (peer_stats.connected == 0) {
                _ = try connection.stream.write("ERROR: No connected peers available for sync\n");
                return;
            }
            
            // Try to get a peer with higher height than us
            var connected_peers = std.ArrayList(*@import("../network/peer.zig").Peer).init(self.allocator);
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
                // Start sync with the best peer
                sync_manager.startSync(peer, peer.height, false) catch |err| {
                    std.log.err("Failed to start sync: {}", .{err});
                    _ = try connection.stream.write("ERROR: Failed to start synchronization\n");
                    return;
                };
                
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "SYNC_STARTED: Syncing from height {} to {} with peer\n",
                    .{current_height, peer.height}
                );
                defer self.allocator.free(response);
                _ = try connection.stream.write(response);
            } else {
                const response = try std.fmt.allocPrint(
                    self.allocator,
                    "SYNC_STATUS: Already up to date (height: {}, {} peers)\n",
                    .{current_height, peer_stats.connected}
                );
                defer self.allocator.free(response);
                _ = try connection.stream.write(response);
            }
        } else {
            _ = try connection.stream.write("ERROR: Network manager not available\n");
        }
    }
    
    fn handleGetBlock(self: *Self, connection: net.Server.Connection, message: []const u8) !void {
        const height_str = std.mem.trim(u8, message[10..], " \n\r"); // "GET_BLOCK:" is 10 chars
        
        const height = std.fmt.parseUnsigned(u32, height_str, 10) catch {
            _ = try connection.stream.write("ERROR: Invalid height format\n");
            return;
        };
        
        const block = self.blockchain.getBlockByHeight(height) catch |err| switch (err) {
            error.NotFound => {
                _ = try connection.stream.write("ERROR: Block not found\n");
                return;
            },
            else => {
                const error_msg = try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Failed to get block: {}\n",
                    .{err}
                );
                defer self.allocator.free(error_msg);
                _ = try connection.stream.write(error_msg);
                return;
            },
        };
        
        // Format block information as JSON-like response
        const block_hash = block.hash();
        var hash_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&block_hash)});
        
        var prev_hash_hex: [64]u8 = undefined;
        _ = try std.fmt.bufPrint(&prev_hash_hex, "{}", .{std.fmt.fmtSliceHexLower(&block.header.previous_hash)});
        
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
        
        _ = try connection.stream.write(response);
    }
    
    fn handleBalance(self: *Self, connection: net.Server.Connection, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[8..], " \n\r");
        
        // Parse bech32 address (modern standard)
        const address = bech32.decodeAddress(self.allocator, address_str) catch {
            _ = try connection.stream.write("ERROR: Invalid bech32 address format\n");
            return;
        };
        const balance = self.blockchain.chain_query.getBalance(address) catch |err| {
            const error_msg = try std.fmt.allocPrint(
                self.allocator,
                "ERROR: Failed to get balance: {}\n",
                .{err}
            );
            defer self.allocator.free(error_msg);
            _ = try connection.stream.write(error_msg);
            return;
        };
        
        const response = try std.fmt.allocPrint(
            self.allocator,
            "BALANCE:{}\n",
            .{balance}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleCheckBalance(self: *Self, connection: net.Server.Connection, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[14..], " \n\r"); // "CHECK_BALANCE:" is 14 chars
        
        // Try to decode as bech32 address
        const decoded_address = bech32.decodeAddress(self.allocator, address_str) catch {
            _ = try connection.stream.write("ERROR: Invalid address format\n");
            return;
        };
        
        // Convert to Address
        const address = types.Address{
            .version = decoded_address.version,
            .hash = decoded_address.hash,
        };
        
        // Get account to retrieve both mature and immature balances
        const account = self.blockchain.chain_query.getAccount(address) catch |err| {
            if (err == error.AccountNotFound) {
                _ = try connection.stream.write("BALANCE:0,0\n");
                return;
            }
            std.log.warn("Failed to get account for address in CHECK_BALANCE: {}", .{err});
            const error_msg = try std.fmt.allocPrint(
                self.allocator,
                "ERROR: Failed to get balance: {}\n",
                .{err}
            );
            defer self.allocator.free(error_msg);
            _ = try connection.stream.write(error_msg);
            return;
        };
        
        
        // Return format: "BALANCE:mature,immature" to match CLI expectations
        const response = try std.fmt.allocPrint(
            self.allocator,
            "BALANCE:{},{}\n",
            .{account.balance, account.immature_balance}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleHeight(self: *Self, connection: net.Server.Connection) !void {
        const height = try self.blockchain.getHeight();
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HEIGHT:{}\n",
            .{height}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleGetHeight(self: *Self, connection: net.Server.Connection) !void {
        const height = try self.blockchain.getHeight();
        const response = try std.fmt.allocPrint(
            self.allocator,
            "HEIGHT:{}\n",
            .{height}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleNonce(self: *Self, connection: net.Server.Connection, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[6..], " \n\r");
        
        // Parse bech32 address (modern standard)
        const address = bech32.decodeAddress(self.allocator, address_str) catch {
            _ = try connection.stream.write("ERROR: Invalid bech32 address format\n");
            return;
        };
        
        const account = self.blockchain.chain_query.getAccount(address) catch types.Account{ .address = address, .balance = 0, .nonce = 0 };
        const nonce = account.nonce;
        
        const response = try std.fmt.allocPrint(
            self.allocator,
            "NONCE:{}\n",
            .{nonce}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleGetNonce(self: *Self, connection: net.Server.Connection, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[10..], " \n\r"); // "GET_NONCE:" is 10 chars
        
        // Parse bech32 address (standardized format)
        const decoded_address = bech32.decodeAddress(self.allocator, address_str) catch {
            _ = try connection.stream.write("ERROR: Invalid bech32 address format\n");
            return;
        };
        
        const address = types.Address{
            .version = decoded_address.version,
            .hash = decoded_address.hash,
        };
        
        const account = self.blockchain.chain_query.getAccount(address) catch |err| {
            if (err == error.AccountNotFound) {
                _ = try connection.stream.write("NONCE:0");
                return;
            }
            std.log.warn("Failed to get account for nonce query: {}", .{err});
            _ = try connection.stream.write("ERROR: Failed to get nonce");
            return;
        };
        
        // Get the next available nonce considering pending transactions in mempool
        const next_nonce = self.blockchain.getNextAvailableNonce(address) catch account.nonce;
        
        const response = try std.fmt.allocPrint(
            self.allocator,
            "NONCE:{}",
            .{next_nonce}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
    }
    
    fn handleTransaction(
        self: *Self,
        connection: net.Server.Connection,
        message: []const u8,
        transaction_count: *u32,
    ) !void {
        if (transaction_count.* >= MAX_TRANSACTIONS_PER_SESSION) {
            _ = try connection.stream.write("ERROR: Transaction limit reached\n");
            return;
        }
        
        const tx_data = message[3..];
        
        // Deserialize transaction
        var stream = std.io.fixedBufferStream(tx_data);
        var tx = serialize.deserialize(stream.reader(), types.Transaction, self.allocator) catch |err| {
            const error_msg = try std.fmt.allocPrint(
                self.allocator,
                "ERROR: Failed to deserialize transaction: {}\n",
                .{err}
            );
            defer self.allocator.free(error_msg);
            _ = try connection.stream.write(error_msg);
            return;
        };
        defer tx.deinit(self.allocator);
        
        // Process transaction
        self.blockchain.addTransaction(tx) catch |err| {
            const error_msg = switch (err) {
                error.InsufficientBalance => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Insufficient balance for transaction\n",
                    .{}
                ),
                error.FeeTooLow => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Transaction fee too low\n",
                    .{}
                ),
                error.InvalidNonce => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Invalid transaction nonce\n",
                    .{}
                ),
                error.TransactionExpired => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Transaction has expired\n",
                    .{}
                ),
                error.DuplicateTransaction => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Transaction already in mempool\n",
                    .{}
                ),
                error.MempoolFull => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Mempool is full\n",
                    .{}
                ),
                else => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: {}\n",
                    .{err}
                ),
            };
            defer self.allocator.free(error_msg);
            _ = try connection.stream.write(error_msg);
            return;
        };
        
        transaction_count.* += 1;
        
        // Send success response with transaction hash
        const tx_hash = tx.hash();
        const response = try std.fmt.allocPrint(
            self.allocator,
            "OK:{}\n",
            .{std.fmt.fmtSliceHexLower(&tx_hash)}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
        
        std.log.info("Processed transaction {} from client", .{
            std.fmt.fmtSliceHexLower(&tx_hash)
        });
    }
    
    fn handleBatchTransactions(
        self: *Self,
        connection: net.Server.Connection,
        message: []const u8,
        transaction_count: *u32,
    ) !void {
        // Format: BATCH_TX:<count>:<serialized_tx1><serialized_tx2>...
        const batch_data = message[9..]; // Skip "BATCH_TX:"
        
        // Parse batch count
        const count_end = std.mem.indexOf(u8, batch_data, ":") orelse {
            _ = try connection.stream.write("ERROR: Invalid batch format\n");
            return;
        };
        
        const batch_count = std.fmt.parseInt(u32, batch_data[0..count_end], 10) catch {
            _ = try connection.stream.write("ERROR: Invalid batch count\n");
            return;
        };
        
        if (batch_count == 0 or batch_count > 100) {
            _ = try connection.stream.write("ERROR: Batch count must be between 1 and 100\n");
            return;
        }
        
        // Check transaction limit
        if (transaction_count.* + batch_count > MAX_TRANSACTIONS_PER_SESSION) {
            _ = try connection.stream.write("ERROR: Transaction limit would be exceeded\n");
            return;
        }
        
        var tx_data = batch_data[count_end + 1..]; // Skip count and colon
        var results = std.ArrayList(u8).init(self.allocator);
        defer results.deinit();
        
        // Process each transaction in the batch
        var success_count: u32 = 0;
        var i: u32 = 0;
        while (i < batch_count) : (i += 1) {
            // Get transaction size (first 4 bytes)
            if (tx_data.len < 4) {
                try results.appendSlice("ERROR:Incomplete transaction data\n");
                break;
            }
            
            const tx_size = std.mem.readInt(u32, tx_data[0..4], .little);
            tx_data = tx_data[4..];
            
            if (tx_data.len < tx_size) {
                try results.appendSlice("ERROR:Incomplete transaction data\n");
                break;
            }
            
            // Deserialize transaction
            var stream = std.io.fixedBufferStream(tx_data[0..tx_size]);
            var tx = serialize.deserialize(stream.reader(), types.Transaction, self.allocator) catch |err| {
                try results.writer().print("ERROR:Failed to deserialize: {}\n", .{err});
                tx_data = tx_data[tx_size..];
                continue;
            };
            defer tx.deinit(self.allocator);
            
            // Process transaction
            self.blockchain.addTransaction(tx) catch |err| {
                const error_msg = switch (err) {
                    error.InsufficientBalance => "Insufficient balance",
                    error.FeeTooLow => "Fee too low",
                    error.InvalidNonce => "Invalid nonce",
                    error.TransactionExpired => "Transaction expired",
                    error.DuplicateTransaction => "Duplicate transaction",
                    error.MempoolFull => "Mempool full",
                    else => "Unknown error",
                };
                try results.writer().print("ERROR:{s}\n", .{error_msg});
                tx_data = tx_data[tx_size..];
                continue;
            };
            
            // Success - add hash to results
            const tx_hash = tx.hash();
            try results.writer().print("OK:{}\n", .{std.fmt.fmtSliceHexLower(&tx_hash)});
            success_count += 1;
            
            tx_data = tx_data[tx_size..];
        }
        
        transaction_count.* += success_count;
        
        // Send batch response with all results
        const response = try std.fmt.allocPrint(
            self.allocator,
            "BATCH_RESULT:{}:{}\n{s}",
            .{ batch_count, success_count, results.items }
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
        
        std.log.info("Processed batch of {} transactions ({} successful)", .{ batch_count, success_count });
    }
    
    fn handleClientTransaction(
        self: *Self,
        connection: net.Server.Connection,
        message: []const u8,
        transaction_count: *u32,
    ) !void {
        if (transaction_count.* >= MAX_TRANSACTIONS_PER_SESSION) {
            _ = try connection.stream.write("ERROR: Transaction limit reached\n");
            return;
        }
        
        // Parse CLIENT_TRANSACTION:sender_bech32:recipient_bech32:amount:fee:nonce:timestamp:expiry_height:signature_hex:sender_public_key_hex
        const parts_str = message[19..]; // Skip "CLIENT_TRANSACTION:" (19 chars)
        var parts = std.mem.splitScalar(u8, parts_str, ':');
        
        const sender_bech32 = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing sender\n");
            return;
        };
        
        const recipient_bech32 = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing recipient\n");
            return;
        };
        
        const amount_str = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing amount\n");
            return;
        };
        
        const fee_str = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing fee\n");
            return;
        };
        
        const nonce_str = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing nonce\n");
            return;
        };
        
        const timestamp_str = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing timestamp\n");
            return;
        };
        
        const expiry_str = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing expiry\n");
            return;
        };
        
        const signature_hex = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing signature\n");
            return;
        };
        
        const sender_key_hex = parts.next() orelse {
            _ = try connection.stream.write("ERROR: Invalid transaction format - missing sender public key\n");
            return;
        };
        
        // Parse numeric values (trim whitespace)
        const amount = std.fmt.parseInt(u64, std.mem.trim(u8, amount_str, " \n\r\t"), 10) catch {
            _ = try connection.stream.write("ERROR: Invalid amount format\n");
            return;
        };
        
        const fee = std.fmt.parseInt(u64, std.mem.trim(u8, fee_str, " \n\r\t"), 10) catch {
            _ = try connection.stream.write("ERROR: Invalid fee format\n");
            return;
        };
        
        const nonce = std.fmt.parseInt(u64, std.mem.trim(u8, nonce_str, " \n\r\t"), 10) catch {
            _ = try connection.stream.write("ERROR: Invalid nonce format\n");
            return;
        };
        
        const timestamp = std.fmt.parseInt(u64, std.mem.trim(u8, timestamp_str, " \n\r\t"), 10) catch {
            _ = try connection.stream.write("ERROR: Invalid timestamp format\n");
            return;
        };
        
        const expiry_height = std.fmt.parseInt(u64, std.mem.trim(u8, expiry_str, " \n\r\t"), 10) catch {
            _ = try connection.stream.write("ERROR: Invalid expiry height format\n");
            return;
        };
        
        // Decode addresses
        const sender_address = bech32.decodeAddress(self.allocator, std.mem.trim(u8, sender_bech32, " \n\r\t")) catch {
            _ = try connection.stream.write("ERROR: Invalid sender address format\n");
            return;
        };
        
        const recipient_address = bech32.decodeAddress(self.allocator, std.mem.trim(u8, recipient_bech32, " \n\r\t")) catch {
            _ = try connection.stream.write("ERROR: Invalid recipient address format\n");
            return;
        };
        
        // Decode signature and public key
        var signature: [64]u8 = undefined;
        _ = std.fmt.hexToBytes(&signature, std.mem.trim(u8, signature_hex, " \n\r\t")) catch {
            _ = try connection.stream.write("ERROR: Invalid signature format\n");
            return;
        };
        
        var sender_public_key: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&sender_public_key, std.mem.trim(u8, sender_key_hex, " \n\r\t")) catch {
            _ = try connection.stream.write("ERROR: Invalid public key format\n");
            return;
        };
        
        // Create transaction
        var tx = types.Transaction{
            .version = 0,
            .flags = types.TransactionFlags{},
            .sender = types.Address{ .version = sender_address.version, .hash = sender_address.hash },
            .recipient = types.Address{ .version = recipient_address.version, .hash = recipient_address.hash },
            .amount = amount,
            .fee = fee,
            .nonce = nonce,
            .timestamp = timestamp,
            .expiry_height = expiry_height,
            .sender_public_key = sender_public_key,
            .signature = signature,
            .script_version = 0,
            .witness_data = &[_]u8{},
            .extra_data = &[_]u8{},
        };
        
        // Process transaction
        self.blockchain.addTransaction(tx) catch |err| {
            const error_msg = switch (err) {
                error.InsufficientBalance => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Insufficient balance for transaction\n",
                    .{}
                ),
                error.FeeTooLow => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Transaction fee too low\n",
                    .{}
                ),
                error.InvalidNonce => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Invalid transaction nonce\n",
                    .{}
                ),
                error.TransactionExpired => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Transaction has expired\n",
                    .{}
                ),
                error.DuplicateTransaction => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Transaction already in mempool\n",
                    .{}
                ),
                error.MempoolFull => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: Mempool is full\n",
                    .{}
                ),
                else => try std.fmt.allocPrint(
                    self.allocator,
                    "ERROR: {}\n",
                    .{err}
                ),
            };
            defer self.allocator.free(error_msg);
            _ = try connection.stream.write(error_msg);
            return;
        };
        
        transaction_count.* += 1;
        
        // Send success response with transaction hash
        const tx_hash = tx.hash();
        const response = try std.fmt.allocPrint(
            self.allocator,
            "OK:{}\n",
            .{std.fmt.fmtSliceHexLower(&tx_hash)}
        );
        defer self.allocator.free(response);
        
        _ = try connection.stream.write(response);
        
        std.log.info("Processed client transaction {} from client", .{
            std.fmt.fmtSliceHexLower(&tx_hash)
        });
    }
    
    fn handleGetHistory(self: *Self, connection: net.Server.Connection, message: []const u8) !void {
        const address_str = std.mem.trim(u8, message[12..], " \n\r"); // "GET_HISTORY:" is 12 chars
        
        const address = types.Address.fromString(self.allocator, address_str) catch {
            _ = try connection.stream.write("ERROR: Invalid address format\n");
            return;
        };
        
        // Get blockchain height
        const chain_height = try self.blockchain.getHeight();
        
        // Create temporary list to store transactions
        var transactions = std.ArrayList(struct {
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
        
        // Scan through all blocks for transactions involving this address
        // Start from height 0 to include genesis block transactions
        var height: u64 = 0;
        while (height <= chain_height) : (height += 1) {
            const block = self.blockchain.database.getBlock(@intCast(height)) catch {
                continue;
            };
            
            // Check each transaction in the block
            for (block.transactions) |tx| {
                var involves_address = false;
                var tx_type: []const u8 = undefined;
                var counterparty: types.Address = undefined;
                
                // Check if this is a coinbase transaction
                if (tx.sender.equals(types.Address.zero())) {
                    if (tx.recipient.equals(address)) {
                        involves_address = true;
                        tx_type = "COINBASE";
                        counterparty = types.Address.zero();
                    }
                } else if (tx.sender.equals(address)) {
                    involves_address = true;
                    tx_type = "SENT";
                    counterparty = tx.recipient;
                } else if (tx.recipient.equals(address)) {
                    involves_address = true;
                    tx_type = "RECEIVED";
                    counterparty = tx.sender;
                }
                
                if (involves_address) {
                    const tx_hash = tx.hash();
                    try transactions.append(.{
                        .height = height,
                        .hash = tx_hash,
                        .tx_type = tx_type,
                        .amount = tx.amount,
                        .fee = tx.fee,
                        .timestamp = tx.timestamp,
                        .confirmations = chain_height - height + 1,
                        .counterparty = counterparty,
                    });
                }
            }
        }
        
        // Format response
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();
        
        try response.appendSlice("HISTORY:");
        try response.writer().print("{}", .{transactions.items.len});
        try response.appendSlice("\n");
        
        // Add each transaction
        for (transactions.items) |tx_info| {
            const counterparty_bech32 = try tx_info.counterparty.toBech32(self.allocator, types.CURRENT_NETWORK);
            defer self.allocator.free(counterparty_bech32);
            
            // Format: height|hash|type|amount|fee|timestamp|confirmations|counterparty
            try response.writer().print("{}|{}|{s}|{}|{}|{}|{}|{s}\n", .{
                tx_info.height,
                std.fmt.fmtSliceHexLower(&tx_info.hash),
                tx_info.tx_type,
                tx_info.amount,
                tx_info.fee,
                tx_info.timestamp,
                tx_info.confirmations,
                counterparty_bech32,
            });
        }
        
        _ = try connection.stream.write(response.items);
    }
    
};