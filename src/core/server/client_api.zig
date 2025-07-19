// client_api.zig - Client API server for ZeiCoin
// Handles transaction submission, balance queries, and other client operations

const std = @import("std");
const print = std.debug.print;
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
        
        std.log.info("Client API listening on {s}:{}", .{self.bind_address, CLIENT_API_PORT});
        
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
            if (std.mem.startsWith(u8, message, "BLOCKCHAIN_STATUS")) {
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
            } else if (std.mem.startsWith(u8, message, "TRIGGER_SYNC")) {
                self.handleTriggerSync(connection) catch |err| {
                    std.log.err("Failed to trigger sync: {}", .{err});
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
    
    fn handleTriggerSync(self: *Self, connection: net.Server.Connection) !void {
        _ = self;
        // For now, just return a Ready status as the sync is handled by the network layer
        _ = try connection.stream.write("Ready\n");
        
        // In a full implementation, this would trigger a sync with peers
        // For now, we return success as the node is always syncing
        std.log.info("Manual sync triggered via client API", .{});
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
        const nonce = account.nonce;
        
        const response = try std.fmt.allocPrint(
            self.allocator,
            "NONCE:{}",
            .{nonce}
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
    
};