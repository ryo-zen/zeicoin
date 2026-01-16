// types.zig - Zeicoin Core Types
// Minimal approach - only what we need, nothing more
// Simple account model with nonce-based double-spend protection

const std = @import("std");
const util = @import("../util/util.zig");
const bech32 = @import("../crypto/bech32.zig");

const log = std.log.scoped(.types);

// Money constants - ZeiCoin monetary units
pub const ZEI_COIN: u64 = 100000000; // 1 Zeicoin = 100,000,000 zei
pub const ZEI_CENT: u64 = 1000000; // 1 cent = 1,000,000 zei

// Supply constraints
pub const MAX_SUPPLY: u64 = 24000000 * ZEI_COIN; // 24 million ZEI total supply cap

// Timing constants - Common intervals used throughout the codebase
pub const TIMING = struct {
    pub const PEER_TIMEOUT_SECONDS: i64 = 60;
    pub const HEIGHT_CHECK_INTERVAL_SECONDS: i64 = 120; // 2 minutes - less frequent
    pub const MAINTENANCE_CYCLE_SECONDS: u64 = 10;
    pub const SERVER_SLEEP_MS: u64 = 10;
    pub const CLI_TIMEOUT_SECONDS: u64 = 5;
    pub const BACKOFF_BASE_SECONDS: i64 = 30;
};

// Progress reporting constants
pub const PROGRESS = struct {
    pub const RANDOMX_REPORT_INTERVAL: u32 = 5_000; // More frequent updates for better feedback
    // SHA256_REPORT_INTERVAL removed - SHA256 mining no longer supported
    pub const DECIMAL_PRECISION_MULTIPLIER: u64 = 100_000;
};

// Headers-first sync protocol constants
pub const HEADERS_SYNC = struct {
    pub const MAX_HEADERS_PER_MESSAGE: u32 = 2000; // Max headers in one message
    pub const HEADER_SIZE: usize = @sizeOf(BlockHeader); // 192 bytes
    pub const MAX_HEADERS_IN_MEMORY: u32 = 100_000; // ~19MB RAM
    pub const HEADERS_BATCH_SIZE: u32 = 2000; // Headers per request
    pub const BLOCK_DOWNLOAD_TIMEOUT: i64 = 30; // Timeout for single block
    pub const MAX_CONCURRENT_DOWNLOADS: u32 = 5; // Parallel block downloads
};

// Parallel block download constants
pub const SYNC = struct {
    pub const DOWNLOAD_TIMEOUT_SECONDS: i64 = 30; // Timeout for parallel downloads
    pub const MAX_DOWNLOAD_RETRIES: u8 = 3; // Maximum retry attempts
};

// Consensus configuration
pub const ConsensusMode = enum {
    disabled, // No consensus checking (single node, testing)
    optional, // Check consensus but only warn on failure
    enforced, // Require consensus or reject block (production)
};

pub const CONSENSUS = struct {
    // Current consensus mode - can be changed via environment variable
    pub var mode: ConsensusMode = .optional; // Default to optional for gradual rollout

    // Minimum percentage of peers that must agree (0.5 = 50%, 0.67 = 67%, etc)
    pub var threshold: f32 = 0.5; // Simple majority by default

    // Timeout for peer responses in seconds
    pub const PEER_RESPONSE_TIMEOUT: i64 = 5;

    // Minimum number of peer responses required (0 = no minimum)
    pub var min_peer_responses: u32 = 0; // Start with no minimum

    // Whether to query peers during normal operation or only during sync
    pub var check_during_normal_operation: bool = false; // Only during sync initially
};

// Block versioning - for protocol upgrades
pub const BlockVersion = enum(u32) {
    V0 = 0, // Initial protocol version
    // Future versions will be added here for protocol upgrades
    _,
};

// Current block version used by the protocol
pub const CURRENT_BLOCK_VERSION: u32 = @intFromEnum(BlockVersion.V0);

// Mining constants - Network-specific coinbase maturity
pub const COINBASE_MATURITY: u32 = switch (CURRENT_NETWORK) {
    .testnet => 10, // TestNet: 10 blocks for faster testing
    .mainnet => 100, // MainNet: 100 blocks for security
};

// Bootstrap node configuration structure
pub const BootstrapConfig = struct {
    network: []const u8,
    nodes: [][]const u8,
};

// Load bootstrap nodes from JSON configuration
pub fn loadBootstrapNodes(allocator: std.mem.Allocator) ![][]const u8 {
    const config_path = "config/bootstrap_testnet.json";

    // Read the JSON file
    const file = std.fs.cwd().openFile(config_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            // Fallback to hardcoded nodes if config file not found
            const fallback_nodes = [_][]const u8{
                "209.38.31.77:10801",
                "134.199.170.129:10801",
            };
            var result = try allocator.alloc([]const u8, fallback_nodes.len);
            for (fallback_nodes, 0..) |node, i| {
                result[i] = try allocator.dupe(u8, node);
            }
            return result;
        },
        else => return err,
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);
    _ = try file.readAll(contents);

    // Parse JSON
    const parsed = try std.json.parseFromSlice(BootstrapConfig, allocator, contents, .{});
    defer parsed.deinit();

    const config = parsed.value;

    // Copy nodes to owned memory
    var result = try allocator.alloc([]const u8, config.nodes.len);
    for (config.nodes, 0..) |node, i| {
        result[i] = try allocator.dupe(u8, node);
    }

    return result;
}

// Free bootstrap nodes memory
pub fn freeBootstrapNodes(allocator: std.mem.Allocator, nodes: [][]const u8) void {
    for (nodes) |node| {
        allocator.free(node);
    }
    allocator.free(nodes);
}

// Network ports - ZeiCoin zen networking
pub const NETWORK_PORTS = struct {
    pub const P2P: u16 = 10801; // Peer-to-peer network
    pub const CLIENT_API: u16 = 10802; // Client API
    // Port 10800 reserved for future QUIC transport implementation
};

// Node types for asymmetric networking
pub const NodeType = enum {
    full_node, // Can accept incoming connections (public IP)
    outbound_only, // Behind NAT, outbound connections only (private IP)
    unknown, // Not yet determined

    pub fn canServeBlocks(self: NodeType) bool {
        return self == .full_node;
    }

    pub fn canReceiveBlocks(self: NodeType) bool {
        _ = self; // All node types can receive blocks
        return true; // All nodes can receive blocks
    }
};

// Address versioning for future extensibility
pub const AddressVersion = enum(u8) {
    P2PKH = 0, // Pay to Public Key Hash (current)
    Multisig = 1, // M-of-N multisignature (future)
    P2SH = 2, // Pay to Script Hash (future)
    P2WSH = 3, // Pay to Witness Script Hash (future)
    Taproot = 4, // Taproot for privacy + smart contracts (future)
    PostQuantum = 5, // Quantum-resistant addresses (future)
    // 6-127 reserved for future standard types
    // 128-255 reserved for experimental/custom
    _,
};

// Modern versioned address structure (21-byte format)
pub const Address = extern struct {
    version: u8, // Address type/version
    hash: [20]u8, // 20-byte address hash (modern standard)

    /// Create a P2PKH address from a public key
    pub fn fromPublicKey(public_key: [32]u8) Address {
        const full_hash = util.blake3Hash(&public_key);
        var addr = Address{
            .version = @intFromEnum(AddressVersion.P2PKH),
            .hash = undefined,
        };
        @memcpy(&addr.hash, full_hash[0..20]);
        return addr;
    }

    /// Create a zero address (for coinbase transactions)
    pub fn zero() Address {
        return Address{
            .version = 0,
            .hash = std.mem.zeroes([20]u8),
        };
    }

    /// Check if this is a zero address
    pub fn isZero(self: Address) bool {
        return self.version == 0 and std.mem.eql(u8, &self.hash, &std.mem.zeroes([20]u8));
    }

    /// Compare two addresses for equality
    pub fn equals(self: Address, other: Address) bool {
        return self.version == other.version and std.mem.eql(u8, &self.hash, &other.hash);
    }

    /// Get the address version as enum (with unknown handling)
    pub fn getVersion(self: Address) AddressVersion {
        return @enumFromInt(self.version);
    }

    /// Convert to standard bytes format for serialization
    pub fn toBytes(self: Address) [21]u8 {
        var result: [21]u8 = undefined;
        result[0] = self.version;
        @memcpy(result[1..], &self.hash);
        return result;
    }

    /// Create from standard bytes format
    pub fn fromBytes(bytes: [21]u8) Address {
        return Address{
            .version = bytes[0],
            .hash = bytes[1..21].*,
        };
    }

    /// Encode address to bech32 string
    pub fn toBech32(self: Address, allocator: std.mem.Allocator, network: NetworkType) ![]u8 {
        return bech32.encodeAddress(allocator, self, network);
    }

    /// Parse address from string (bech32 or hex)
    pub fn fromString(allocator: std.mem.Allocator, str: []const u8) !Address {
        return bech32.parseAddress(allocator, str);
    }
};

// Transaction signature (Ed25519 signature)
pub const Signature = [64]u8;

// Hash types for various purposes
pub const Hash = [32]u8;
pub const TxHash = Hash;
pub const BlockHash = Hash;

// Script types for future smart contracts
pub const ScriptVersion = u16;
pub const ScriptOpcode = enum(u8) {
    // Constants
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,

    // Crypto
    OP_CHECKSIG = 0xac,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKSIGVERIFY = 0xad,

    // Reserved for future opcodes
    _,
};

// Transaction flags for soft fork activation
pub const TransactionFlags = packed struct(u16) {
    witness_enabled: bool = false, // Bit 0: Witness data present
    script_enabled: bool = false, // Bit 1: Script execution enabled
    multisig_enabled: bool = false, // Bit 2: Multisig support
    taproot_enabled: bool = false, // Bit 3: Taproot support
    // Bits 4-15: Reserved for future features
    reserved: u12 = 0,
};

/// ZeiCoin Transaction- Future Proof Design
pub const Transaction = struct {
    // Core fields (existing)
    version: u16, // Transaction version for protocol upgrades
    flags: TransactionFlags, // Feature flags for soft forks
    sender: Address, // Versioned sender address
    recipient: Address, // Versioned recipient address
    amount: u64, // Amount in zei (base unit)
    fee: u64, // Transaction fee paid to miner
    nonce: u64, // Sender's transaction counter
    timestamp: u64, // Unix timestamp when created
    expiry_height: u64, // Block height after which expires
    sender_public_key: [32]u8, // Public key of sender
    signature: Signature, // Ed25519 signature (moves to witness later)

    // Future-proofing fields
    script_version: ScriptVersion, // Script language version (0 = none)
    witness_data: []const u8, // Signatures, scripts, proofs (empty for now)
    extra_data: []const u8, // Arbitrary data for soft forks (empty for now)

    /// Calculate the hash of this transaction (used as transaction ID)
    pub fn hash(self: *const Transaction) TxHash {
        return self.hashForSigning();
    }

    /// Calculate hash of transaction data for signing (excludes signature field)
    pub fn hashForSigning(self: *const Transaction) Hash {
        // Create a copy without signature for hashing
        const tx_for_hash = struct {
            version: u16,
            flags: TransactionFlags,
            sender: Address,
            recipient: Address,
            amount: u64,
            fee: u64,
            nonce: u64,
            timestamp: u64,
            expiry_height: u64,
            sender_public_key: [32]u8,
            script_version: ScriptVersion,
            // Note: witness_data and extra_data are included in hash
        }{
            .version = self.version,
            .flags = self.flags,
            .sender = self.sender,
            .recipient = self.recipient,
            .amount = self.amount,
            .fee = self.fee,
            .nonce = self.nonce,
            .timestamp = self.timestamp,
            .expiry_height = self.expiry_height,
            .sender_public_key = self.sender_public_key,
            .script_version = self.script_version,
        };

        // Serialize and hash the transaction data
        // Use larger buffer to handle transactions with extra_data up to limit
        // Buffer size matches TransactionLimits.MAX_TX_SIZE (100KB)
        var buffer: [TransactionLimits.MAX_TX_SIZE]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        const writer = stream.writer();

        // Simple serialization for hashing (order matters!)
        writer.writeInt(u16, tx_for_hash.version, .little) catch unreachable;
        writer.writeInt(u16, @bitCast(tx_for_hash.flags), .little) catch unreachable;
        writer.writeAll(std.mem.asBytes(&tx_for_hash.sender)) catch unreachable;
        writer.writeAll(std.mem.asBytes(&tx_for_hash.recipient)) catch unreachable;
        writer.writeInt(u64, tx_for_hash.amount, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.fee, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.nonce, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.timestamp, .little) catch unreachable;
        writer.writeInt(u64, tx_for_hash.expiry_height, .little) catch unreachable;
        writer.writeAll(&tx_for_hash.sender_public_key) catch unreachable;
        writer.writeInt(u16, tx_for_hash.script_version, .little) catch unreachable;

        // Include witness_data and extra_data in hash
        writer.writeInt(u32, @intCast(self.witness_data.len), .little) catch unreachable;
        writer.writeAll(self.witness_data) catch unreachable;
        writer.writeInt(u32, @intCast(self.extra_data.len), .little) catch unreachable;
        writer.writeAll(self.extra_data) catch unreachable;

        const data = stream.getWritten();
        return util.blake3Hash(data);
    }

    /// Check if this is a coinbase transaction (created from thin air)
    pub fn isCoinbase(self: *const Transaction) bool {
        return self.sender.isZero();
    }

    /// Check if transaction has valid basic structure
    pub fn isValid(self: *const Transaction) bool {
        // Version validation - only version 0 is currently supported
        if (self.version != 0) {
            log.warn("❌ Transaction invalid: unsupported version {}", .{self.version});
            return false;
        }

        // Size validation - prevent DoS with oversized transactions
        const tx_size = self.getSerializedSize();
        if (tx_size > TransactionLimits.MAX_TX_SIZE) {
            log.warn("❌ Transaction invalid: size {} bytes exceeds maximum {} bytes", .{ tx_size, TransactionLimits.MAX_TX_SIZE });
            return false;
        }

        // Validate field sizes
        if (self.witness_data.len > TransactionLimits.MAX_WITNESS_SIZE) {
            log.warn("❌ Transaction invalid: witness_data size {} bytes exceeds maximum {} bytes", .{ self.witness_data.len, TransactionLimits.MAX_WITNESS_SIZE });
            return false;
        }

        if (self.extra_data.len > TransactionLimits.MAX_EXTRA_DATA_SIZE) {
            log.warn("❌ Transaction invalid: extra_data size {} bytes exceeds maximum {} bytes", .{ self.extra_data.len, TransactionLimits.MAX_EXTRA_DATA_SIZE });
            return false;
        }

        // Coinbase transactions have simpler validation rules
        if (self.isCoinbase()) {
            // Coinbase validation: amount > 0, timestamp > 0
            if (self.amount == 0) {
                log.warn("❌ Coinbase invalid: amount is 0", .{});
                return false;
            }
            if (self.timestamp == 0) {
                log.warn("❌ Coinbase invalid: timestamp is 0", .{});
                return false;
            }
            // Coinbase can send to any recipient
            return true;
        }

        // Regular transaction validation
        if (self.amount == 0) {
            log.warn("❌ Transaction invalid: amount is 0", .{});
            return false;
        }
        if (self.timestamp == 0) {
            log.warn("❌ Transaction invalid: timestamp is 0", .{});
            return false;
        }

        // Reject timestamps beyond year 2222 (catches bitcast negative i64 values)
        // Timestamp is in milliseconds, so multiply seconds by 1000
        const MAX_REASONABLE_TIMESTAMP: u64 = 7952422942 * 1000;
        if (self.timestamp > MAX_REASONABLE_TIMESTAMP) {
            log.warn("❌ Transaction invalid: timestamp {} exceeds year 2222", .{self.timestamp});
            return false;
        }

        if (self.sender.equals(self.recipient)) {
            log.warn("❌ Transaction invalid: sender equals recipient", .{});
            return false;
        }

        // Prevent arithmetic overflow when calculating total cost
        const total_cost = @addWithOverflow(self.amount, self.fee);
        if (total_cost[1] != 0) {
            log.warn("❌ Transaction invalid: amount + fee would overflow (amount={}, fee={})", .{ self.amount, self.fee });
            return false;
        }

        // Validate future-proof fields
        if (self.script_version != 0) {
            log.warn("❌ Transaction invalid: unsupported script version {}", .{self.script_version});
            return false;
        }

        // Note: witness_data and extra_data are allowed but size-limited
        // The size limits were already checked above in the size validation section

        // Verify that sender address matches the hash of provided public key
        const derived_address = Address.fromPublicKey(self.sender_public_key);
        if (!self.sender.equals(derived_address)) {
            log.warn("❌ Transaction invalid: sender address doesn't match public key", .{});
            return false;
        }

        return true;
    }

    /// Get the serialized size of this transaction in bytes
    pub fn getSerializedSize(self: *const Transaction) usize {
        // Base size for fixed fields
        var size: usize = 0;
        size += @sizeOf(u16); // version
        size += @sizeOf(TransactionFlags); // flags
        size += @sizeOf(Address); // sender
        size += @sizeOf(Address); // recipient
        size += @sizeOf(u64); // amount
        size += @sizeOf(u64); // fee
        size += @sizeOf(u64); // nonce
        size += @sizeOf(u64); // timestamp
        size += @sizeOf(u64); // expiry_height
        size += @sizeOf([32]u8); // sender_public_key
        size += @sizeOf(Signature); // signature
        size += @sizeOf(ScriptVersion); // script_version

        // Variable length fields
        size += @sizeOf(u32); // witness_data length prefix
        size += self.witness_data.len;
        size += @sizeOf(u32); // extra_data length prefix
        size += self.extra_data.len;

        return size;
    }

    /// Free all dynamically allocated memory in this transaction
    /// Safe to call on any transaction - will only free heap-allocated memory
    pub fn deinit(self: *Transaction, allocator: std.mem.Allocator) void {
        // For empty slices, check if they're the static empty slice by comparing the pointer
        // The static empty slice &[_]u8{} has a special sentinel address
        const empty_slice = &[_]u8{};

        // Only free if the slices are non-empty and not pointing to the static empty slice
        if (self.witness_data.len > 0 and self.witness_data.ptr != empty_slice.ptr) {
            allocator.free(self.witness_data);
        }
        if (self.extra_data.len > 0 and self.extra_data.ptr != empty_slice.ptr) {
            allocator.free(self.extra_data);
        }
    }

    /// Create a deep copy of the transaction, allocating new memory for slices
    pub fn dupe(self: *const Transaction, allocator: std.mem.Allocator) !Transaction {
        var new_tx = self.*;

        // Deep copy witness_data if not empty
        if (self.witness_data.len > 0) {
            new_tx.witness_data = try allocator.dupe(u8, self.witness_data);
        }

        // Deep copy extra_data if not empty
        if (self.extra_data.len > 0) {
            new_tx.extra_data = try allocator.dupe(u8, self.extra_data);
        }

        return new_tx;
    }
};

/// Account state in ZeiCoin network
pub const Account = struct {
    address: Address,
    balance: u64, // Current balance in zei (mature, spendable)
    nonce: u64, // Next expected transaction nonce
    immature_balance: u64 = 0, // Balance from recent coinbase transactions (not spendable)

    /// Check if account can afford a transaction (only considers mature balance)
    pub fn canAfford(self: *const Account, amount: u64) bool {
        return self.balance >= amount;
    }

    /// Get expected nonce for next transaction
    pub fn nextNonce(self: *const Account) u64 {
        return self.nonce;
    }

    /// Get total balance (mature + immature)
    pub fn totalBalance(self: *const Account) u64 {
        return self.balance + self.immature_balance;
    }
};

/// Track immature coinbase rewards for an account
pub const ImmatureCoins = struct {
    address: Address,
    entries: [100]ImmatureCoinEntry = std.mem.zeroes([100]ImmatureCoinEntry), // Max 100 immature entries
    count: u32 = 0, // Number of valid entries
};

/// Individual immature coin entry
pub const ImmatureCoinEntry = struct {
    height: u32, // Block height where coins were created
    amount: u64, // Amount of coins that are immature
};

/// Dynamic difficulty target for constrained adjustment
pub const DifficultyTarget = struct {
    base_bytes: u8, // 1 for TestNet, 2 for MainNet (never changes)
    threshold: u32, // Value within the remaining bytes (0x00000000 to 0xFFFFFFFF)

    /// Create initial difficulty target for network
    pub fn initial(network: NetworkType) DifficultyTarget {
        return switch (network) {
            .testnet => DifficultyTarget{
                .base_bytes = 1,
                .threshold = 0xFFFFFFF0, // EXTREMELY easy difficulty - instant blocks for low-end hardware
            },
            .mainnet => DifficultyTarget{
                .base_bytes = 2,
                .threshold = 0x00008000, // Middle of 2-byte range
            },
        };
    }

    /// Check if hash meets this difficulty target
    pub fn meetsDifficulty(self: DifficultyTarget, hash: [32]u8) bool {
        // First check required zero bytes
        for (0..self.base_bytes) |i| {
            if (hash[i] != 0) return false;
        }

        // Then check threshold in next 4 bytes
        if (self.base_bytes + 4 > 32) return true; // Edge case: not enough bytes

        var hash_value: u32 = 0;
        for (0..4) |i| {
            if (self.base_bytes + i < 32) {
                hash_value = (hash_value << 8) | @as(u32, hash[self.base_bytes + i]);
            }
        }

        return hash_value < self.threshold;
    }

    /// Adjust difficulty by factor, constrained to network limits (LEGACY - use adjustFixed for determinism)
    pub fn adjust(self: DifficultyTarget, factor: f64, network: NetworkType) DifficultyTarget {
        // Clamp factor to prevent extreme changes
        const clamped_factor = @max(0.5, @min(2.0, factor));

        // Calculate new threshold (inverse relationship: higher factor = higher threshold = easier)
        const new_threshold_f64 = @as(f64, @floatFromInt(self.threshold)) * clamped_factor;
        var new_threshold = @as(u32, @intFromFloat(@max(1.0, @min(0xFFFFFFFF, new_threshold_f64))));

        // Ensure we stay within network constraints
        const min_threshold: u32 = switch (network) {
            .testnet => 0x00010000, // Hardest 1-byte difficulty
            .mainnet => 0x00000001, // Hardest 2-byte difficulty
        };
        const max_threshold: u32 = switch (network) {
            .testnet => 0xFFFFF000, // Allow MUCH easier difficulty for testing (almost no work required)
            .mainnet => 0x00FF0000, // Easiest 2-byte difficulty
        };

        new_threshold = @max(min_threshold, @min(max_threshold, new_threshold));

        return DifficultyTarget{
            .base_bytes = self.base_bytes,
            .threshold = new_threshold,
        };
    }

    /// DETERMINISTIC: Adjust difficulty using fixed-point arithmetic (completely deterministic)
    /// @param factor_fixed: Adjustment factor multiplied by fixed_point_multiplier
    /// @param fixed_point_multiplier: The multiplier used (typically 1,000,000)
    /// @param network: Network type for constraint validation
    pub fn adjustFixed(self: DifficultyTarget, factor_fixed: u64, fixed_point_multiplier: u64, network: NetworkType) DifficultyTarget {
        const debug_log = std.log.scoped(.chain);

        // DETERMINISTIC: Clamp factor to prevent extreme changes using integer math
        // Convert bounds to fixed-point: 0.5 -> (0.5 * multiplier), 2.0 -> (2.0 * multiplier)
        const min_factor_fixed = fixed_point_multiplier / 2; // 0.5 in fixed-point
        const max_factor_fixed = fixed_point_multiplier * 2; // 2.0 in fixed-point
        const clamped_factor_fixed = if (factor_fixed < min_factor_fixed)
            min_factor_fixed
        else if (factor_fixed > max_factor_fixed)
            max_factor_fixed
        else
            factor_fixed;

        // DEBUG: Log factor clamping
        debug_log.info("   🔧 Factor clamping: {} -> {} (min: {}, max: {})", .{ factor_fixed, clamped_factor_fixed, min_factor_fixed, max_factor_fixed });

        // DETERMINISTIC: Calculate new threshold using integer-only arithmetic
        // IMPORTANT: When factor < 1.0 (blocks too slow), we want HIGHER threshold (easier mining)
        // So we DIVIDE by the factor: new_threshold = (current_threshold * multiplier) / factor
        const threshold_u64 = @as(u64, self.threshold);
        const new_threshold_u64 = (threshold_u64 * fixed_point_multiplier) / clamped_factor_fixed;

        // DEBUG: Log threshold calculation
        debug_log.info("   🎯 Threshold calc: {} * {} / {} = {}", .{ threshold_u64, fixed_point_multiplier, clamped_factor_fixed, new_threshold_u64 });

        // Ensure result fits in u32
        var new_threshold = if (new_threshold_u64 > 0xFFFFFFFF)
            0xFFFFFFFF
        else if (new_threshold_u64 == 0)
            1
        else
            @as(u32, @intCast(new_threshold_u64));

        // DETERMINISTIC: Network constraints using simple integer comparison
        const min_threshold: u32 = switch (network) {
            .testnet => 0x00010000, // Hardest 1-byte difficulty
            .mainnet => 0x00000001, // Hardest 2-byte difficulty
        };
        const max_threshold: u32 = switch (network) {
            .testnet => 0xFFFFF000, // Allow MUCH easier difficulty for testing (almost no work required)
            .mainnet => 0x00FF0000, // Easiest 2-byte difficulty
        };

        // Apply network constraints
        const unconstrained_threshold = new_threshold;
        if (new_threshold < min_threshold) new_threshold = min_threshold;
        if (new_threshold > max_threshold) new_threshold = max_threshold;

        // DEBUG: Log network constraints
        debug_log.info("   🌐 Network constraints: {} -> {} (min: 0x{X}, max: 0x{X})", .{ unconstrained_threshold, new_threshold, min_threshold, max_threshold });

        return DifficultyTarget{
            .base_bytes = self.base_bytes,
            .threshold = new_threshold,
        };
    }

    /// Serialize difficulty target to u64 for storage compatibility
    pub fn toU64(self: DifficultyTarget) u64 {
        return (@as(u64, self.base_bytes) << 32) | @as(u64, self.threshold);
    }

    /// Deserialize difficulty target from u64
    pub fn fromU64(value: u64) DifficultyTarget {
        return DifficultyTarget{
            .base_bytes = @intCast((value >> 32) & 0xFF),
            .threshold = @intCast(value & 0xFFFFFFFF),
        };
    }

    /// Calculate work contribution of this difficulty target
    /// ZeiCoin implementation - CRITICAL CONSENSUS CODE
    /// Work = 2^256 / target for Nakamoto Consensus
    pub fn toWork(self: DifficultyTarget) ChainWork {
        // Convert ZeiCoin difficulty format to 256-bit target
        const target = zeiCoinToTarget(self.base_bytes, self.threshold);

        // Use industry-standard work calculation (zero tolerance for error)
        return calculateWork(target);
    }
};

/// Block header containing essential block information
pub const BlockHeader = struct {
    // Core fields (existing)
    version: u32, // Block version for protocol upgrades
    previous_hash: BlockHash, // Hash of previous block
    merkle_root: Hash, // Root of transaction merkle tree
    timestamp: u64, // Unix timestamp when block was created
    difficulty: u64, // Dynamic difficulty target
    nonce: u32, // Proof-of-work nonce

    // Future-proofing fields
    witness_root: Hash, // Merkle root of witness data (unused for now)
    state_root: Hash, // For future state commitments (unused for now)
    extra_nonce: u64, // Extra nonce for mining pools
    extra_data: [32]u8, // For soft fork signaling and future use

    /// Serialize block header to bytes
    pub fn serialize(self: *const BlockHeader, writer: anytype) !void {
        try writer.writeInt(u32, self.version, .little);
        try writer.writeAll(&self.previous_hash);
        try writer.writeAll(&self.merkle_root);
        try writer.writeInt(u64, self.timestamp, .little);
        try writer.writeInt(u64, self.difficulty, .little);
        try writer.writeInt(u32, self.nonce, .little);

        // New future-proof fields
        try writer.writeAll(&self.witness_root);
        try writer.writeAll(&self.state_root);
        try writer.writeInt(u64, self.extra_nonce, .little);
        try writer.writeAll(&self.extra_data);
    }

    /// Deserialize block header from bytes
    pub fn deserialize(reader: anytype) !BlockHeader {
        var header: BlockHeader = undefined;

        header.version = try reader.readInt(u32, .little);
        _ = try reader.readAll(&header.previous_hash);
        _ = try reader.readAll(&header.merkle_root);
        header.timestamp = try reader.readInt(u64, .little);
        header.difficulty = try reader.readInt(u64, .little);
        header.nonce = try reader.readInt(u32, .little);

        // New future-proof fields
        _ = try reader.readAll(&header.witness_root);
        _ = try reader.readAll(&header.state_root);
        header.extra_nonce = try reader.readInt(u64, .little);
        _ = try reader.readAll(&header.extra_data);

        return header;
    }

    /// Get difficulty target from header
    pub fn getDifficultyTarget(self: *const BlockHeader) DifficultyTarget {
        return DifficultyTarget.fromU64(self.difficulty);
    }

    /// Calculate hash of this block header
    pub fn hash(self: *const BlockHeader) BlockHash {
        // Serialize the block header to bytes
        var buffer: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        const writer = stream.writer();

        // Simple serialization for hashing (order matters!)
        self.serialize(writer) catch unreachable;

        const data = stream.getWritten();
        return util.blake3Hash(data);
    }

    /// Calculate the work contribution of this block
    pub fn getWork(self: *const BlockHeader) ChainWork {
        const target = self.getDifficultyTarget();
        const work = target.toWork();

        // Log work calculation for consensus debugging
        if (work > 1000000) { // Only log significant work values
            log.debug("⚡ [CONSENSUS] Block work calculated: {} (difficulty: base_bytes={}, threshold={x})", .{ work, target.base_bytes, target.threshold });
        }

        return work;
    }
};

/// Complete block with header and transactions
pub const Block = struct {
    header: BlockHeader,
    transactions: []Transaction,
    height: u32, // Block height in the chain (Fix 2: explicit height to prevent calculation errors)
    chain_work: ChainWork = 0, // Cumulative proof-of-work up to this block (for reorganization)

    /// Get the hash of this block
    pub fn hash(self: *const Block) BlockHash {
        return self.header.hash();
    }

    /// Get number of transactions in this block
    pub fn txCount(self: *const Block) u32 {
        return @intCast(self.transactions.len);
    }

    /// Calculate the serialized size of this block in bytes
    pub fn getSize(self: *const Block) usize {
        var size: usize = 0;

        // Header size (fixed): 4 + 32 + 32 + 8 + 8 + 4 = 88 bytes
        size += @sizeOf(u32); // version: 4 bytes
        size += @sizeOf(BlockHash); // previous_hash: 32 bytes
        size += @sizeOf(Hash); // merkle_root: 32 bytes
        size += @sizeOf(u64); // timestamp: 8 bytes
        size += @sizeOf(u64); // difficulty: 8 bytes
        size += @sizeOf(u32); // nonce: 4 bytes

        // Transaction count: 4 bytes
        size += @sizeOf(u32);

        // Each transaction size (approximate)
        for (self.transactions) |_| {
            // Transaction structure:
            // version: 2, sender: 32, recipient: 32, amount: 8, fee: 8, nonce: 8,
            // timestamp: 8, sender_public_key: 32, signature: 64
            size += 2 + 32 + 32 + 8 + 8 + 8 + 8 + 32 + 64; // 194 bytes per transaction
        }

        return size;
    }

    /// Check if block structure is valid
    pub fn isValid(self: *const Block) bool {
        // Check block version - only version 0 is currently supported
        if (self.header.version != 0) {
            log.warn("❌ Block invalid: unsupported version {}", .{self.header.version});
            return false;
        }

        // Genesis blocks can have transactions (they contain coinbase)
        // Regular blocks must have at least one transaction

        // Regular blocks must have transactions
        if (self.transactions.len == 0) {
            log.warn("❌ Block invalid: no transactions", .{});
            return false;
        }

        // All transactions must be valid
        for (self.transactions, 0..) |tx, i| {
            if (!tx.isValid()) {
                log.warn("❌ Block invalid: transaction {} failed validation", .{i});
                return false;
            }
        }

        return true;
    }

    /// Compare two blocks for equality
    pub fn equals(self: *const Block, other: *const Block) bool {
        // Compare headers
        if (!std.mem.eql(u8, &self.header.hash(), &other.header.hash())) {
            return false;
        }

        // Compare transaction count
        if (self.transactions.len != other.transactions.len) {
            return false;
        }

        // Compare each transaction
        for (self.transactions, other.transactions) |tx1, tx2| {
            if (!std.mem.eql(u8, &tx1.hash(), &tx2.hash())) {
                return false;
            }
        }

        return true;
    }

    /// Calculate Merkle root of transactions
    /// Uses Bitcoin-style double SHA256 hashing
    pub fn calculateMerkleRoot(self: *const Block, allocator: std.mem.Allocator) !Hash {
        if (self.transactions.len == 0) {
            // Empty merkle root (all zeros)
            return [_]u8{0} ** 32;
        }

        // Special case: single transaction
        if (self.transactions.len == 1) {
            return self.transactions[0].hash();
        }

        // Build merkle tree from transaction hashes
        var current_level = try allocator.alloc(Hash, self.transactions.len);
        
        // Use a flag to track if we need to manually free on error
        // This is safer than nested errdefers during reassignment
        var success = false;
        defer if (!success) allocator.free(current_level);

        // First level: transaction hashes
        for (self.transactions, 0..) |tx, i| {
            current_level[i] = tx.hash();
        }

        // Build tree bottom-up
        while (current_level.len > 1) {
            const next_level_size = (current_level.len + 1) / 2;
            var next_level = try allocator.alloc(Hash, next_level_size);
            errdefer allocator.free(next_level);

            var i: usize = 0;
            while (i < current_level.len) : (i += 2) {
                var hasher = std.crypto.hash.sha2.Sha256.init(.{});

                // Hash left child
                hasher.update(&current_level[i]);

                // Hash right child (or duplicate left if odd number)
                if (i + 1 < current_level.len) {
                    hasher.update(&current_level[i + 1]);
                } else {
                    hasher.update(&current_level[i]); // Duplicate last hash
                }

                // Double SHA256
                var first_hash: [32]u8 = undefined;
                hasher.final(&first_hash);

                var hasher2 = std.crypto.hash.sha2.Sha256.init(.{});
                hasher2.update(&first_hash);
                hasher2.final(&next_level[i / 2]);
            }

            // Free the previous level as we're done with it
            allocator.free(current_level);
            // Update to the new level
            current_level = next_level;
        }

        const root = current_level[0];
        // Clean up the final level
        allocator.free(current_level);
        // Mark as successful so the defer doesn't free it again
        success = true;
        return root;
    }

    /// Free all dynamically allocated memory in this block
    /// This includes the transactions array and any nested allocations
    /// IMPORTANT: Only call this on blocks loaded from disk/database
    pub fn deinit(self: *Block, allocator: std.mem.Allocator) void {
        // First free all nested allocations in each transaction
        for (self.transactions) |*tx| {
            tx.deinit(allocator);
        }
        // Then free the transactions array itself
        allocator.free(self.transactions);
    }

    /// Create a deep copy of this block
    /// The caller owns the returned block and must call deinit on it
    pub fn dupe(self: *const Block, allocator: std.mem.Allocator) !Block {
        // Copy the header (simple value copy)
        var new_block = Block{
            .header = self.header,
            .transactions = undefined,
            .height = self.height, // Fix 2: Copy height from original block
            .chain_work = self.chain_work, // Copy cumulative work
        };

        // Allocate array for transactions
        new_block.transactions = try allocator.alloc(Transaction, self.transactions.len);
        var copied_count: usize = 0;
        errdefer {
            // Clean up on error
            for (new_block.transactions[0..copied_count]) |*tx| {
                tx.deinit(allocator);
            }
            allocator.free(new_block.transactions);
        }

        // Deep copy each transaction
        for (self.transactions, 0..) |tx, i| {
            new_block.transactions[i] = try tx.dupe(allocator);
            copied_count += 1;
        }

        return new_block;
    }

    /// Alias for dupe() - creates a deep copy of this block
    /// The caller owns the returned block and must call deinit on it
    pub fn clone(self: *const Block, allocator: std.mem.Allocator) !Block {
        return try self.dupe(allocator);
    }
};

/// Genesis block configuration
pub const GenesisConfig = struct {
    timestamp: u64,
    message: []const u8,
    reward: u64,
    nonce: u64, // Unique nonce for each network
};

/// Chain work - cumulative proof of work (u256 for maximum precision)
// =============================================================================
// PROOF OF WORK CALCULATIONS
// =============================================================================

/// Convert ZeiCoin difficulty format to 256-bit target
/// ZeiCoin uses: base_bytes (leading zeros) + threshold (next 4 bytes)
/// Output: full 256-bit target value for work calculation
///
/// ZeiCoin format: [base_bytes zeros][threshold 4 bytes][remaining 0xFF bytes]
/// More leading zeros = smaller target = higher difficulty = more work
fn zeiCoinToTarget(base_bytes: u8, threshold: u32) u256 {
    // Validate inputs to prevent overflow
    if (base_bytes >= 31) { // Leave room for threshold bytes
        // Too many leading zero bytes - return minimum target (maximum difficulty)
        return 1;
    }

    if (threshold == 0) {
        // Zero threshold - return minimum target (maximum difficulty)
        return 1;
    }

    // Build target step by step: [zeros][threshold][fill]
    var target: u256 = 0;

    // Position threshold after the leading zero bytes
    // Each base_byte represents 8 bits of leading zeros
    const threshold_position = @as(u16, base_bytes) * 8;

    if (threshold_position + 32 <= 256) { // Ensure we don't overflow
        // Place threshold at the correct bit position
        const shift_amount: u16 = 256 - threshold_position - 32;
        target = @as(u256, threshold) << @intCast(shift_amount);

        // Fill the remaining lower bits with 0xFF pattern (except the threshold area)
        if (threshold_position + 32 < 256) {
            const fill_bits: u16 = 256 - threshold_position - 32;
            if (fill_bits <= 64) { // Safety limit for shift operations
                const fill_mask = (@as(u256, 1) << @intCast(fill_bits)) - 1;
                target = target | fill_mask;
            } else {
                // For large fills, set maximum possible value in lower bits
                target = target | 0xFFFFFFFFFFFFFFFF; // Fill lower 64 bits
            }
        }
    } else {
        // Fallback: if positioning would overflow, just use threshold value
        target = threshold;
    }

    // Ensure target is never zero (would cause division by zero)
    if (target == 0) {
        return 1;
    }

    return target;
}

/// ZeiCoin work calculation with zero tolerance for error
/// Formula: work = ~target / (target + 1) + 1
/// Industry-standard proof-of-work calculation for Nakamoto consensus
fn calculateWork(target: u256) u256 {
    // Handle edge case: target = 0 would cause division by zero
    if (target == 0) {
        return 0; // Invalid targets return zero work
    }

    // Handle edge case: target = MAX_TARGET would cause overflow in target + 1
    const MAX_TARGET = std.math.maxInt(u256);
    if (target == MAX_TARGET) {
        return 1; // Minimum work for maximum target
    }

    // Industry-standard algorithm for proof-of-work:
    // We need to compute 2**256 / (target+1), but we can't represent 2**256
    // as it's too large for a u256. However, as 2**256 is at least as large
    // as target+1, it is equal to ((2**256 - target - 1) / (target+1)) + 1,
    // or ~target / (target+1) + 1.

    const inverted_target = ~target; // Bitwise NOT of target
    const denominator = target + 1;

    return (inverted_target / denominator) + 1;
}

/// This is critical consensus code for ZeiCoin's highest cumulative work rule
pub const ChainWork = u256;

/// Chain state for tracking competing blockchain forks
/// This implements the core of Nakamoto Consensus - highest cumulative work rule
pub const ChainState = struct {
    tip_hash: BlockHash,
    tip_height: u32,
    cumulative_work: ChainWork,

    pub fn init(genesis_hash: BlockHash, genesis_work: ChainWork) ChainState {
        return .{
            .tip_hash = genesis_hash,
            .tip_height = 0,
            .cumulative_work = genesis_work,
        };
    }

    /// Compare two chains by cumulative work
    /// The chain with more cumulative proof-of-work wins
    pub fn hasMoreWork(self: ChainState, other: ChainState) bool {
        return self.cumulative_work > other.cumulative_work;
    }
};

/// Fork block - block waiting to be connected to main chain
pub const ForkBlock = struct {
    block: Block,
    height: u32,
    cumulative_work: ChainWork,
    received_time: i64,
};

/// Mining state for thread-safe mining operations
pub const MiningState = struct {
    /// Mutex for thread-safe access to mining-related data
    mutex: std.Thread.Mutex,
    /// Condition variable for signaling new work
    condition: std.Thread.Condition,
    /// Flag indicating if mining is active
    active: std.atomic.Value(bool),
    /// Mining thread handle
    thread: ?std.Thread,
    /// Flag to indicate mining should stop current work
    should_restart: std.atomic.Value(bool),
    /// Current mining block height
    current_height: std.atomic.Value(u32),

    pub fn init() MiningState {
        return .{
            .mutex = std.Thread.Mutex{},
            .condition = std.Thread.Condition{},
            .active = std.atomic.Value(bool).init(false),
            .thread = null,
            .should_restart = std.atomic.Value(bool).init(false),
            .current_height = std.atomic.Value(u32).init(0),
        };
    }

    pub fn deinit(self: *MiningState) void {
        // Stop mining if active
        self.active.store(false, .release);
        // Signal the condition to wake up the thread if waiting
        self.condition.signal();
        // Wait for thread to finish
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }
};

/// Network-specific genesis configurations
pub const Genesis = struct {
    pub fn getConfig() GenesisConfig {
        return switch (CURRENT_NETWORK) {
            .testnet => GenesisConfig{
                .timestamp = 1757408949090, // September 9, 2025 09:09:09.090 UTC in milliseconds
                .message = "ZeiCoin TestNet Genesis - A minimal digital currency written in ⚡Zig",
                .reward = 50 * ZEI_COIN,
                .nonce = 0x7E57DE7,
            },
            .mainnet => GenesisConfig{
                .timestamp = 1736150400000, // January 6, 2025 00:00:00 UTC (PLACEHOLDER) in milliseconds
                .message = "ZeiCoin MainNet Launch - [Quote]",
                .reward = 50 * ZEI_COIN,
                .nonce = 0x3A1F1E7,
            },
        };
    }

    // Helper to get individual values for backward compatibility
    pub fn timestamp() u64 {
        return getConfig().timestamp;
    }

    pub fn message() []const u8 {
        return getConfig().message;
    }

    pub fn reward() u64 {
        return getConfig().reward;
    }
};

/// Network configuration - TestNet vs MainNet
pub const NetworkType = enum {
    testnet,
    mainnet,

    /// Get the network ID for protocol identification
    pub fn getNetworkId(self: NetworkType) u32 {
        return switch (self) {
            .testnet => 0x74657374, // 'test' in hex
            .mainnet => 0x6D61696E, // 'main' in hex
        };
    }

    /// Get the data directory name for the network
    pub fn getDataDir(self: NetworkType) []const u8 {
        return switch (self) {
            .testnet => "zeicoin_data_testnet",
            .mainnet => "zeicoin_data_mainnet",
        };
    }
};

/// Current network configuration
pub const CURRENT_NETWORK: NetworkType = .testnet; // Change to .mainnet for production

/// Network-specific configurations
pub const NetworkConfig = struct {
    randomx_mode: bool, // false = light (256MB), true = fast (2GB)
    target_block_time: u64, // seconds
    max_nonce: u32,
    block_reward: u64,
    min_fee: u64,

    pub fn current() NetworkConfig {
        return switch (CURRENT_NETWORK) {
            .testnet => NetworkConfig{
                .randomx_mode = false, // Light mode (256MB RAM)
                .target_block_time = 60, // 60 seconds (Slow down for testing)
                .max_nonce = 1_000_000, // Reasonable limit for testing
                .block_reward = 10 * ZEI_COIN, // 10 ZEI per block
                .min_fee = 1000, // 0.00001 ZEI minimum fee
            },
            .mainnet => NetworkConfig{
                .randomx_mode = true, // Fast mode (2GB RAM) for better performance
                .target_block_time = 120, // 2 minutes (Monero-like)
                .max_nonce = 10_000_000, // Higher limit for production
                .block_reward = 50 * ZEI_CENT, // 0.5 ZEI per block (deflationary)
                .min_fee = 5000, // 0.00005 ZEI minimum fee
            },
        };
    }

    pub fn networkName() []const u8 {
        return switch (CURRENT_NETWORK) {
            .testnet => "TestNet",
            .mainnet => "MainNet",
        };
    }

    pub fn displayInfo() void {
        const config = current();
        const initial_difficulty = ZenMining.initialDifficultyTarget();
        log.info("🌐 Network: {s}", .{networkName()});
        log.info("⚡ Difficulty: {}-byte range (dynamic)", .{initial_difficulty.base_bytes});
        // Always use RandomX for consistent security
        log.info("🧠 Mining Algorithm: RandomX {s}", .{if (config.randomx_mode) "Fast (2GB RAM)" else "Light (256MB RAM)"});
        log.info("⏰ Target Block Time: {}s", .{config.target_block_time});
        log.info("💰 Block Reward: {d:.8} ZEI", .{@as(f64, @floatFromInt(config.block_reward)) / @as(f64, @floatFromInt(ZEI_COIN))});
        log.info("💸 Minimum Fee: {d:.8} ZEI", .{@as(f64, @floatFromInt(config.min_fee)) / @as(f64, @floatFromInt(ZEI_COIN))});
    }
};

/// Zeicoin mining configuration - network-aware
pub const ZenMining = struct {
    /// Initial block reward (before any halvings)
    pub const INITIAL_BLOCK_REWARD: u64 = NetworkConfig.current().block_reward;

    /// Legacy constant for backwards compatibility - use calculateBlockReward() instead
    pub const BLOCK_REWARD: u64 = NetworkConfig.current().block_reward;

    pub const TARGET_BLOCK_TIME: u64 = NetworkConfig.current().target_block_time;
    pub const MAX_NONCE: u32 = NetworkConfig.current().max_nonce;
    pub const RANDOMX_MODE: bool = NetworkConfig.current().randomx_mode;
    pub const DIFFICULTY_ADJUSTMENT_PERIOD: u64 = 20; // Adjust every 20 blocks (balanced security vs responsiveness)
    pub const MAX_ADJUSTMENT_FACTOR: f64 = 2.0; // Maximum 2x change per adjustment
    pub const COINBASE_MATURITY: u32 = switch (CURRENT_NETWORK) {
        .testnet => 10, // TestNet: 10 blocks for faster testing
        .mainnet => 100, // MainNet: 100 blocks for security
    };

    /// Halving interval - blocks between each reward halving
    /// TestNet: 100 blocks (~17 minutes at 10s blocks) for fast testing
    /// MainNet: 525,600 blocks (~2 years at 2-minute blocks)
    pub const HALVING_INTERVAL: u32 = switch (CURRENT_NETWORK) {
        .testnet => 100, // Fast halving for testing
        .mainnet => 525_600, // ~2 years at 2-min blocks
    };

    /// Minimum block reward (tail emission) - prevents reward from going to zero
    /// This ensures miners always have incentive to secure the network
    pub const MINIMUM_BLOCK_REWARD: u64 = switch (CURRENT_NETWORK) {
        .testnet => 1000, // 0.00001 ZEI minimum
        .mainnet => 1000, // 0.00001 ZEI minimum
    };

    /// Calculate block reward for a given height with halving schedule
    /// Reward halves every HALVING_INTERVAL blocks until MINIMUM_BLOCK_REWARD
    pub fn calculateBlockReward(height: u32) u64 {
        // Genesis block (height 0) has no mining reward - only pre-mine distributions
        if (height == 0) {
            return 0;
        }

        // Calculate number of halvings that have occurred
        const halvings = height / HALVING_INTERVAL;

        // Cap halvings to prevent shift overflow (max 63 halvings)
        const capped_halvings: u6 = @intCast(@min(halvings, 63));

        // Calculate reward: initial_reward >> halvings
        const reward = INITIAL_BLOCK_REWARD >> capped_halvings;

        // Enforce minimum reward (tail emission)
        return @max(reward, MINIMUM_BLOCK_REWARD);
    }

    /// Get initial difficulty target for current network
    pub fn initialDifficultyTarget() DifficultyTarget {
        return DifficultyTarget.initial(CURRENT_NETWORK);
    }

    /// Calculate total theoretical supply from mining (not including pre-mine)
    /// This is the maximum supply that could be mined given the halving schedule
    pub fn calculateTheoreticalMiningSupply() u64 {
        var total: u64 = 0;
        var reward = INITIAL_BLOCK_REWARD;
        const blocks_at_reward: u64 = HALVING_INTERVAL;

        // Sum rewards for each halving epoch until minimum reward
        while (reward > MINIMUM_BLOCK_REWARD) {
            total += reward * blocks_at_reward;
            reward = reward >> 1;
        }

        // Add tail emission (continues indefinitely, but we cap at reasonable estimate)
        // For practical purposes, estimate 10 more halving periods at minimum reward
        total += MINIMUM_BLOCK_REWARD * HALVING_INTERVAL * 10;

        return total;
    }
};

/// 💰 Zeicoin transaction fee configuration - network-aware economic incentives
pub const ZenFees = struct {
    pub const MIN_FEE: u64 = NetworkConfig.current().min_fee;
    pub const STANDARD_FEE: u64 = NetworkConfig.current().min_fee * 5; // 5x minimum
    pub const PRIORITY_FEE: u64 = NetworkConfig.current().min_fee * 10; // 10x minimum
};

/// 📦 Block size limits - prevent spam while allowing growth
pub const BlockLimits = struct {
    /// Maximum block size in bytes (16MB) - hard consensus limit
    pub const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024; // 16MB

    /// Soft limit for miners (2MB) - can be adjusted without fork
    pub const SOFT_BLOCK_SIZE: usize = 2 * 1024 * 1024; // 2MB

    /// Average transaction size estimate for capacity planning
    pub const AVG_TX_SIZE: usize = 2048; // 2KB average

    /// Estimated transactions per block at soft limit
    pub const SOFT_TXS_PER_BLOCK: usize = SOFT_BLOCK_SIZE / AVG_TX_SIZE; // ~1000 txs

    /// Estimated transactions per block at hard limit
    pub const MAX_TXS_PER_BLOCK: usize = MAX_BLOCK_SIZE / AVG_TX_SIZE; // ~8000 txs
};

/// 🏊 Mempool limits - prevent memory exhaustion attacks
pub const MempoolLimits = struct {
    /// Maximum number of transactions in mempool
    pub const MAX_TRANSACTIONS: usize = 10_000;

    /// Maximum total size of mempool in bytes (50MB)
    pub const MAX_SIZE_BYTES: usize = 50 * 1024 * 1024;

    /// Transaction size for serialization (includes all fields)
    pub const TRANSACTION_SIZE: usize = 214; // Base fields + version(2) + flags(2) + script_version(2) + witness_data_len(4) + extra_data_len(4)
};

/// 💸 Transaction limits - prevent individual transaction DoS attacks
pub const TransactionLimits = struct {
    /// Maximum size of a single transaction in bytes (100KB)
    pub const MAX_TX_SIZE: usize = 100 * 1024; // 100KB

    /// Maximum witness_data size (for future use)
    pub const MAX_WITNESS_SIZE: usize = 10 * 1024; // 10KB

    /// Maximum extra_data size (for messages/future use)
    pub const MAX_EXTRA_DATA_SIZE: usize = 1024; // 1KB
};

/// 📅 Transaction expiration configuration - prevents old transaction replay
pub const TransactionExpiry = struct {
    /// Default expiry window in blocks (24 hours worth)
    pub const EXPIRY_WINDOW_TESTNET: u64 = 8_640; // 24 hours * 60 minutes * 6 blocks/minute
    pub const EXPIRY_WINDOW_MAINNET: u64 = 720; // 24 hours * 60 minutes * 0.5 blocks/minute

    /// Get expiry window for current network
    pub fn getExpiryWindow() u64 {
        return switch (CURRENT_NETWORK) {
            .testnet => EXPIRY_WINDOW_TESTNET,
            .mainnet => EXPIRY_WINDOW_MAINNET,
        };
    }
};

/// ⏰ Timestamp validation configuration - prevents time-based attacks
pub const TimestampValidation = struct {
    /// Maximum allowed timestamp in the future (seconds)
    /// Reduced from 2 hours to 10 minutes to prevent time-warp attacks
    pub const MAX_FUTURE_TIME: i64 = 10 * 60; // 10 minutes

    /// Minimum blocks for median time past calculation
    pub const MTP_BLOCK_COUNT: u32 = 11; // Use last 11 blocks for median

    /// Maximum timestamp adjustment per block (seconds)
    pub const MAX_TIME_ADJUSTMENT: i64 = 90 * 60; // 90 minutes

    /// Validate a block timestamp against current time
    pub fn isTimestampValid(timestamp: u64, current_time: i64) bool {
        // Block timestamps are in milliseconds, convert to seconds
        const block_time_seconds = @divFloor(@as(i64, @intCast(timestamp)), 1000);
        return block_time_seconds <= current_time + MAX_FUTURE_TIME;
    }

    /// Check if timestamp is not too far in the past
    pub fn isNotTooOld(timestamp: u64, previous_timestamp: u64) bool {
        // Block timestamp must be greater than previous block
        return timestamp > previous_timestamp;
    }
};

// Tests
const testing = std.testing;

test "transaction validation" {
    // Create a test public key and derive address from it
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = Address.fromPublicKey(alice_public_key);
    var bob_hash: [31]u8 = undefined;
    @memset(&bob_hash, 0);
    bob_hash[0] = 1; // Make it different from alice
    const bob_addr = Address{
        .version = @intFromEnum(AddressVersion.P2PKH),
        .hash = bob_hash,
    };

    const tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * ZEI_COIN,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 1,
        .timestamp = 1757419151000,
        .expiry_height = 10000,
        .sender_public_key = alice_public_key,
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    try testing.expect(tx.isValid());
}

test "account affordability" {
    const addr = std.mem.zeroes(Address);
    const account = Account{
        .address = addr,
        .balance = 50 * ZEI_COIN,
        .nonce = 0,
    };

    try testing.expect(account.canAfford(25 * ZEI_COIN));
    try testing.expect(!account.canAfford(100 * ZEI_COIN));
}

test "block validation" {
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = Address.fromPublicKey(alice_public_key);
    var bob_hash: [31]u8 = undefined;
    @memset(&bob_hash, 0);
    bob_hash[0] = 1;
    const bob_addr = Address{
        .version = @intFromEnum(AddressVersion.P2PKH),
        .hash = bob_hash,
    };

    const tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * ZEI_COIN,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 1,
        .timestamp = 1757419151000,
        .expiry_height = 10000,
        .sender_public_key = alice_public_key,
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    var transactions = [_]Transaction{tx};

    const block = Block{
        .header = BlockHeader{
            .version = 0, // Block version 0 for current protocol
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1757419151000,
            .difficulty = ZenMining.initialDifficultyTarget().toU64(),
            .nonce = 0,
            .witness_root = std.mem.zeroes(Hash),
            .state_root = std.mem.zeroes(Hash),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        },
        .transactions = &transactions,
        .height = 1, // Test block at height 1
    };

    try testing.expect(block.isValid());
    try testing.expectEqual(@as(u32, 1), block.txCount());
}

test "money constants" {
    try testing.expectEqual(@as(u64, 100000000), ZEI_COIN);
    try testing.expectEqual(@as(u64, 1000000), ZEI_CENT);
    try testing.expectEqual(@as(u64, 100), ZEI_COIN / ZEI_CENT);
}

test "transaction hash" {
    // Create test public key and address
    const public_key = std.mem.zeroes([32]u8);
    const sender_addr = Address.fromPublicKey(public_key);

    var recipient_hash: [31]u8 = undefined;
    @memset(&recipient_hash, 0);
    recipient_hash[0] = 1;
    const recipient_addr = Address{
        .version = @intFromEnum(AddressVersion.P2PKH),
        .hash = recipient_hash,
    };

    // Create test transaction
    const tx1 = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = sender_addr,
        .recipient = recipient_addr,
        .amount = 1000000000,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1234567890000,
        .expiry_height = 10000,
        .sender_public_key = public_key,
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Create identical transaction
    const tx2 = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = sender_addr,
        .recipient = recipient_addr,
        .amount = 1000000000,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1234567890000,
        .expiry_height = 10000,
        .sender_public_key = public_key,
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Identical transactions should have same hash
    const hash1 = tx1.hash();
    const hash2 = tx2.hash();
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Different transactions should have different hashes
    const tx3 = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = sender_addr,
        .recipient = recipient_addr,
        .amount = 2000000000, // Different amount
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 0,
        .timestamp = 1234567890000,
        .expiry_height = 10000,
        .sender_public_key = public_key,
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    const hash3 = tx3.hash();
    try testing.expect(!std.mem.eql(u8, &hash1, &hash3));
}

test "block header hash consistency" {
    // Create test block header
    const test_difficulty = ZenMining.initialDifficultyTarget().toU64();
    const header1 = BlockHeader{
        .version = 0, // Block version 0 for current protocol
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1757419151000,
        .difficulty = test_difficulty,
        .nonce = 42,
        .witness_root = std.mem.zeroes(Hash),
        .state_root = std.mem.zeroes(Hash),
        .extra_nonce = 0,
        .extra_data = std.mem.zeroes([32]u8),
    };

    // Create identical header
    const header2 = BlockHeader{
        .version = 0, // Block version 0 for current protocol
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1757419151000,
        .difficulty = test_difficulty,
        .nonce = 42,
        .witness_root = std.mem.zeroes(Hash),
        .state_root = std.mem.zeroes(Hash),
        .extra_nonce = 0,
        .extra_data = std.mem.zeroes([32]u8),
    };

    // Identical headers should have same hash
    const hash1 = header1.hash();
    const hash2 = header2.hash();
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Hash should not be all zeros
    const zero_hash = std.mem.zeroes(Hash);
    try testing.expect(!std.mem.eql(u8, &hash1, &zero_hash));
}

test "block header hash uniqueness" {
    const test_difficulty = ZenMining.initialDifficultyTarget().toU64();
    const base_header = BlockHeader{
        .version = 0, // Block version 0 for current protocol
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = std.mem.zeroes(Hash),
        .timestamp = 1757419151000,
        .difficulty = test_difficulty,
        .nonce = 0,
        .witness_root = std.mem.zeroes(Hash),
        .state_root = std.mem.zeroes(Hash),
        .extra_nonce = 0,
        .extra_data = std.mem.zeroes([32]u8),
    };

    // Different nonce should produce different hash
    var header_nonce1 = base_header;
    header_nonce1.nonce = 1;
    var header_nonce2 = base_header;
    header_nonce2.nonce = 2;

    const hash_nonce1 = header_nonce1.hash();
    const hash_nonce2 = header_nonce2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_nonce1, &hash_nonce2));

    // Different timestamp should produce different hash
    var header_time1 = base_header;
    header_time1.timestamp = 1757419151000;
    var header_time2 = base_header;
    header_time2.timestamp = 1704067300000;

    const hash_time1 = header_time1.hash();
    const hash_time2 = header_time2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_time1, &hash_time2));

    // Different difficulty should produce different hash
    var header_diff1 = base_header;
    header_diff1.difficulty = test_difficulty;
    var header_diff2 = base_header;
    header_diff2.difficulty = test_difficulty + 1;

    const hash_diff1 = header_diff1.hash();
    const hash_diff2 = header_diff2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_diff1, &hash_diff2));
}

test "block hash delegated to header hash" {
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = Address.fromPublicKey(alice_public_key);
    var bob_hash: [31]u8 = undefined;
    @memset(&bob_hash, 0);
    bob_hash[0] = 1;
    const bob_addr = Address{
        .version = @intFromEnum(AddressVersion.P2PKH),
        .hash = bob_hash,
    };

    const tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = alice_addr,
        .recipient = bob_addr,
        .amount = 100 * ZEI_COIN,
        .fee = ZenFees.STANDARD_FEE,
        .nonce = 1,
        .timestamp = 1757419151000,
        .expiry_height = 10000,
        .sender_public_key = alice_public_key,
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    var transactions = [_]Transaction{tx};

    const block = Block{
        .header = BlockHeader{
            .version = 0, // Block version 0 for current protocol
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1757419151000,
            .difficulty = ZenMining.initialDifficultyTarget().toU64(),
            .nonce = 12345,
            .witness_root = std.mem.zeroes(Hash),
            .state_root = std.mem.zeroes(Hash),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        },
        .transactions = &transactions,
        .height = 1, // Test block at height 1
    };

    // Block hash should equal header hash
    const block_hash = block.hash();
    const header_hash = block.header.hash();
    try testing.expectEqualSlices(u8, &block_hash, &header_hash);
}

test "block version validation" {
    const allocator = testing.allocator;

    // Create a valid transaction
    const tx = Transaction{
        .version = 0,
        .flags = std.mem.zeroes(TransactionFlags),
        .sender = std.mem.zeroes(Address),
        .recipient = std.mem.zeroes(Address),
        .amount = 100,
        .fee = 0,
        .nonce = 0,
        .timestamp = 1000,
        .expiry_height = std.math.maxInt(u64),
        .sender_public_key = std.mem.zeroes([32]u8),
        .signature = std.mem.zeroes(Signature),
        .script_version = 0,
        .witness_data = &[_]u8{},
        .extra_data = &[_]u8{},
    };

    // Create transactions array
    const txs = try allocator.alloc(Transaction, 1);
    defer allocator.free(txs);
    txs[0] = tx;

    // Test version 0 block (should be valid)
    var block_v0 = Block{
        .header = BlockHeader{
            .version = 0,
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1000,
            .difficulty = 0,
            .nonce = 0,
            .witness_root = std.mem.zeroes(Hash),
            .state_root = std.mem.zeroes(Hash),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        },
        .transactions = txs,
        .height = 1, // Test block at height 1
    };
    try testing.expect(block_v0.isValid());

    // Test version 1 block (should be invalid)
    var block_v1 = Block{
        .header = BlockHeader{
            .version = 1,
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1000,
            .difficulty = 0,
            .nonce = 0,
            .witness_root = std.mem.zeroes(Hash),
            .state_root = std.mem.zeroes(Hash),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        },
        .transactions = txs,
        .height = 1, // Test block at height 1
    };
    try testing.expect(!block_v1.isValid());

    // Test high version block (should be invalid)
    var block_v999 = Block{
        .header = BlockHeader{
            .version = 999,
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1000,
            .difficulty = 0,
            .nonce = 0,
            .witness_root = std.mem.zeroes(Hash),
            .state_root = std.mem.zeroes(Hash),
            .extra_nonce = 0,
            .extra_data = std.mem.zeroes([32]u8),
        },
        .transactions = txs,
        .height = 1, // Test block at height 1
    };
    try testing.expect(!block_v999.isValid());
}
