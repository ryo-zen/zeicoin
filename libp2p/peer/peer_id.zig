// peer_id.zig - libp2p PeerId + Ed25519 identity key support
// Implements deterministic protobuf key encoding + multihash PeerId derivation.

const std = @import("std");

const ED25519_KEY_TYPE: u8 = 1;
const IDENTITY_MULTIHASH_CODE: u64 = 0x00;
const SHA2_256_MULTIHASH_CODE: u64 = 0x12;
const SHA2_256_SIZE: usize = 32;

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const PRIVATE_KEY_PROTO_LEN: usize = 68; // 0x08 0x01 0x12 0x40 + 64 bytes
const CIDV1_VERSION: u64 = 1;
const LIBP2P_KEY_MULTICODEC: u64 = 0x72;

pub const PeerIdError = error{
    InvalidPeerId,
    InvalidMultihash,
    UnsupportedPeerIdTextEncoding,
    InvalidBase58,
    InvalidPrivateKeyEncoding,
};

/// Peer ID represented as raw multihash bytes + base58btc text form.
pub const PeerId = struct {
    bytes: []u8,
    string: []u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Create a random PeerId by generating an Ed25519 key and deriving PeerId from its public key.
    pub fn random(allocator: std.mem.Allocator) !Self {
        const io = std.Io.Threaded.global_single_threaded.ioBasic();
        const keypair = std.crypto.sign.Ed25519.KeyPair.generate(io);
        return fromPublicKey(allocator, keypair.public_key.bytes);
    }

    /// Build PeerId from Ed25519 public key bytes.
    pub fn fromPublicKey(allocator: std.mem.Allocator, public_key: [32]u8) !Self {
        var encoded: [36]u8 = undefined;
        encoded[0] = 0x08; // field 1, varint
        encoded[1] = ED25519_KEY_TYPE;
        encoded[2] = 0x12; // field 2, bytes
        encoded[3] = 0x20; // 32-byte public key
        @memcpy(encoded[4..], &public_key);
        return fromEncodedPublicKey(allocator, &encoded);
    }

    /// Build PeerId from encoded libp2p PublicKey protobuf bytes.
    pub fn fromEncodedPublicKey(allocator: std.mem.Allocator, encoded_public_key: []const u8) !Self {
        const multihash = try buildPeerIdMultihash(allocator, encoded_public_key);
        errdefer allocator.free(multihash);
        const text = try encodeBase58(allocator, multihash);
        errdefer allocator.free(text);
        return .{
            .bytes = multihash,
            .string = text,
            .allocator = allocator,
        };
    }

    /// Create from raw multihash bytes.
    pub fn fromBytes(allocator: std.mem.Allocator, bytes: []const u8) !Self {
        try validateMultihash(bytes);
        const bytes_copy = try allocator.dupe(u8, bytes);
        errdefer allocator.free(bytes_copy);
        const text = try encodeBase58(allocator, bytes_copy);
        errdefer allocator.free(text);
        return .{
            .bytes = bytes_copy,
            .string = text,
            .allocator = allocator,
        };
    }

    /// Parse from legacy base58btc or CIDv1 text.
    pub fn fromString(allocator: std.mem.Allocator, text: []const u8) !Self {
        if (text.len == 0) return PeerIdError.InvalidPeerId;

        if (text[0] == 'b' or text[0] == 'B') {
            const decoded = try decodeBase32Multibase(allocator, text);
            defer allocator.free(decoded);

            var off: usize = 0;
            const version = readVarint(decoded, &off) catch return PeerIdError.InvalidPeerId;
            const codec = readVarint(decoded, &off) catch return PeerIdError.InvalidPeerId;
            if (version != CIDV1_VERSION or codec != LIBP2P_KEY_MULTICODEC) {
                return PeerIdError.InvalidPeerId;
            }
            return fromBytes(allocator, decoded[off..]);
        }

        const decoded = try decodeBase58(allocator, text);
        errdefer allocator.free(decoded);
        try validateMultihash(decoded);

        const text_copy = try allocator.dupe(u8, text);
        errdefer allocator.free(text_copy);
        return .{
            .bytes = decoded,
            .string = text_copy,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.string);
    }

    pub fn toString(self: *const Self) []const u8 {
        return self.string;
    }

    pub fn getBytes(self: *const Self) []const u8 {
        return self.bytes;
    }

    pub fn equals(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.bytes, other.bytes);
    }
};

/// Persistent Ed25519 identity key material + derived PeerId.
pub const IdentityKey = struct {
    allocator: std.mem.Allocator,
    private_key: [64]u8,
    public_key: [32]u8,
    peer_id: PeerId,

    const Self = @This();

    pub fn generate(allocator: std.mem.Allocator, io: std.Io) !Self {
        const kp = std.crypto.sign.Ed25519.KeyPair.generate(io);
        return fromPrivateKeyBytes(allocator, kp.secret_key.bytes);
    }

    pub fn fromPrivateKeyBytes(allocator: std.mem.Allocator, private_key: [64]u8) !Self {
        const secret_key = try std.crypto.sign.Ed25519.SecretKey.fromBytes(private_key);
        const kp = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret_key);
        var peer_id = try PeerId.fromPublicKey(allocator, kp.public_key.bytes);
        errdefer peer_id.deinit();

        return .{
            .allocator = allocator,
            .private_key = private_key,
            .public_key = kp.public_key.bytes,
            .peer_id = peer_id,
        };
    }

    pub fn loadOrCreate(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Self {
        const loaded = load(allocator, io, path) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (loaded) |identity| return identity;

        var generated = try generate(allocator, io);
        errdefer generated.deinit();
        try generated.save(io, path);
        return generated;
    }

    pub fn load(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Self {
        const dir = std.Io.Dir.cwd();
        const file = try dir.openFile(io, path, .{});
        defer file.close(io);

        var buf: [PRIVATE_KEY_PROTO_LEN]u8 = undefined;
        const bytes_read = try file.readStreaming(io, &[_][]u8{&buf});
        if (bytes_read != PRIVATE_KEY_PROTO_LEN) return PeerIdError.InvalidPrivateKeyEncoding;
        return fromPrivateKeyProtobuf(allocator, buf[0..bytes_read]);
    }

    pub fn save(self: *const Self, io: std.Io, path: []const u8) !void {
        const dir = std.Io.Dir.cwd();
        const file = try dir.createFile(io, path, .{});
        defer file.close(io);

        var encoded: [PRIVATE_KEY_PROTO_LEN]u8 = undefined;
        encoded[0] = 0x08;
        encoded[1] = ED25519_KEY_TYPE;
        encoded[2] = 0x12;
        encoded[3] = 0x40;
        @memcpy(encoded[4..], &self.private_key);
        _ = try file.writeStreamingAll(io, &encoded);
    }

    pub fn deinit(self: *Self) void {
        self.peer_id.deinit();
        std.crypto.secureZero(u8, &self.private_key);
    }
};

fn fromPrivateKeyProtobuf(allocator: std.mem.Allocator, encoded: []const u8) !IdentityKey {
    if (encoded.len != PRIVATE_KEY_PROTO_LEN) return PeerIdError.InvalidPrivateKeyEncoding;
    if (encoded[0] != 0x08 or encoded[1] != ED25519_KEY_TYPE) return PeerIdError.InvalidPrivateKeyEncoding;
    if (encoded[2] != 0x12 or encoded[3] != 0x40) return PeerIdError.InvalidPrivateKeyEncoding;

    var private_key: [64]u8 = undefined;
    @memcpy(&private_key, encoded[4..68]);
    return IdentityKey.fromPrivateKeyBytes(allocator, private_key);
}

fn buildPeerIdMultihash(allocator: std.mem.Allocator, encoded_public_key: []const u8) ![]u8 {
    if (encoded_public_key.len <= 42) {
        const header_len = varintLen(IDENTITY_MULTIHASH_CODE) + varintLen(encoded_public_key.len);
        const out = try allocator.alloc(u8, header_len + encoded_public_key.len);
        var off: usize = 0;
        off += writeVarint(out[off..], IDENTITY_MULTIHASH_CODE);
        off += writeVarint(out[off..], encoded_public_key.len);
        @memcpy(out[off .. off + encoded_public_key.len], encoded_public_key);
        return out;
    }

    var digest: [SHA2_256_SIZE]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded_public_key, &digest, .{});

    const header_len = varintLen(SHA2_256_MULTIHASH_CODE) + varintLen(SHA2_256_SIZE);
    const out = try allocator.alloc(u8, header_len + SHA2_256_SIZE);
    var off: usize = 0;
    off += writeVarint(out[off..], SHA2_256_MULTIHASH_CODE);
    off += writeVarint(out[off..], SHA2_256_SIZE);
    @memcpy(out[off .. off + SHA2_256_SIZE], &digest);
    return out;
}

fn validateMultihash(bytes: []const u8) !void {
    if (bytes.len < 3) return PeerIdError.InvalidMultihash;

    var off: usize = 0;
    const code = readVarint(bytes, &off) catch return PeerIdError.InvalidMultihash;
    const digest_len = readVarint(bytes, &off) catch return PeerIdError.InvalidMultihash;

    if (bytes.len - off != digest_len) return PeerIdError.InvalidMultihash;
    switch (code) {
        IDENTITY_MULTIHASH_CODE => {},
        SHA2_256_MULTIHASH_CODE => {
            if (digest_len != SHA2_256_SIZE) return PeerIdError.InvalidMultihash;
        },
        else => return PeerIdError.InvalidMultihash,
    }
}

fn varintLen(value: usize) usize {
    var v = value;
    var n: usize = 1;
    while (v >= 0x80) : (v >>= 7) n += 1;
    return n;
}

fn writeVarint(out: []u8, value: usize) usize {
    var v = value;
    var i: usize = 0;
    while (v >= 0x80) : (v >>= 7) {
        out[i] = @as(u8, @intCast(v & 0x7F)) | 0x80;
        i += 1;
    }
    out[i] = @as(u8, @intCast(v));
    return i + 1;
}

fn readVarint(data: []const u8, off: *usize) !usize {
    var result: usize = 0;
    var shift: u6 = 0;
    while (off.* < data.len) {
        const b = data[off.*];
        off.* += 1;
        result |= @as(usize, b & 0x7F) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift >= @bitSizeOf(usize)) return error.VarintOverflow;
    }
    return error.EndOfStream;
}

fn encodeBase58(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return allocator.dupe(u8, "");

    var zeroes: usize = 0;
    while (zeroes < input.len and input[zeroes] == 0) : (zeroes += 1) {}

    const size = ((input.len - zeroes) * 138 / 100) + 1;
    const b58 = try allocator.alloc(u8, size);
    defer allocator.free(b58);
    @memset(b58, 0);

    var length: usize = 0;
    for (input[zeroes..]) |byte| {
        var carry: usize = byte;
        var i: usize = 0;
        while (i < length) : (i += 1) {
            const idx = size - 1 - i;
            carry += @as(usize, b58[idx]) << 8;
            b58[idx] = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            b58[size - 1 - length] = @intCast(carry % 58);
            length += 1;
            carry /= 58;
        }
    }

    const out_len = zeroes + length;
    const out = try allocator.alloc(u8, out_len);
    for (out[0..zeroes]) |*c| c.* = '1';
    var i: usize = 0;
    while (i < length) : (i += 1) {
        out[zeroes + i] = BASE58_ALPHABET[b58[size - length + i]];
    }
    return out;
}

fn decodeBase58(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len == 0) return allocator.dupe(u8, "");

    var zeroes: usize = 0;
    while (zeroes < input.len and input[zeroes] == '1') : (zeroes += 1) {}

    const size = ((input.len - zeroes) * 733 / 1000) + 1;
    const b256 = try allocator.alloc(u8, size);
    defer allocator.free(b256);
    @memset(b256, 0);

    var length: usize = 0;
    for (input[zeroes..]) |ch| {
        const val = base58Value(ch) orelse return PeerIdError.InvalidBase58;
        var carry: usize = val;
        var i: usize = 0;
        while (i < length) : (i += 1) {
            const idx = size - 1 - i;
            carry += @as(usize, b256[idx]) * 58;
            b256[idx] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) {
            b256[size - 1 - length] = @intCast(carry & 0xff);
            length += 1;
            carry >>= 8;
        }
    }

    const out_len = zeroes + length;
    const out = try allocator.alloc(u8, out_len);
    @memset(out, 0);
    @memcpy(out[zeroes..], b256[size - length ..]);
    return out;
}

fn base58Value(ch: u8) ?u8 {
    for (BASE58_ALPHABET, 0..) |c, idx| {
        if (c == ch) return @intCast(idx);
    }
    return null;
}

fn decodeBase32Multibase(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len < 2) return PeerIdError.InvalidPeerId;

    const encoded = input[1..];
    const out_len = (encoded.len * 5) / 8 + 1;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var out_len_actual: usize = 0;
    var acc: u32 = 0;
    var bits: u8 = 0;
    for (encoded) |ch| {
        const value = base32Value(ch) orelse return PeerIdError.UnsupportedPeerIdTextEncoding;
        acc = (acc << 5) | value;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            out[out_len_actual] = @intCast((acc >> @as(u5, @intCast(bits))) & 0xFF);
            out_len_actual += 1;
        }
    }

    if (bits > 0 and (acc & ((@as(u32, 1) << @as(u5, @intCast(bits))) - 1)) != 0) {
        return PeerIdError.InvalidPeerId;
    }

    return allocator.realloc(out, out_len_actual);
}

fn base32Value(ch: u8) ?u32 {
    const lower = std.ascii.toLower(ch);
    for (BASE32_ALPHABET, 0..) |c, idx| {
        if (c == lower) return @intCast(idx);
    }
    return null;
}

test "create random peer ID" {
    const allocator = std.testing.allocator;
    var peer_id = try PeerId.random(allocator);
    defer peer_id.deinit();

    try std.testing.expect(peer_id.bytes.len > 4);
    try std.testing.expect(peer_id.string.len > 0);
}

test "peer ID from bytes and string roundtrip" {
    const allocator = std.testing.allocator;
    var id1 = try PeerId.random(allocator);
    defer id1.deinit();

    var id2 = try PeerId.fromBytes(allocator, id1.getBytes());
    defer id2.deinit();
    try std.testing.expect(id1.equals(&id2));

    var id3 = try PeerId.fromString(allocator, id1.toString());
    defer id3.deinit();
    try std.testing.expect(id1.equals(&id3));
}

test "derive identity-multihash peer id from Ed25519 public key" {
    const allocator = std.testing.allocator;
    const public_key = [32]u8{
        0x1e, 0xd1, 0xe8, 0xfa, 0xe2, 0xc4, 0xa1, 0x44,
        0xb8, 0xbe, 0x8f, 0xd4, 0xb4, 0x7b, 0xf3, 0xd3,
        0xb3, 0x4b, 0x87, 0x1c, 0x3c, 0xac, 0xf6, 0x01,
        0x0f, 0x0e, 0x42, 0xd4, 0x74, 0xfc, 0xe2, 0x7e,
    };
    var peer_id = try PeerId.fromPublicKey(allocator, public_key);
    defer peer_id.deinit();

    // identity multihash: code(0x00), len(0x24), then protobuf public key bytes.
    try std.testing.expectEqual(@as(u8, 0x00), peer_id.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x24), peer_id.bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x08), peer_id.bytes[2]);
    try std.testing.expectEqual(@as(u8, ED25519_KEY_TYPE), peer_id.bytes[3]);
    try std.testing.expectEqual(@as(u8, 0x12), peer_id.bytes[4]);
    try std.testing.expectEqual(@as(u8, 0x20), peer_id.bytes[5]);
    try std.testing.expectEqualSlices(u8, &public_key, peer_id.bytes[6..38]);

    var parsed = try PeerId.fromString(allocator, peer_id.toString());
    defer parsed.deinit();
    try std.testing.expect(peer_id.equals(&parsed));
}

test "peer ID parses CIDv1 base32 form" {
    const allocator = std.testing.allocator;
    const cid_text = "bafzaajaiaejcal72gwuz2or47oyxxn6b3rkwdmmkrxgkjxzy3rqt5kczyn7lcm3l";

    var parsed = try PeerId.fromString(allocator, cid_text);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA", parsed.toString());
}

test "identity key load/create persists stable peer id" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const path = "libp2p_identity_test.key";
    const dir = std.Io.Dir.cwd();
    defer {
        dir.deleteFile(io, path) catch {};
    }
    dir.deleteFile(io, path) catch {};

    var first = try IdentityKey.loadOrCreate(allocator, io, path);
    defer first.deinit();
    const first_text = try allocator.dupe(u8, first.peer_id.toString());
    defer allocator.free(first_text);

    var second = try IdentityKey.loadOrCreate(allocator, io, path);
    defer second.deinit();

    try std.testing.expectEqualStrings(first_text, second.peer_id.toString());
}
