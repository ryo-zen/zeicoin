// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: MIT

const std = @import("std");
const tcp = @import("../transport/tcp.zig");
const inproc = @import("../transport/inproc.zig");
const peer = @import("../peer/peer_id.zig");
const yamux = @import("../muxer/yamux.zig");
const Multiaddr = @import("../multiaddr/multiaddr.zig").Multiaddr;

pub const PROTOCOL_ID = "/noise";
pub const PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const SIGNATURE_PREFIX = "noise-libp2p-static-key:";

const Connection = @import("../transport/connection.zig").Connection;
const IdentityKey = peer.IdentityKey;
const PeerId = peer.PeerId;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const noise_frame_ciphertext_limit: usize = std.math.maxInt(u16);
const noise_frame_plaintext_limit: usize = noise_frame_ciphertext_limit - ChaCha20Poly1305.tag_length;

const KeyPair2 = struct {
    k1: [32]u8,
    k2: [32]u8,
};

pub const HandshakeError = error{
    InvalidFrameLength,
    InvalidMessage,
    InvalidPayload,
    InvalidIdentityKey,
    InvalidIdentitySignature,
    UnexpectedPeerId,
    AuthenticationFailed,
    AuthenticationFailedMessage2Static,
    AuthenticationFailedMessage2Payload,
    AuthenticationFailedMessage3Static,
    AuthenticationFailedMessage3Payload,
    NonceExhausted,
};

pub const HandshakeResult = struct {
    remote_peer_id: PeerId,
    remote_noise_static_key: [32]u8,
    tx_key: [32]u8,
    rx_key: [32]u8,
    session_key_material: [32]u8,
    used_early_yamux: bool,

    pub fn deinit(self: *HandshakeResult) void {
        self.remote_peer_id.deinit();
        std.crypto.secureZero(u8, &self.tx_key);
        std.crypto.secureZero(u8, &self.rx_key);
        std.crypto.secureZero(u8, &self.session_key_material);
    }
};

pub const InitiatorFuture = std.Io.Future(anyerror!HandshakeResult);
pub const ResponderFuture = std.Io.Future(anyerror!HandshakeResult);

const CipherState = struct {
    key: [32]u8,
    nonce: u64 = 0,

    fn encrypt(self: *CipherState, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        if (self.nonce == std.math.maxInt(u64)) return HandshakeError.NonceExhausted;
        const out = try allocator.alloc(u8, plaintext.len + ChaCha20Poly1305.tag_length);
        const n = noiseNonce(self.nonce);
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, "", n, self.key);
        @memcpy(out[plaintext.len..], &tag);
        self.nonce += 1;
        return out;
    }

    fn decrypt(self: *CipherState, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        if (self.nonce == std.math.maxInt(u64)) return HandshakeError.NonceExhausted;
        if (ciphertext.len < ChaCha20Poly1305.tag_length) return HandshakeError.InvalidMessage;

        const ct_len = ciphertext.len - ChaCha20Poly1305.tag_length;
        const out = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(out);

        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        @memcpy(&tag, ciphertext[ct_len..]);
        const n = noiseNonce(self.nonce);
        ChaCha20Poly1305.decrypt(out, ciphertext[0..ct_len], tag, "", n, self.key) catch {
            return HandshakeError.AuthenticationFailed;
        };
        self.nonce += 1;
        return out;
    }

    fn encryptInto(self: *CipherState, plaintext: []const u8, out: []u8) ![]u8 {
        if (self.nonce == std.math.maxInt(u64)) return HandshakeError.NonceExhausted;
        if (out.len < plaintext.len + ChaCha20Poly1305.tag_length) return error.NoSpaceLeft;

        const n = noiseNonce(self.nonce);
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(out[0..plaintext.len], &tag, plaintext, "", n, self.key);
        @memcpy(out[plaintext.len .. plaintext.len + ChaCha20Poly1305.tag_length], &tag);
        self.nonce += 1;
        return out[0 .. plaintext.len + ChaCha20Poly1305.tag_length];
    }

    fn decryptInto(self: *CipherState, ciphertext: []const u8, out: []u8) ![]u8 {
        if (self.nonce == std.math.maxInt(u64)) return HandshakeError.NonceExhausted;
        if (ciphertext.len < ChaCha20Poly1305.tag_length) return HandshakeError.InvalidMessage;

        const ct_len = ciphertext.len - ChaCha20Poly1305.tag_length;
        if (out.len < ct_len) return error.NoSpaceLeft;

        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        @memcpy(&tag, ciphertext[ct_len..]);
        const n = noiseNonce(self.nonce);
        ChaCha20Poly1305.decrypt(out[0..ct_len], ciphertext[0..ct_len], tag, "", n, self.key) catch {
            return HandshakeError.AuthenticationFailed;
        };
        self.nonce += 1;
        return out[0..ct_len];
    }
};

pub const SecureTransport = struct {
    allocator: std.mem.Allocator,
    conn: Connection,
    tx: CipherState,
    rx: CipherState,
    tx_plain: std.array_list.Managed(u8),
    tx_cipher: std.array_list.Managed(u8),
    rx_frame: std.array_list.Managed(u8),
    rx_buffer: std.array_list.Managed(u8),
    rx_offset: usize = 0,
    rx_frame_prealloc_done: bool = false,
    tx_cipher_prealloc_done: bool = false,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        conn: Connection,
        tx_key: [32]u8,
        rx_key: [32]u8,
    ) Self {
        return .{
            .allocator = allocator,
            .conn = conn,
            .tx = .{ .key = tx_key, .nonce = 0 },
            .rx = .{ .key = rx_key, .nonce = 0 },
            .tx_plain = std.array_list.Managed(u8).init(allocator),
            .tx_cipher = std.array_list.Managed(u8).init(allocator),
            .rx_frame = std.array_list.Managed(u8).init(allocator),
            .rx_buffer = std.array_list.Managed(u8).init(allocator),
            .rx_offset = 0,
            .rx_frame_prealloc_done = false,
            .tx_cipher_prealloc_done = false,
        };
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(u8, &self.tx.key);
        std.crypto.secureZero(u8, &self.rx.key);
        self.tx_plain.deinit();
        self.tx_cipher.deinit();
        self.rx_frame.deinit();
        self.rx_buffer.deinit();
    }

    pub fn writeAll(self: *Self, io: std.Io, data: []const u8) !void {
        _ = io;
        var fragments = [_][]const u8{data};
        try self.writeSlices(&fragments);
    }

    pub fn writeVecAll(self: *Self, io: std.Io, fragments: anytype) !void {
        _ = io;
        const Fragments = @TypeOf(fragments.*);
        switch (@typeInfo(Fragments)) {
            .array => {},
            else => @compileError("writeVecAll expects a pointer to an array of byte slices"),
        }
        var vecs = fragments.*;
        try self.writeSlices(&vecs);
    }

    pub fn writeByte(self: *Self, io: std.Io, b: u8) !void {
        const one = [_]u8{b};
        try self.writeAll(io, &one);
    }

    pub fn readSome(self: *Self, io: std.Io, dest: []u8) !usize {
        if (dest.len == 0) return 0;

        if (!self.rx_frame_prealloc_done) {
            try self.rx_frame.ensureTotalCapacity(noise_frame_ciphertext_limit);
            self.rx_frame_prealloc_done = true;
        }

        while (self.rx_offset >= self.rx_buffer.items.len) {
            self.rx_offset = 0;
            try readNoiseFrameInto(&self.rx_frame, self.conn, io);
            try self.rx_buffer.resize(self.rx_frame.items.len - ChaCha20Poly1305.tag_length);
            _ = try self.rx.decryptInto(self.rx_frame.items, self.rx_buffer.items);
        }

        const remaining = self.rx_buffer.items.len - self.rx_offset;
        const n = @min(remaining, dest.len);
        @memcpy(dest[0..n], self.rx_buffer.items[self.rx_offset .. self.rx_offset + n]);
        self.rx_offset += n;
        return n;
    }

    fn writeSlices(self: *Self, fragments: []const []const u8) !void {
        if (!self.tx_cipher_prealloc_done) {
            try self.tx_cipher.ensureTotalCapacity(noise_frame_ciphertext_limit);
            self.tx_cipher_prealloc_done = true;
        }

        var fragment_index: usize = 0;
        var fragment_offset: usize = 0;

        while (fragment_index < fragments.len) {
            const fragment = fragments[fragment_index][fragment_offset..];
            // Fast path: if the next frame can be sourced from a single fragment,
            // encrypt directly from that slice and skip tx_plain assembly.
            if (fragment.len > 0 and (fragment.len >= noise_frame_plaintext_limit or fragment_index + 1 == fragments.len)) {
                const take = @min(fragment.len, noise_frame_plaintext_limit);
                if (self.tx_cipher.capacity < take + ChaCha20Poly1305.tag_length) {
                    try self.tx_cipher.ensureTotalCapacity(take + ChaCha20Poly1305.tag_length);
                }
                self.tx_cipher.items.len = take + ChaCha20Poly1305.tag_length;
                const ciphertext = try self.tx.encryptInto(fragment[0..take], self.tx_cipher.items);
                try writeNoiseFrame(self.conn, ciphertext);
                fragment_offset += take;
                if (fragment_offset == fragments[fragment_index].len) {
                    fragment_index += 1;
                    fragment_offset = 0;
                }
                continue;
            }

            self.tx_plain.clearRetainingCapacity();
            var remaining = noise_frame_plaintext_limit;

            while (fragment_index < fragments.len and remaining > 0) {
                const part = fragments[fragment_index][fragment_offset..];
                if (part.len == 0) {
                    fragment_index += 1;
                    fragment_offset = 0;
                    continue;
                }

                const take = @min(part.len, remaining);
                try self.tx_plain.appendSlice(part[0..take]);
                remaining -= take;
                fragment_offset += take;

                if (fragment_offset == fragments[fragment_index].len) {
                    fragment_index += 1;
                    fragment_offset = 0;
                }
            }

            const out_len = self.tx_plain.items.len + ChaCha20Poly1305.tag_length;
            if (self.tx_cipher.capacity < out_len) {
                try self.tx_cipher.ensureTotalCapacity(out_len);
            }
            self.tx_cipher.items.len = out_len;
            const ciphertext = try self.tx.encryptInto(self.tx_plain.items, self.tx_cipher.items);
            try writeNoiseFrame(self.conn, ciphertext);
        }
    }
};

const SymmetricState = struct {
    ck: [32]u8,
    h: [32]u8,
    k: ?[32]u8 = null,
    n: u64 = 0,

    fn init() SymmetricState {
        var initial: [32]u8 = undefined;
        @memset(&initial, 0);
        if (PROTOCOL_NAME.len <= initial.len) {
            @memcpy(initial[0..PROTOCOL_NAME.len], PROTOCOL_NAME);
        } else {
            std.crypto.hash.sha2.Sha256.hash(PROTOCOL_NAME, &initial, .{});
        }
        return .{
            .ck = initial,
            .h = initial,
            .k = null,
            .n = 0,
        };
    }

    fn mixHash(self: *SymmetricState, data: []const u8) void {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&self.h);
        hasher.update(data);
        hasher.final(&self.h);
    }

    fn mixKey(self: *SymmetricState, ikm: []const u8) void {
        const out = hkdf2(self.ck, ikm);
        self.ck = out.k1;
        self.k = out.k2;
        self.n = 0;
    }

    fn encryptAndHash(self: *SymmetricState, allocator: std.mem.Allocator, plaintext: []const u8) ![]u8 {
        if (self.k == null) {
            const out = try allocator.dupe(u8, plaintext);
            self.mixHash(out);
            return out;
        }

        const key = self.k.?;
        const out = try allocator.alloc(u8, plaintext.len + ChaCha20Poly1305.tag_length);
        const nonce = noiseNonce(self.n);
        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        ChaCha20Poly1305.encrypt(
            out[0..plaintext.len],
            &tag,
            plaintext,
            &self.h,
            nonce,
            key,
        );
        @memcpy(out[plaintext.len..], &tag);
        self.n += 1;
        self.mixHash(out);
        return out;
    }

    fn decryptAndHash(self: *SymmetricState, allocator: std.mem.Allocator, ciphertext: []const u8) ![]u8 {
        if (self.k == null) {
            const out = try allocator.dupe(u8, ciphertext);
            self.mixHash(ciphertext);
            return out;
        }

        if (ciphertext.len < ChaCha20Poly1305.tag_length) return HandshakeError.InvalidMessage;
        const key = self.k.?;
        const ct_len = ciphertext.len - ChaCha20Poly1305.tag_length;
        const out = try allocator.alloc(u8, ct_len);
        errdefer allocator.free(out);

        var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
        @memcpy(&tag, ciphertext[ct_len..]);
        const nonce = noiseNonce(self.n);
        ChaCha20Poly1305.decrypt(
            out,
            ciphertext[0..ct_len],
            tag,
            &self.h,
            nonce,
            key,
        ) catch return HandshakeError.AuthenticationFailed;

        self.n += 1;
        self.mixHash(ciphertext);
        return out;
    }

    fn split(self: *const SymmetricState) KeyPair2 {
        return hkdf2(self.ck, &[_]u8{});
    }
};

pub fn performInitiator(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: Connection,
    local_identity: *const IdentityKey,
    expected_remote_peer_id: ?[]const u8,
) !HandshakeResult {
    var ss = SymmetricState.init();
    ss.mixHash("");

    const ei = std.crypto.dh.X25519.KeyPair.generate(io);
    const si = std.crypto.dh.X25519.KeyPair.generate(io);
    const local_payload = try buildHandshakePayload(allocator, local_identity, si.public_key);
    defer allocator.free(local_payload);

    // XX msg1: -> e
    ss.mixHash(&ei.public_key);
    ss.mixHash("");
    try writeNoiseFrame(conn, &ei.public_key);

    // XX msg2: <- e, ee, s, es, payload
    const m2 = try readNoiseFrame(allocator, conn);
    defer allocator.free(m2);
    if (m2.len < 32 + 48 + 16) return HandshakeError.InvalidMessage;

    var re_pub: [32]u8 = undefined;
    @memcpy(&re_pub, m2[0..32]);
    ss.mixHash(&re_pub);

    const dh_ee = try std.crypto.dh.X25519.scalarmult(ei.secret_key, re_pub);
    ss.mixKey(&dh_ee);

    const enc_rs = m2[32 .. 32 + 48];
    const rs_plain = ss.decryptAndHash(allocator, enc_rs) catch |err| switch (err) {
        HandshakeError.AuthenticationFailed => return HandshakeError.AuthenticationFailedMessage2Static,
        else => return err,
    };
    defer allocator.free(rs_plain);
    if (rs_plain.len != 32) return HandshakeError.InvalidMessage;

    var rs_pub: [32]u8 = undefined;
    @memcpy(&rs_pub, rs_plain[0..32]);

    const dh_es = try std.crypto.dh.X25519.scalarmult(ei.secret_key, rs_pub);
    ss.mixKey(&dh_es);

    const payload2_ct = m2[32 + 48 ..];
    const payload2 = ss.decryptAndHash(allocator, payload2_ct) catch |err| switch (err) {
        HandshakeError.AuthenticationFailed => return HandshakeError.AuthenticationFailedMessage2Payload,
        else => return err,
    };
    defer allocator.free(payload2);

    const remote_payload = try validateRemotePayload(
        allocator,
        payload2,
        rs_pub,
        expected_remote_peer_id,
    );
    var remote_peer_id = remote_payload.peer_id;
    errdefer remote_peer_id.deinit();

    // XX msg3: -> s, se, payload
    const enc_si = try ss.encryptAndHash(allocator, &si.public_key);
    defer allocator.free(enc_si);

    const dh_se = try std.crypto.dh.X25519.scalarmult(si.secret_key, re_pub);
    ss.mixKey(&dh_se);

    const payload3_ct = try ss.encryptAndHash(allocator, local_payload);
    defer allocator.free(payload3_ct);

    const m3 = try allocator.alloc(u8, enc_si.len + payload3_ct.len);
    defer allocator.free(m3);
    @memcpy(m3[0..enc_si.len], enc_si);
    @memcpy(m3[enc_si.len..], payload3_ct);
    try writeNoiseFrame(conn, m3);

    const keys = ss.split();
    var material_input: [64]u8 = undefined;
    @memcpy(material_input[0..32], &keys.k1);
    @memcpy(material_input[32..64], &keys.k2);
    var session_material: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material_input, &session_material, .{});
    std.crypto.secureZero(u8, &material_input);

    return .{
        .remote_peer_id = remote_peer_id,
        .remote_noise_static_key = rs_pub,
        .tx_key = keys.k1,
        .rx_key = keys.k2,
        .session_key_material = session_material,
        .used_early_yamux = remote_payload.supports_yamux,
    };
}

pub fn performInitiatorConcurrent(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: Connection,
    local_identity: *const IdentityKey,
    expected_remote_peer_id: ?[]const u8,
) std.Io.ConcurrentError!InitiatorFuture {
    return io.concurrent(performInitiatorTaskMain, .{
        allocator,
        io,
        conn,
        local_identity,
        expected_remote_peer_id,
    });
}

pub fn performResponder(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: Connection,
    local_identity: *const IdentityKey,
    expected_remote_peer_id: ?[]const u8,
) !HandshakeResult {
    var ss = SymmetricState.init();
    ss.mixHash("");

    // XX msg1: <- e
    const m1 = try readNoiseFrame(allocator, conn);
    defer allocator.free(m1);
    if (m1.len != 32) return HandshakeError.InvalidMessage;

    var ei_pub: [32]u8 = undefined;
    @memcpy(&ei_pub, m1[0..32]);
    ss.mixHash(&ei_pub);
    ss.mixHash("");

    const er = std.crypto.dh.X25519.KeyPair.generate(io);
    const sr = std.crypto.dh.X25519.KeyPair.generate(io);
    const local_payload = try buildHandshakePayload(allocator, local_identity, sr.public_key);
    defer allocator.free(local_payload);

    // XX msg2: -> e, ee, s, es, payload
    ss.mixHash(&er.public_key);

    const dh_ee = try std.crypto.dh.X25519.scalarmult(er.secret_key, ei_pub);
    ss.mixKey(&dh_ee);

    const enc_sr = try ss.encryptAndHash(allocator, &sr.public_key);
    defer allocator.free(enc_sr);

    const dh_es = try std.crypto.dh.X25519.scalarmult(sr.secret_key, ei_pub);
    ss.mixKey(&dh_es);

    const payload2_ct = try ss.encryptAndHash(allocator, local_payload);
    defer allocator.free(payload2_ct);

    const m2 = try allocator.alloc(u8, 32 + enc_sr.len + payload2_ct.len);
    defer allocator.free(m2);
    @memcpy(m2[0..32], &er.public_key);
    @memcpy(m2[32 .. 32 + enc_sr.len], enc_sr);
    @memcpy(m2[32 + enc_sr.len ..], payload2_ct);
    try writeNoiseFrame(conn, m2);

    // XX msg3: <- s, se, payload
    const m3 = try readNoiseFrame(allocator, conn);
    defer allocator.free(m3);
    if (m3.len < 48 + 16) return HandshakeError.InvalidMessage;

    const enc_si = m3[0..48];
    const si_plain = ss.decryptAndHash(allocator, enc_si) catch |err| switch (err) {
        HandshakeError.AuthenticationFailed => return HandshakeError.AuthenticationFailedMessage3Static,
        else => return err,
    };
    defer allocator.free(si_plain);
    if (si_plain.len != 32) return HandshakeError.InvalidMessage;

    var si_pub: [32]u8 = undefined;
    @memcpy(&si_pub, si_plain[0..32]);

    const dh_se = try std.crypto.dh.X25519.scalarmult(er.secret_key, si_pub);
    ss.mixKey(&dh_se);

    const payload3_ct = m3[48..];
    const payload3 = ss.decryptAndHash(allocator, payload3_ct) catch |err| switch (err) {
        HandshakeError.AuthenticationFailed => return HandshakeError.AuthenticationFailedMessage3Payload,
        else => return err,
    };
    defer allocator.free(payload3);

    const remote_payload = try validateRemotePayload(
        allocator,
        payload3,
        si_pub,
        expected_remote_peer_id,
    );
    var remote_peer_id = remote_payload.peer_id;
    errdefer remote_peer_id.deinit();

    const keys = ss.split();
    var material_input: [64]u8 = undefined;
    @memcpy(material_input[0..32], &keys.k1);
    @memcpy(material_input[32..64], &keys.k2);
    var session_material: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&material_input, &session_material, .{});
    std.crypto.secureZero(u8, &material_input);

    return .{
        .remote_peer_id = remote_peer_id,
        .remote_noise_static_key = si_pub,
        .tx_key = keys.k2,
        .rx_key = keys.k1,
        .session_key_material = session_material,
        .used_early_yamux = remote_payload.supports_yamux,
    };
}

pub fn performResponderConcurrent(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: Connection,
    local_identity: *const IdentityKey,
    expected_remote_peer_id: ?[]const u8,
) std.Io.ConcurrentError!ResponderFuture {
    return io.concurrent(performResponderTaskMain, .{
        allocator,
        io,
        conn,
        local_identity,
        expected_remote_peer_id,
    });
}

fn performInitiatorTaskMain(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: Connection,
    local_identity: *const IdentityKey,
    expected_remote_peer_id: ?[]const u8,
) anyerror!HandshakeResult {
    return performInitiator(allocator, io, conn, local_identity, expected_remote_peer_id);
}

fn performResponderTaskMain(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: Connection,
    local_identity: *const IdentityKey,
    expected_remote_peer_id: ?[]const u8,
) anyerror!HandshakeResult {
    return performResponder(allocator, io, conn, local_identity, expected_remote_peer_id);
}

fn hkdf2(ck: [32]u8, ikm: []const u8) KeyPair2 {
    const prk = HkdfSha256.extract(&ck, ikm);
    var out: [64]u8 = undefined;
    HkdfSha256.expand(&out, "", prk);

    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    @memcpy(&k1, out[0..32]);
    @memcpy(&k2, out[32..64]);
    std.crypto.secureZero(u8, &out);
    return .{ .k1 = k1, .k2 = k2 };
}

fn noiseNonce(n: u64) [12]u8 {
    var nonce = [_]u8{0} ** 12;
    std.mem.writeInt(u64, nonce[4..12], n, .little);
    return nonce;
}

fn buildHandshakePayload(
    allocator: std.mem.Allocator,
    identity: *const IdentityKey,
    local_noise_static_pub: [32]u8,
) ![]u8 {
    const identity_key = encodeIdentityPublicKey(identity.public_key);
    const identity_sig = try signNoiseStaticKey(identity.private_key, local_noise_static_pub);
    const stream_muxer = yamux.PROTOCOL_ID;

    const len1 = varintLen(identity_key.len);
    const len2 = varintLen(identity_sig.len);
    const ext_payload_len = 1 + varintLen(stream_muxer.len) + stream_muxer.len;
    const total = 1 + len1 + identity_key.len + 1 + len2 + identity_sig.len + 1 + varintLen(ext_payload_len) + ext_payload_len;
    const out = try allocator.alloc(u8, total);

    var off: usize = 0;
    out[off] = 0x0A; // field 1, bytes
    off += 1;
    off += writeVarint(out[off..], identity_key.len);
    @memcpy(out[off .. off + identity_key.len], &identity_key);
    off += identity_key.len;

    out[off] = 0x12; // field 2, bytes
    off += 1;
    off += writeVarint(out[off..], identity_sig.len);
    @memcpy(out[off .. off + identity_sig.len], &identity_sig);
    off += identity_sig.len;

    out[off] = 0x22; // field 4, bytes (extensions)
    off += 1;
    off += writeVarint(out[off..], ext_payload_len);
    out[off] = 0x12; // extensions field 2, bytes (stream_muxers)
    off += 1;
    off += writeVarint(out[off..], stream_muxer.len);
    @memcpy(out[off .. off + stream_muxer.len], stream_muxer);

    return out;
}

const ValidatedRemotePayload = struct {
    peer_id: PeerId,
    supports_yamux: bool,
};

fn validateRemotePayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
    remote_noise_static_pub: [32]u8,
    expected_remote_peer_id: ?[]const u8,
) !ValidatedRemotePayload {
    const decoded = try decodeHandshakePayload(payload);
    const key_type = decoded.identity_key[1];
    if (decoded.identity_key.len != 36 or decoded.identity_key[0] != 0x08 or key_type != 1) {
        return HandshakeError.InvalidIdentityKey;
    }
    if (decoded.identity_key[2] != 0x12 or decoded.identity_key[3] != 0x20) {
        return HandshakeError.InvalidIdentityKey;
    }
    if (decoded.identity_sig.len != 64) return HandshakeError.InvalidIdentitySignature;

    var remote_pub: [32]u8 = undefined;
    @memcpy(&remote_pub, decoded.identity_key[4..36]);
    try verifyNoiseStaticSignature(remote_pub, remote_noise_static_pub, decoded.identity_sig);

    var remote_peer_id = try PeerId.fromEncodedPublicKey(allocator, decoded.identity_key);
    errdefer remote_peer_id.deinit();
    if (expected_remote_peer_id) |expected| {
        if (!std.mem.eql(u8, expected, remote_peer_id.toString())) {
            return HandshakeError.UnexpectedPeerId;
        }
    }
    return .{
        .peer_id = remote_peer_id,
        .supports_yamux = decoded.supports_yamux,
    };
}

const DecodedPayload = struct {
    identity_key: []const u8,
    identity_sig: []const u8,
    supports_yamux: bool,
};

fn decodeHandshakePayload(payload: []const u8) !DecodedPayload {
    var off: usize = 0;
    var out: DecodedPayload = .{
        .identity_key = "",
        .identity_sig = "",
        .supports_yamux = false,
    };

    while (off < payload.len) {
        const tag = payload[off];
        off += 1;
        const field_len = try readVarint(payload, &off);
        if (off + field_len > payload.len) return HandshakeError.InvalidPayload;
        const value = payload[off .. off + field_len];
        off += field_len;

        switch (tag) {
            0x0A => out.identity_key = value,
            0x12 => out.identity_sig = value,
            0x22 => out.supports_yamux = try decodeNoiseExtensions(value),
            else => {}, // ignore unknown fields
        }
    }

    if (out.identity_key.len == 0 or out.identity_sig.len == 0) {
        return HandshakeError.InvalidPayload;
    }
    return out;
}

fn decodeNoiseExtensions(payload: []const u8) !bool {
    var off: usize = 0;
    var supports_yamux = false;

    while (off < payload.len) {
        const tag = payload[off];
        off += 1;
        const field_len = try readVarint(payload, &off);
        if (off + field_len > payload.len) return HandshakeError.InvalidPayload;
        const value = payload[off .. off + field_len];
        off += field_len;

        if (tag == 0x12 and std.mem.eql(u8, value, yamux.PROTOCOL_ID)) {
            supports_yamux = true;
        }
    }

    return supports_yamux;
}

fn encodeIdentityPublicKey(public_key: [32]u8) [36]u8 {
    var out: [36]u8 = undefined;
    out[0] = 0x08; // field 1 varint
    out[1] = 0x01; // Ed25519
    out[2] = 0x12; // field 2 bytes
    out[3] = 0x20; // 32-byte key
    @memcpy(out[4..], &public_key);
    return out;
}

fn signNoiseStaticKey(identity_private_key: [64]u8, noise_static_pub: [32]u8) ![64]u8 {
    var data: [SIGNATURE_PREFIX.len + 32]u8 = undefined;
    @memcpy(data[0..SIGNATURE_PREFIX.len], SIGNATURE_PREFIX);
    @memcpy(data[SIGNATURE_PREFIX.len..], &noise_static_pub);

    const secret = try std.crypto.sign.Ed25519.SecretKey.fromBytes(identity_private_key);
    const kp = try std.crypto.sign.Ed25519.KeyPair.fromSecretKey(secret);
    const sig = try kp.sign(&data, null);
    return sig.toBytes();
}

fn verifyNoiseStaticSignature(
    identity_public_key: [32]u8,
    noise_static_pub: [32]u8,
    signature: []const u8,
) !void {
    if (signature.len != 64) return HandshakeError.InvalidIdentitySignature;
    var data: [SIGNATURE_PREFIX.len + 32]u8 = undefined;
    @memcpy(data[0..SIGNATURE_PREFIX.len], SIGNATURE_PREFIX);
    @memcpy(data[SIGNATURE_PREFIX.len..], &noise_static_pub);

    const pubkey = std.crypto.sign.Ed25519.PublicKey.fromBytes(identity_public_key) catch {
        return HandshakeError.InvalidIdentityKey;
    };
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, signature[0..64]);
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(&data, pubkey) catch return HandshakeError.InvalidIdentitySignature;
}

fn writeNoiseFrame(conn: Connection, payload: []const u8) !void {
    if (payload.len > std.math.maxInt(u16)) return HandshakeError.InvalidFrameLength;
    var len_prefix: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_prefix, @intCast(payload.len), .big);
    var fragments = [_][]const u8{ &len_prefix, payload };
    try conn.writeVecAll(&fragments);
}

fn readNoiseFrame(allocator: std.mem.Allocator, conn: Connection) ![]u8 {
    var len_prefix: [2]u8 = undefined;
    try readNoEof(conn, &len_prefix);
    const frame_len = std.mem.readInt(u16, &len_prefix, .big);
    const out = try allocator.alloc(u8, frame_len);
    errdefer allocator.free(out);
    try readNoEof(conn, out);
    return out;
}

fn readNoiseFrameInto(buffer: *std.array_list.Managed(u8), conn: Connection, io: std.Io) !void {
    _ = io;
    var len_prefix: [2]u8 = undefined;
    try readNoEof(conn, &len_prefix);
    const frame_len = std.mem.readInt(u16, &len_prefix, .big);
    if (buffer.capacity < frame_len) {
        try buffer.ensureTotalCapacity(frame_len);
    }
    buffer.items.len = frame_len;
    try readNoEof(conn, buffer.items);
}

fn readNoEof(conn: Connection, dest: []u8) !void {
    var off: usize = 0;
    while (off < dest.len) {
        const n = try conn.readSome(dest[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
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

test "noise handshake payload encode/decode and signature validation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var identity = try IdentityKey.generate(allocator, io);
    defer identity.deinit();

    const static_noise = std.crypto.dh.X25519.KeyPair.generate(io);
    const encoded = try buildHandshakePayload(allocator, &identity, static_noise.public_key);
    defer allocator.free(encoded);

    const decoded = try decodeHandshakePayload(encoded);
    try std.testing.expect(decoded.identity_key.len == 36);
    try std.testing.expect(decoded.identity_sig.len == 64);

    var remote_payload = try validateRemotePayload(allocator, encoded, static_noise.public_key, null);
    defer remote_payload.peer_id.deinit();
    try std.testing.expect(remote_payload.supports_yamux);
    try std.testing.expectEqualStrings(identity.peer_id.toString(), remote_payload.peer_id.toString());
}

test "symmetricstate encrypt/decrypt roundtrip" {
    const allocator = std.testing.allocator;
    var a = SymmetricState.init();
    var b = SymmetricState.init();

    const ikm = [_]u8{0x42} ** 32;
    a.mixKey(&ikm);
    b.mixKey(&ikm);
    try std.testing.expect(a.k != null and b.k != null);

    const pt = "hello-noise";
    const ct = try a.encryptAndHash(allocator, pt);
    defer allocator.free(ct);
    const rt = try b.decryptAndHash(allocator, ct);
    defer allocator.free(rt);

    try std.testing.expectEqualStrings(pt, rt);
    try std.testing.expectEqualSlices(u8, &a.h, &b.h);
}

test "noise XX matches official flynn vector through responder message 2" {
    const fmt = std.fmt;

    var init_seed: [32]u8 = undefined;
    var resp_seed: [32]u8 = undefined;
    var init_e_seed: [32]u8 = undefined;
    var resp_e_seed: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&init_seed, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    _ = try fmt.hexToBytes(&resp_seed, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    _ = try fmt.hexToBytes(&init_e_seed, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    _ = try fmt.hexToBytes(&resp_e_seed, "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60");

    _ = try std.crypto.dh.X25519.KeyPair.generateDeterministic(init_seed);
    const resp_static = try std.crypto.dh.X25519.KeyPair.generateDeterministic(resp_seed);
    const init_e = try std.crypto.dh.X25519.KeyPair.generateDeterministic(init_e_seed);
    const resp_e = try std.crypto.dh.X25519.KeyPair.generateDeterministic(resp_e_seed);

    var responder_ss = SymmetricState.init();
    responder_ss.mixHash("");
    responder_ss.mixHash(&init_e.public_key);
    responder_ss.mixHash("");

    var msg0_hex: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
        try fmt.bufPrint(&msg0_hex, "{x}", .{init_e.public_key}),
    );

    responder_ss.mixHash(&resp_e.public_key);

    const dh_ee = try std.crypto.dh.X25519.scalarmult(resp_e.secret_key, init_e.public_key);
    responder_ss.mixKey(&dh_ee);

    const allocator = std.testing.allocator;
    const enc_rs = try responder_ss.encryptAndHash(allocator, &resp_static.public_key);
    defer allocator.free(enc_rs);

    const dh_es = try std.crypto.dh.X25519.scalarmult(resp_static.secret_key, init_e.public_key);
    responder_ss.mixKey(&dh_es);

    const payload2 = try responder_ss.encryptAndHash(allocator, "");
    defer allocator.free(payload2);

    const msg2 = try allocator.alloc(u8, 32 + enc_rs.len + payload2.len);
    defer allocator.free(msg2);
    @memcpy(msg2[0..32], &resp_e.public_key);
    @memcpy(msg2[32 .. 32 + enc_rs.len], enc_rs);
    @memcpy(msg2[32 + enc_rs.len ..], payload2);

    var msg2_hex: [192]u8 = undefined;
    try std.testing.expectEqualStrings(
        "64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484663414af878d3e46a2f58911a816d6e8346d4ea17a6f2a0bb4ef4ed56c133cff4560a34e36ea82109f26cf2e5a5caf992b608d55c747f615e5a3425a7a19eefb8f",
        try fmt.bufPrint(&msg2_hex, "{x}", .{msg2}),
    );

    var initiator_ss = SymmetricState.init();
    initiator_ss.mixHash("");
    initiator_ss.mixHash(&init_e.public_key);
    initiator_ss.mixHash("");
    initiator_ss.mixHash(&resp_e.public_key);
    const init_dh_ee = try std.crypto.dh.X25519.scalarmult(init_e.secret_key, resp_e.public_key);
    initiator_ss.mixKey(&init_dh_ee);

    const dec_rs = try initiator_ss.decryptAndHash(allocator, msg2[32 .. 32 + 48]);
    defer allocator.free(dec_rs);
    try std.testing.expectEqualSlices(u8, &resp_static.public_key, dec_rs);

    const init_dh_es = try std.crypto.dh.X25519.scalarmult(init_e.secret_key, resp_static.public_key);
    initiator_ss.mixKey(&init_dh_es);

    const dec_payload2 = try initiator_ss.decryptAndHash(allocator, msg2[32 + 48 ..]);
    defer allocator.free(dec_payload2);
    try std.testing.expectEqual(@as(usize, 0), dec_payload2.len);
}

test "noise concurrent handshake helpers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var initiator_identity = try IdentityKey.generate(allocator, io);
    defer initiator_identity.deinit();
    var responder_identity = try IdentityKey.generate(allocator, io);
    defer responder_identity.deinit();

    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();

    var responder_future = try performResponderConcurrent(
        allocator,
        io,
        responder_conn.connection(),
        &responder_identity,
        initiator_identity.peer_id.toString(),
    );
    defer _ = responder_future.cancel(io) catch {};

    var initiator_future = try performInitiatorConcurrent(
        allocator,
        io,
        initiator_conn.connection(),
        &initiator_identity,
        responder_identity.peer_id.toString(),
    );
    defer _ = initiator_future.cancel(io) catch {};

    var initiator_result = try initiator_future.await(io);
    defer initiator_result.deinit();
    var responder_result = try responder_future.await(io);
    defer responder_result.deinit();

    try std.testing.expectEqualStrings(responder_identity.peer_id.toString(), initiator_result.remote_peer_id.toString());
    try std.testing.expectEqualStrings(initiator_identity.peer_id.toString(), responder_result.remote_peer_id.toString());
    try std.testing.expectEqualSlices(u8, &initiator_result.tx_key, &responder_result.rx_key);
    try std.testing.expectEqualSlices(u8, &initiator_result.rx_key, &responder_result.tx_key);
}

test "noise wrong peer id is rejected during handshake" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var conn_pair = try inproc.InProcConnection.initPair(allocator, io);
    var initiator_conn = conn_pair.initiator;
    defer initiator_conn.deinit();
    var responder_conn = conn_pair.responder;
    defer responder_conn.deinit();

    var initiator_identity = try IdentityKey.generate(allocator, io);
    defer initiator_identity.deinit();
    var responder_identity = try IdentityKey.generate(allocator, io);
    defer responder_identity.deinit();
    var unrelated_identity = try IdentityKey.generate(allocator, io);
    defer unrelated_identity.deinit();

    const RespCtx = struct {
        conn: *inproc.InProcConnection,
        allocator: std.mem.Allocator,
        io: std.Io,
        identity: *IdentityKey,

        fn run(ctx: *@This()) anyerror!HandshakeResult {
            return performResponder(ctx.allocator, ctx.io, ctx.conn.connection(), ctx.identity, null);
        }
    };
    var resp_ctx = RespCtx{ .conn = &responder_conn, .allocator = allocator, .io = io, .identity = &responder_identity };
    var resp_future = try io.concurrent(RespCtx.run, .{&resp_ctx});

    // Initiator presents an expected peer ID that does not match the responder's.
    const init_result = performInitiator(allocator, io, initiator_conn.connection(), &initiator_identity, unrelated_identity.peer_id.toString());
    try std.testing.expectError(HandshakeError.UnexpectedPeerId, init_result);

    // Signal the responder that the connection is gone so it can exit cleanly.
    try initiator_conn.close(io);
    _ = resp_future.await(io) catch {};
}

test "noise cipher nonce exhaustion is rejected" {
    const allocator = std.testing.allocator;

    const key = [_]u8{0x42} ** 32;

    // Encrypt at the nonce boundary — should fail before attempting AEAD.
    var enc = CipherState{ .key = key, .nonce = std.math.maxInt(u64) };
    try std.testing.expectError(HandshakeError.NonceExhausted, enc.encrypt(allocator, "test"));

    // Decrypt at the nonce boundary — same guard.
    var dec = CipherState{ .key = key, .nonce = std.math.maxInt(u64) };
    const dummy_ct = [_]u8{0} ** (4 + ChaCha20Poly1305.tag_length);
    try std.testing.expectError(HandshakeError.NonceExhausted, dec.decrypt(allocator, &dummy_ct));
}
