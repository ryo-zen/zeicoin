// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// bootstrap.zig - Bootstrap node configuration using libp2p multiaddr
// Replaces the legacy ip:port format with /ip4/x.x.x.x/tcp/port(/p2p/<peer-id>)

const std = @import("std");
const libp2p = @import("libp2p");
const types = @import("../types/types.zig");

const log = std.log.scoped(.bootstrap);

// Hardcoded fallback bootstrap nodes per network.
// Selected by CURRENT_NETWORK at runtime.
const TESTNET_NODES = [_][]const u8{
    "/ip4/209.38.84.23/tcp/10801",
};
const MAINNET_NODES = [_][]const u8{};

pub const BootstrapAddr = struct {
    multiaddr: libp2p.Multiaddr,

    pub fn deinit(self: *BootstrapAddr) void {
        self.multiaddr.deinit();
    }

    pub fn tcpAddress(self: *const BootstrapAddr) ?std.Io.net.IpAddress {
        return self.multiaddr.getTcpAddress();
    }

    pub fn peerId(self: *const BootstrapAddr) ?[]const u8 {
        return self.multiaddr.getPeerId();
    }

    /// Return an independent copy. Caller owns the result; call deinit() on it.
    pub fn clone(self: *const BootstrapAddr, allocator: std.mem.Allocator) !BootstrapAddr {
        const ma = try libp2p.Multiaddr.create(allocator, self.multiaddr.getStringAddress());
        return .{ .multiaddr = ma };
    }
};

/// Free a slice returned by parseList, hardcodedNodes, or resolveBootstrapNodes.
pub fn freeList(allocator: std.mem.Allocator, nodes: []const BootstrapAddr) void {
    for (nodes) |*node| @constCast(node).deinit();
    allocator.free(nodes);
}

/// Parse comma-separated multiaddr strings from ZEICOIN_BOOTSTRAP env var value.
/// Legacy ip:port entries are logged with a migration hint and skipped.
/// Returns an owned slice — caller must call freeList.
pub fn parseList(allocator: std.mem.Allocator, input: []const u8) ![]BootstrapAddr {
    var list = std.array_list.Managed(BootstrapAddr).init(allocator);
    errdefer {
        for (list.items) |*n| n.deinit();
        list.deinit();
    }

    var iter = std.mem.tokenizeScalar(u8, input, ',');
    while (iter.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (token.len == 0) continue;

        if (!std.mem.startsWith(u8, token, "/")) {
            // Legacy ip:port format — reject with migration hint.
            var it = std.mem.tokenizeScalar(u8, token, ':');
            const ip = it.next() orelse token;
            log.err(
                "Bootstrap node '{s}' uses legacy ip:port format. " ++
                    "Migrate to: /ip4/{s}/tcp/<port>",
                .{ token, ip },
            );
            continue;
        }

        var ma = libp2p.Multiaddr.create(allocator, token) catch |err| {
            log.warn("Skipping invalid bootstrap multiaddr '{s}': {}", .{ token, err });
            continue;
        };
        errdefer ma.deinit();

        if (!isSupportedBootstrapMultiaddr(&ma)) {
            log.warn("Skipping bootstrap multiaddr '{s}': no TCP address component", .{token});
            ma.deinit();
            continue;
        }

        try list.append(.{ .multiaddr = ma });
    }

    return list.toOwnedSlice();
}

/// Return the hardcoded fallback list for CURRENT_NETWORK.
/// Caller must call freeList on the result.
pub fn hardcodedNodes(allocator: std.mem.Allocator) ![]BootstrapAddr {
    const strs: []const []const u8 = switch (types.CURRENT_NETWORK) {
        .testnet => &TESTNET_NODES,
        .mainnet => &MAINNET_NODES,
    };
    return parseStrings(allocator, strs);
}

/// Main entry point for initialization.zig.
/// If from_cli is non-empty (set from --bootstrap or ZEICOIN_BOOTSTRAP by command_line.zig),
/// returns a clone of it. If bootstrap was explicitly configured but the list is
/// empty, returns an empty list so nodes can opt out of the hardcoded fallback.
/// Otherwise returns the hardcoded fallback list.
/// Caller must call freeList on the result.
pub fn resolveBootstrapNodes(
    allocator: std.mem.Allocator,
    from_cli: []const BootstrapAddr,
    was_configured: bool,
) ![]BootstrapAddr {
    if (from_cli.len > 0) return cloneList(allocator, from_cli);
    if (was_configured) return allocator.dupe(BootstrapAddr, &.{});
    return hardcodedNodes(allocator);
}

// --- Private helpers ---

fn parseStrings(allocator: std.mem.Allocator, strs: []const []const u8) ![]BootstrapAddr {
    var list = std.array_list.Managed(BootstrapAddr).init(allocator);
    errdefer {
        for (list.items) |*n| n.deinit();
        list.deinit();
    }
    for (strs) |str| {
        var ma = try libp2p.Multiaddr.create(allocator, str);
        errdefer ma.deinit();
        try list.append(.{ .multiaddr = ma });
    }
    return list.toOwnedSlice();
}

fn isSupportedBootstrapMultiaddr(ma: *const libp2p.Multiaddr) bool {
    if (!ma.hasProtocol(.tcp)) return false;
    return ma.hasProtocol(.ip4) or
        ma.hasProtocol(.ip6) or
        ma.hasProtocol(.dns) or
        ma.hasProtocol(.dns4) or
        ma.hasProtocol(.dns6) or
        ma.hasProtocol(.dns_addr);
}

/// Return an independent copy of a slice. Caller must call freeList on the result.
pub fn cloneList(allocator: std.mem.Allocator, nodes: []const BootstrapAddr) ![]BootstrapAddr {
    var list = std.array_list.Managed(BootstrapAddr).init(allocator);
    errdefer {
        for (list.items) |*n| n.deinit();
        list.deinit();
    }
    for (nodes) |*node| {
        var copy = try node.clone(allocator);
        errdefer copy.deinit();
        try list.append(copy);
    }
    return list.toOwnedSlice();
}

// --- Tests ---

test "valid multiaddr without peer ID" {
    const allocator = std.testing.allocator;
    const nodes = try parseList(allocator, "/ip4/1.2.3.4/tcp/10801");
    defer freeList(allocator, nodes);

    try std.testing.expectEqual(@as(usize, 1), nodes.len);
    try std.testing.expect(nodes[0].tcpAddress() != null);
    try std.testing.expect(nodes[0].peerId() == null);
}

test "valid multiaddr with peer ID" {
    const allocator = std.testing.allocator;
    // A minimal valid peer ID base58 string (26 bytes, sha256 multihash of empty key)
    const nodes = try parseList(
        allocator,
        "/ip4/1.2.3.4/tcp/10801/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwnfma1vAPLMkPpxZe",
    );
    defer freeList(allocator, nodes);

    try std.testing.expectEqual(@as(usize, 1), nodes.len);
    try std.testing.expect(nodes[0].peerId() != null);
}

test "valid ipv6 and dns bootstrap multiaddrs" {
    const allocator = std.testing.allocator;
    const nodes = try parseList(
        allocator,
        "/ip6/2001:db8::1/tcp/10801,/dns4/bootstrap.example.com/tcp/10801",
    );
    defer freeList(allocator, nodes);

    try std.testing.expectEqual(@as(usize, 2), nodes.len);
}

test "legacy ip:port format is skipped" {
    const allocator = std.testing.allocator;
    const nodes = try parseList(allocator, "1.2.3.4:10801");
    defer freeList(allocator, nodes);

    try std.testing.expectEqual(@as(usize, 0), nodes.len);
}

test "comma-separated list" {
    const allocator = std.testing.allocator;
    const nodes = try parseList(
        allocator,
        "/ip4/1.2.3.4/tcp/10801,/ip4/5.6.7.8/tcp/10801",
    );
    defer freeList(allocator, nodes);

    try std.testing.expectEqual(@as(usize, 2), nodes.len);
}

test "invalid multiaddr string is skipped" {
    const allocator = std.testing.allocator;
    const nodes = try parseList(allocator, "/notaprotocol/garbage");
    defer freeList(allocator, nodes);

    try std.testing.expectEqual(@as(usize, 0), nodes.len);
}

test "hardcodedNodes testnet has at least one entry" {
    const allocator = std.testing.allocator;
    const nodes = try hardcodedNodes(allocator);
    defer freeList(allocator, nodes);

    try std.testing.expect(nodes.len >= 1);
}
