// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// ip_detection.zig - Public IP detection utilities
// Provides methods to detect the node's public IP address using system interfaces

const std = @import("std");
const net = std.Io.net;
const posix = std.posix;

pub const Reachability = enum {
    unknown,
    private,
    public,
};

/// Detect our public IP address by checking which interface routes to the internet
/// NOTE: Requires io parameter in Zig 0.16
pub fn detectPublicIP(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    // Method 1: Connect to a well-known address and check our local socket address
    // This tells us which interface/IP we use to reach the internet
    // Using Cloudflare DNS (1.1.1.1:53)
    const remote_addr = try net.IpAddress.parse("1.1.1.1", 53);

    // Connect using Io.net API (IpAddress.connect returns Stream)
    const conn = remote_addr.connect(io, .{ .mode = .stream }) catch return error.IPDetectionFailed;
    defer conn.close(io);

    // Get our local address from the connected socket
    // Socket.address contains the local address after connecting
    const local_address = conn.socket.address;

    // Extract IP string from the IpAddress
    const ip_str = switch (local_address) {
        .ip4 => |ip4| try std.fmt.allocPrint(allocator, "{}.{}.{}.{}", .{
            ip4.bytes[0],
            ip4.bytes[1],
            ip4.bytes[2],
            ip4.bytes[3],
        }),
        .ip6 => return error.IPv6NotSupported, // For now, only handle IPv4
    };

    std.log.debug("Detected outbound IP via Cloudflare DNS: {s}", .{ip_str});

    // Check if this looks like a private IP - if so, we're behind NAT
    if (isPrivateIP(ip_str)) {
        std.log.debug("Detected private IP {s} - node is behind NAT", .{ip_str});
        // For local development, this is fine. In production, you'd need port forwarding
        // or UPnP to get the actual public IP, but for self-connection prevention,
        // the private IP is sufficient since peers will use public IPs
    }

    return ip_str;
}

pub fn detectOutboundReachability(allocator: std.mem.Allocator, io: std.Io) !Reachability {
    const ip = try detectPublicIP(allocator, io);
    defer allocator.free(ip);
    return reachabilityFromIpString(ip);
}

pub fn classifyLocalReachability(allocator: std.mem.Allocator, io: std.Io, bind_addr: net.IpAddress) Reachability {
    return switch (explicitBindReachability(bind_addr)) {
        .unknown => detectOutboundReachability(allocator, io) catch .unknown,
        .private => .private,
        .public => .public,
    };
}

pub fn explicitBindReachability(bind_addr: net.IpAddress) Reachability {
    return switch (bind_addr) {
        .ip4 => |ip4| reachabilityFromIpv4Bytes(ip4.bytes),
        .ip6 => |ip6| reachabilityFromIpv6Bytes(ip6.bytes),
    };
}

pub fn reachabilityFromIpString(ip_str: []const u8) Reachability {
    return if (isPrivateIP(ip_str)) .private else .public;
}

/// Check if an IP address is in private address ranges
fn isPrivateIP(ip_str: []const u8) bool {
    const octets = parseIpv4Octets(ip_str) orelse return false;
    return reachabilityFromIpv4Bytes(octets) == .private;
}

/// Check if an address is a self-connection by comparing with our public IP
/// NOTE: Requires io parameter in Zig 0.16
pub fn isSelfConnection(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress) bool {
    // Get our public IP
    const public_ip = detectPublicIP(allocator, io) catch |err| {
        std.log.warn("⚠️  Failed to detect public IP: {}, allowing connection", .{err});
        return false;
    };
    defer allocator.free(public_ip);
    
    // Parse target IP from address
    const target_ip = switch (address) {
        .ip4 => |ip4| blk: {
            var buf: [16]u8 = undefined;
            break :blk std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
                ip4.bytes[0],
                ip4.bytes[1],
                ip4.bytes[2],
                ip4.bytes[3],
            }) catch return false;
        },
        else => return false,
    };
    
    std.log.debug("🔍 Self-connection check: target={s}, our_public_ip={s}", .{ target_ip, public_ip });
    
    // Compare IPs
    const is_self = std.mem.eql(u8, public_ip, target_ip);
    if (is_self) {
        std.log.info("🔍 Self-connection detected: {} matches our public IP {s}", .{ address, public_ip });
    }
    return is_self;
}

fn parseIpv4Octets(ip_str: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var it = std.mem.tokenizeScalar(u8, ip_str, '.');
    var index: usize = 0;
    while (it.next()) |part| {
        if (index >= octets.len) return null;
        octets[index] = std.fmt.parseInt(u8, part, 10) catch return null;
        index += 1;
    }
    if (index != octets.len) return null;
    return octets;
}

fn reachabilityFromIpv4Bytes(bytes: [4]u8) Reachability {
    if (bytes[0] == 0 and bytes[1] == 0 and bytes[2] == 0 and bytes[3] == 0) return .unknown;
    if (bytes[0] == 127) return .private;
    if (bytes[0] == 10) return .private;
    if (bytes[0] == 172 and bytes[1] >= 16 and bytes[1] <= 31) return .private;
    if (bytes[0] == 192 and bytes[1] == 168) return .private;
    if (bytes[0] == 169 and bytes[1] == 254) return .private;
    return .public;
}

fn reachabilityFromIpv6Bytes(bytes: [16]u8) Reachability {
    const all_zero = blk: {
        for (bytes) |b| {
            if (b != 0) break :blk false;
        }
        break :blk true;
    };
    if (all_zero) return .unknown;

    const is_loopback = blk: {
        for (bytes[0..15]) |b| {
            if (b != 0) break :blk false;
        }
        break :blk bytes[15] == 1;
    };
    if (is_loopback) return .private;

    if ((bytes[0] & 0xfe) == 0xfc) return .private; // fc00::/7 unique-local
    if (bytes[0] == 0xfe and (bytes[1] & 0xc0) == 0x80) return .private; // fe80::/10 link-local

    return .public;
}

test "explicit bind reachability classifies ipv4 loopback private and public" {
    const loopback = try net.IpAddress.parse("127.0.0.1", 10801);
    const private = try net.IpAddress.parse("10.1.2.3", 10801);
    const wildcard = try net.IpAddress.parse("0.0.0.0", 10801);
    const public = try net.IpAddress.parse("209.38.84.23", 10801);

    try std.testing.expectEqual(Reachability.private, explicitBindReachability(loopback));
    try std.testing.expectEqual(Reachability.private, explicitBindReachability(private));
    try std.testing.expectEqual(Reachability.unknown, explicitBindReachability(wildcard));
    try std.testing.expectEqual(Reachability.public, explicitBindReachability(public));
}

test "reachability from ip string treats rfc1918 and loopback as private" {
    try std.testing.expectEqual(Reachability.private, reachabilityFromIpString("10.2.0.2"));
    try std.testing.expectEqual(Reachability.private, reachabilityFromIpString("172.20.0.4"));
    try std.testing.expectEqual(Reachability.private, reachabilityFromIpString("192.168.1.99"));
    try std.testing.expectEqual(Reachability.private, reachabilityFromIpString("127.0.0.1"));
    try std.testing.expectEqual(Reachability.public, reachabilityFromIpString("209.38.84.23"));
}
