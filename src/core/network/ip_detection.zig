// ip_detection.zig - Public IP detection utilities
// Provides methods to detect the node's public IP address using system interfaces

const std = @import("std");
const net = std.Io.net;
const posix = std.posix;

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

/// Check if an IP address is in private address ranges
fn isPrivateIP(ip_str: []const u8) bool {
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
    return std.mem.startsWith(u8, ip_str, "10.") or
           std.mem.startsWith(u8, ip_str, "192.168.") or
           std.mem.startsWith(u8, ip_str, "172.16.") or  // This is simplified - should check 172.16-31
           std.mem.startsWith(u8, ip_str, "127.");
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
