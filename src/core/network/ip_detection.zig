// ip_detection.zig - Public IP detection utilities
// Provides methods to detect the node's public IP address using system interfaces

const std = @import("std");
const net = std.net;
const posix = std.posix;

/// Detect our public IP address by checking which interface routes to the internet
pub fn detectPublicIP(allocator: std.mem.Allocator) ![]u8 {
    // Method 1: Connect to a well-known address and check our local socket address
    // This tells us which interface/IP we use to reach the internet
    const remote_addr = net.Address.parseIp4("1.1.1.1", 53) catch return error.IPDetectionFailed;
    
    const socket_fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return error.IPDetectionFailed;
    defer posix.close(socket_fd);
    
    // Connect to determine routing
    _ = posix.connect(socket_fd, &remote_addr.any, remote_addr.getOsSockLen()) catch return error.IPDetectionFailed;
    
    // Get our local address from this socket
    var local_addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    posix.getsockname(socket_fd, &local_addr, &addr_len) catch return error.IPDetectionFailed;
    
    // Extract IP from sockaddr_in
    const sockaddr_in: *const posix.sockaddr.in = @ptrCast(@alignCast(&local_addr));
    const ip_int = sockaddr_in.addr;
    
    // Convert network byte order to host byte order and format as string
    const ip_bytes = [4]u8{
        @truncate(ip_int & 0xFF),           // First byte (little endian)
        @truncate((ip_int >> 8) & 0xFF),    // Second byte
        @truncate((ip_int >> 16) & 0xFF),   // Third byte  
        @truncate((ip_int >> 24) & 0xFF),   // Fourth byte
    };
    
    const ip_str = try std.fmt.allocPrint(allocator, "{}.{}.{}.{}", .{
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
    });
    
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
pub fn isSelfConnection(allocator: std.mem.Allocator, address: net.Address) bool {
    // Get our public IP
    const public_ip = detectPublicIP(allocator) catch |err| {
        std.log.warn("⚠️  Failed to detect public IP: {}, allowing connection", .{err});
        return false;
    };
    defer allocator.free(public_ip);
    
    // Parse target IP from address
    const target_ip = switch (address.any.family) {
        std.posix.AF.INET => blk: {
            var buf: [16]u8 = undefined;
            break :blk std.fmt.bufPrint(&buf, "{}.{}.{}.{}", .{
                address.in.sa.addr & 0xFF,
                (address.in.sa.addr >> 8) & 0xFF,
                (address.in.sa.addr >> 16) & 0xFF,
                (address.in.sa.addr >> 24) & 0xFF,
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