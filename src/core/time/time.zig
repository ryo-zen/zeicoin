// time.zig - Network Time Synchronization for ZeiCoin
// Provides accurate time synchronization using NTP servers and peer consensus

const std = @import("std");

const log = std.log.scoped(.time);

/// Time synchronization configuration
pub const TimeConfig = struct {
    /// Maximum allowed time offset from peers before NTP verification (seconds)
    max_peer_offset: i64 = 5 * 60, // 5 minutes

    /// Maximum allowed time disagreement between NTP and peers (seconds)
    max_ntp_disagreement: i64 = 2 * 60, // 2 minutes

    /// NTP query timeout (milliseconds)
    ntp_timeout_ms: u32 = 5000, // 5 seconds

    /// Enable debug logging
    debug: bool = false,
};

/// Time synchronization manager
pub const TimeSynchronizer = struct {
    config: TimeConfig,
    time_offset: i64 = 0,
    last_ntp_sync: i64 = 0,

    const Self = @This();

    /// NTP servers to query (in order of preference)
    const NTP_SERVERS = [_][]const u8{
        "time.google.com",
        "time.cloudflare.com",
        "pool.ntp.org",
        "time.apple.com",
        "time.nist.gov",
    };

    pub fn init(config: TimeConfig) Self {
        return .{
            .config = config,
        };
    }

    /// Get current network-adjusted time
    pub fn getNetworkTime(self: *const Self) i64 {
        return std.time.timestamp() + self.time_offset;
    }

    /// Get current system time
    pub fn getSystemTime(_: *const Self) i64 {
        return std.time.timestamp();
    }

    /// Get current time offset from system time
    pub fn getTimeOffset(self: *const Self) i64 {
        return self.time_offset;
    }

    /// Update time offset based on peer consensus
    pub fn updateFromPeerConsensus(self: *Self, allocator: std.mem.Allocator, peer_times: []const i64) !void {
        if (peer_times.len == 0) return;

        const system_time = std.time.timestamp();

        // Calculate offsets from each peer
        var offsets = std.ArrayList(i64).init(allocator);
        defer offsets.deinit();

        for (peer_times) |peer_time| {
            const offset = peer_time - system_time;
            try offsets.append(offset);
        }

        // Sort offsets to find median
        std.sort.heap(i64, offsets.items, {}, std.sort.asc(i64));
        const median_offset = offsets.items[offsets.items.len / 2];

        // Check if offset is large enough to warrant NTP verification
        if (@abs(median_offset) > self.config.max_peer_offset) {
            if (self.config.debug) {
                log.info("⏰ Large time offset detected: {:+}s, verifying with NTP...", .{median_offset});
            }

            try self.verifyWithNTP(median_offset);
        } else {
            // Small offset, trust peer consensus
            self.time_offset = median_offset;

            if (self.config.debug) {
                log.info("⏰ Time synchronized with peers (offset: {:+}s)", .{median_offset});
            }
        }
    }

    /// Verify time offset using NTP servers
    fn verifyWithNTP(self: *Self, peer_offset: i64) !void {
        const ntp_time = self.getNTPTime() catch |err| {
            if (self.config.debug) {
                log.info("⚠️ NTP verification failed: {}, using peer consensus", .{err});
            }
            self.time_offset = peer_offset;
            return;
        };

        const system_time = std.time.timestamp();
        const ntp_offset = ntp_time - system_time;

        // Compare NTP vs peer consensus
        const disagreement = @abs(ntp_offset - peer_offset);

        if (disagreement > self.config.max_ntp_disagreement) {
            // Significant disagreement - prefer NTP (more authoritative)
            if (self.config.debug) {
                log.info("🕐 NTP disagrees with peers (NTP: {:+}s, Peers: {:+}s), using NTP", .{ ntp_offset, peer_offset });
            }
            self.time_offset = ntp_offset;
        } else {
            // NTP and peers agree - use peer consensus
            if (self.config.debug) {
                log.info("✅ NTP confirms peer consensus (offset: {:+}s)", .{peer_offset});
            }
            self.time_offset = peer_offset;
        }

        self.last_ntp_sync = system_time;
    }

    /// Force NTP synchronization
    pub fn syncWithNTP(self: *Self) !void {
        const ntp_time = try self.getNTPTime();
        const system_time = std.time.timestamp();
        self.time_offset = ntp_time - system_time;
        self.last_ntp_sync = system_time;

        if (self.config.debug) {
            log.info("🌐 Force NTP sync completed (offset: {:+}s)", .{self.time_offset});
        }
    }

    /// Get time from NTP servers
    fn getNTPTime(self: *const Self) !i64 {
        // Try each NTP server until one works
        for (Self.NTP_SERVERS) |server| {
            if (self.queryNTPServer(server)) |ntp_time| {
                return ntp_time;
            } else |_| {
                continue; // Try next server
            }
        }

        return error.AllNTPServersFailed;
    }

    /// Query a single NTP server
    fn queryNTPServer(self: *const Self, server: []const u8) !i64 {
        // Create NTP request packet (48 bytes, RFC 5905)
        var ntp_packet = [_]u8{0} ** 48;
        ntp_packet[0] = 0x1B; // LI=0, VN=3, Mode=3 (client request)

        // Resolve server address and connect
        const address = std.net.Address.resolveIp(server, 123) catch |err| {
            if (self.config.debug) {
                log.info("⚠️ Failed to resolve NTP server {s}: {}", .{ server, err });
            }
            return err;
        };

        // Use UDP for NTP (standard protocol)
        const socket = std.net.tcpConnectToAddress(address) catch |err| {
            if (self.config.debug) {
                log.info("⚠️ Failed to connect to NTP server {s}: {}", .{ server, err });
            }
            return err;
        };
        defer socket.close();

        // Send NTP request
        _ = socket.writeAll(&ntp_packet) catch |err| {
            if (self.config.debug) {
                log.info("⚠️ Failed to send NTP request to {s}: {}", .{ server, err });
            }
            return err;
        };

        // Read NTP response with timeout
        var response: [48]u8 = undefined;
        const bytes_read = socket.readAll(&response) catch |err| {
            if (self.config.debug) {
                log.info("⚠️ Failed to read NTP response from {s}: {}", .{ server, err });
            }
            return err;
        };

        if (bytes_read != 48) {
            if (self.config.debug) {
                log.info("⚠️ Invalid NTP response size from {s}: {} bytes", .{ server, bytes_read });
            }
            return error.InvalidNTPResponse;
        }

        // Extract transmit timestamp (bytes 40-43, RFC 5905)
        const ntp_timestamp = std.mem.readInt(u32, response[40..44], .big);

        // Convert from NTP epoch (1900-01-01) to Unix epoch (1970-01-01)
        const unix_timestamp: i64 = @as(i64, ntp_timestamp) - 2208988800;

        if (self.config.debug) {
            log.info("✅ NTP response from {s}: {}", .{ server, unix_timestamp });
        }

        return unix_timestamp;
    }

    /// Check if time is considered accurate
    pub fn isTimeAccurate(self: *const Self) bool {
        // Consider time accurate if offset is less than 30 seconds
        return @abs(self.time_offset) < 30;
    }

    /// Get time accuracy status
    pub fn getTimeStatus(self: *const Self) TimeStatus {
        const offset_abs = @abs(self.time_offset);

        if (offset_abs < 5) return .excellent;
        if (offset_abs < 30) return .good;
        if (offset_abs < 120) return .poor;
        return .inaccurate;
    }

    /// Get seconds since last NTP sync
    pub fn getSecondsSinceNTPSync(self: *const Self) i64 {
        if (self.last_ntp_sync == 0) return -1; // Never synced
        return std.time.timestamp() - self.last_ntp_sync;
    }
};

/// Time accuracy status
pub const TimeStatus = enum {
    excellent, // ±5 seconds
    good, // ±30 seconds
    poor, // ±2 minutes
    inaccurate, // >2 minutes

    pub fn toString(self: TimeStatus) []const u8 {
        return switch (self) {
            .excellent => "Excellent",
            .good => "Good",
            .poor => "Poor",
            .inaccurate => "Inaccurate",
        };
    }
};

// Tests
test "time synchronizer initialization" {
    const config = TimeConfig{ .debug = false };
    const sync = TimeSynchronizer.init(config);

    try std.testing.expect(sync.time_offset == 0);
    try std.testing.expect(sync.getTimeOffset() == 0);
    try std.testing.expect(sync.getTimeStatus() == .excellent);
}

test "time status accuracy levels" {
    var sync = TimeSynchronizer.init(.{});

    sync.time_offset = 3;
    try std.testing.expect(sync.getTimeStatus() == .excellent);

    sync.time_offset = 15;
    try std.testing.expect(sync.getTimeStatus() == .good);

    sync.time_offset = 90;
    try std.testing.expect(sync.getTimeStatus() == .poor);

    sync.time_offset = 300;
    try std.testing.expect(sync.getTimeStatus() == .inaccurate);
}

// IruPlorpbehoryhgshwdwuxhiljkwhu
