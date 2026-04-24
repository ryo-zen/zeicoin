// SPDX-FileCopyrightText: 2025-2026 Ryo Zen (https://github.com/ryo-zen)
// SPDX-License-Identifier: Apache-2.0

// get_peers.zig - Request peer addresses for discovery
// Simple message with no payload

const std = @import("std");

pub const GetPeersMessage = struct {
    pub fn encode(self: *const GetPeersMessage, writer: anytype) !void {
        _ = self;
        _ = writer;
        // Empty message
    }
    
    pub fn decode(reader: anytype) !GetPeersMessage {
        _ = reader;
        return .{};
    }
    
    pub fn estimateSize(self: GetPeersMessage) usize {
        _ = self;
        return 0;
    }
};