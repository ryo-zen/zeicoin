// test_multistream_parser.zig - Tests for streaming multistream parser

const std = @import("std");
const parser = @import("multistream_parser.zig");
const multistream = @import("multistream.zig");

test "varint reader basic functionality" {
    var reader = parser.VarintReader.init();
    
    // Test single byte varint (value 42)
    var data: []const u8 = &[_]u8{42};
    const state = reader.consume(&data);
    
    try std.testing.expectEqual(parser.ParserState.Ready, state);
    try std.testing.expect(reader.isReady());
    try std.testing.expectEqual(@as(usize, 42), reader.getValue().?);
    try std.testing.expectEqual(@as(usize, 0), data.len); // All data consumed
}

test "varint reader multi-byte varint" {
    var reader = parser.VarintReader.init();
    
    // Test two byte varint (value 300 = 0x12C)
    // 300 in varint: 0xAC 0x02 (little-endian, 7-bit chunks)
    var data: []const u8 = &[_]u8{ 0xAC, 0x02 };
    const state = reader.consume(&data);
    
    try std.testing.expectEqual(parser.ParserState.Ready, state);
    try std.testing.expectEqual(@as(usize, 300), reader.getValue().?);
}

test "varint reader partial data" {
    var reader = parser.VarintReader.init();
    
    // Feed first byte of two-byte varint
    var data1: []const u8 = &[_]u8{0xAC}; // First byte of 300
    const state1 = reader.consume(&data1);
    
    try std.testing.expectEqual(parser.ParserState.Underflow, state1);
    try std.testing.expect(!reader.isReady());
    
    // Feed second byte
    var data2: []const u8 = &[_]u8{0x02}; // Second byte of 300
    const state2 = reader.consume(&data2);
    
    try std.testing.expectEqual(parser.ParserState.Ready, state2);
    try std.testing.expectEqual(@as(usize, 300), reader.getValue().?);
}

test "buffer collector basic functionality" {
    const allocator = std.testing.allocator;
    
    var collector = parser.BufferCollector.init(allocator);
    defer collector.deinit();
    
    // Set expected size
    try collector.expectSize(10);
    
    // Add partial data
    const complete1 = try collector.add("hello");
    try std.testing.expect(complete1 == null); // Not complete yet
    
    // Add remaining data
    const complete2 = try collector.add("world");
    try std.testing.expect(complete2 != null);
    try std.testing.expectEqualStrings("helloworld", complete2.?);
}

test "buffer collector overflow handling" {
    const allocator = std.testing.allocator;
    
    var collector = parser.BufferCollector.init(allocator);
    defer collector.deinit();
    
    // Set expected size to 5
    try collector.expectSize(5);
    
    // Add exactly 5 bytes
    const complete = try collector.add("hello");
    try std.testing.expect(complete != null);
    try std.testing.expectEqualStrings("hello", complete.?);
    
    // Verify collector knows it's complete
    try std.testing.expect(collector.isComplete());
}

test "multistream parser initialization" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    try std.testing.expectEqual(parser.ParserState.Underflow, mp.getState());
    try std.testing.expect(!mp.hasMessages());
    try std.testing.expectEqual(@as(usize, 1), mp.bytesNeeded()); // Needs at least 1 byte for varint
}

test "multistream parser single complete message" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    // Create a test message manually (protocol ID with length prefix)
    var message_buffer = std.ArrayList(u8).init(allocator);
    defer message_buffer.deinit();
    
    const test_msg = multistream.PROTOCOL_ID;
    const total_len = test_msg.len + 1; // +1 for newline
    
    // Write varint length prefix
    try multistream.writeVarint(message_buffer.writer(), total_len);
    
    // Write message and newline  
    try message_buffer.appendSlice(test_msg);
    try message_buffer.append(multistream.NEWLINE);
    
    // Parse the complete message
    const state = try mp.consume(message_buffer.items);
    
    try std.testing.expectEqual(parser.ParserState.Ready, state);
    try std.testing.expect(mp.hasMessages());
    
    const parsed_msg = mp.peekMessage().?;
    try std.testing.expectEqualStrings(test_msg, parsed_msg.data);
    try std.testing.expectEqual(multistream.MessageType.RightProtocolVersion, parsed_msg.message_type);
}

test "multistream parser partial message reads" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    // Create test message
    var message_buffer = std.ArrayList(u8).init(allocator);
    defer message_buffer.deinit();
    
    const test_msg = "/yamux/1.0.0";
    const total_len = test_msg.len + 1;
    
    try multistream.writeVarint(message_buffer.writer(), total_len);
    try message_buffer.appendSlice(test_msg);
    try message_buffer.append(multistream.NEWLINE);
    
    const complete_message = message_buffer.items;
    
    // Feed message in small chunks
    var offset: usize = 0;
    const chunk_size = 3;
    
    while (offset < complete_message.len) {
        const end = @min(offset + chunk_size, complete_message.len);
        const chunk = complete_message[offset..end];
        
        const state = try mp.consume(chunk);
        
        if (end < complete_message.len) {
            // Should still be waiting for more data
            try std.testing.expectEqual(parser.ParserState.Underflow, state);
        } else {
            // Should be complete now
            try std.testing.expectEqual(parser.ParserState.Ready, state);
        }
        
        offset = end;
    }
    
    // Verify final message
    try std.testing.expect(mp.hasMessages());
    const parsed_msg = mp.peekMessage().?;
    try std.testing.expectEqualStrings(test_msg, parsed_msg.data);
    try std.testing.expectEqual(multistream.MessageType.ProtocolName, parsed_msg.message_type);
}

test "multistream parser multiple messages" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    // Create buffer with multiple messages
    var message_buffer = std.ArrayList(u8).init(allocator);
    defer message_buffer.deinit();
    
    // Message 1: Protocol ID
    const msg1 = multistream.PROTOCOL_ID;
    try multistream.writeVarint(message_buffer.writer(), msg1.len + 1);
    try message_buffer.appendSlice(msg1);
    try message_buffer.append(multistream.NEWLINE);
    
    // Message 2: NA
    const msg2 = multistream.NA;
    try multistream.writeVarint(message_buffer.writer(), msg2.len + 1);
    try message_buffer.appendSlice(msg2);
    try message_buffer.append(multistream.NEWLINE);
    
    // Parse all messages at once
    const state = try mp.consume(message_buffer.items);
    try std.testing.expectEqual(parser.ParserState.Ready, state);
    
    // Should have one message (parser processes one at a time)
    try std.testing.expect(mp.hasMessages());
    
    // Get first message
    const first_msg = mp.popMessage().?;
    try std.testing.expectEqualStrings(msg1, first_msg.data);
    try std.testing.expectEqual(multistream.MessageType.RightProtocolVersion, first_msg.message_type);
    
    // Parser should reset to underflow for next message
    try std.testing.expectEqual(parser.ParserState.Underflow, mp.getState());
    
    // Parse remaining data (this is a simplified test - in real usage,
    // we'd need to track how much data was consumed from the first parse)
}

test "multistream parser message types" {
    const allocator = std.testing.allocator;
    
    const test_cases = [_]struct {
        message: []const u8,
        expected_type: multistream.MessageType,
    }{
        .{ .message = multistream.PROTOCOL_ID, .expected_type = .RightProtocolVersion },
        .{ .message = multistream.NA, .expected_type = .NAMessage },
        .{ .message = "ls", .expected_type = .LSMessage },
        .{ .message = "/yamux/1.0.0", .expected_type = .ProtocolName },
        .{ .message = "/multistream/2.0.0", .expected_type = .WrongProtocolVersion },
        .{ .message = "invalid", .expected_type = .InvalidMessage },
    };
    
    for (test_cases) |test_case| {
        var mp = parser.MultistreamParser.init(allocator);
        defer mp.deinit();
        
        // Create message with length prefix
        var message_buffer = std.ArrayList(u8).init(allocator);
        defer message_buffer.deinit();
        
        const total_len = test_case.message.len + 1;
        try multistream.writeVarint(message_buffer.writer(), total_len);
        try message_buffer.appendSlice(test_case.message);
        try message_buffer.append(multistream.NEWLINE);
        
        // Parse
        const state = try mp.consume(message_buffer.items);
        try std.testing.expectEqual(parser.ParserState.Ready, state);
        
        // Verify type
        const parsed_msg = mp.peekMessage().?;
        try std.testing.expectEqual(test_case.expected_type, parsed_msg.message_type);
        try std.testing.expectEqualStrings(test_case.message, parsed_msg.data);
    }
}

test "multistream parser overflow protection" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    // Create a varint that represents a message larger than MAX_MESSAGE_SIZE
    var overflow_buffer = std.ArrayList(u8).init(allocator);
    defer overflow_buffer.deinit();
    
    const huge_size = multistream.MAX_MESSAGE_SIZE + 1000;
    try multistream.writeVarint(overflow_buffer.writer(), huge_size);
    
    // Parse should detect overflow
    const state = try mp.consume(overflow_buffer.items);
    try std.testing.expectEqual(parser.ParserState.Overflow, state);
}

test "multistream parser reset functionality" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    // Parse a message to get to Ready state
    var message_buffer = std.ArrayList(u8).init(allocator);
    defer message_buffer.deinit();
    
    const test_msg = "test";
    try multistream.writeVarint(message_buffer.writer(), test_msg.len + 1);
    try message_buffer.appendSlice(test_msg);
    try message_buffer.append(multistream.NEWLINE);
    
    _ = try mp.consume(message_buffer.items);
    try std.testing.expectEqual(parser.ParserState.Ready, mp.getState());
    try std.testing.expect(mp.hasMessages());
    
    // Reset parser
    mp.reset();
    
    // Should be back to initial state
    try std.testing.expectEqual(parser.ParserState.Underflow, mp.getState());
    try std.testing.expect(!mp.hasMessages());
    try std.testing.expectEqual(@as(usize, 1), mp.bytesNeeded());
}