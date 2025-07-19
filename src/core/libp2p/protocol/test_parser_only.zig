// test_parser_only.zig - Isolated test for just the parser

const std = @import("std");
const parser = @import("multistream_parser.zig");
const multistream = @import("multistream.zig");

test "parser varint functionality" {
    var reader = parser.VarintReader.init();
    
    // Test single byte varint
    var data: []const u8 = &[_]u8{42};
    const state = reader.consume(&data);
    
    try std.testing.expectEqual(parser.ParserState.Ready, state);
    try std.testing.expectEqual(@as(usize, 42), reader.getValue().?);
}

test "parser complete message" {
    const allocator = std.testing.allocator;
    
    var mp = parser.MultistreamParser.init(allocator);
    defer mp.deinit();
    
    // Create test message
    var message_buffer = std.ArrayList(u8).init(allocator);
    defer message_buffer.deinit();
    
    const test_msg = multistream.PROTOCOL_ID;
    const total_len = test_msg.len + 1;
    
    // Write varint length prefix
    try multistream.writeVarint(message_buffer.writer(), total_len);
    try message_buffer.appendSlice(test_msg);
    try message_buffer.append(multistream.NEWLINE);
    
    // Parse
    const state = try mp.consume(message_buffer.items);
    
    try std.testing.expectEqual(parser.ParserState.Ready, state);
    try std.testing.expect(mp.hasMessages());
    
    const parsed_msg = mp.peekMessage().?;
    try std.testing.expectEqualStrings(test_msg, parsed_msg.data);
    try std.testing.expectEqual(multistream.MessageType.RightProtocolVersion, parsed_msg.message_type);
}