// request.zig - Request specific inventory items
// Used after receiving announcements to get full data

const std = @import("std");
const protocol = @import("../protocol.zig");
const announce = @import("announce.zig");

pub const RequestMessage = announce.AnnounceMessage;

// RequestMessage uses the same format as AnnounceMessage
// The only difference is the message type in the header