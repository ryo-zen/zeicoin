// not_found.zig - Response when requested items are not available
// Allows peers to stop waiting for items that don't exist

const std = @import("std");
const protocol = @import("../protocol.zig");
const announce = @import("announce.zig");

pub const NotFoundMessage = announce.AnnounceMessage;

// NotFoundMessage uses the same format as AnnounceMessage
// Contains list of items that were requested but not found