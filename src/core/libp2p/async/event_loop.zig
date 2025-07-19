// event_loop.zig - Simple event loop for async I/O operations
// Provides non-blocking socket operations similar to boost::asio

const std = @import("std");
const net = std.net;
const posix = std.posix;

pub const EventType = enum {
    read,
    write,
    accept,
    connect,
};

pub const Event = struct {
    fd: posix.socket_t,
    type: EventType,
    callback: *const fn (fd: posix.socket_t, event: EventType) void,
};

/// Simple event loop using poll()
pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    running: bool,
    events: std.ArrayList(Event),
    poll_fds: std.ArrayList(posix.pollfd),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .running = false,
            .events = std.ArrayList(Event).init(allocator),
            .poll_fds = std.ArrayList(posix.pollfd).init(allocator),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.events.deinit();
        self.poll_fds.deinit();
    }
    
    /// Register a socket for events
    pub fn register(self: *Self, fd: posix.socket_t, event_type: EventType, callback: *const fn (fd: posix.socket_t, event: EventType) void) !void {
        try self.events.append(.{
            .fd = fd,
            .type = event_type,
            .callback = callback,
        });
        
        const poll_events: i16 = switch (event_type) {
            .read, .accept => posix.POLL.IN,
            .write, .connect => posix.POLL.OUT,
        };
        
        try self.poll_fds.append(.{
            .fd = fd,
            .events = poll_events,
            .revents = 0,
        });
    }
    
    /// Unregister a socket
    pub fn unregister(self: *Self, fd: posix.socket_t) void {
        var i: usize = 0;
        while (i < self.events.items.len) {
            if (self.events.items[i].fd == fd) {
                _ = self.events.swapRemove(i);
                _ = self.poll_fds.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
    
    /// Run the event loop
    pub fn run(self: *Self) !void {
        self.running = true;
        
        while (self.running) {
            if (self.poll_fds.items.len == 0) {
                // No events to wait for
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            
            // Wait for events (100ms timeout)
            const n = posix.poll(self.poll_fds.items, 100) catch |err| {
                if (err == error.SystemResources) continue;
                return err;
            };
            
            if (n == 0) continue; // Timeout
            
            // Process events
            for (self.poll_fds.items, 0..) |poll_fd, i| {
                if (poll_fd.revents == 0) continue;
                
                const event = self.events.items[i];
                if ((poll_fd.revents & posix.POLL.IN) != 0 and 
                    (event.type == .read or event.type == .accept)) {
                    event.callback(event.fd, event.type);
                }
                if ((poll_fd.revents & posix.POLL.OUT) != 0 and 
                    (event.type == .write or event.type == .connect)) {
                    event.callback(event.fd, event.type);
                }
                if ((poll_fd.revents & posix.POLL.ERR) != 0) {
                    // Handle error
                    self.unregister(event.fd);
                }
            }
        }
    }
    
    /// Stop the event loop
    pub fn stop(self: *Self) void {
        self.running = false;
    }
};

/// Async TCP connection with event loop integration
pub const AsyncTcpConnection = struct {
    fd: posix.socket_t,
    event_loop: *EventLoop,
    read_callback: ?ReadCallback,
    write_callback: ?WriteCallback,
    connect_callback: ?ConnectCallback,
    
    pub const ReadCallback = *const fn (self: *AsyncTcpConnection, data: []const u8) void;
    pub const WriteCallback = *const fn (self: *AsyncTcpConnection, bytes_written: usize) void;
    pub const ConnectCallback = *const fn (self: *AsyncTcpConnection, success: bool) void;
    
    const Self = @This();
    
    pub fn init(event_loop: *EventLoop) Self {
        return .{
            .fd = undefined,
            .event_loop = event_loop,
            .read_callback = null,
            .write_callback = null,
            .connect_callback = null,
        };
    }
    
    /// Async connect to address
    pub fn asyncConnect(self: *Self, address: net.Address, callback: ConnectCallback) !void {
        self.fd = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(self.fd);
        
        self.connect_callback = callback;
        
        // Start non-blocking connect
        posix.connect(self.fd, &address.any, address.getOsSockLen()) catch |err| {
            if (err != error.WouldBlock) return err;
        };
        
        // Register for write event (connect complete)
        try self.event_loop.register(self.fd, .connect, handleConnectEvent);
    }
    
    /// Async read
    pub fn asyncRead(self: *Self, buffer: []u8, callback: ReadCallback) !void {
        self.read_callback = callback;
        try self.event_loop.register(self.fd, .read, handleReadEvent);
    }
    
    /// Async write
    pub fn asyncWrite(self: *Self, data: []const u8, callback: WriteCallback) !void {
        self.write_callback = callback;
        
        // Try immediate write
        const n = posix.send(self.fd, data, posix.MSG.NOSIGNAL) catch |err| {
            if (err == error.WouldBlock) {
                // Register for write event
                try self.event_loop.register(self.fd, .write, handleWriteEvent);
                return;
            }
            return err;
        };
        
        // Immediate success
        if (callback) |cb| {
            cb(self, n);
        }
    }
    
    fn handleConnectEvent(fd: posix.socket_t, event: EventType) void {
        _ = event;
        // Check if connect succeeded
        var error_code: u32 = 0;
        var error_len: posix.socklen_t = @sizeOf(u32);
        posix.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, std.mem.asBytes(&error_code), &error_len) catch {
            // Handle error
            return;
        };
        
        const success = error_code == 0;
        // TODO: Find connection by fd and call callback
    }
    
    fn handleReadEvent(fd: posix.socket_t, event: EventType) void {
        _ = fd;
        _ = event;
        // TODO: Implement read handling
    }
    
    fn handleWriteEvent(fd: posix.socket_t, event: EventType) void {
        _ = fd;
        _ = event;
        // TODO: Implement write handling
    }
};

// Tests
test "event loop basic operations" {
    const allocator = std.testing.allocator;
    
    var loop = EventLoop.init(allocator);
    defer loop.deinit();
    
    // Test registration
    const dummy_callback = struct {
        fn callback(fd: posix.socket_t, event: EventType) void {
            _ = fd;
            _ = event;
        }
    }.callback;
    
    try loop.register(1, .read, dummy_callback);
    try std.testing.expectEqual(@as(usize, 1), loop.events.items.len);
    
    loop.unregister(1);
    try std.testing.expectEqual(@as(usize, 0), loop.events.items.len);
}