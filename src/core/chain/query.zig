// query.zig - Blockchain Query Module
// Handles all read-only blockchain queries and calculations

const std = @import("std");
const types = @import("../types/types.zig");
const db = @import("../storage/db.zig");
const ChainState = @import("state.zig").ChainState;

pub const ChainQuery = struct {
    allocator: std.mem.Allocator,
    database: *db.Database,
    chain_state: *ChainState,
    
    pub fn init(allocator: std.mem.Allocator, database: *db.Database, chain_state: *ChainState) ChainQuery {
        return .{
            .allocator = allocator,
            .database = database,
            .chain_state = chain_state,
        };
    }
    
    pub fn deinit(self: *ChainQuery) void {
        _ = self;
    }
    
    pub fn getAccount(self: *ChainQuery, address: types.Address) !types.Account {
        return try self.chain_state.getAccount(address);
    }
    
    pub fn getHeight(self: *ChainQuery) !u32 {
        return try self.database.getHeight();
    }
    
    pub fn getBlockByHeight(self: *ChainQuery, height: u32) !types.Block {
        return try self.database.getBlock(height);
    }
    
    pub fn getBlock(self: *ChainQuery, height: u32) !types.Block {
        return try self.database.getBlock(height);
    }
    
    pub fn getMedianTimePast(self: *ChainQuery, height: u32) !u64 {
        if (height < types.TimestampValidation.MTP_BLOCK_COUNT) {
            return types.Genesis.timestamp();
        }
        
        var timestamps = std.ArrayList(u64).init(self.allocator);
        defer timestamps.deinit();
        
        const start_height = height - types.TimestampValidation.MTP_BLOCK_COUNT + 1;
        for (start_height..height + 1) |h| {
            var block = try self.database.getBlock(@intCast(h));
            defer block.deinit(self.allocator);
            try timestamps.append(block.header.timestamp);
        }
        
        std.sort.heap(u64, timestamps.items, {}, comptime std.sort.asc(u64));
        const median_index = timestamps.items.len / 2;
        return timestamps.items[median_index];
    }
    
    pub fn estimateCumulativeWork(self: *ChainQuery, height: u32) !types.ChainWork {
        var total_work: types.ChainWork = 0;
        for (0..height + 1) |h| {
            var block = self.database.getBlock(@intCast(h)) catch continue;
            defer block.deinit(self.allocator);
            total_work += block.header.getWork();
        }
        return total_work;
    }
    
    pub fn getBalance(self: *ChainQuery, address: types.Address) !u64 {
        const account = try self.getAccount(address);
        return account.balance;
    }
};