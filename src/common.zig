pub const MemPtr = [*]u8;
pub const FuncPtr = *const anyopaque;
pub var allocator = @import("std").heap.GeneralPurposeAllocator(.{}).init;
