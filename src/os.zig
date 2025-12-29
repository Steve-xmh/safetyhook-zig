const builtin = @import("builtin");
const std = @import("std");
const common = @import("common.zig");

const MemPtr = common.MemPtr;

const platform = switch (builtin.os.tag) {
    .windows => @import("os.windows.zig"),
    else => @compileError("Unsupported OS"),
};

pub const vm_allocate = platform.vm_allocate;
pub const vm_free = platform.vm_free;
pub const vm_protect = platform.vm_protect;

pub const VmAccess = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,

    pub const Read = VmAccess{ .read = true };
    pub const Write = VmAccess{ .write = true };
    pub const Execute = VmAccess{ .execute = true };
    pub const R = Read;
    pub const W = Write;
    pub const X = Execute;
    pub const RW = VmAccess{ .read = true, .write = true };
    pub const RX = VmAccess{ .read = true, .execute = true };
    pub const RWX = VmAccess{ .read = true, .write = true, .execute = true };

    pub inline fn is_same(a: VmAccess, b: VmAccess) bool {
        return a.read == b.read and a.write == b.write and a.execute == b.execute;
    }
};

pub const VmBasicInfo = struct {
    address: MemPtr,
    size: usize,
    access: VmAccess,
    is_free: bool,
};

pub const SystemInfo = struct {
    page_size: usize,
    allocation_granularity: usize,
    min_address: MemPtr,
    max_address: MemPtr,
};

pub const VMError = error{
    InvalidAccessFlags,
};

test "vm_allocate" {
    const buf = try vm_allocate(null, 4096, VmAccess.RWX);
    defer vm_free(buf);
}

test "vm_protect" {
    const buf = try std.heap.page_allocator.alloc(u8, 4096);
    defer std.heap.page_allocator.free(buf);

    try std.testing.expect(VmAccess.RW != VmAccess.RWX);

    const old_access = try vm_protect(buf.ptr, buf.len, VmAccess.RWX);
    try std.testing.expectEqual(old_access, VmAccess.RW);

    const new_access = try vm_protect(buf.ptr, buf.len, old_access);
    try std.testing.expectEqual(new_access, VmAccess.RWX);
}
