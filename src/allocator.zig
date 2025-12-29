const os = @import("os.zig");

pub const Allocation = struct {
    ptr: ?os.MemPtr = null,
    size: usize = 0,

    pub inline fn isValid(self: Allocation) bool {
        return self.ptr != null;
    }

    pub inline fn address(self: Allocation) os.MemPtr {
        return self.ptr.?;
    }
};

var global_vm_allocator = VMAllocator{};

pub const VMAllocator = struct {
    pub inline fn global() *VMAllocator {
        return &global_vm_allocator;
    }

    pub fn alloc(self: *VMAllocator, size: usize, access: os.VmAccess) !Allocation {
        _ = self;
        const ptr = try os.vm_allocate(null, size, access);
        return .{ .ptr = ptr, .size = size };
    }

    pub fn free(self: *VMAllocator, allocation: *Allocation) void {
        _ = self;
        if (allocation.ptr) |ptr| {
            os.vm_free(ptr);
        }
        allocation.* = .{};
    }

    pub fn protect(self: *VMAllocator, ptr: os.MemPtr, size: usize, access: os.VmAccess) !os.VmAccess {
        _ = self;
        return os.vm_protect(ptr, size, access);
    }
};

test "allocator" {
    const allocator = VMAllocator.global();

    var allocation = try allocator.alloc(128, os.VmAccess.RWX);
    defer allocator.free(&allocation);
}
