const os = @import("os.zig");
const std = @import("std");

pub const Allocation = struct {
    ptr: ?os.MemPtr = undefined,
    size: usize = 0,
    allocator: *VMAllocator = undefined,

    pub inline fn isValid(self: Allocation) bool {
        return self.ptr != null;
    }

    pub inline fn address(self: Allocation) os.MemPtr {
        return self.ptr.?;
    }

    pub fn deinit(self: *Allocation) void {
        self.allocator.free(self);
    }
};

var global_vm_allocator = VMAllocator{};

pub const VMAllocator = struct {
    const Self = @This();

    m_mutex: std.Thread.Mutex = .{},

    pub inline fn global() *Self {
        return &global_vm_allocator;
    }

    pub fn alloc(self: *Self, size: usize) !Allocation {
        return self.alloc_near(size, std.math.maxInt(usize));
    }

    pub fn alloc_near(self: *Self, size: usize, max_distance: usize) !Allocation {
        _ = .{
            size,
            max_distance,
        };
        self.m_mutex.lock();
        defer self.m_mutex.unlock();
        @panic("TODO");
    }

    pub fn free(self: *Self, allocation: *Allocation) void {
        _ = self;
        if (allocation.ptr) |ptr| {
            os.vm_free(ptr);
        }
        allocation.* = .{};
    }

    fn internal_allocate_near(self: *Self, desired_addr: os.MemPtr, size: usize, max_distance: usize) !Allocation {
        _ = .{
            self,
            desired_addr,
            size,
            max_distance,
        };
        @panic("TODO");
    }

    pub fn protect(self: *Self, ptr: os.MemPtr, size: usize, access: os.VmAccess) !os.VmAccess {
        _ = self;
        return os.vm_protect(ptr, size, access);
    }
};

test "allocator" {
    const allocator = VMAllocator.global();

    var allocation = try allocator.alloc(128, os.VmAccess.RWX);
    defer allocator.free(&allocation);
}
