const std = @import("std");

var global_vm_allocator: *VMAllocator = VMAllocator.create();
var global_vm_allocator_mutex = std.Thread.Mutex{};

pub const VMAllocator = struct {
    pub fn create() *VMAllocator {
        const allocator = std.heap.GeneralPurposeAllocator(.{}).init();
        const boxed = allocator.create(VMAllocator) catch unreachable;
        return boxed;
    }

    pub fn global() *VMAllocator {
        global_vm_allocator_mutex.lock();
        defer global_vm_allocator_mutex.unlock();
        if (global_vm_allocator) |alloc| {
            return alloc;
        } else {
            const allocator = std.heap.GeneralPurposeAllocator(.{}).init();
            const boxed = allocator.create(VMAllocator) catch unreachable;
            global_vm_allocator = boxed;
            return boxed;
        }
    }

    pub fn close(self: *VMAllocator) void {
        _ = self;
    }
};
