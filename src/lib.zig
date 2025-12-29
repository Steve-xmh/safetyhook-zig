const os = @import("os.zig");
const allocator = @import("allocator.zig");

pub fn vm_allocate() !void {
    os.vm_allocate(123, 456);
    os.vm_protect(123, 456, os.VmAccess.RW);
    _ = allocator.VMAllocator.global();
}
