const common_os = @import("os.zig");
const VmAccess = common_os.VmAccess;
const VMError = common_os.VMError;
const MemPtr = common_os.MemPtr;
const std = @import("std");

fn convert_access_to_protect(access: VmAccess) !std.os.windows.DWORD {
    if (access.is_same(VmAccess.R)) {
        return std.os.windows.PAGE_READONLY;
    } else if (access.is_same(VmAccess.RW)) {
        return std.os.windows.PAGE_READWRITE;
    } else if (access.is_same(VmAccess.RX)) {
        return std.os.windows.PAGE_EXECUTE_READ;
    } else if (access.is_same(VmAccess.RWX)) {
        return std.os.windows.PAGE_EXECUTE_READWRITE;
    } else {
        return VMError.InvalidAccessFlags;
    }
}

fn convert_protect_to_access(protect: std.os.windows.DWORD) !VmAccess {
    return switch (protect) {
        std.os.windows.PAGE_READONLY => VmAccess.R,
        std.os.windows.PAGE_READWRITE => VmAccess.RW,
        std.os.windows.PAGE_EXECUTE_READ => VmAccess.RX,
        std.os.windows.PAGE_EXECUTE_READWRITE => VmAccess.RWX,
        else => VMError.InvalidAccessFlags,
    };
}

pub fn vm_allocate(addr: ?MemPtr, size: usize, access: VmAccess) !MemPtr {
    const protect = try convert_access_to_protect(access);

    const ret = try std.os.windows.VirtualAlloc(
        @ptrCast(addr),
        size,
        std.os.windows.MEM_RESERVE | std.os.windows.MEM_COMMIT,
        protect,
    );

    return @ptrCast(ret);
}

pub fn vm_free(ptr: MemPtr) void {
    std.os.windows.VirtualFree(@ptrCast(ptr), 0, std.os.windows.MEM_RELEASE);
}

pub fn vm_protect(ptr: MemPtr, size: usize, access: VmAccess) !VmAccess {
    const protect = try convert_access_to_protect(access);

    var old_protect: std.os.windows.DWORD = 0;
    try std.os.windows.VirtualProtect(@ptrCast(ptr), size, protect, &old_protect);

    return try convert_protect_to_access(old_protect);
}
