const common_os = @import("os.zig");
const VmAccess = common_os.VmAccess;
const VMError = common_os.VMError;
const MemPtr = common_os.MemPtr;
const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;
const utility = @import("utility.zig");

fn convert_access_to_protect(access: VmAccess) !win.DWORD {
    if (access.is_same(VmAccess.R)) {
        return win.PAGE_READONLY;
    } else if (access.is_same(VmAccess.RW)) {
        return win.PAGE_READWRITE;
    } else if (access.is_same(VmAccess.RX)) {
        return win.PAGE_EXECUTE_READ;
    } else if (access.is_same(VmAccess.RWX)) {
        return win.PAGE_EXECUTE_READWRITE;
    } else {
        return VMError.InvalidAccessFlags;
    }
}

fn convert_protect_to_access(protect: win.DWORD) !VmAccess {
    return switch (protect) {
        win.PAGE_READONLY => VmAccess.R,
        win.PAGE_READWRITE => VmAccess.RW,
        win.PAGE_EXECUTE_READ => VmAccess.RX,
        win.PAGE_EXECUTE_READWRITE => VmAccess.RWX,
        else => VMError.InvalidAccessFlags,
    };
}

pub fn vm_allocate(addr: ?MemPtr, size: usize, access: VmAccess) !MemPtr {
    const protect = try convert_access_to_protect(access);

    const ret = try win.VirtualAlloc(
        @ptrCast(addr),
        size,
        win.MEM_RESERVE | win.MEM_COMMIT,
        protect,
    );

    return @ptrCast(ret);
}

pub fn vm_query(ptr: MemPtr) !common_os.VmBasicInfo {
    var mem_info: win.MEMORY_BASIC_INFORMATION = undefined;
    const result_size = win.VirtualQuery(
        @ptrCast(ptr),
        &mem_info,
        @sizeOf(win.MEMORY_BASIC_INFORMATION),
    );
    if (result_size == 0) {
        return error.QueryFailed;
    }

    const access = try convert_protect_to_access(mem_info.Protect);

    return common_os.VmBasicInfo{
        .address = @ptrCast(mem_info.BaseAddress),
        .size = mem_info.RegionSize,
        .access = access,
        .is_free = mem_info.State == win.MEM_FREE,
    };
}

pub fn vm_free(ptr: MemPtr) void {
    win.VirtualFree(@ptrCast(ptr), 0, win.MEM_RELEASE);
}

pub fn vm_protect(ptr: MemPtr, size: usize, access: VmAccess) !VmAccess {
    const protect = try convert_access_to_protect(access);

    var old_protect: win.DWORD = 0;
    try win.VirtualProtect(@ptrCast(ptr), size, protect, &old_protect);

    return try convert_protect_to_access(old_protect);
}

fn system_info() common_os.SystemInfo {
    var info: common_os.SystemInfo = .{};
    var si: win.SYSTEM_INFO = .{};
    win.kernel32.GetSystemInfo(&si);

    info.page_size = si.dwPageSize;
    info.allocation_granularity = si.dwAllocationGranularity;
    info.min_address = @ptrCast(si.lpMinimumApplicationAddress);
    info.max_address = @ptrCast(si.lpMaximumApplicationAddress);

    return info;
}

const TrapInfo = struct {
    from_page_start: MemPtr,
    from_page_end: MemPtr,
    from: MemPtr,
    to_page_start: MemPtr,
    to_page_end: MemPtr,
    to: MemPtr,
    len: usize,
};

const TrapManager = struct {
    const TrapMap = std.AutoHashMap(MemPtr, TrapInfo);

    allocator: std.mem.Allocator,
    m_trap_veh: win.PVOID,
    mutex: std.Thread.Mutex,
    m_traps: TrapMap,

    pub fn create(allocator: std.mem.Allocator) TrapManager {
        return TrapManager{
            .allocator = allocator,
            .m_trap_veh = win.kernel32.AddVectoredExceptionHandler(
                1,
                trap_handler,
            ),
            .mutex = std.Thread.Mutex{},
            .m_traps = TrapMap.init(allocator),
        };
    }

    pub fn add_trap(self: *TrapManager, from: MemPtr, to: MemPtr, len: usize) !void {
        const info = TrapInfo{
            .from = from,
            .to = to,
            .from_page_start = utility.align_down(from, 0x1000),
            .from_page_end = utility.align_up(from + len, 0x1000),
            .to_page_start = utility.align_down(to, 0x1000),
            .to_page_end = utility.align_up(to + len, 0x1000),
            .len = len,
        };

        try self.m_traps.put(from, info);
    }

    pub fn find_trap(self: *TrapManager, addr: MemPtr) ?*TrapInfo {
        var it = self.m_traps.valueIterator();
        while (it.next()) |trap| {
            if (addr >= trap.from and addr < trap.from + trap.len) {
                return trap;
            }
        }
        return null;
    }

    pub fn find_trap_page(self: *TrapManager, addr: MemPtr) ?*TrapInfo {
        var it = self.m_traps.valueIterator();

        while (it.next()) |trap| {
            if (addr >= trap.from_page_start and addr < trap.from_page_end) {
                return trap;
            }
        }

        while (it.next()) |trap| {
            if (addr >= trap.to_page_start and addr < trap.to_page_end) {
                return trap;
            }
        }

        return null;
    }

    pub fn close(self: *TrapManager) void {
        if (self.m_trap_veh != null) {
            _ = win.kernel32.RemoveVectoredExceptionHandler(self.m_trap_veh);
            self.m_trap_veh = null;
        }
        self.m_traps.deinit();
    }

    fn trap_handler(exp: *win.EXCEPTION_POINTERS) win.LONG {
        const exception_code = exp.ExceptionRecord.ExceptionCode;

        if (exception_code != win.EXCEPTION_ACCESS_VIOLATION) {
            return win.EXCEPTION_CONTINUE_SEARCH;
        }

        trap_manager.mutex.lock();
        defer trap_manager.mutex.unlock();

        const faulting_address: MemPtr = @ptrCast(exp.ExceptionRecord.ExceptionInformation[1]);
        const opt_trap = trap_manager.find_trap(faulting_address);

        if (opt_trap) |trap| {
            for (0..trap.len) |i| {
                fix_ip(&exp.ContextRecord, trap.from + i, trap.to + i);
            }

            return -1; // EXCEPTION_CONTINUE_EXECUTION
        } else {
            if (trap_manager.find_trap_page(faulting_address) != null) {
                return -1; // EXCEPTION_CONTINUE_EXECUTION
            } else {
                return win.EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }
};

var trap_manager = TrapManager.create(std.heap.page_allocator);
var virtual_protect_mutex = std.Thread.Mutex{};

fn find_me() void {}

pub fn trap_threads(from: MemPtr, to: MemPtr, size: usize, run_func: *const fn () void) void {
    var find_me_mbi: win.MEMORY_BASIC_INFORMATION = .{};
    var from_mbi: win.MEMORY_BASIC_INFORMATION = .{};
    var to_mbi: win.MEMORY_BASIC_INFORMATION = .{};

    win.VirtualQuery(@ptrCast(find_me), &find_me_mbi, @sizeOf(win.MEMORY_BASIC_INFORMATION));
    win.VirtualQuery(@ptrCast(from), &from_mbi, @sizeOf(win.MEMORY_BASIC_INFORMATION));
    win.VirtualQuery(@ptrCast(to), &to_mbi, @sizeOf(win.MEMORY_BASIC_INFORMATION));

    const new_protect = win.PAGE_READWRITE;

    if (from_mbi.AllocationBase == find_me_mbi.AllocationBase or
        to_mbi.AllocationBase == find_me_mbi.AllocationBase)
    {
        new_protect = win.PAGE_EXECUTE_READWRITE;
    }

    const si = system_info();
    const from_page_start = utility.align_down(from, si.page_size);
    const from_page_end = utility.align_up(from + size, si.page_size);
    const vp_start: MemPtr = @ptrCast(&win.VirtualProtect);
    const vp_end = vp_start + 0x20;

    if (!(from_page_end < vp_start or vp_end < from_page_start)) {
        new_protect = win.PAGE_EXECUTE_READWRITE;
    }

    trap_manager.mutex.lock();
    defer trap_manager.mutex.unlock();
    trap_manager.add_trap(from, to, size) catch {
        return;
    };

    var from_protect: win.DWORD = 0;
    var to_protect: win.DWORD = 0;

    win.VirtualProtect(from, size, new_protect, &from_protect);
    win.VirtualProtect(to, size, new_protect, &to_protect);

    run_func();

    win.VirtualProtect(from, size, from_protect, &from_protect);
    win.VirtualProtect(to, size, to_protect, &to_protect);
}

fn fix_ip(thread_ctx: *win.CONTEXT, old_ip: MemPtr, new_ip: MemPtr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            if (thread_ctx.Rip == @intFromPtr(old_ip)) {
                thread_ctx.Rip = @ptrFromInt(new_ip);
            }
        },
        .x86 => {
            if (thread_ctx.Eip == @intFromPtr(old_ip)) {
                thread_ctx.Eip = @ptrFromInt(new_ip);
            }
        },
        else => @compileError("unsupported os"),
    }
}
