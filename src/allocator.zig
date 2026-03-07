const common = @import("common.zig");
const os = @import("os.zig");
const std = @import("std");
const utility = @import("utility.zig");
const log = std.log.scoped(.allocator);

const FreeNode = struct {
    next: ?*FreeNode,
    start: common.MemPtr,
    end: common.MemPtr,
};

const Memory = struct {
    address: common.MemPtr,
    size: usize,
    free_list: ?*FreeNode,
};

pub const Allocation = struct {
    ptr: ?common.MemPtr = undefined,
    size: usize = 0,
    allocator: *VMAllocator = undefined,

    pub inline fn isValid(self: Allocation) bool {
        return self.ptr != null;
    }

    pub inline fn address(self: Allocation) common.MemPtr {
        return self.ptr.?;
    }

    pub fn deinit(self: *Allocation) void {
        self.allocator.free(self);
    }
};

var global_vm_allocator = VMAllocator.init(common.allocator.allocator());

pub const VMAllocator = struct {
    const Self = @This();

    m_memory: std.ArrayListUnmanaged(Memory),
    allocator: std.mem.Allocator,
    m_mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .m_memory = .{},
            .allocator = allocator,
            .m_mutex = .{},
        };
    }

    pub inline fn global() *Self {
        return &global_vm_allocator;
    }

    pub fn alloc(self: *Self, size: usize) !Allocation {
        return self.alloc_near(&[_]common.MemPtr{}, size, std.math.maxInt(usize));
    }

    pub fn alloc_near(self: *Self, desired_addrs: []const common.MemPtr, size: usize, max_distance: usize) !Allocation {
        self.m_mutex.lock();
        defer self.m_mutex.unlock();
        return self.internal_allocate_near(desired_addrs, size, max_distance);
    }

    pub fn free(self: *Self, allocation: *Allocation) void {
        if (allocation.ptr == null or allocation.size == 0) {
            allocation.* = .{};
            return;
        }

        self.m_mutex.lock();
        defer self.m_mutex.unlock();

        self.internal_free(allocation.address(), allocation.size) catch |err| {
            // Allocation struct is reset regardless to avoid double free attempts.
            allocation.* = .{};
            std.debug.panic("allocator free failed: {s}", .{@errorName(err)});
        };

        allocation.* = .{};
    }

    fn internal_allocate_near(self: *Self, desired_addrs: []const common.MemPtr, size: usize, max_distance: usize) !Allocation {
        // Align to 2 bytes to pass MFP virtual method check
        // See https://itanium-cxx-abi.github.io/cxx-abi/abi.html#member-function-pointers
        const aligned_size = utility.align_up(size, 2);

        // First search through our list of allocations for a free block that is large enough.
        for (self.m_memory.items) |memory| {
            if (memory.size < aligned_size) continue;

            var node_opt = memory.free_list;
            while (node_opt) |node| : (node_opt = node.next) {
                if (@intFromPtr(node.end) - @intFromPtr(node.start) < aligned_size) continue;

                const address = node.start;
                if (!in_range(address, desired_addrs, max_distance)) continue;

                node.start = node.start + aligned_size;

                return Allocation{
                    .ptr = address,
                    .size = size,
                    .allocator = self,
                };
            }
        }

        // If we didn't find a free block, allocate a new one near the desired addresses.
        const si = system_info();
        const allocation_size = utility.align_up(aligned_size, si.allocation_granularity);
        const allocation_address = try self.allocate_nearby_memory(desired_addrs, allocation_size, max_distance);

        var free_node: ?*FreeNode = null;
        const remainder = allocation_size - aligned_size;
        if (remainder > 0) {
            free_node = try make_free_node(self.allocator, allocation_address + aligned_size, allocation_address + allocation_size);
        }

        try self.m_memory.append(self.allocator, .{
            .address = allocation_address,
            .size = allocation_size,
            .free_list = free_node,
        });

        return Allocation{
            .ptr = allocation_address,
            .size = size,
            .allocator = self,
        };
    }

    pub fn protect(self: *Self, ptr: os.MemPtr, size: usize, access: os.VmAccess) !os.VmAccess {
        _ = self;
        return os.vm_protect(ptr, size, access);
    }

    fn internal_free(self: *Self, address: common.MemPtr, size: usize) !void {
        const aligned_size = utility.align_up(size, 2);

        for (self.m_memory.items) |*memory| {
            const start_ok = @intFromPtr(memory.address) <= @intFromPtr(address);
            const end_ok = @intFromPtr(memory.address) + memory.size > @intFromPtr(address);
            if (!start_ok or !end_ok) continue;

            var prev: ?*FreeNode = null;
            var node_opt = memory.free_list;
            while (node_opt) |node| : (node_opt = node.next) {
                if (@intFromPtr(node.start) > @intFromPtr(address)) break;
                prev = node;
            }

            const free_node = try make_free_node(self.allocator, address, address + aligned_size);

            if (prev == null) {
                free_node.next = memory.free_list;
                memory.free_list = free_node;
            } else {
                free_node.next = prev.?.next;
                prev.?.next = free_node;
            }

            self.combine_adjacent(memory);
            return;
        }

        return error.MemoryNotOwned;
    }

    fn combine_adjacent(self: *Self, memory: *Memory) void {
        var prev_opt = memory.free_list;
        if (prev_opt == null) return;

        var node_opt = prev_opt.?.next;
        while (node_opt) |node| {
            if (prev_opt.?.end == node.start) {
                prev_opt.?.end = node.end;
                prev_opt.?.next = node.next;
                self.allocator.destroy(node);
                node_opt = prev_opt.?.next;
            } else {
                prev_opt = node;
                node_opt = node.next;
            }
        }
    }

    fn allocate_nearby_memory(self: *Self, desired_addrs: []const common.MemPtr, size: usize, max_distance: usize) !common.MemPtr {
        _ = self;
        if (desired_addrs.len == 0) {
            return os.vm_allocate(null, size, os.VmAccess.RWX);
        }

        const si = system_info();
        const desired_address_unaligned = desired_addrs[0];

        var search_start = si.min_address;
        var search_end = si.max_address;

        if (ptr_diff(desired_address_unaligned, search_start) > max_distance) {
            search_start = desired_address_unaligned - max_distance;
        }

        if (ptr_diff(search_end, desired_address_unaligned) > max_distance) {
            search_end = desired_address_unaligned + max_distance;
        }

        search_start = @ptrFromInt(@max(@intFromPtr(search_start), @intFromPtr(si.min_address)));
        search_end = @ptrFromInt(@min(@intFromPtr(search_end), @intFromPtr(si.max_address)));

        const desired_address = align_ptr_up(desired_address_unaligned, si.allocation_granularity);
        var mbi = os.VmBasicInfo{
            .address = desired_address,
            .size = si.allocation_granularity,
            .access = .{},
            .is_free = false,
        };

        const attempt_allocation = struct {
            fn run(ptr: common.MemPtr, desired: []const common.MemPtr, alloc_size: usize, max_dist: usize) ?common.MemPtr {
                if (!in_range(ptr, desired, max_dist)) return null;
                const allocation = os.vm_allocate(ptr, alloc_size, os.VmAccess.RWX) catch return null;
                return allocation;
            }

            fn run_in_region(
                mbi_info: os.VmBasicInfo,
                probe: common.MemPtr,
                prefer_high: bool,
                desired: []const common.MemPtr,
                alloc_size: usize,
                max_dist: usize,
                granularity: usize,
            ) ?common.MemPtr {
                const region_start_int = utility.align_up(@intFromPtr(mbi_info.address), granularity);
                const region_end_int = @intFromPtr(mbi_info.address) + mbi_info.size;

                if (region_end_int <= region_start_int) return null;

                const available = region_end_int - region_start_int;
                if (available < alloc_size) return null;

                const max_base_int = region_end_int - alloc_size;
                const probe_int = @intFromPtr(probe);

                var candidate_int = if (prefer_high)
                    utility.align_down(@min(probe_int, max_base_int), granularity)
                else
                    utility.align_up(@max(probe_int, region_start_int), granularity);

                if (candidate_int < region_start_int) {
                    candidate_int = region_start_int;
                }

                if (candidate_int > max_base_int) {
                    candidate_int = utility.align_down(max_base_int, granularity);
                }

                if (candidate_int < region_start_int or candidate_int > max_base_int) return null;

                const primary = run(@ptrFromInt(candidate_int), desired, alloc_size, max_dist);
                if (primary) |addr| return addr;

                const fallback_int = if (prefer_high)
                    region_start_int
                else
                    utility.align_down(max_base_int, granularity);

                if (fallback_int == candidate_int) return null;
                if (fallback_int < region_start_int or fallback_int > max_base_int) return null;

                return run(@ptrFromInt(fallback_int), desired, alloc_size, max_dist);
            }
        };

        // Search backwards from the desired address.
        var p = desired_address;
        while (@intFromPtr(p) > @intFromPtr(search_start) and in_range(p, desired_addrs, max_distance)) : (p = align_ptr_down(mbi.address - 1, si.allocation_granularity)) {
            mbi = vm_query(p) catch |err| {
                log.err("backward vm_query failed at 0x{x}: {s}", .{ @intFromPtr(p), @errorName(err) });
                break;
            };
            if (!mbi.is_free) continue;
            if (attempt_allocation.run_in_region(mbi, p, true, desired_addrs, size, max_distance, si.allocation_granularity)) |addr| return addr;
        }

        // Search forwards from the desired address.
        p = desired_address;
        while (@intFromPtr(p) < @intFromPtr(search_end) and in_range(p, desired_addrs, max_distance)) : (p += mbi.size) {
            mbi = vm_query(p) catch |err| {
                log.err("forward vm_query failed at 0x{x}: {s}", .{ @intFromPtr(p), @errorName(err) });
                break;
            };
            if (!mbi.is_free) continue;
            if (attempt_allocation.run_in_region(mbi, p, false, desired_addrs, size, max_distance, si.allocation_granularity)) |addr| return addr;
        }

        log.err(
            "NoMemoryInRange: desired0=0x{x}, size={}, max_distance=0x{x}, search=[0x{x},0x{x}]",
            .{ @intFromPtr(desired_address_unaligned), size, max_distance, @intFromPtr(search_start), @intFromPtr(search_end) },
        );

        return error.NoMemoryInRange;
    }
};

fn make_free_node(allocator: std.mem.Allocator, start: common.MemPtr, end: common.MemPtr) !*FreeNode {
    const node = try allocator.create(FreeNode);
    node.* = .{
        .next = null,
        .start = start,
        .end = end,
    };
    return node;
}

fn ptr_diff(a: common.MemPtr, b: common.MemPtr) usize {
    const ai = @intFromPtr(a);
    const bi = @intFromPtr(b);
    return if (ai > bi) ai - bi else bi - ai;
}

fn align_ptr_up(ptr: common.MemPtr, alignment: usize) common.MemPtr {
    const aligned = utility.align_up(@intFromPtr(ptr), alignment);
    return @ptrFromInt(aligned);
}

fn align_ptr_down(ptr: common.MemPtr, alignment: usize) common.MemPtr {
    const aligned = utility.align_down(@intFromPtr(ptr), alignment);
    return @ptrFromInt(aligned);
}

fn in_range(address: common.MemPtr, desired_addrs: []const common.MemPtr, max_distance: usize) bool {
    if (desired_addrs.len == 0) return true;
    for (desired_addrs) |desired| {
        if (ptr_diff(address, desired) > max_distance) return false;
    }
    return true;
}

fn system_info() os.SystemInfo {
    var si = std.mem.zeroes(std.os.windows.SYSTEM_INFO);
    std.os.windows.kernel32.GetSystemInfo(&si);

    return .{
        .page_size = si.dwPageSize,
        .allocation_granularity = si.dwAllocationGranularity,
        .min_address = @ptrCast(si.lpMinimumApplicationAddress),
        .max_address = @ptrCast(si.lpMaximumApplicationAddress),
    };
}

fn convert_protect_to_access(protect: std.os.windows.DWORD) !os.VmAccess {
    const win = std.os.windows;
    const p = protect & 0xFF;
    return switch (p) {
        win.PAGE_NOACCESS => .{},
        win.PAGE_READONLY => os.VmAccess.R,
        win.PAGE_READWRITE => os.VmAccess.RW,
        win.PAGE_WRITECOPY => os.VmAccess.RW,
        win.PAGE_EXECUTE => os.VmAccess.X,
        win.PAGE_EXECUTE_READ => os.VmAccess.RX,
        win.PAGE_EXECUTE_READWRITE => os.VmAccess.RWX,
        win.PAGE_EXECUTE_WRITECOPY => os.VmAccess.RWX,
        else => .{},
    };
}

fn vm_query(ptr: common.MemPtr) !os.VmBasicInfo {
    const win = std.os.windows;
    var mem_info: win.MEMORY_BASIC_INFORMATION = undefined;
    const result_size = win.VirtualQuery(
        @ptrCast(ptr),
        &mem_info,
        @sizeOf(win.MEMORY_BASIC_INFORMATION),
    ) catch return error.QueryFailed;
    if (result_size == 0) {
        return error.QueryFailed;
    }

    const is_free = mem_info.State == win.MEM_FREE;
    const access = if (is_free) os.VmAccess{} else try convert_protect_to_access(mem_info.Protect);

    return .{
        .address = @ptrCast(mem_info.BaseAddress),
        .size = mem_info.RegionSize,
        .access = access,
        .is_free = is_free,
    };
}

test "allocator" {
    const allocator = VMAllocator.global();

    var allocation = try allocator.alloc(128);
    defer allocator.free(&allocation);
}
