const builtin = @import("builtin");
const std = @import("std");
const os = @import("os.zig");
const common = @import("common.zig");
const allocator_mod = @import("allocator.zig");
const zydis = @import("zydis");

const FuncPtr = common.FuncPtr;
const MemPtr = common.MemPtr;

const JmpE9 = extern struct {
    opcode: u8 align(1) = 0xE9,
    relative_address: u32 align(1) = 0,

    pub fn make(from: os.MemPtr, to: os.MemPtr) JmpE9 {
        const from_int: isize = @intCast(@intFromPtr(from));
        const to_int: isize = @intCast(@intFromPtr(to));
        const offset = to_int - (from_int + 5);
        return JmpE9{
            .relative_address = @bitCast(@as(i32, @intCast(offset))),
        };
    }
};

const JmpFF = if (builtin.cpu.arch == .x86_64)
    extern struct {
        opcode1: u8 align(1) = 0xFF,
        opcode2: u8 align(1) = 0x25,
        address: u32 align(1) = 0,
    }
else
    void;

const TrampolineEpilogueE9 = if (builtin.cpu.arch == .x86_64)
    extern struct {
        jmp_to_original: JmpE9 align(1) = .{},
        jmp_to_destination: JmpFF align(1) = .{},
        destination_address: u64 align(1) = 0,
    }
else if (builtin.cpu.arch == .x86)
    extern struct {
        jmp_to_original: JmpE9 align(1) = .{},
        jmp_to_destination: JmpE9 align(1) = .{},
    }
else
    void;

const TrampolineEpilogueFF = if (builtin.cpu.arch == .x86_64)
    extern struct {
        jump_to_original: JmpFF align(1) = .{},
        original_address: u64 align(1) = 0,
    }
else
    void;

pub const InlineHookError = error{
    UnsupportedArchitecture,
    DecodeFailed,
    NotEnoughSpace,
    BadAllocation,
    UnsupportedInstructionInTrampoline,
    IpRelativeInstructionOutOfRange,
};

pub const InlineHookFlags = packed struct {
    start_disabled: bool = false,
};

const HookType = enum {
    unset,
    e9,
    ff,
};

const TrapContext = struct {
    hook: ?*InlineHook = null,
    epilogue_e9: ?*align(1) TrampolineEpilogueE9 = null,
    epilogue_ff: ?*align(1) TrampolineEpilogueFF = null,
    hook_error: ?InlineHookError = null,
};

var trap_context = TrapContext{};

pub const InlineHook = struct {
    m_target: MemPtr,
    m_destination: MemPtr,
    m_trampoline: allocator_mod.Allocation,
    m_trampoline_size: usize = 0,
    m_original_bytes: std.ArrayList(u8),
    m_enabled: bool = false,
    m_type: HookType = .unset,
    m_mutex: std.Thread.Mutex = .{},
    gpa: std.mem.Allocator,
    vm_allocator: *allocator_mod.VMAllocator,

    const Self = @This();

    pub fn create(src: FuncPtr, dest: FuncPtr, flags: InlineHookFlags) !InlineHook {
        const gpa = common.allocator.allocator();
        return create_with_alloc(gpa, allocator_mod.VMAllocator.global(), src, dest, flags);
    }

    pub fn create_with_alloc(gpa: std.mem.Allocator, vm_allocator: *allocator_mod.VMAllocator, src: FuncPtr, dest: FuncPtr, flags: InlineHookFlags) !InlineHook {
        var hook = InlineHook{
            .m_target = @ptrCast(@constCast(src)),
            .m_destination = @ptrCast(@constCast(dest)),
            .m_trampoline = .{ .ptr = null, .size = 0, .allocator = vm_allocator },
            .m_original_bytes = std.ArrayList(u8).empty,
            .vm_allocator = vm_allocator,
            .gpa = gpa,
        };

        errdefer hook.deinit();

        try hook.setup();

        if (!flags.start_disabled) {
            try hook.enable();
        }

        return hook;
    }

    pub fn trampoline(self: *Self) FuncPtr {
        return @ptrCast(self.m_trampoline.address());
    }

    pub fn hookType(self: *Self) HookType {
        return self.m_type;
    }

    pub fn deinit(self: *Self) void {
        self.disable() catch {};

        if (self.m_trampoline.isValid()) {
            self.vm_allocator.free(&self.m_trampoline);
        }

        self.m_original_bytes.deinit(self.gpa);
        self.m_original_bytes = std.ArrayList(u8).empty;
        self.m_trampoline = .{ .ptr = null, .size = 0, .allocator = self.vm_allocator };
        self.m_trampoline_size = 0;
        self.m_enabled = false;
        self.m_type = .unset;
    }

    fn setup(self: *Self) !void {
        if (comptime builtin.cpu.arch == .x86_64) {
            self.e9_hook() catch |err| switch (err) {
                InlineHookError.UnsupportedInstructionInTrampoline, InlineHookError.DecodeFailed => try self.ff_hook(),
                else => return err,
            };
        } else if (comptime builtin.cpu.arch == .x86) {
            try self.e9_hook();
        } else {
            return InlineHookError.UnsupportedArchitecture;
        }
    }

    pub fn enable(self: *Self) !void {
        self.m_mutex.lock();
        defer self.m_mutex.unlock();

        if (self.m_enabled) return;

        var hook_error: ?InlineHookError = null;

        if (self.m_type == .e9) {
            const epilogue: *align(1) TrampolineEpilogueE9 = @ptrCast(self.m_trampoline.address() + self.m_trampoline_size - @sizeOf(TrampolineEpilogueE9));
            trap_context = .{
                .hook = self,
                .epilogue_e9 = epilogue,
                .hook_error = null,
            };

            try os.trap_threads(self.m_target, self.m_trampoline.address(), self.m_original_bytes.items.len, enable_e9_callback);
            hook_error = trap_context.hook_error;
        }

        if (comptime builtin.cpu.arch == .x86_64) {
            if (self.m_type == .ff) {
                const epilogue: *align(1) TrampolineEpilogueFF = @ptrCast(self.m_trampoline.address() + self.m_trampoline_size - @sizeOf(TrampolineEpilogueFF));
                trap_context = .{
                    .hook = self,
                    .epilogue_ff = epilogue,
                    .hook_error = null,
                };

                try os.trap_threads(self.m_target, self.m_destination, self.m_original_bytes.items.len, enable_ff_callback);
                hook_error = trap_context.hook_error;
            }
        }

        if (hook_error) |err| return err;

        self.m_enabled = true;
    }

    pub fn disable(self: *Self) !void {
        self.m_mutex.lock();
        defer self.m_mutex.unlock();

        if (!self.m_enabled) return;

        trap_context = .{ .hook = self, .hook_error = null };
        try os.trap_threads(self.m_trampoline.address(), self.m_target, self.m_original_bytes.items.len, disable_callback);

        if (trap_context.hook_error) |err| return err;

        self.m_enabled = false;
    }

    fn e9_hook(self: *Self) !void {
        self.m_original_bytes.clearRetainingCapacity();
        self.m_trampoline_size = @sizeOf(TrampolineEpilogueE9);

        var desired = std.ArrayList(MemPtr).empty;
        defer desired.deinit(self.gpa);
        try desired.append(self.gpa, self.m_target);

        var ix: zydis.ZydisDecodedInstruction = undefined;

        var ip: MemPtr = self.m_target;
        const end_int = @intFromPtr(self.m_target) + 5;

        while (@intFromPtr(ip) < end_int) : (ip += ix.length) {
            try decode(&ix, ip);

            self.m_trampoline_size += ix.length;
            try self.m_original_bytes.appendSlice(self.gpa, ip[0..ix.length]);

            if (!is_relative(&ix)) continue;

            const ip_int: isize = @intCast(@intFromPtr(ip));
            const length: isize = @intCast(ix.length);

            if (ix.raw.disp.size == 32) {
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.disp.value));
                try desired.append(self.gpa, @ptrFromInt(@as(usize, @intCast(target_int))));
            } else if (ix.raw.imm[0].size == 32) {
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.imm[0].value.s));
                try desired.append(self.gpa, @ptrFromInt(@as(usize, @intCast(target_int))));
            } else if (ix.meta.category == zydis.ZYDIS_CATEGORY_COND_BR and ix.meta.branch_type == zydis.ZYDIS_BRANCH_TYPE_SHORT) {
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.imm[0].value.s));
                try desired.append(self.gpa, @ptrFromInt(@as(usize, @intCast(target_int))));
                self.m_trampoline_size += 4; // near conditional branches are 4 bytes larger
            } else if (ix.meta.category == zydis.ZYDIS_CATEGORY_UNCOND_BR and ix.meta.branch_type == zydis.ZYDIS_BRANCH_TYPE_SHORT) {
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.imm[0].value.s));
                try desired.append(self.gpa, @ptrFromInt(@as(usize, @intCast(target_int))));
                self.m_trampoline_size += 3; // near unconditional branches are 3 bytes larger
            } else {
                return InlineHookError.UnsupportedInstructionInTrampoline;
            }
        }

        self.m_trampoline = try self.vm_allocator.alloc_near(desired.items, self.m_trampoline_size, std.math.maxInt(usize));

        ip = self.m_target;
        var tramp_ip: MemPtr = self.m_trampoline.address();
        const copy_end = @intFromPtr(self.m_target) + self.m_original_bytes.items.len;

        while (@intFromPtr(ip) < copy_end) : (ip += ix.length) {
            try decode(&ix, ip);

            const ip_int: isize = @intCast(@intFromPtr(ip));
            var tramp_int: isize = @intCast(@intFromPtr(tramp_ip));
            const length: isize = @intCast(ix.length);

            if (is_relative(&ix) and ix.raw.disp.size == 32) {
                std.mem.copyForwards(u8, tramp_ip[0..ix.length], ip[0..ix.length]);
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.disp.value));
                const new_disp = target_int - (tramp_int + length);
                store_i32(@ptrFromInt(@as(usize, @intCast(tramp_int + ix.raw.disp.offset))), @intCast(new_disp));
                tramp_int += length;
            } else if (is_relative(&ix) and ix.raw.imm[0].size == 32) {
                std.mem.copyForwards(u8, tramp_ip[0..ix.length], ip[0..ix.length]);
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.imm[0].value.s));
                const new_disp = target_int - (tramp_int + length);
                store_i32(@ptrFromInt(@as(usize, @intCast(tramp_int + ix.raw.imm[0].offset))), @intCast(new_disp));
                tramp_int += length;
            } else if (ix.meta.category == zydis.ZYDIS_CATEGORY_COND_BR and ix.meta.branch_type == zydis.ZYDIS_BRANCH_TYPE_SHORT) {
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.imm[0].value.s));
                var new_disp = target_int - (tramp_int + 6);

                const start_int = @intFromPtr(self.m_target);
                const end_int2 = start_int + self.m_original_bytes.items.len;
                if (target_int >= @as(isize, @intCast(start_int)) and target_int < @as(isize, @intCast(end_int2))) {
                    new_disp = @as(isize, @intCast(ix.raw.imm[0].value.s));
                }

                tramp_ip[0] = 0x0F;
                tramp_ip[1] = 0x10 + ix.opcode;
                store_i32(@ptrFromInt(@as(usize, @intCast(tramp_int + 2))), @intCast(new_disp));
                tramp_int += 6;
            } else if (ix.meta.category == zydis.ZYDIS_CATEGORY_UNCOND_BR and ix.meta.branch_type == zydis.ZYDIS_BRANCH_TYPE_SHORT) {
                const target_int = ip_int + length + @as(isize, @intCast(ix.raw.imm[0].value.s));
                var new_disp = target_int - (tramp_int + 5);

                const start_int = @intFromPtr(self.m_target);
                const end_int2 = start_int + self.m_original_bytes.items.len;
                if (target_int >= @as(isize, @intCast(start_int)) and target_int < @as(isize, @intCast(end_int2))) {
                    new_disp = @as(isize, @intCast(ix.raw.imm[0].value.s));
                }

                tramp_ip[0] = 0xE9;
                store_i32(@ptrFromInt(@as(usize, @intCast(tramp_int + 1))), @intCast(new_disp));
                tramp_int += 5;
            } else {
                std.mem.copyForwards(u8, tramp_ip[0..ix.length], ip[0..ix.length]);
                tramp_int += length;
            }

            tramp_ip = @ptrFromInt(@as(usize, @intCast(tramp_int)));
        }

        const trampoline_epilogue: *align(1) TrampolineEpilogueE9 = @ptrCast(self.m_trampoline.address() + self.m_trampoline_size - @sizeOf(TrampolineEpilogueE9));

        try emit_jmp_e9(@ptrCast(&trampoline_epilogue.jmp_to_original), self.m_target + self.m_original_bytes.items.len, 5);

        if (comptime builtin.cpu.arch == .x86_64) {
            try emit_jmp_ff(@ptrCast(&trampoline_epilogue.jmp_to_destination), self.m_destination, @ptrCast(&trampoline_epilogue.destination_address), 6);
        } else {
            try emit_jmp_e9(@ptrCast(&trampoline_epilogue.jmp_to_destination), self.m_destination, 5);
        }

        self.m_type = .e9;
    }

    fn ff_hook(self: *Self) !void {
        if (comptime builtin.cpu.arch != .x86_64) return InlineHookError.UnsupportedArchitecture;

        self.m_original_bytes.clearRetainingCapacity();
        self.m_trampoline_size = @sizeOf(TrampolineEpilogueFF);

        var ix: zydis.ZydisDecodedInstruction = undefined;

        var ip: MemPtr = self.m_target;
        const end_int = @intFromPtr(self.m_target) + 6 + @sizeOf(usize);

        while (@intFromPtr(ip) < end_int) : (ip += ix.length) {
            try decode(&ix, ip);

            if ((ix.attributes & zydis.ZYDIS_ATTRIB_IS_RELATIVE) != 0) {
                return InlineHookError.IpRelativeInstructionOutOfRange;
            }

            try self.m_original_bytes.appendSlice(self.gpa, ip[0..ix.length]);
            self.m_trampoline_size += ix.length;
        }

        self.m_trampoline = try self.vm_allocator.alloc(self.m_trampoline_size);

        std.mem.copyForwards(u8, self.m_trampoline.address()[0..self.m_original_bytes.items.len], self.m_original_bytes.items);

        const trampoline_epilogue: *align(1) TrampolineEpilogueFF = @ptrCast(self.m_trampoline.address() + self.m_trampoline_size - @sizeOf(TrampolineEpilogueFF));

        try emit_jmp_ff(@ptrCast(&trampoline_epilogue.jump_to_original), self.m_target + self.m_original_bytes.items.len, @ptrCast(&trampoline_epilogue.original_address), 6);

        self.m_type = .ff;
    }
};

fn decode(ix: *zydis.ZydisDecodedInstruction, ip: [*]const u8) InlineHookError!void {
    var decoder: zydis.ZydisDecoder = undefined;
    var status: zydis.ZyanStatus = undefined;

    if (builtin.cpu.arch == .x86_64) {
        status = zydis.ZydisDecoderInit(&decoder, zydis.ZYDIS_MACHINE_MODE_LONG_64, zydis.ZYDIS_STACK_WIDTH_64);
    } else if (builtin.cpu.arch == .x86) {
        status = zydis.ZydisDecoderInit(&decoder, zydis.ZYDIS_MACHINE_MODE_LEGACY_32, zydis.ZYDIS_STACK_WIDTH_32);
    } else {
        return InlineHookError.UnsupportedArchitecture;
    }

    if (!zydis.ZYAN_SUCCESS(status)) {
        return InlineHookError.DecodeFailed;
    }

    status = zydis.ZydisDecoderDecodeInstruction(
        &decoder,
        null,
        ip,
        15,
        ix,
    );

    if (!zydis.ZYAN_SUCCESS(status)) {
        return InlineHookError.DecodeFailed;
    }
}

fn is_relative(ix: *const zydis.ZydisDecodedInstruction) bool {
    return (ix.attributes & zydis.ZYDIS_ATTRIB_IS_RELATIVE) != 0;
}

fn store_value(dest: MemPtr, value: anytype) void {
    const bytes = std.mem.asBytes(&value);
    std.mem.copyForwards(u8, dest[0..bytes.len], bytes);
}

fn store_i32(dest: MemPtr, value: i32) void {
    std.mem.writeInt(i32, dest[0..@sizeOf(i32)], value, .little);
}

fn emit_jmp_e9(src: MemPtr, dst: MemPtr, size: usize) InlineHookError!void {
    if (size < 5) return InlineHookError.NotEnoughSpace;

    if (size > 5) {
        for (0..size) |i| {
            src[i] = 0x90;
        }
    }

    const jmp = JmpE9.make(src, dst);
    store_value(src, jmp);
}

fn make_jmp_ff(src: MemPtr, dst: MemPtr, data: MemPtr) JmpFF {
    var jmp: JmpFF = .{};
    const offset = @intFromPtr(data) - (@intFromPtr(src) + 6);
    jmp.address = @bitCast(@as(i32, @intCast(offset)));
    store_value(data, dst);
    return jmp;
}

fn emit_jmp_ff(src: MemPtr, dst: MemPtr, data: MemPtr, size: usize) InlineHookError!void {
    if (comptime builtin.cpu.arch != .x86_64) return InlineHookError.UnsupportedArchitecture;
    if (size < 6) return InlineHookError.NotEnoughSpace;

    if (size > 6) {
        for (0..size) |i| {
            src[i] = 0x90;
        }
    }

    const jmp = make_jmp_ff(src, dst, data);
    store_value(src, jmp);
}

fn enable_e9_callback() void {
    if (trap_context.hook) |hook| {
        const ep = trap_context.epilogue_e9.?;
        emit_jmp_e9(hook.m_target, @ptrCast(&ep.jmp_to_destination), hook.m_original_bytes.items.len) catch |err| {
            trap_context.hook_error = err;
        };
    }
}
fn enable_ff_callback() void {
    if (trap_context.hook) |hook| {
        const data_ptr: MemPtr = @ptrFromInt(@intFromPtr(hook.m_target) + @sizeOf(JmpFF));
        emit_jmp_ff(hook.m_target, hook.m_destination, data_ptr, hook.m_original_bytes.items.len) catch |err| {
            trap_context.hook_error = err;
        };
    }
}

fn disable_callback() void {
    if (trap_context.hook) |hook| {
        std.mem.copyForwards(u8, hook.m_target[0..hook.m_original_bytes.items.len], hook.m_original_bytes.items);
    }
}
