const builtin = @import("builtin");
const std = @import("std");
const os = @import("os.zig");
const common = @import("common.zig");
const allocator_mod = @import("allocator.zig");
const zydis = @import("zydis");

const JmpE9 = packed struct {
    opcode: u8 = 0xE9,
    relative_address: i32,

    pub fn make(from: os.MemPtr, to: os.MemPtr) JmpE9 {
        const offset = @intFromPtr(to) - (@intFromPtr(from) + @sizeOf(JmpE9));
        return JmpE9{
            .relative_address = @intCast(offset),
        };
    }
};

const JmpFF = if (builtin.cpu.arch == .x86_64)
    packed struct {
        opcode1: u8 = 0xFF,
        opcode2: u8 = 0x25,
        address: u32 = 0,
    }
else
    void;

const TrampolineEpilogueE9 = if (builtin.cpu.arch == .x86_64)
    packed struct {
        jmp_to_original: JmpE9 = .{},
        jmp_to_destination: JmpFF = .{},
        destination_address: u64 = 0,
    }
else if (builtin.cpu.arch == .x86)
    packed struct {
        jmp_to_original: JmpE9 = .{},
        jmp_to_destination: JmpE9 = .{},
    }
else
    void;

const TrampolineEpilogueFF = if (builtin.cpu.arch == .x86_64)
    packed struct {
        jump_to_original: JmpFF = .{},
        original_address: u64 = 0,
    }
else
    void;

pub const InlineHookError = error{
    UnsupportedArchitecture,
    DecodeFailed,
};

pub const InlineHookFlags = packed struct {
    start_disabled: bool = false,
};

pub const InlineHook = struct {
    pub fn create(src: common.FuncPtr, dest: common.FuncPtr, flags: InlineHookFlags) !InlineHook {
        return create_with_alloc(allocator_mod.VMAllocator.global(), src, dest, flags);
    }

    pub fn create_with_alloc(allocator: *allocator_mod.VMAllocator, src: common.FuncPtr, dest: common.FuncPtr, flags: InlineHookFlags) !InlineHook {
        _ = .{
            allocator,
            src,
            dest,
            flags,
        };
        return .{};
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
        return error.UnsupportedArchitecture;
    }

    if (!zydis.ZYAN_SUCCESS(status)) {
        return error.DecodeFailed;
    }

    status = zydis.ZydisDecoderDecodeInstruction(
        &decoder,
        null,
        ip,
        15,
        ix,
    );

    if (!zydis.ZYAN_SUCCESS(status)) {
        return error.DecodeFailed;
    }
}
