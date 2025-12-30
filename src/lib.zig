pub const common = @import("common.zig");
const os = @import("os.zig");
const allocator = @import("allocator.zig");
const inline_hook = @import("inline_hook.zig");
const mid_hook = @import("mid_hook.zig");

pub const MemPtr = common.MemPtr;
pub const FuncPtr = common.FuncPtr;
pub const InlineHook = inline_hook.InlineHook;
pub const InlineHookFlags = inline_hook.InlineHookFlags;
pub const MidHook = mid_hook.MidHook;
pub const MidHookFlags = mid_hook.MidHookFlags;
pub const MidHookFn = mid_hook.MidHookFn;
pub const Context = mid_hook.Context;

pub inline fn create_inline(src: FuncPtr, dest: FuncPtr, flags: InlineHookFlags) !InlineHook {
    return try InlineHook.create(src, dest, flags);
}

pub inline fn create_mid(src: FuncPtr, dest: MidHookFn, flags: MidHookFlags) !MidHook {
    return try MidHook.create(src, dest, flags);
}

test "test" {
    _ = .{
        @import("os.zig"),
        @import("allocator.zig"),
        @import("inline_hook.zig"),
    };
}
