pub const common = @import("common.zig");
const os = @import("os.zig");
const allocator = @import("allocator.zig");
const inline_hook = @import("inline_hook.zig");

pub const MemPtr = common.MemPtr;
pub const FuncPtr = common.FuncPtr;
pub const InlineHook = inline_hook.InlineHook;
pub const InlineHookFlags = inline_hook.InlineHookFlags;

pub inline fn create_inline(src: FuncPtr, dest: FuncPtr, flags: InlineHookFlags) !InlineHook {
    return try InlineHook.create(src, dest, flags);
}

test "test" {
    _ = .{
        @import("os.zig"),
        @import("allocator.zig"),
        @import("inline_hook.zig"),
    };
}
