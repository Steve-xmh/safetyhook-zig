const safetyhook = @import("safetyhook");
const std = @import("std");

var hook_handle: safetyhook.InlineHook = undefined;

noinline fn hook(a: u32, b: u32) callconv(.c) u32 {
    std.debug.print("Hooked!\n", .{});
    const original: *const fn (u32, u32) callconv(.c) u32 = @ptrCast(hook_handle.trampoline());
    return original(a, b);
}

noinline fn original_function(a: u32, b: u32) callconv(.c) u32 {
    std.debug.print("Original function called with: {}, {}\n", .{ a, b });
    return a * b;
}

pub noinline fn main() !void {
    std.debug.print("Hooking original_function at: 0x{x}\n", .{@intFromPtr(&original_function)});
    hook_handle = try safetyhook.create_inline(original_function, hook, .{});
    std.mem.doNotOptimizeAway(hook_handle);

    const result = original_function(6, 7);

    std.debug.print("Result: {}\n", .{result});
}
