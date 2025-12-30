const safetyhook = @import("safetyhook");
const std = @import("std");

noinline fn hook() void {
    std.debug.print("Hooked!\n", .{});
}

noinline fn original_function(a: u32, b: u32) callconv(.c) u32 {
    return a * b;
}

pub noinline fn main() !void {
    std.mem.doNotOptimizeAway(try safetyhook.create_inline(original_function, hook, .{}));

    const result = original_function(6, 7);

    std.debug.print("Result: {}\n", .{result});
}
