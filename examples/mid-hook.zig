const safetyhook = @import("safetyhook");
const std = @import("std");

fn hook() void {
    std.debug.print("Hooked!\n", .{});
}

fn original_function(a: u32, b: u32) u32 {
    return a * b;
}

pub fn main() !void {
    _ = try safetyhook.create_inline(original_function, hook, .{});

    const result = original_function(3, 4);
    std.debug.print("Result: {}\n", .{result});
}
