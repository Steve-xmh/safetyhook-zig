const safetyhook = @import("safetyhook");
const std = @import("std");
const builtin = @import("builtin");

noinline fn hook(ctx: *safetyhook.Context) callconv(.c) void {
    std.debug.print("Middle function has called!\n", .{});
    if (comptime builtin.os.tag == .windows) {
        if (comptime builtin.cpu.arch == .x86_64) {
            ctx.rcx = 1337 - 42;
        } else if (comptime builtin.cpu.arch == .x86) {
            ctx.ecx = 1337 - 42;
        }
    } else if (comptime builtin.os.tag == .linux) {
        if (comptime builtin.cpu.arch == .x86_64) {
            ctx.rdi = 1337 - 42;
        } else if (comptime builtin.cpu.arch == .x86) {
            ctx.edi = 1337 - 42;
        }
    }
}

noinline fn original_function(a: u32) callconv(.c) u32 {
    return a + 42;
}

pub noinline fn main() !void {
    std.debug.print("Hooking original_function at: 0x{x}\n", .{@intFromPtr(&original_function)});

    var handle = try safetyhook.create_mid(original_function, hook, .{});
    std.mem.doNotOptimizeAway(handle);

    try std.testing.expectEqual(1337, original_function(1));
    std.debug.print("original_function returned expected value after hook.\n", .{});

    handle.deinit();

    try std.testing.expectEqual(44, original_function(2));
    std.debug.print("original_function returned expected value after unhook.\n", .{});
}
