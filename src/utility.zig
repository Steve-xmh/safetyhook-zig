pub fn align_up(addr: anytype, alignment: usize) @TypeOf(addr) {
    const is_pointer = comptime @typeInfo(@TypeOf(addr)) == .pointer;
    const addr_val: usize = if (is_pointer) @intFromPtr(addr) else addr;
    const aligned = (addr_val + alignment - 1) & ~(alignment - 1);
    if (is_pointer) {
        return @ptrFromInt(aligned);
    } else {
        return @intCast(aligned);
    }
}

pub fn align_down(addr: anytype, alignment: usize) @TypeOf(addr) {
    const is_pointer = comptime @typeInfo(@TypeOf(addr)) == .pointer;
    const addr_val: usize = if (is_pointer) @intFromPtr(addr) else addr;
    const aligned = addr_val & ~(alignment - 1);
    if (is_pointer) {
        return @ptrFromInt(aligned);
    } else {
        return @intCast(aligned);
    }
}
