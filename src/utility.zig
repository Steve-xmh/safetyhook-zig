pub fn align_up(addr: anytype, alignment: usize) @TypeOf(addr) {
    const mask = @as(@TypeOf(addr), alignment - 1);
    return (addr + mask) & ~mask;
}

pub fn align_down(addr: anytype, alignment: usize) @TypeOf(addr) {
    const mask = @as(@TypeOf(addr), alignment - 1);
    return addr & ~mask;
}
