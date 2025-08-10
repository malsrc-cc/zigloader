const std = @import("std");
const windows = std.os.windows;
const Syscalls = @import("../syscall.zig").Syscalls;

pub fn sleep(syscalls: Syscalls, ms: usize) void {
    const interval: windows.LARGE_INTEGER = -@as(windows.LARGE_INTEGER, @intCast(ms * 10_000));
    _ = syscalls.NtDelayExecution.?.syscall4(
        0, // false
        @intFromPtr(&interval),
        0, 0, // unused
    );
}
