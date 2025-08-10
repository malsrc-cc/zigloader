const std = @import("std");
const windows = std.os.windows;
const Syscalls = @import("../syscall.zig").Syscalls;
const win32 = @import("../win32.zig");

pub const DynamicBuffer = struct {
    syscalls: Syscalls,

    data: []u8,
    len: usize,
    capacity: usize,
    
    pub fn init(syscalls: Syscalls, initial_capacity: usize) !DynamicBuffer {
        const data = try ntAlloc(
            syscalls,
            null,
            initial_capacity,
            windows.MEM_COMMIT | windows.MEM_RESERVE,
            windows.PAGE_READWRITE,
        );
        return DynamicBuffer{
            .syscalls = syscalls,
            .data = data,
            .len = 0,
            .capacity = initial_capacity,
        };
    }
    
    pub fn ensureCapacity(self: *DynamicBuffer, new_capacity: usize) !void {
        if (new_capacity <= self.capacity) return;
        
        const new_data = try ntAlloc(
            self.syscalls,
            null,
            new_capacity,
            windows.MEM_COMMIT | windows.MEM_RESERVE,
            windows.PAGE_READWRITE,
        );
        @memcpy(new_data[0..self.len], self.data[0..self.len]);
        ntFree(self.syscalls, self.data);
        
        self.data = new_data;
        self.capacity = new_capacity;
    }
    
    pub fn append(self: *DynamicBuffer, data: []const u8) !void {
        const new_len = self.len + data.len;
        try self.ensureCapacity(new_len);
        @memcpy(self.data[self.len..new_len], data);
        self.len = new_len;
    }
    
    pub fn toOwnedSlice(self: *DynamicBuffer) []u8 {
        const result = self.data[0..self.len];
        self.data = &[_]u8{};
        self.len = 0;
        self.capacity = 0;
        return result;
    }

    pub fn deinit(self: *DynamicBuffer) void {
        ntFree(self.syscalls, self.data);
    }
};

pub fn ntAlloc(
    syscalls: Syscalls,
    h_process: ?windows.HANDLE,
    alloc_size: usize,
    alloc_type: windows.ULONG,
    protection: windows.ULONG
) ![]u8 {
    var base_addr: ?windows.LPVOID = null;
    var region_size: windows.SIZE_T = alloc_size;

    const status = syscalls.NtAllocateVirtualMemory.?.syscall6(
        if (h_process == null) @intFromPtr(win32.NtCurrentProcess()) else @intFromPtr(h_process),
        @intFromPtr(&base_addr),
        0,
        @intFromPtr(&region_size),
        @intCast(alloc_type),
        @intCast(protection),
    );
    if (status != win32.STATUS_SUCCESS or base_addr == null) {
        return error.AllocationFailed;
    }
    
    return @as([*]u8, @ptrCast(base_addr.?))[0..region_size];
}

pub fn ntAllocWriteProtect(
    syscalls: Syscalls,
    h_process: ?windows.HANDLE,
    alloc_size: usize,
    alloc_type: windows.ULONG,
    buffer: []const u8,
) !windows.LPVOID {
    const addr = try ntAlloc(syscalls, h_process, alloc_size, alloc_type, windows.PAGE_READWRITE);
    try ntWrite(syscalls, h_process, addr.ptr, buffer);
    try ntProtect(syscalls, h_process, addr.ptr, alloc_size, windows.PAGE_EXECUTE_READWRITE);
    return addr.ptr; // needs to be freed by caller
}

pub fn ntClose(syscalls: Syscalls, handle: windows.HANDLE) void {
    _ = syscalls.NtClose.?.syscall4(
        @intFromPtr(handle),
        0, 0, 0, // unused
    );
}

pub fn ntCreateRemoteThread(
    syscalls: Syscalls,
    h_process: ?windows.HANDLE,
    addr_ptr: windows.LPVOID,
) !windows.HANDLE {
    var h_thread: ?windows.HANDLE = null;
    var obj_attrs = win32.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(win32.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = null,
        .Attributes = windows.OBJ_INHERIT,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    const status = syscalls.NtCreateThreadEx.?.syscall12(
        @intFromPtr(&h_thread),
        @intCast(win32.THREAD_ALL_ACCESS),
        @intFromPtr(&obj_attrs),
        if (h_process == null) @intFromPtr(win32.NtCurrentProcess()) else @intFromPtr(h_process),
        @intFromPtr(@as(*win32.USER_THREAD_START_ROUTINE, @alignCast(@ptrCast(addr_ptr)))),
        0, 0, 0, 0, 0, 0, 0,
    );
    if (status != win32.STATUS_SUCCESS or h_thread == windows.INVALID_HANDLE_VALUE) {
        return error.NtCreateThreadExFailed;
    }

    return h_thread.?; // needs to be closed by caller
}

pub fn ntCreateSection(
    syscalls: Syscalls,
    size_ptr: *windows.LARGE_INTEGER,
) !windows.HANDLE {
    var h_section: ?windows.HANDLE = null;

    const status = syscalls.NtCreateSection.?.syscall12(
        @intFromPtr(&h_section),
        @intCast(windows.SECTION_ALL_ACCESS),
        0, // null
        @intFromPtr(size_ptr),
        @intCast(windows.PAGE_EXECUTE_READWRITE),
        @intCast(windows.SEC_COMMIT),
        0, // null
        0, 0, 0, 0, 0, // unused
    );
    if (status != win32.STATUS_SUCCESS or h_section == null) {
        return error.NtCreateSectionFailed;
    }

    return h_section.?; // needs to be closed by caller
}

pub fn ntFree(syscalls: Syscalls, memory: []u8) void {
    var base_address: ?windows.LPVOID = memory.ptr;
    var region_size: usize = 0;

     _ = syscalls.NtFreeVirtualMemory.?.syscall4(
        @intFromPtr(win32.NtCurrentProcess()),
        @intFromPtr(&base_address),
        @intFromPtr(&region_size),
        windows.MEM_RELEASE,
    );
}

pub fn ntFreePtr(syscalls: Syscalls, ptr: windows.LPVOID) void {
    var region_size: usize = 0;

     _ = syscalls.NtFreeVirtualMemory.?.syscall4(
        @intFromPtr(win32.NtCurrentProcess()),
        @intFromPtr(&ptr),
        @intFromPtr(&region_size),
        windows.MEM_RELEASE,
    );
}

pub fn ntMapSection(
    syscalls: Syscalls,
    h_section: windows.HANDLE,
    h_process: ?windows.HANDLE,
    view_size_ptr: *windows.SIZE_T,
) !windows.PVOID {
    var map_addr_ptr: ?windows.PVOID = null;

    const status = syscalls.NtMapViewOfSection.?.syscall12(
        @intFromPtr(h_section),
        if (h_process == null) @intFromPtr(win32.NtCurrentProcess()) else @intFromPtr(h_process),
        @intFromPtr(&map_addr_ptr),
        0,
        0,
        0, // null
        @intFromPtr(view_size_ptr),
        @intFromEnum(win32.SECTION_INHERIT.ViewUnmap),
        0,
        @intCast(windows.PAGE_EXECUTE_READWRITE),
        0, 0, // unused
    );
    if (status != win32.STATUS_SUCCESS or map_addr_ptr == null) {
        return error.NtMapViewOfSectionFailed;
    }

    return map_addr_ptr.?;
}

pub fn ntProtect(
    syscalls: Syscalls,
    h_process: ?windows.HANDLE,
    addr: windows.LPVOID,
    alloc_size: usize,
    protection: windows.ULONG,
) !void {
    var old_protect: windows.DWORD = 0;
    const status = syscalls.NtProtectVirtualMemory.?.syscall6(
        if (h_process == null) @intFromPtr(win32.NtCurrentProcess()) else @intFromPtr(h_process),
        @intFromPtr(&addr),
        @intFromPtr(&alloc_size),
        @intCast(protection),
        @intFromPtr(&old_protect),
        0, // unused
    );
    if (status != win32.STATUS_SUCCESS) {
        std.debug.print("status: 0x{x}\n", .{ status });
        return error.NtProtectVirtualMemoryFailed;
    }
}

pub fn ntResumeThread(syscalls: Syscalls, h_thread: windows.HANDLE) void {
    _ = syscalls.NtResumeThread.?.syscall4(@intFromPtr(h_thread), 0, 0, 0);
}

pub fn ntUnmapSection(
    syscalls: Syscalls,
    h_process: ?windows.HANDLE,
    map_addr: windows.LPVOID,
) void {
    _ = syscalls.NtUnmapViewOfSection.?.syscall4(
        if (h_process == null) @intFromPtr(win32.NtCurrentProcess()) else @intFromPtr(h_process),
        @intFromPtr(map_addr),
        0, 0,
    );
}

pub fn ntWait(syscalls: Syscalls, h_thread: windows.HANDLE) void {
    _ = syscalls.NtWaitForSingleObject.?.syscall6(
        @intFromPtr(h_thread),
        0, 0, 0, 0, 0,
    );
}

pub fn ntWrite(
    syscalls: Syscalls,
    h_process: ?windows.HANDLE,
    addr_ptr: windows.LPVOID,
    buffer: []const u8,
) !void {
    var bytes_written: windows.SIZE_T = 0;
    const status = syscalls.NtWriteVirtualMemory.?.syscall6(
        if (h_process == null) @intFromPtr(win32.NtCurrentProcess()) else @intFromPtr(h_process),
        @intFromPtr(addr_ptr),
        @intFromPtr(@as(windows.LPVOID, @constCast(@ptrCast(buffer.ptr)))),
        @intCast(buffer.len),
        @intFromPtr(&bytes_written),
        0, // unused
    );
    if (status != win32.STATUS_SUCCESS) {
        return error.NtWriteVirtualMemoryFailed;
    }
}