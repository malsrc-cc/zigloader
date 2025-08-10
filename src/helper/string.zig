const std = @import("std");
const windows = std.os.windows;
const mem = @import("mem.zig");
const Syscalls = @import("../syscall.zig").Syscalls;

// UTF8 => UTF16 + '\0'
pub fn L(comptime str: []const u8) [str.len:0]u16 {
    comptime var buffer: [str.len:0]u16 = undefined;
    inline for (str, 0..) |c, i| {
        buffer[i] = c;
    }
    buffer[str.len] = 0;
    return buffer;
}

pub fn trimFixedCString(comptime N: usize, name: *const [N]u8) []const u8 {
    var len: usize = 0;
    while (len < N and name.*[len] != 0) : (len += 1) {}
    return name.*[0..len];
}

pub inline fn cStringToSlice(buf: [*c]u8) []u8 {
    var len: usize = 0;
    while (buf[len] != 0) : ({
        len += 1;
    }) {}
    return buf[0..len];
}

// Helper function to convert UNICODE_STRING to Zig slice (credit: https://github.com/CX330Blake/Black-Hat-Zig/blob/main/src/Advanced-Malware-Techniques/Process-Enumeration/nt_query_system_information.md)
pub fn unicodeStringToSlice(unicode_str: windows.UNICODE_STRING) []u16 {
    if (unicode_str.Buffer == null or unicode_str.Length == 0) {
        return &[_]u16{};
    }
    return @as([*]u16, @ptrCast(unicode_str.Buffer))[0 .. unicode_str.Length / 2];
}

pub fn utf8ToUtf16Z(syscalls: Syscalls, input: []const u8) ![]u16 {
    const max_utf16_len = input.len;
    const buffer = try mem.ntAlloc(
        syscalls,
        null,
        (max_utf16_len + 1) * 2,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    
    const utf16_buffer = @as([*]u16, @ptrCast(@alignCast(buffer.ptr)))[0..max_utf16_len + 1];
    const actual_len = try std.unicode.utf8ToUtf16Le(utf16_buffer[0..max_utf16_len], input);
    utf16_buffer[actual_len] = 0; // null terminator
    
    return utf16_buffer[0..actual_len + 1];
}

pub fn utf16LeToUtf8Z(syscalls: Syscalls, input: []const u16) ![]u8 {
    const max_utf8_len = input.len * 3;
    
    const buffer = try mem.ntAlloc(
        syscalls,
        null,
        max_utf8_len + 1, // +1 for null terminator
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    errdefer mem.ntFree(buffer);
    
    const utf8_buffer = buffer.ptr[0..max_utf8_len + 1];
    const actual_len = try std.unicode.utf16LeToUtf8(utf8_buffer[0..max_utf8_len], input);
    utf8_buffer[actual_len] = 0; // add null terminator
    
    return utf8_buffer[0..actual_len + 1]; // needs to be freed
}

pub fn utf16LeToUtf8(syscalls: Syscalls, input: []const u16) ![]u8 {
    const max_utf8_len = input.len * 3;
    
    const buffer = try mem.ntAlloc(
        syscalls,
        null,
        max_utf8_len,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    errdefer mem.ntFree(syscalls, buffer);
    
    const utf8_buffer = buffer.ptr[0..max_utf8_len];
    const actual_len = try std.unicode.utf16LeToUtf8(utf8_buffer, input);
    
    return utf8_buffer[0..actual_len]; // needs to be freed
}

pub fn wcslen(p: [*]const u16, max_len: usize) usize {
    var i: usize = 0;
    while (i < max_len and p[i] != 0) : (i += 1) {}
    return i;
}