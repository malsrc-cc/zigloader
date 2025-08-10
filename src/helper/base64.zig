const std = @import("std");
const windows = std.os.windows;
const base64 = std.base64;
const mem = @import("mem.zig");
const Syscalls = @import("../syscall.zig").Syscalls;

pub fn decodeBase64(syscalls: Syscalls, input: []const u8) ![]u8 {
    const decoder = base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(input);
    const result = try mem.ntAlloc(syscalls, null, decoded_len, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE);
    try decoder.decode(result, input);
    return result[0..decoded_len]; // needs to be freed by caller
}

pub fn encodeBase64(syscalls: Syscalls, input: []const u8) ![]u8 {
    const encoder = base64.standard.Encoder;
    const encoded_len = encoder.calcSize(input.len);   
    const result = try mem.ntAlloc(syscalls, null, encoded_len, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE);
    return @constCast(encoder.encode(result, input)); // needs to be freed by caller
}
