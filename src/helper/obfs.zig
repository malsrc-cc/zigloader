// Obfuscation at comptime
pub fn deobfsBytes(comptime N: usize, data: [N]u8, key: u8) [N]u8 {
    var decoded: [N]u8 = undefined;
    var state: u8 = key;
    for (data, 0..) |b, i| {
        const xored = (b >> 2) | (b << 6); // ROR 2
        const original = xored ^ state;
        decoded[i] = original;
        state = b;
    }
    return decoded;
}

// Obfuscation at runtime
pub fn deobfsBytesRt(data: []const u8, output: []u8, key: u8) !void {
    if (data.len != output.len) {
        return error.InvalidSize;
    }
    
    var state: u8 = key;
    for (data, 0..) |b, i| {
        const xored = (b >> 2) | (b << 6); // ROR 2
        const original = xored ^ state;
        output[i] = original;
        state = b;
    }
}

pub fn obfsBytes(dst: []u8, src: []const u8, key: u8) void {
    var state: u8 = key;
    for (src, 0..) |b, i| {
        const obfs = ((b ^ state) << 2) | ((b ^ state) >> 6); // ROL 2
        dst[i] = obfs;
        state = obfs;
    }
}
