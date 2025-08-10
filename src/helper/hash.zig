pub fn hashFNV1a(s: []const u8) u32 {
    var hash: u32 = 0x811C9DC5;
    for (s) |c| {
        hash = (hash ^ toLowerAscii(c)) *% 16777619;
    }
    return hash;
}

pub fn hashFNV1aW(sW: [*]const u16, len: usize) u32 {
    var hash: u32 = 0x811C9DC5;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const ch = toLowerAscii(@intCast(sW[i] & 0xFF));
        hash = (hash ^ ch) *% 16777619;
    }
    return hash;
}

inline fn toLowerAscii(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') {
        return c + 32;
    }
    return c;
}