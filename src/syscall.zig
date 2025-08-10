const builtin = @import("builtin");
const Apis = @import("api.zig").Apis;
const win32 = @import("win32.zig");

pub const Syscall = struct {
    ssn: ?u32 = null,
    addr: ?[*]const u8 = null,

    const Self = @This();

    pub fn syscall4(
        self: Self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
    ) usize {
        if (self.ssn == null) return win32.STATUS_PROCEDURE_NOT_FOUND;

        switch (builtin.cpu.arch) {
            // TODO
            // .x86 => {},
            .x86_64 => {
                return asm volatile (
                    \\movq %%rcx, %%r10
                    \\movl %[ssn], %%eax
                    \\syscall
                    : [ret] "={rax}" (-> usize)
                    : [ssn] "r" (self.ssn.?),
                    [_] "{rcx}" (arg1),
                    [_] "{rdx}" (arg2),
                    [_] "{r8}"  (arg3),
                    [_] "{r9}"  (arg4)
                    : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
                );
            },
            .aarch64 => {
                return asm volatile (
                    \\mov x8, %[ssn]
                    \\svc #0
                    : [ret] "={x0}" (-> usize)
                    : [ssn] "r" (self.ssn.?),
                    [_] "{x0}" (arg1),
                    [_] "{x1}" (arg2),
                    [_] "{x2}" (arg3),
                    [_] "{x3}" (arg4)
                    : "x0", "x1", "x2", "x3", "x8", "memory"
                );
            },
            else => return win32.STATUS_NOT_SUPPORTED,
        }
    }

    pub fn syscall6(
        self: Self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
    ) usize {
        if (self.ssn == null) return win32.STATUS_PROCEDURE_NOT_FOUND;

        switch (builtin.cpu.arch) {
            // TODO
            // .x86 => {},
            .x86_64 => {
                return asm volatile (
                    \\movq %%rcx, %%r10
                    \\sub  $0x38, %%rsp       // shadow space + align
                    \\mov  %[a5], 0x28(%%rsp) // arg5 -> [rsp+0x28]
                    \\mov  %[a6], 0x30(%%rsp) // arg6 -> [rsp+0x30]
                    \\movl %[ssn], %%eax
                    \\syscall
                    \\add  $0x38, %%rsp
                    : [ret] "={rax}" (-> usize)
                    : [ssn] "r" (self.ssn.?),
                    [_] "{rcx}" (arg1),
                    [_] "{rdx}" (arg2),
                    [_] "{r8}"  (arg3),
                    [_] "{r9}"  (arg4),
                    [a5] "r"    (arg5),
                    [a6] "r"    (arg6)
                    : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
                );
            },
            .aarch64 => {
                return asm volatile (
                    \\mov x8, %[ssn]  // syscall number in x8
                    \\svc #0
                    : [ret] "={x0}" (-> usize)
                    : [ssn] "r" (self.ssn.?),
                    [_] "{x0}" (arg1),
                    [_] "{x1}" (arg2),
                    [_] "{x2}" (arg3),
                    [_] "{x3}" (arg4),
                    [_] "{x4}" (arg5),
                    [_] "{x5}" (arg6)
                    : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
                );
            },
            else => return win32.STATUS_NOT_SUPPORTED,
        }
    }

    pub fn syscall12(
        self: Self,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
        arg6: usize,
        arg7: usize,
        arg8: usize,
        arg9: usize,
        arg10: usize,
        arg11: usize,
        arg12: usize,
    ) usize {
        switch (builtin.cpu.arch) {
            // TODO
            //.x86 => {},
            .x86_64 => {
                const args = [_]usize{ arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12 };
                
                return asm volatile (
                    \\movq %%rcx,  %%r10
                    \\sub  $0x68,  %%rsp       // shadow space + align
                    \\movq %[args], %%r11
                    \\movq 0x00(%%r11), %%rax  // args[0] = arg5
                    \\movq %%rax, 0x28(%%rsp)
                    \\movq 0x08(%%r11), %%rax  // args[1] = arg6
                    \\movq %%rax, 0x30(%%rsp)
                    \\movq 0x10(%%r11), %%rax  // args[2] = arg7
                    \\movq %%rax, 0x38(%%rsp)
                    \\movq 0x18(%%r11), %%rax  // args[3] = arg8
                    \\movq %%rax, 0x40(%%rsp)
                    \\movq 0x20(%%r11), %%rax  // args[4] = arg9
                    \\movq %%rax, 0x48(%%rsp)
                    \\movq 0x28(%%r11), %%rax  // args[5] = arg10
                    \\movq %%rax, 0x50(%%rsp)
                    \\movq 0x30(%%r11), %%rax  // args[6] = arg11
                    \\movq %%rax, 0x58(%%rsp)
                    \\movq 0x38(%%r11), %%rax  // args[7] = arg12
                    \\movq %%rax, 0x60(%%rsp)
                    \\movl %[ssn], %%eax
                    \\syscall
                    \\add  $0x68,  %%rsp
                    : [ret] "={rax}" (-> usize)
                    : [ssn] "r" (self.ssn.?),
                    [_] "{rcx}" (arg1),
                    [_] "{rdx}" (arg2),
                    [_] "{r8}"  (arg3),
                    [_] "{r9}"  (arg4),
                    [args] "r" (&args)
                    : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
                );
            },
            // .aarch64 => {},
            else => return win32.STATUS_NOT_SUPPORTED,
        }
    }
};

pub const Syscalls = struct {
    NtAllocateVirtualMemory: ?Syscall = null,
    NtClose: ?Syscall = null,
    NtCreateSection: ?Syscall = null,
    NtCreateThreadEx: ?Syscall = null,
    NtDelayExecution: ?Syscall = null,
    NtFreeVirtualMemory: ?Syscall = null,
    NtMapViewOfSection: ?Syscall = null,
    NtOpenKey: ?Syscall = null,
    NtOpenProcess: ?Syscall = null,
    NtOpenProcessToken: ?Syscall = null,
    NtProtectVirtualMemory: ?Syscall = null,
    NtQueryInformationProcess: ?Syscall = null,
    NtQueryInformationToken: ?Syscall = null,
    NtQuerySystemInformation: ?Syscall = null,
    NtQueryValueKey: ?Syscall = null,
    NtQueueApcThread: ?Syscall = null,
    NtReadVirtualMemory: ?Syscall = null,
    NtResumeThread: ?Syscall = null,
    NtTerminateProcess: ?Syscall = null,
    NtUnmapViewOfSection: ?Syscall = null,
    NtWaitForSingleObject: ?Syscall = null,
    NtWriteVirtualMemory: ?Syscall = null,

    const Self = @This();

    pub fn get(self: *Self, apis: *Apis) bool {
        inline for (@typeInfo(Syscalls).@"struct".fields) |field| {
            const func_ptr = @field(apis, field.name);
            if (func_ptr) |p| {
                @field(self, field.name) = Syscall{
                    .ssn = self.getSSN(@as([*]const u8, @ptrCast(p))),
                    .addr = @ptrCast(p),
                };
            }
        }
        if (self.ok()) {
            return true;
        }
        return false;
    }

    // Currentrly x86_64 supported only
    pub fn getSSN(_: *Self, func_ptr: [*]const u8) ?u32 {
        // Windows syscall stub:
        //  mov eax, <id>
        //  mov r10, rcx
        //  syscall
        //  ret
        const code: [20]u8 = func_ptr[0..20].*;
        if (code[0] != 0x4c or code[1] != 0x8b or code[2] != 0xd1) return null;
        if (code[3] != 0xb8) return null;

        // Extract <id>
        const ssn_bytes = code[4..8];
        return @as(u32, ssn_bytes[0]) | 
            (@as(u32, ssn_bytes[1]) << 8) | 
            (@as(u32, ssn_bytes[2]) << 16) | 
            (@as(u32, ssn_bytes[3]) << 24);
    }

    fn ok(self: *Self) bool {
        inline for (@typeInfo(Syscalls).@"struct".fields) |field| {
            if (@field(self, field.name) == null) {
                return false;
            }
        }
        return true;
    }
};
