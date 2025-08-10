const std = @import("std");
const windows = std.os.windows;
const builtin = @import("builtin");
const hashFNV1a = @import("helper/hash.zig").hashFNV1a;
const hashFNV1aW = @import("helper/hash.zig").hashFNV1aW;
const string = @import("helper/string.zig");

pub const CREATE_SUSPENDED = 0x00000004;

pub const DLL_PROCESS_DETACH = 0;
pub const DLL_PROCESS_ATTACH = 1;
pub const DLL_THREAD_ATTACH = 2;
pub const DLL_THREAD_DETACH = 3;

pub const HINTERNET = ?windows.LPVOID;

pub const INTERNET_PORT = windows.WORD;

pub const KEY_READ = 0x20019;

pub const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 1 << 44;

pub const PROCESS_ALL_ACCESS = 0x000F0000 | (0x00100000) | 0xFFFF;
pub const PROCESS_CREATE_THREAD = 0x0002;
pub const PROCESS_QUERY_INFORMATION = 0x0400;
pub const PROCESS_VM_OPERATION = 0x0008;
pub const PROCESS_VM_WRITE = 0x0020;

pub const PROCESS_CREATE_FLAGS_BREAKAWAY = 0x00000001;
pub const PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT = 0x00000002;
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;
pub const PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE = 0x00000008;
pub const PROCESS_CREATE_FLAGS_LARGE_PAGES = 0x00000010;
pub const PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL = 0x00000020;
pub const PROCESS_CREATE_FLAGS_PROTECTED_PROCESS = 0x00000040;
pub const PROCESS_CREATE_FLAGS_CREATE_SESSION = 0x00000080;
pub const PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT = 0x00000100;
pub const PROCESS_CREATE_FLAGS_SUSPENDED = 0x00000200;
pub const PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY = 0x00000400;

pub const REG_BINARY = 3;

pub const STATUS_SUCCESS = 0x00000000;
pub const STATUS_BUFFER_TOO_SMALL = 0xC0000023;
pub const STATUS_NOT_SUPPORTED = 0xC00000BB;
pub const STATUS_PROCEDURE_NOT_FOUND = 0xC000007A;

pub const SW_HIDE = 0;
pub const SW_SHOWNORMAL = 1;
pub const SW_NORMAL = 1;
pub const SW_SHOWMINIMIZED = 2;
pub const SW_SHOWMAXIMIZED = 3;
pub const SW_MAXIMIZE = 3;
pub const SW_SHOWNOACTIVATE = 4;
pub const SW_SHOW = 5;
pub const SW_MINIMIZE = 6;
pub const SW_SHOWMINNOACTIVE = 7;
pub const SW_SHOWNA = 8;
pub const SW_RESTORE = 9;
pub const SW_SHOWDEFAULT = 10;
pub const SW_FORCEMINIMIZE = 11;
pub const SW_MAX = 11;

pub const THREAD_ALL_ACCESS = 0x001FFFFF;

pub const TOKEN_QUERY = 0x0008;

pub const WINHTTP_FLAG_SECURE = 0x00800000;

pub const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
pub const WINHTTP_ACCESS_TYPE_NO_PROXY = 1;
pub const WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;
pub const WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4;

pub const INTERNET_SCHEME = enum(c_int) {
    INTERNET_SCHEME_PARTIAL = -2,
    INTERNET_SCHEME_UNKNOWN = -1,
    INTERNET_SCHEME_DEFAULT = 0,
    INTERNET_SCHEME_FTP = 1,
    INTERNET_SCHEME_GOPHER = 2,
    INTERNET_SCHEME_HTTP = 3,
    INTERNET_SCHEME_HTTPS = 4,
    INTERNET_SCHEME_FILE = 5,
    INTERNET_SCHEME_NEWS = 6,
    INTERNET_SCHEME_MAILTO = 7,
    INTERNET_SCHEME_SOCKS = 8,
    INTERNET_SCHEME_JAVASCRIPT = 9,
    INTERNET_SCHEME_VBSCRIPT = 10,
    INTERNET_SCHEME_RES = 11,
    INTERNET_SCHEME_FIRST = 12,
    INTERNET_SCHEME_LAST = 13,
};

pub const KEY_VALUE_INFORMATION_CLASS = enum(u32) {
    KeyValueBasicInformation, // KEY_VALUE_BASIC_INFORMATION
    KeyValueFullInformation, // KEY_VALUE_FULL_INFORMATION
    KeyValuePartialInformation, // KEY_VALUE_PARTIAL_INFORMATION
    KeyValueFullInformationAlign64, // KEY_VALUE_FULL_INFORMATION_ALIGN64
    KeyValuePartialInformationAlign64,  // KEY_VALUE_PARTIAL_INFORMATION_ALIGN64
    KeyValueLayerInformation, // KEY_VALUE_LAYER_INFORMATION
    MaxKeyValueInfoClass,
};

pub const PROCESSINFOCLASS = enum(u32) {
    ProcessBasicInformation = 0,
};

pub const SECTION_INHERIT = enum(c_int) {
    ViewShare = 1,
    ViewUnmap = 2,
};

pub const TOKEN_INFORMATION_CLASS = enum(u32) {
    TokenUser = 1,
    // omitted...
};

pub const CLIENT_ID = extern struct {
    UniqueProcess: ?windows.HANDLE,
    UniqueThread: ?windows.HANDLE,
};

pub const URL_COMPONENTS = struct {
    dwStructSize: windows.DWORD,
    lpszScheme: windows.LPWSTR,
    dwSchemeLength: windows.DWORD,
    nScheme: INTERNET_SCHEME,
    lpszHostName: windows.LPWSTR,
    dwHostNameLength: windows.DWORD,
    nPort: INTERNET_PORT,
    lpszUserName: windows.LPWSTR,
    dwUserNameLength: windows.DWORD,
    lpszPassword: windows.LPWSTR,
    dwPasswordLength: windows.DWORD,
    lpszUrlPath: windows.LPWSTR,
    dwUrlPathLength: windows.DWORD,
    lpszExtraInfo: windows.LPWSTR,
    dwExtraInfoLength: windows.DWORD,
};


pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: windows.WORD,
    e_cblp: windows.WORD,
    e_cp: windows.WORD,
    e_crlc: windows.WORD,
    e_cparhdr: windows.WORD,
    e_minalloc: windows.WORD,
    e_maxalloc: windows.WORD,
    e_ss: windows.WORD,
    e_sp: windows.WORD,
    e_csum: windows.WORD,
    e_ip: windows.WORD,
    e_cs: windows.WORD,
    e_lfarlc: windows.WORD,
    e_ovno: windows.WORD,
    e_res: [4]windows.WORD,
    e_oemid: windows.WORD,
    e_oeminfo: windows.WORD,
    e_res2: [10]windows.WORD,
    e_lfanew: windows.LONG,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: windows.DWORD,
    Size: windows.DWORD,
};
pub const IMAGE_OPTIONAL_HEADER32 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    BaseOfData: windows.DWORD,
    ImageBase: windows.DWORD,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeaders: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.DWORD,
    SizeOfStackCommit: windows.DWORD,
    SizeOfHeapReserve: windows.DWORD,
    SizeOfHeapCommit: windows.DWORD,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSizes: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: windows.WORD,
    MajorLinkerVersion: windows.BYTE,
    MinorLinkerVersion: windows.BYTE,
    SizeOfCode: windows.DWORD,
    SizeOfInitializedData: windows.DWORD,
    SizeOfUninitializedData: windows.DWORD,
    AddressOfEntryPoint: windows.DWORD,
    BaseOfCode: windows.DWORD,
    ImageBase: windows.ULONGLONG,
    SectionAlignment: windows.DWORD,
    FileAlignment: windows.DWORD,
    MajorOperatingSystemVersion: windows.WORD,
    MinorOperatingSystemVersion: windows.WORD,
    MajorImageVersion: windows.WORD,
    MinorImageVersion: windows.WORD,
    MajorSubsystemVersion: windows.WORD,
    MinorSubsystemVersion: windows.WORD,
    Win32VersionValue: windows.DWORD,
    SizeOfImage: windows.DWORD,
    SizeOfHeaders: windows.DWORD,
    CheckSum: windows.DWORD,
    Subsystem: windows.WORD,
    DllCharacteristics: windows.WORD,
    SizeOfStackReserve: windows.ULONGLONG,
    SizeOfStackCommit: windows.ULONGLONG,
    SizeOfHeapReserve: windows.ULONGLONG,
    SizeOfHeapCommit: windows.ULONGLONG,
    LoaderFlags: windows.DWORD,
    NumberOfRvaAndSizes: windows.DWORD,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};
pub const IMAGE_FILE_HEADER = extern struct {
    Machine: windows.WORD,
    NumberOfSections: windows.WORD,
    TimeDateStamp: windows.DWORD,
    PointerToSymbolTable: windows.DWORD,
    NumberOfSymbols: windows.DWORD,
    SizeOfOptionalHeader: windows.WORD,
    Characteristics: windows.WORD,
};
pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_NT_HEADERS32 = extern struct {
    Signature: windows.DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER32,
};

pub const IMAGE_OPTIONAL_HEADER = if (@sizeOf(usize) == 4) IMAGE_OPTIONAL_HEADER32 else IMAGE_OPTIONAL_HEADER64;
pub const IMAGE_NT_HEADERS = if (@sizeOf(usize) == 4) IMAGE_NT_HEADERS32 else IMAGE_NT_HEADERS64;

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: windows.DWORD,
    TimeDateStamp: windows.DWORD,
    MajorVersion: windows.WORD,
    MinorVersion: windows.WORD,
    Name: windows.DWORD,
    Base: windows.DWORD,
    NumberOfFunctions: windows.DWORD,
    NumberOfNames: windows.DWORD,
    AddressOfFunctions: windows.DWORD,
    AddressOfNames: windows.DWORD,
    AddressOfNameOrdinals: windows.DWORD,
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT = @as(c_int, 0);
pub const IMAGE_DIRECTORY_ENTRY_IMPORT = @as(c_int, 1);
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE = @as(c_int, 2);
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION = @as(c_int, 3);
pub const IMAGE_DIRECTORY_ENTRY_SECURITY = @as(c_int, 4);
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC = @as(c_int, 5);
pub const IMAGE_DIRECTORY_ENTRY_DEBUG = @as(c_int, 6);
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = @as(c_int, 7);
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR = @as(c_int, 8);
pub const IMAGE_DIRECTORY_ENTRY_TLS = @as(c_int, 9);
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = @as(c_int, 10);
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = @as(c_int, 11);
pub const IMAGE_DIRECTORY_ENTRY_IAT = @as(c_int, 12);
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = @as(c_int, 13);
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = @as(c_int, 14);

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]windows.UCHAR,
    VirtualSize: windows.ULONG,
    VirtualAddress: windows.ULONG,
    SizeOfRawData: windows.ULONG,
    PointerToRawData: windows.ULONG,
    PointerToRelocations: windows.ULONG,
    PointerToLinenumbers: windows.ULONG,
    NumberOfRelocations: windows.USHORT,
    NumberOfLinenumbers: windows.USHORT,
    Characteristics: windows.ULONG,
};

pub const IMAGE_BASE_RELOCATION = extern struct {
    VirtualAddress: windows.DWORD,
    SizeOfBlock: windows.DWORD,
};

pub const IMAGE_RELOC = packed struct(u16) {
    offset: u12,
    typ: u4,
};
pub const IMAGE_REL_BASED_DIR64: u6 = 10;
pub const IMAGE_REL_BASED_HIGHLOW: u6 = 3;
pub const IMAGE_REL_TYPE = if (@sizeOf(usize) == 4) IMAGE_REL_BASED_HIGHLOW else IMAGE_REL_BASED_DIR64;

pub const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    OriginalFirstThunk: windows.DWORD,
    TimeDateStamp: windows.DWORD,
    ForwarderChain: windows.DWORD,
    Name: windows.DWORD,
    FirstThunk: windows.DWORD,
};
pub const IMAGE_THUNK_DATA64 = extern union {
    const Self = @This();
    ForwarderString: windows.ULONGLONG,
    Function: windows.ULONGLONG,
    Ordinal: windows.ULONGLONG,
    AddressOfData: windows.ULONGLONG,
    pub fn IMAGE_SNAP_BY_ORDINAL(self: *Self) bool {
        return (self.Ordinal & 0x8000000000000000) != 0;
    }
    pub fn IMAGE_ORDINAL(self: *Self) usize {
        return self.Ordinal & 0xFFFF;
    }
};
pub const IMAGE_THUNK_DATA32 = extern union {
    const Self = @This();
    ForwarderString: windows.DWORD,
    Function: windows.DWORD,
    Ordinal: windows.DWORD,
    AddressOfData: windows.DWORD,
    pub fn IMAGE_SNAP_BY_ORDINAL(self: *Self) bool {
        return (self.Ordinal & 0x80000000) != 0;
    }
    pub fn IMAGE_ORDINAL(self: *Self) usize {
        return self.Ordinal & 0xFFFF;
    }
};

pub const IMAGE_THUNK_DATA = if (@sizeOf(usize) == 4) IMAGE_THUNK_DATA32 else IMAGE_THUNK_DATA64;

pub const IMAGE_IMPORT_BY_NAME = extern struct {
    Hint: windows.WORD,
    Name: [1]windows.CHAR,
};

pub const IMAGE_FILE_RELOCS_STRIPPED = 0x0001;

pub const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
pub const IMAGE_SCN_MEM_READ = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE = 0x80000000;

pub const KEY_VALUE_PARTIAL_INFORMATION = extern struct {
    TitleIndex: windows.ULONG,
    Type: windows.ULONG,
    DataLength: windows.ULONG,
    // Data: [1]windows.UCHAR, // frexible size
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: windows.LIST_ENTRY,
    InMemoryOrderLinks: windows.LIST_ENTRY,
    InInitializationOrderLinks: windows.LIST_ENTRY, //Reserved2: [2]windows.PVOID,
    DllBase: ?windows.PVOID,
    EntryPoint: windows.PVOID,
    SizeOfImage: windows.ULONG,
    FullDllName: windows.UNICODE_STRING,

    // Reserved4: [8]windows.BYTE,
    // Reserved5: [3]windows.PVOID,
    // u: extern union {
    //     CheckSum: windows.ULONG,
    //     Reserved6: windows.PVOID,
    // },
    // TimeDateStamp: windows.ULONG,

    BaseDllName: windows.UNICODE_STRING,
    // union_1: extern union {
    //     FlagGroup: [4]u8,
    //     Flags: windows.ULONG,
    // },
    // Omitted...
};

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: windows.ULONG,
    RootDirectory: ?windows.HANDLE,
    ObjectName: ?*windows.UNICODE_STRING,
    Attributes: windows.ULONG,
    SecurityDescriptor: ?windows.PVOID,
    SecurityQualityOfService: ?windows.PVOID,
};

pub const PS_ATTRIBUTE = extern struct {
    Attribute: windows.ULONG_PTR,
    Size: windows.SIZE_T,
    u: extern union {
        Value: windows.ULONG_PTR,
        ValuePtr: windows.PVOID,
    },
    ReturnLength: ?*windows.SIZE_T,
};

pub const PS_ATTRIBUTE_LIST = extern struct {
    TotalLength: windows.SIZE_T,
    Attributes: [3]PS_ATTRIBUTE,
};

pub const PS_APC_ROUTINE = extern struct {
    ApcArgument1: ?windows.PVOID,
    ApcArgument2: ?windows.PVOID,
    ApcArgument3: ?windows.PVOID,
};

pub const SINGLE_LIST_ENTRY = extern struct {
    Next: ?*SINGLE_LIST_ENTRY,
};

pub const SLIST_HEADER = switch(builtin.cpu.arch) {
    .x86 => extern union {
        Alignment: u64,
        Anonymous: extern struct {
            Next: SINGLE_LIST_ENTRY,
            Depth: u16,
            CpuId: u16,
        },
    },
    .x86_64 => extern union {
        Anonymous: extern struct {
            Alignment: u64,
            Region: u64,
        },
        HeaderX64: extern struct {
            _bitfield1: u64,
            _bitfield2: u64,
        },
    },
    .aarch64 => extern union {
        Anonymous: extern struct {
            Alignment: u64,
            Region: u64,
        },
        HeaderArm64: extern struct {
            _bitfield1: u64,
            _bitfield2: u64,
        },
    },
    else => {
        @compileError("Unsupported architecture");
    },
};

pub const STARTUPINFOA = extern struct {
    cb: windows.DWORD,
    lpReserved: ?windows.LPSTR,
    lpDesktop: ?windows.LPSTR,
    lpTitle: ?windows.LPSTR,
    dwX: windows.DWORD,
    dwY: windows.DWORD,
    dwXSize: windows.DWORD,
    dwYSize: windows.DWORD,
    dwXCountChars: windows.DWORD,
    dwYCountChars: windows.DWORD,
    dwFillAttribute: windows.DWORD,
    dwFlags: windows.DWORD,
    wShowWindow: windows.WORD,
    cbReserved2: windows.WORD,
    lpReserved2: ?*windows.BYTE,
    hStdInput: ?windows.HANDLE,
    hStdOutput: ?windows.HANDLE,
    hStdError: ?windows.HANDLE,
};

pub const SYSTEM_PROCESS_INFORMATION = extern struct {
    NextEntryOffset: windows.ULONG,
    NumberOfThreads: windows.ULONG,
    WorkingSetPrivateSize: windows.LARGE_INTEGER, // VISTA
    HardFaultCount: windows.ULONG, // WIN7
    NumberOfThreadsHighWatermark: windows.ULONG, // WIN7
    CycleTime: windows.ULONGLONG, // WIN7
    CreateTime: windows.LARGE_INTEGER,
    UserTime: windows.LARGE_INTEGER,
    KernelTime: windows.LARGE_INTEGER,
    ImageName: windows.UNICODE_STRING,
    BasePriority: windows.KPRIORITY,
    UniqueProcessId: windows.HANDLE,
    InheritedFromUniqueProcessId: windows.HANDLE,
    HandleCount: windows.ULONG,
    SessionId: windows.ULONG,
    PageDirectoryBase: windows.ULONG_PTR,

    // VM_COUNTERS_EX part
    // NOTE: *NOT* THE SAME AS VM_COUNTERS!
    PeakVirtualSize: windows.SIZE_T,
    VirtualSize: windows.SIZE_T,
    PageFaultCount: windows.ULONG,
    PeakWorkingSetSize: windows.SIZE_T,
    WorkingSetSize: windows.SIZE_T,
    QuotaPeakPagedPoolUsage: windows.SIZE_T,
    QuotaPagedPoolUsage: windows.SIZE_T,
    QuotaPeakNonPagedPoolUsage: windows.SIZE_T,
    QuotaNonPagedPoolUsage: windows.SIZE_T,
    PagefileUsage: windows.SIZE_T,
    PeakPagefileUsage: windows.SIZE_T,
    PrivatePageCount: windows.SIZE_T,

    // IO_COUNTERS part
    ReadOperationCount: windows.LARGE_INTEGER,
    WriteOperationCount: windows.LARGE_INTEGER,
    OtherOperationCount: windows.LARGE_INTEGER,
    ReadTransferCount: windows.LARGE_INTEGER,
    WriteTransferCount: windows.LARGE_INTEGER,
    OtherTransferCount: windows.LARGE_INTEGER,
    // SYSTEM_THREAD_INFORMATION TH[1]; - Usually accessed separately
};

pub const USER_THREAD_START_ROUTINE = *const fn (ThreadParameter: ?*anyopaque) callconv(windows.WINAPI) windows.NTSTATUS;

pub const WNDENUMPROC = *const fn (windows.HWND, windows.LPARAM) callconv(windows.WINAPI) windows.BOOL;

pub fn IMAGE_FIRST_SECTION(nt: *const IMAGE_NT_HEADERS) [*]const IMAGE_SECTION_HEADER {
    const opt: [*]const u8 = @ptrCast(&nt.OptionalHeader);
    const size: usize = nt.FileHeader.SizeOfOptionalHeader;
    const sec: [*]const IMAGE_SECTION_HEADER = @alignCast(@ptrCast(opt[size..]));
    return sec;
}

pub fn NtCurrentProcess() windows.HANDLE {
    return @as(windows.HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));
}

pub fn getTEB() *const windows.TEB {
    const teb_ptr: *const windows.TEB = switch (builtin.cpu.arch) {
        .x86 => @ptrFromInt(asm volatile (
            "mov %%fs:0x18, %[result]"
            : [result] "=r" (-> u32),
        )),
        .x86_64 => @ptrFromInt(asm volatile (
            "movq %%gs:0x30, %[result]"
            : [result] "=r" (-> u64),
        )),
        .aarch64 => @ptrFromInt(asm volatile (
            "mrs %[result], tpidr_el0"
            : [result] "=r" (-> u64),
        )),
        else => @compileError("Unsupported architecture"),
    };
    return teb_ptr;
}

pub fn getPEB() *const windows.PEB {
    const teb_ptr = getTEB();
    return teb_ptr.ProcessEnvironmentBlock;
}

pub fn getNt(base: *anyopaque) !*anyopaque {
    const dos: *IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    if (dos.e_magic != 0x5A4D) return error.InvalidMagic; // "MZ"
    return @ptrFromInt(@intFromPtr(base) + @as(u32, @bitCast(dos.e_lfanew)));
}

pub fn getModuleBase() *anyopaque {
    return getPEB().ImageBaseAddress;
}

pub fn getModuleHandleByHash(hash: u32) ?windows.HANDLE {
    const peb = getPEB();
    const ldr = peb.Ldr;
    var dte: *LDR_DATA_TABLE_ENTRY = @ptrCast(ldr.InLoadOrderModuleList.Flink);

    while (dte.DllBase != null) : (dte = @ptrCast(dte.InLoadOrderLinks.Flink)) {
        const base_dll_name = dte.BaseDllName;
        const dll_hash = hashFNV1aW(base_dll_name.Buffer.?, base_dll_name.Length / 2);
        if (dll_hash == hash) {
            return @ptrCast(dte.DllBase);
        }
    }

    return null;
}

pub fn getSectionAddrByHash(h_module: windows.HANDLE, hash: u32) ?windows.PVOID {
    const dos_header: *IMAGE_DOS_HEADER = @alignCast(@ptrCast(h_module));
    const nt = getNt(@ptrCast(h_module)) catch return null;
    const nt_header: *IMAGE_NT_HEADERS = @alignCast(@ptrCast(nt));
    const sec_header: [*]IMAGE_SECTION_HEADER = @constCast(@ptrCast(IMAGE_FIRST_SECTION(nt_header)));

    var i: u32 = 0;
    while (i < nt_header.FileHeader.NumberOfSections) : (i += 1) {
        const section_hash = hashFNV1a(string.trimFixedCString(8, &sec_header[i].Name));
        if (section_hash == hash) {
            const base_addr = @intFromPtr(dos_header);
            const virtual_addr = sec_header[i].VirtualAddress;
            return @as(windows.PVOID, @ptrFromInt(base_addr + virtual_addr));
        }
    }

    return null;
}

pub fn rva2va(comptime T: type, base: *const anyopaque, rva: usize) T {
    const ptr = @intFromPtr(base) + rva;
    return switch (@typeInfo(T)) {
        .pointer => {
            return @as(T, @ptrFromInt(ptr));
        },
        .int => {
            if (T != usize) {
                @compileError("expected usize, found '" ++ @typeName(T) ++ "'");
            }
            return @as(T, ptr);
        },
        else => {
            @compileError("expected pointer or int, found '" ++ @typeName(T) ++ "'");
        },
    };
}
