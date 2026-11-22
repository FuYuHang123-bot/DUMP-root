using System.Runtime.InteropServices;
using System.Text;

namespace MemScope.Interop;

internal static class Win32
{
    // ---- 进程访问权限 ----
    public const uint PROCESS_TERMINATE = 0x0001;
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;

    // ---- 内存 ----
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_FREE = 0x10000;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOCACHE = 0x200;

    public const uint MEM_IMAGE = 0x1000000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint MEM_PRIVATE = 0x20000;

    public const uint LIST_MODULES_ALL = 0x03;
    public const int MAX_PATH = 260;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags,
        [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer,
        IntPtr nSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string? lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

#if MEMSCOPE_ADVANCED
    // 仅直连系统调用层用它来放置调用桩；标准构建不编译，发布件里也就没有这几项导入
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, IntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
#endif

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool QueryDosDeviceW([MarshalAs(UnmanagedType.LPWStr)] string lpDeviceName,
        [Out] StringBuilder lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetLogicalDrives();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
        uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule,
        int cb, out int lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule,
        [Out] StringBuilder lpFilename, int nSize);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int GetMappedFileNameW(IntPtr hProcess, IntPtr lpv,
        [Out] StringBuilder lpFilename, int nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, int cb);

    // ---- ntdll（未走 syscall 桩时的回退路径）----
    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int systemInformationClass, IntPtr systemInformation,
        int systemInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryObject(IntPtr handle, int objectInformationClass, IntPtr objectInformation,
        int objectInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr handle);

    [DllImport("ntdll.dll")]
    public static extern int RtlAdjustPrivilege(int privilege, bool enable, bool currentThread, out bool enabled);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValueW(string? systemName, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr tokenHandle, int infoClass, IntPtr info, int len, out int retLen);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool IsWellKnownSid(IntPtr pSid, int wellKnownSidType);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    public const int TokenElevation = 20;
    public const int TokenUser = 1;
    public const int WinBuiltinAdministratorsSid = 26;

    public static bool IsElevated()
    {
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0008, out var token)) return false;
            try
            {
                var buf = Marshal.AllocHGlobal(4);
                try
                {
                    if (!GetTokenInformation(token, TokenElevation, buf, 4, out _)) return false;
                    return Marshal.ReadInt32(buf) != 0;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { CloseHandle(token); }
        }
        catch { return false; }
    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    public const uint PROCESS_DUP_HANDLE = 0x0040;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess,
        bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr min, IntPtr max);
}

[StructLayout(LayoutKind.Sequential)]
internal struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public ushort PartitionId;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MODULEINFO
{
    public IntPtr lpBaseOfDll;
    public uint SizeOfImage;
    public IntPtr EntryPoint;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TOKEN_PRIVILEGES
{
    public uint PrivilegeCount;
    public long Luid;
    public uint Attributes;
}

/// <summary>
/// SYSTEM_PROCESS_INFORMATION 的 x64 布局（字段顺序与 winternl.h 一致）。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct SYSTEM_PROCESS_INFORMATION
{
    public uint NextEntryOffset;
    public uint NumberOfThreads;
    public long WorkingSetPrivateSize;
    public uint HardFaultCount;
    public uint NumberOfThreadsHighWatermark;
    public ulong CycleTime;
    public long CreateTime;
    public long UserTime;
    public long KernelTime;
    public UNICODE_STRING ImageName;
    public int BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
    public uint HandleCount;
    public uint SessionId;
    public IntPtr UniqueProcessKey;
    public IntPtr PeakVirtualSize;
    public IntPtr VirtualSize;
    public uint PageFaultCount;
    public IntPtr PeakWorkingSetSize;
    public IntPtr WorkingSetSize;
    public IntPtr QuotaPeakPagedPoolUsage;
    public IntPtr QuotaPagedPoolUsage;
    public IntPtr QuotaPeakNonPagedPoolUsage;
    public IntPtr QuotaNonPagedPoolUsage;
    public IntPtr PagefileUsage;
    public IntPtr PeakPagefileUsage;
    public IntPtr PrivatePageCount;
    public long ReadOperationCount;
    public long WriteOperationCount;
    public long OtherOperationCount;
    public long ReadTransferCount;
    public long WriteTransferCount;
    public long OtherTransferCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    public IntPtr Object;
    public IntPtr UniqueProcessId;
    public IntPtr HandleValue;
    public uint GrantedAccess;
    public ushort CreatorBackTraceIndex;
    public ushort ObjectTypeIndex;
    public uint HandleAttributes;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct OBJECT_NAME_INFORMATION
{
    public UNICODE_STRING Name;
}

internal static class NtStatus
{
    public const int Success = 0;
    public const int InfoLengthMismatch = unchecked((int)0xC0000004);
    public const int BufferOverflow = unchecked((int)0x80000005);
    public const int BufferTooSmall = unchecked((int)0xC0000023);
    public const int AccessDenied = unchecked((int)0xC0000022);
    public const int InvalidCid = unchecked((int)0xC000000B);
    public const int InvalidParameter = unchecked((int)0xC000000D);
    public const int ProcessIsTerminating = unchecked((int)0xC000010A);

    public static string Describe(int status) => status switch
    {
        0 => "成功",
        AccessDenied => "拒绝访问 (0xC0000022) — 被内核保护/权限不足",
        InvalidCid => "进程不存在 (0xC000000B)",
        InvalidParameter => "参数无效 (0xC000000D)",
        ProcessIsTerminating => "进程正在退出 (0xC000010A)",
        _ => $"0x{status:X8}"
    };
}
