using System.Runtime.InteropServices;

namespace MemScope.Interop;

#if MEMSCOPE_ADVANCED

/// <summary>
/// 直接系统调用层（**仅在「高级终止」开启时使用**）。
///
/// 原理：从磁盘上的 ntdll.dll 解析每个 Nt* 导出的系统调用号（SSN），
/// 自行构造 x64 调用序列（mov r10, rcx / mov eax, SSN / syscall / ret）并调用。
/// 调用链不经过 ntdll 的代码段，因此当用户态 API 被 hook 时仍然可用。
///
/// 设计取舍：这条路对「内核态回调保护」没有任何帮助（ObRegisterCallbacks 在打开句柄时
/// 就剥掉权限，跟走哪条用户态路径无关），但对少数做了 ntdll inline hook 的软件有效。
/// 由于这类实现会显著提高安全软件的关注度，默认关闭，由用户在设置里显式开启。
///
/// **本文件整块受 MEMSCOPE_ADVANCED 控制**：对外发布的标准构建不包含本类，
/// 因此发布件里既没有系统调用号解析代码，也没有可执行内存分配与注入相关导入。
/// </summary>
internal static class Syscall
{
    private static readonly Dictionary<string, int> Ssn = new(StringComparer.Ordinal);
    private static readonly Dictionary<string, IntPtr> Stubs = new(StringComparer.Ordinal);
    private static readonly Dictionary<string, Delegate> Delegates = new(StringComparer.Ordinal);

    public static bool Ready { get; private set; }
    public static string StatusMessage { get; private set; } = "未初始化";

    private static bool _initialized;

    /// <summary>未开启高级模式时的状态说明（让设置界面与日志能如实显示为什么没就绪）。</summary>
    public static void Disable(string reason)
    {
        Ready = false;
        StatusMessage = reason;
    }

    public static void Initialize()
    {
        if (_initialized)
        {
            // 之前被 Disable 过：系统调用号已经在表里，直接恢复即可，不必重新解析
            if (Ssn.Count > 0)
            {
                Ready = true;
                StatusMessage = $"已解析 {Ssn.Count} 个系统调用号";
            }
            return;
        }
        _initialized = true;
        try
        {
            var path = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
            var image = File.ReadAllBytes(path);
            ParseExports(image);
            Ready = Ssn.Count > 0;
            StatusMessage = Ready ? $"已解析 {Ssn.Count} 个系统调用号" : "未解析到系统调用号";
        }
        catch (Exception ex)
        {
            Ready = false;
            StatusMessage = "解析失败：" + ex.Message;
        }
    }

    // ---------------- PE 导出表解析 ----------------

    private static void ParseExports(byte[] image)
    {
        if (image.Length < 0x200) return;
        int peOff = BitConverter.ToInt32(image, 0x3C);
        if (peOff <= 0 || peOff + 0x100 >= image.Length) return;
        if (BitConverter.ToUInt32(image, peOff) != 0x00004550) return;

        int coff = peOff + 4;
        int numSections = BitConverter.ToUInt16(image, coff + 2);
        int optSize = BitConverter.ToUInt16(image, coff + 16);
        int opt = coff + 20;
        if (BitConverter.ToUInt16(image, opt) != 0x20B) return; // 仅 x64

        int exportRva = BitConverter.ToInt32(image, opt + 112);
        if (exportRva <= 0) return;

        var sections = new List<(uint Va, uint VSize, uint RawSize, uint RawPtr)>(numSections);
        int sec = opt + optSize;
        for (int i = 0; i < numSections; i++)
        {
            int p = sec + i * 40;
            if (p + 40 > image.Length) break;
            sections.Add((
                BitConverter.ToUInt32(image, p + 12),  // VirtualAddress
                BitConverter.ToUInt32(image, p + 8),   // VirtualSize
                BitConverter.ToUInt32(image, p + 16),  // SizeOfRawData
                BitConverter.ToUInt32(image, p + 20))); // PointerToRawData
        }

        int Rva2Off(int rva)
        {
            foreach (var s in sections)
            {
                uint size = Math.Max(s.VSize, s.RawSize);
                if (rva >= s.Va && rva < s.Va + size) return (int)(rva - s.Va + s.RawPtr);
            }
            return rva;
        }

        int exp = Rva2Off(exportRva);
        if (exp + 40 > image.Length) return;
        int numNames = BitConverter.ToInt32(image, exp + 24);
        int addrFunctions = BitConverter.ToInt32(image, exp + 28);
        int addrNames = BitConverter.ToInt32(image, exp + 32);
        int addrOrdinals = BitConverter.ToInt32(image, exp + 36);
        if (numNames <= 0 || numNames > 8192) return;

        int offFunc = Rva2Off(addrFunctions);
        int offNames = Rva2Off(addrNames);
        int offOrd = Rva2Off(addrOrdinals);

        for (int i = 0; i < numNames; i++)
        {
            int nameRva = BitConverter.ToInt32(image, offNames + i * 4);
            int nameOff = Rva2Off(nameRva);
            if (nameOff <= 0 || nameOff >= image.Length) continue;

            int end = nameOff;
            while (end < image.Length && image[end] != 0) end++;
            string name = System.Text.Encoding.ASCII.GetString(image, nameOff, end - nameOff);
            if (name.Length < 3 || name[0] != 'N' || name[1] != 't') continue;

            int ord = BitConverter.ToUInt16(image, offOrd + i * 2);
            int funcRva = BitConverter.ToInt32(image, offFunc + ord * 4);
            if (funcRva <= 0) continue;

            int code = Rva2Off(funcRva);
            if (code + 8 >= image.Length) continue;

            // 4C 8B D1        mov r10, rcx
            // B8 xx xx xx xx  mov eax, SSN
            if (image[code] == 0x4C && image[code + 1] == 0x8B && image[code + 2] == 0xD1 && image[code + 3] == 0xB8)
            {
                int ssn = BitConverter.ToInt32(image, code + 4);
                if (ssn > 0 && ssn < 0x2000) Ssn[name] = ssn;
            }
        }
    }

    // ---------------- 调用序列构造 ----------------

    /// <summary>
    /// 所有调用序列共用一个 4 KB 页：
    /// 分配时给 PAGE_READWRITE，写入后立刻 VirtualProtect 成 PAGE_EXECUTE_READ。
    /// 进程里因此不会出现 RWX 页——那既是不必要的权限组合，也是安全软件最先看的地方。
    /// </summary>
    private static IntPtr _codePage;
    private static int _codeUsed;
    private const int CodePageSize = 4096;

    private static IntPtr PlaceStub(byte[] code)
    {
        if (_codePage == IntPtr.Zero)
        {
            _codePage = Win32.VirtualAlloc(IntPtr.Zero, (IntPtr)CodePageSize,
                                           Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
            if (_codePage == IntPtr.Zero) return IntPtr.Zero;
        }

        int need = (code.Length + 15) & ~15;
        if (_codeUsed + need > CodePageSize) return IntPtr.Zero;

        IntPtr at = _codePage + _codeUsed;

        // 写入窗口内临时给写权限，写完立即收回成只读可执行
        Win32.VirtualProtect(_codePage, (IntPtr)CodePageSize, Win32.PAGE_READWRITE, out _);
        Marshal.Copy(code, 0, at, code.Length);
        Win32.VirtualProtect(_codePage, (IntPtr)CodePageSize, Win32.PAGE_EXECUTE_READ, out _);

        _codeUsed += need;
        return at;
    }

    public static IntPtr Resolve(string name)
    {
        if (Stubs.TryGetValue(name, out var cached)) return cached;
        if (!Ready || !Ssn.TryGetValue(name, out int ssn))
        {
            Stubs[name] = IntPtr.Zero;
            return IntPtr.Zero;
        }

        byte[] stub =
        [
            0x4C, 0x8B, 0xD1,                                  // mov r10, rcx
            0xB8, (byte)ssn, (byte)(ssn >> 8), (byte)(ssn >> 16), (byte)(ssn >> 24), // mov eax, ssn
            0x0F, 0x05,                                        // syscall
            0xC3                                               // ret
        ];

        IntPtr mem = PlaceStub(stub);
        Stubs[name] = mem;
        return mem;
    }

    private static T? GetDelegate<T>(string name) where T : Delegate
    {
        if (Delegates.TryGetValue(name, out var d)) return (T)d;
        var stub = Resolve(name);
        if (stub == IntPtr.Zero) return null;
        var fn = Marshal.GetDelegateForFunctionPointer<T>(stub);
        Delegates[name] = fn;
        return fn;
    }

    // ---------------- 常用封装 ----------------

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtOpenProcessFn(out IntPtr processHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr clientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtTerminateProcessFn(IntPtr processHandle, int exitStatus);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtQuerySystemInformationFn(int cls, IntPtr info, int len, out int retLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtQueryObjectFn(IntPtr handle, int cls, IntPtr info, int len, out int retLen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtCreateThreadExFn(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes,
        IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags, IntPtr zeroBits,
        IntPtr stackSize, IntPtr maximumStackSize, IntPtr attributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtQueueApcThreadFn(IntPtr threadHandle, IntPtr apcRoutine, IntPtr arg1, IntPtr arg2, IntPtr arg3);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtGetNextThreadFn(IntPtr processHandle, IntPtr threadHandle, uint desiredAccess,
        uint handleAttributes, uint flags, out IntPtr newThreadHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtSuspendProcessFn(IntPtr processHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtResumeProcessFn(IntPtr processHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtReadVirtualMemoryFn(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer,
        IntPtr numberOfBytesToRead, out IntPtr numberOfBytesRead);

    public static int OpenProcess(out IntPtr handle, uint access, IntPtr objectAttributes, IntPtr clientId)
    {
        var fn = GetDelegate<NtOpenProcessFn>("NtOpenProcess");
        if (fn != null) return fn(out handle, access, objectAttributes, clientId);
        return NtNative.NtOpenProcess(out handle, access, objectAttributes, clientId);
    }

    public static int TerminateProcess(IntPtr handle, int exitStatus)
    {
        var fn = GetDelegate<NtTerminateProcessFn>("NtTerminateProcess");
        if (fn != null) return fn(handle, exitStatus);
        return NtNative.NtTerminateProcess(handle, exitStatus);
    }

    public static int QuerySystemInformation(int cls, IntPtr info, int len, out int retLen)
    {
        var fn = GetDelegate<NtQuerySystemInformationFn>("NtQuerySystemInformation");
        if (fn != null) return fn(cls, info, len, out retLen);
        return NtNative.NtQuerySystemInformation(cls, info, len, out retLen);
    }

    public static int QueryObject(IntPtr handle, int cls, IntPtr info, int len, out int retLen)
    {
        var fn = GetDelegate<NtQueryObjectFn>("NtQueryObject");
        if (fn != null) return fn(handle, cls, info, len, out retLen);
        return NtNative.NtQueryObject(handle, cls, info, len, out retLen);
    }

    public static int CreateThreadEx(out IntPtr thread, IntPtr process, IntPtr start, IntPtr arg, uint flags)
    {
        var fn = GetDelegate<NtCreateThreadExFn>("NtCreateThreadEx");
        if (fn != null) return fn(out thread, 0x1FFFFF, IntPtr.Zero, process, start, arg, flags,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        return InjectionNative.NtCreateThreadEx(out thread, 0x1FFFFF, IntPtr.Zero, process, start, arg, flags,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
    }

    public static int QueueApcThread(IntPtr thread, IntPtr routine, IntPtr arg1, IntPtr arg2, IntPtr arg3)
    {
        var fn = GetDelegate<NtQueueApcThreadFn>("NtQueueApcThread");
        if (fn != null) return fn(thread, routine, arg1, arg2, arg3);
        return InjectionNative.NtQueueApcThread(thread, routine, arg1, arg2, arg3);
    }

    public static int GetNextThread(IntPtr process, IntPtr thread, uint access, out IntPtr next)
    {
        var fn = GetDelegate<NtGetNextThreadFn>("NtGetNextThread");
        if (fn != null) return fn(process, thread, access, 0, 0, out next);
        return NtNative.NtGetNextThread(process, thread, access, 0, 0, out next);
    }

    public static int SuspendProcess(IntPtr process)
    {
        var fn = GetDelegate<NtSuspendProcessFn>("NtSuspendProcess");
        if (fn != null) return fn(process);
        return NtNative.NtSuspendProcess(process);
    }

    public static int ResumeProcess(IntPtr process)
    {
        var fn = GetDelegate<NtResumeProcessFn>("NtResumeProcess");
        if (fn != null) return fn(process);
        return NtNative.NtResumeProcess(process);
    }

    /// <summary>读目标进程内存：优先直连系统调用 NtReadVirtualMemory，绕过用户态 ReadProcessMemory 钩子。</summary>
    public static int ReadVirtualMemory(IntPtr process, IntPtr baseAddress, IntPtr buffer, int size, out long bytesRead)
    {
        var fn = GetDelegate<NtReadVirtualMemoryFn>("NtReadVirtualMemory");
        int st;
        IntPtr got;
        if (fn != null) st = fn(process, baseAddress, buffer, (IntPtr)size, out got);
        else st = NtNative.NtReadVirtualMemory(process, baseAddress, buffer, (IntPtr)size, out got);
        bytesRead = got.ToInt64();
        return st;
    }

    /// <summary>注入相关导入只存在于高级构建，标准构建完全不编译它们。</summary>
    private static class InjectionNative
    {
        [DllImport("ntdll.dll")]
        public static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes,
            IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags, IntPtr zeroBits,
            IntPtr stackSize, IntPtr maximumStackSize, IntPtr attributeList);

        [DllImport("ntdll.dll")]
        public static extern int NtQueueApcThread(IntPtr threadHandle, IntPtr apcRoutine, IntPtr arg1, IntPtr arg2, IntPtr arg3);
    }
}

#else

/// <summary>
/// 标准构建：不包含直连系统调用层。
///
/// 保留同名同签名的门面，使调用方无需改动；所有方法直接落到 ntdll 常规导出
/// （<see cref="NtNative"/>），行为与常规进程工具一致：不解析系统调用号、
/// 不申请可执行内存、不构造任何调用桩。
/// </summary>
internal static class Syscall
{
    public static bool Ready => false;

    public static string StatusMessage { get; private set; } = "标准构建：不含直连系统调用层";

    public static void Disable(string reason) => StatusMessage = reason;

    /// <summary>标准构建无需准备任何东西，保留为空操作。</summary>
    public static void Initialize() { }

    /// <summary>标准构建没有调用桩，恒返回零。</summary>
    public static IntPtr Resolve(string name) => IntPtr.Zero;

    public static int OpenProcess(out IntPtr handle, uint access, IntPtr objectAttributes, IntPtr clientId)
        => NtNative.NtOpenProcess(out handle, access, objectAttributes, clientId);

    public static int TerminateProcess(IntPtr handle, int exitStatus)
        => NtNative.NtTerminateProcess(handle, exitStatus);

    public static int QuerySystemInformation(int cls, IntPtr info, int len, out int retLen)
        => NtNative.NtQuerySystemInformation(cls, info, len, out retLen);

    public static int QueryObject(IntPtr handle, int cls, IntPtr info, int len, out int retLen)
        => NtNative.NtQueryObject(handle, cls, info, len, out retLen);

    public static int GetNextThread(IntPtr process, IntPtr thread, uint access, out IntPtr next)
        => NtNative.NtGetNextThread(process, thread, access, 0, 0, out next);

    public static int SuspendProcess(IntPtr process) => NtNative.NtSuspendProcess(process);

    public static int ResumeProcess(IntPtr process) => NtNative.NtResumeProcess(process);

    public static int ReadVirtualMemory(IntPtr process, IntPtr baseAddress, IntPtr buffer, int size, out long bytesRead)
    {
        int st = NtNative.NtReadVirtualMemory(process, baseAddress, buffer, (IntPtr)size, out IntPtr got);
        bytesRead = got.ToInt64();
        return st;
    }
}

#endif
