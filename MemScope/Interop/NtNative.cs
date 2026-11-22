using System.Runtime.InteropServices;

namespace MemScope.Interop;

/// <summary>
/// ntdll 常规导出直调层。
///
/// 这是**标准路径**：所有版本都会编译进来，功能与进程浏览器等常规工具一致。
/// 直连系统调用层（<see cref="Syscall"/>）不可用时，其封装会回退到这里。
/// </summary>
internal static class NtNative
{
    [DllImport("ntdll.dll")]
    public static extern int NtOpenProcess(out IntPtr processHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr clientId);

    [DllImport("ntdll.dll")]
    public static extern int NtTerminateProcess(IntPtr processHandle, int exitStatus);

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int cls, IntPtr info, int len, out int retLen);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryObject(IntPtr handle, int cls, IntPtr info, int len, out int retLen);

    [DllImport("ntdll.dll")]
    public static extern int NtGetNextThread(IntPtr processHandle, IntPtr threadHandle, uint desiredAccess,
        uint handleAttributes, uint flags, out IntPtr newThreadHandle);

    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    public static extern int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer,
        IntPtr numberOfBytesToRead, out IntPtr numberOfBytesRead);
}
