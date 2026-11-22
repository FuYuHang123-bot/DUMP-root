using System.Runtime.InteropServices;
using MemScope.Interop;

namespace MemScope.Core;

/// <summary>
/// 统一的“打开目标进程”入口：先用 kernel32.OpenProcess，
/// 失败（被用户态 Hook 拦截 / 句柄被剥夺）时改走直连系统调用 NtOpenProcess。
/// </summary>
internal static class TargetProcess
{
    public static IntPtr Open(int pid, uint access)
    {
        IntPtr h = Win32.OpenProcess(access, false, pid);
        if (h != IntPtr.Zero) return h;

        if (!Syscall.Ready) return IntPtr.Zero;

        IntPtr oa = ProcessSnapshot.ObjectAttributes();
        IntPtr cid = ProcessSnapshot.ClientId(pid);
        try
        {
            int st = Syscall.OpenProcess(out h, access, oa, cid);
            return st == 0 ? h : IntPtr.Zero;
        }
        finally
        {
            Marshal.FreeHGlobal(oa);
            Marshal.FreeHGlobal(cid);
        }
    }
}
