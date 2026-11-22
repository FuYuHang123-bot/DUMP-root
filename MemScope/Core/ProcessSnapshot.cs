using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using MemScope.Interop;

namespace MemScope.Core;

/// <summary>一次采样的单进程原始数据。</summary>
internal sealed class ProcSample
{
    public int Pid;
    public int ParentPid;
    public string Name = "";
    public uint Threads;
    public uint Handles;
    public ulong WorkingSet;
    public ulong PrivateBytes;
    public ulong VirtualBytes;
    public long CreateTime;
    public long KernelTime;
    public long UserTime;
    public uint SessionId;
    public int BasePriority;
    public bool IsElevatedCandidate;
    public string ImagePath = "";
}

internal sealed class SystemSnapshot
{
    public readonly List<ProcSample> Processes = new(512);
    public long TakenAtTicks;
    public double ElapsedMs;
    public int ThreadTotal;
    public ulong WorkingSetTotal;
    public ulong PrivateTotal;
}

/// <summary>
/// 用 NtQuerySystemInformation(SystemProcessInformation) 一次性取回全系统进程快照。
/// 比 Process.GetProcesses() 逐个查询快一个数量级，且包含私有工作集等 Process 类拿不到的字段。
/// </summary>
internal static class ProcessSnapshot
{
    private const int SystemProcessInformation = 5;

    private static readonly Dictionary<(int Pid, long Create), string> PathCache = new();

    public static string GetImagePath(int pid, long createTime)
    {
        var key = (pid, createTime);
        if (PathCache.TryGetValue(key, out var cached)) return cached;

        string path = "";
        IntPtr h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero)
        {
            // 直连系统调用再试一次（绕过用户态 OpenProcess 钩子）
            var oa = ObjectAttributes();
            var cid = ClientId(pid);
            try
            {
                if (Syscall.OpenProcess(out h, Win32.PROCESS_QUERY_LIMITED_INFORMATION, oa, cid) != 0) h = IntPtr.Zero;
            }
            finally
            {
                Marshal.FreeHGlobal(oa);
                Marshal.FreeHGlobal(cid);
            }
        }

        if (h != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (Win32.QueryFullProcessImageNameW(h, 0, sb, ref size)) path = sb.ToString(0, size);
            }
            finally { Win32.CloseHandle(h); }
        }

        PathCache[key] = path;
        return path;
    }

    public static SystemSnapshot Capture()
    {
        var sw = Stopwatch.StartNew();
        var snap = new SystemSnapshot();

        int len = 1 << 20;
        IntPtr buf = Marshal.AllocHGlobal(len);
        int status;
        try
        {
            while (true)
            {
                status = Syscall.QuerySystemInformation(SystemProcessInformation, buf, len, out int ret);
                if (status == NtStatus.InfoLengthMismatch || status == NtStatus.BufferTooSmall || status == NtStatus.BufferOverflow)
                {
                    if (ret <= 0) ret = len * 2;
                    len = ret + (64 * 1024);
                    buf = Marshal.ReAllocHGlobal(buf, (IntPtr)len);
                    continue;
                }
                break;
            }

            if (status != 0)
            {
                snap.ElapsedMs = sw.Elapsed.TotalMilliseconds;
                return snap;
            }

            long now = DateTime.UtcNow.Ticks;
            int offset = 0;
            while (true)
            {
                IntPtr p = buf + offset;
                var spi = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(p);

                var item = new ProcSample
                {
                    Pid = (int)spi.UniqueProcessId,
                    ParentPid = (int)spi.InheritedFromUniqueProcessId,
                    Name = spi.ImageName.Buffer != IntPtr.Zero && spi.ImageName.Length > 0
                        ? Marshal.PtrToStringUni(spi.ImageName.Buffer, spi.ImageName.Length / 2) ?? ""
                        : "(System Idle)" + "",
                    Threads = spi.NumberOfThreads,
                    Handles = spi.HandleCount,
                    WorkingSet = (ulong)spi.WorkingSetSize.ToInt64(),
                    PrivateBytes = (ulong)spi.PrivatePageCount.ToInt64(),
                    VirtualBytes = (ulong)spi.VirtualSize.ToInt64(),
                    CreateTime = spi.CreateTime,
                    KernelTime = spi.KernelTime,
                    UserTime = spi.UserTime,
                    SessionId = spi.SessionId,
                    BasePriority = spi.BasePriority,
                    IsElevatedCandidate = spi.UniqueProcessId == IntPtr.Zero
                };

                if (string.IsNullOrEmpty(item.Name) && item.Pid == 0) item.Name = "Idle";
                if (string.IsNullOrEmpty(item.Name)) item.Name = "System";

                snap.Processes.Add(item);
                snap.ThreadTotal += (int)item.Threads;
                snap.WorkingSetTotal += item.WorkingSet;
                snap.PrivateTotal += item.PrivateBytes;

                if (spi.NextEntryOffset == 0) break;
                offset += (int)spi.NextEntryOffset;
                if (offset <= 0 || offset >= len) break;
            }

            snap.TakenAtTicks = now;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }

        snap.ElapsedMs = sw.Elapsed.TotalMilliseconds;
        return snap;
    }

    internal static IntPtr ClientId(int pid)
    {
        IntPtr cid = Marshal.AllocHGlobal(16);
        Marshal.WriteInt64(cid, 0, pid);
        Marshal.WriteInt64(cid, 8, 0);
        return cid;
    }

    internal static IntPtr ObjectAttributes()
    {
        // OBJECT_ATTRIBUTES: Length(4) + pad + RootDirectory(8) + ObjectName(8) + Attributes(4) + SecurityDescriptor(8) + SQOS(8)
        IntPtr oa = Marshal.AllocHGlobal(48);
        for (int i = 0; i < 48; i += 8) Marshal.WriteInt64(oa, i, 0);
        Marshal.WriteInt32(oa, 0, 48);
        return oa;
    }

    public static void ClearPathCache() => PathCache.Clear();
}
