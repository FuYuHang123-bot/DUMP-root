using System.Diagnostics;
using System.Runtime.InteropServices;
using MemScope.Interop;

namespace MemScope.Core;

internal sealed class KillStage
{
    public string Name = "";
    public bool Ok;
    public bool Skipped;          // 未启用（例如高级模式未开启），不是失败
    public string Detail = "";
    public override string ToString() =>
        Skipped ? $"[跳过] {Name}：{Detail}" : $"[{(Ok ? "成功" : "失败")}] {Name}：{Detail}";
}

/// <summary>
/// 分层强制终止。
///
/// 标准模式（默认）：
///   L0 提权 SeDebugPrivilege
///   L1 kernel32 TerminateProcess
///
/// 高级模式（设置里显式开启后追加）：
///   L1' 直连系统调用 NtOpenProcess + NtTerminateProcess
///   L3  远程线程注入 RtlExitUserProcess（由目标进程自己退出）
///   L4  全线程 APC 投递 RtlExitUserProcess + 恢复线程
///
/// 为什么默认不开后三条：它们对「内核态回调保护」毫无作用（ObRegisterCallbacks 在打开句柄
/// 时就剥权限，与用户态走哪条路径无关），却会让程序看起来像注入器。只有目标存在用户态
/// hook 时才需要，届时由用户判断后开启。
///
/// 实事求是：若目标被内核态 ObRegisterCallbacks / PPL 保护，用户态没有任何方法能突破，
/// 必须由内核驱动在 Ring0 处理。每一步的 NTSTATUS 都会明确输出。
/// </summary>
internal static class Killer
{
    private static readonly HashSet<string> CriticalProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Memory Compression", "smss", "csrss", "wininit",
        "winlogon", "services", "lsass", "lsaiso", "MsMpEng", "SecurityHealthService", "SgrmBroker"
    };

    public static bool IsCritical(string name) => CriticalProcesses.Contains(name);

    public static bool EnableDebugPrivilege()
    {
        try
        {
            if (Win32.RtlAdjustPrivilege(20, true, false, out _) == 0) return true;
        }
        catch { }

        try
        {
            if (!Win32.OpenProcessToken(Win32.GetCurrentProcess(), 0x0020 | 0x0008, out IntPtr token)) return false;
            try
            {
                if (!Win32.LookupPrivilegeValueW(null, "SeDebugPrivilege", out long luid)) return false;
                var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = 0x2 };
                return Win32.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally { Win32.CloseHandle(token); }
        }
        catch { return false; }
    }

    // ---------------- 存活判定 ----------------

    private static bool OpenWith(int pid, uint access, out IntPtr handle, out int status)
    {
        handle = Win32.OpenProcess(access, false, pid);
        if (handle != IntPtr.Zero) { status = 0; return true; }

        IntPtr oa = ProcessSnapshot.ObjectAttributes();
        IntPtr cid = ProcessSnapshot.ClientId(pid);
        try
        {
            status = Syscall.OpenProcess(out handle, access, oa, cid);
            return status == 0 && handle != IntPtr.Zero;
        }
        finally
        {
            Marshal.FreeHGlobal(oa);
            Marshal.FreeHGlobal(cid);
        }
    }

    /// <summary>准确判断进程是否还存在（能区分“正在退出”）。</summary>
    public static bool IsAlive(int pid)
    {
        if (pid <= 0) return false;

        if (OpenWith(pid, 0x00100000 /*SYNCHRONIZE*/, out IntPtr h, out int status))
        {
            uint r = Win32.WaitForSingleObject(h, 0);
            Win32.CloseHandle(h);
            return r != 0; // WAIT_OBJECT_0(0) 表示已退出
        }

        if (status == NtStatus.ProcessIsTerminating || status == NtStatus.InvalidCid) return false;
        if (status == NtStatus.AccessDenied)
        {
            // 打不开但可能只是被保护：用系统快照确认是否真在运行
            return ProcessSnapshot.Capture().Processes.Any(p => p.Pid == pid);
        }
        return false;
    }

    private static async Task<bool> WaitExitAsync(int pid, int timeoutMs)
    {
        if (OpenWith(pid, 0x00100000, out IntPtr h, out int status))
        {
            try
            {
                var r = await Task.Run(() => Win32.WaitForSingleObject(h, (uint)timeoutMs));
                return r == 0;
            }
            finally { Win32.CloseHandle(h); }
        }
        if (status == NtStatus.ProcessIsTerminating || status == NtStatus.InvalidCid) return true;

        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            await Task.Delay(100);
            if (!IsAlive(pid)) return true;
        }
        return !IsAlive(pid);
    }

    // ---------------- 主流程 ----------------

    public static async Task<List<KillStage>> ForceKillAsync(int pid, string name)
    {
        var stages = new List<KillStage>();

        if (!IsAlive(pid))
        {
            stages.Add(new KillStage { Name = "检查", Ok = true, Detail = "进程已不存在" });
            return stages;
        }

        if (IsCritical(name))
        {
            stages.Add(new KillStage
            {
                Name = "安全检查",
                Ok = false,
                Detail = $"“{name}” 是 Windows 关键进程，终止会导致系统蓝屏/重启，已拒绝执行"
            });
            return stages;
        }

        bool elevated = EnableDebugPrivilege();
        stages.Add(new KillStage
        {
            Name = "L0 提权",
            Ok = elevated,
            Detail = elevated ? "SeDebugPrivilege 已启用" : "SeDebugPrivilege 启用失败（需要管理员权限）"
        });

        bool advanced = AppSettings.AdvancedActive;

        // ---- L1：直连系统调用（仅高级模式）----
        if (!advanced)
        {
            stages.Add(new KillStage
            {
                Name = "L1 直连 syscall",
                Skipped = true,
                Detail = "标准模式下不启用（设置 → 高级终止 可开启）"
            });
        }
        else if (OpenWith(pid, Win32.PROCESS_TERMINATE, out IntPtr hProc, out int openStatus))
        {
            int st = Syscall.TerminateProcess(hProc, 0);
            Win32.CloseHandle(hProc);
            stages.Add(new KillStage
            {
                Name = "L1 直连 syscall 终止",
                Ok = st == 0,
                Detail = st == 0 ? "NtTerminateProcess 返回成功" : NtStatus.Describe(st)
            });

            if (st == 0 && await WaitExitAsync(pid, 3000))
            {
                stages.Add(new KillStage { Name = "结果", Ok = true, Detail = "进程已终止（直连系统调用生效）" });
                return stages;
            }
        }
        else
        {
            stages.Add(new KillStage
            {
                Name = "L1 直连 syscall 终止",
                Ok = false,
                Detail = "打开句柄失败：" + NtStatus.Describe(openStatus)
            });

            if (openStatus == NtStatus.ProcessIsTerminating && await WaitExitAsync(pid, 2000))
            {
                stages.Add(new KillStage { Name = "结果", Ok = true, Detail = "进程正在退出，已结束" });
                return stages;
            }
        }

        // ---- L2：常规 API ----
        IntPtr h2 = Win32.OpenProcess(Win32.PROCESS_TERMINATE, false, pid);
        if (h2 != IntPtr.Zero)
        {
            bool ok = Win32.TerminateProcess(h2, 0);
            int err = Marshal.GetLastWin32Error();
            Win32.CloseHandle(h2);
            stages.Add(new KillStage
            {
                Name = "L2 TerminateProcess",
                Ok = ok,
                Detail = ok ? "调用成功" : $"失败，Win32 错误码 {err}"
            });
            if (ok && await WaitExitAsync(pid, 3000))
            {
                stages.Add(new KillStage { Name = "结果", Ok = true, Detail = "进程已终止（常规 API 生效）" });
                return stages;
            }
        }
        else
        {
            stages.Add(new KillStage { Name = "L2 TerminateProcess", Ok = false, Detail = "无法打开进程（拒绝访问）" });
        }

        // ---- L3 / L4：仅在高级模式执行（注入类操作，默认不启用）----
        if (!advanced)
        {
            stages.Add(new KillStage { Name = "L3 远程线程退出", Skipped = true, Detail = "标准模式下不启用" });
            stages.Add(new KillStage { Name = "L4 线程 APC 投递", Skipped = true, Detail = "标准模式下不启用" });
        }
        else
        {
            IntPtr remoteExit = RemoteExitRoutine();

            // ---- L3：远程线程让目标自杀 ----
            if (remoteExit != IntPtr.Zero)
            {
                if (OpenWith(pid, Win32.PROCESS_CREATE_THREAD | Win32.PROCESS_QUERY_INFORMATION |
                                 Win32.PROCESS_VM_OPERATION | Win32.PROCESS_VM_WRITE | Win32.PROCESS_SUSPEND_RESUME,
                        out IntPtr hT, out int stOpen))
                {
                    int st = Syscall.CreateThreadEx(out IntPtr hThread, hT, remoteExit, IntPtr.Zero, 0);
                    if (st == 0 && hThread != IntPtr.Zero)
                    {
                        Win32.WaitForSingleObject(hThread, 600);
                        Win32.CloseHandle(hThread);
                    }
                    Win32.CloseHandle(hT);

                    bool gone = await WaitExitAsync(pid, 2500);
                    stages.Add(new KillStage
                    {
                        Name = "L3 远程线程退出",
                        Ok = gone,
                        Detail = st == 0 ? (gone ? "目标进程已自行退出" : "线程已创建但进程仍在") : NtStatus.Describe(st)
                    });
                    if (gone) return stages;
                }
                else
                {
                    stages.Add(new KillStage
                    {
                        Name = "L3 远程线程退出",
                        Ok = false,
                        Detail = "无法获取注入所需句柄：" + NtStatus.Describe(stOpen)
                    });
                }
            }

            // ---- L4：全线程 APC ----
            if (remoteExit != IntPtr.Zero)
            {
                if (OpenWith(pid, Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_OPERATION | Win32.PROCESS_SUSPEND_RESUME,
                        out IntPtr hP, out _))
                {
                    int queued = 0, threads = 0;
                    IntPtr t = IntPtr.Zero;
                    while (true)
                    {
                        int st = Syscall.GetNextThread(hP, t, 0x0010 /*THREAD_SET_CONTEXT*/ | 0x0002 /*THREAD_SUSPEND_RESUME*/, out IntPtr next);
                        if (t != IntPtr.Zero) Win32.CloseHandle(t);
                        if (st != 0 || next == IntPtr.Zero) { t = IntPtr.Zero; break; }
                        t = next;
                        threads++;
                        if (Syscall.QueueApcThread(t, remoteExit, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero) == 0) queued++;
                        if (threads > 4000) break;
                    }
                    if (t != IntPtr.Zero) Win32.CloseHandle(t);

                    Syscall.ResumeProcess(hP);
                    hP.Close();
                    bool gone = await WaitExitAsync(pid, 2500);

                    stages.Add(new KillStage
                    {
                        Name = "L4 线程 APC 投递",
                        Ok = gone,
                        Detail = gone ? $"已向 {queued}/{threads} 个线程投递退出 APC，进程退出"
                                      : $"已向 {queued}/{threads} 个线程投递，进程仍存活"
                    });
                    if (gone) return stages;
                }
            }
        }

        stages.Add(new KillStage
        {
            Name = "结论",
            Ok = false,
            Detail = advanced
                ? "所有用户态路径均被拦截。目标大概率受内核回调（ObRegisterCallbacks/PPL）保护，" +
                  "必须用内核驱动（.sys）在 Ring0 解除保护后再终止。"
                : "标准路径被拒绝。若目标是自保护软件，可在「设置 → 高级终止」里开启直连系统调用与远程线程重试；" +
                  "若仍失败，说明目标受内核回调（ObRegisterCallbacks/PPL）保护，用户态无解，需要 Ring0 驱动。"
        });
        return stages;
    }

    /// <summary>目标进程内 RtlExitUserProcess 地址（ntdll 由 KnownDlls 共享映射，跨进程同址）。</summary>
    private static IntPtr RemoteExitRoutine()
    {
        IntPtr ntdll = Win32.GetModuleHandleW("ntdll.dll");
        if (ntdll != IntPtr.Zero)
        {
            IntPtr p = Win32.GetProcAddress(ntdll, "RtlExitUserProcess");
            if (p != IntPtr.Zero) return p;
        }
        IntPtr k32 = Win32.GetModuleHandleW("kernel32.dll");
        if (k32 != IntPtr.Zero)
        {
            IntPtr p = Win32.GetProcAddress(k32, "ExitProcess");
            if (p != IntPtr.Zero) return p;
        }
        return IntPtr.Zero;
    }

    /// <summary>结束整个进程树（先子后父）。</summary>
    public static async Task<List<string>> ForceKillTreeAsync(int rootPid, Func<int, string> nameOf, Action<string> log)
    {
        var lines = new List<string>();

        var snap = ProcessSnapshot.Capture();
        var children = new Dictionary<int, List<int>>();
        foreach (var p in snap.Processes)
        {
            if (!children.TryGetValue(p.ParentPid, out var list))
                children[p.ParentPid] = list = new List<int>();
            list.Add(p.Pid);
        }

        var order = new List<int>();
        void Walk(int pid, int depth)
        {
            if (depth > 12) return;
            if (children.TryGetValue(pid, out var kids))
                foreach (int k in kids) Walk(k, depth + 1);
            order.Add(pid);
        }
        Walk(rootPid, 0);

        foreach (int pid in order)
        {
            string name = nameOf(pid);
            var stages = await ForceKillAsync(pid, name);
            foreach (var s in stages) log($"  [PID {pid}] {s}");
            bool ok = stages.Count > 0 && stages[^1].Ok;
            lines.Add($"{name}({pid}) → {(ok ? "已终止" : "失败")}");
        }
        return lines;
    }
}

internal static class IntPtrExtensions
{
    public static void Close(this IntPtr h)
    {
        if (h != IntPtr.Zero) Win32.CloseHandle(h);
    }
}
