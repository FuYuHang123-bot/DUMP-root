using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Windows;
using MemScope.Core;
using MemScope.Interop;

namespace MemScope;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AppSettings.Load();

        // 直连系统调用只在显式开启「高级终止」时才准备。
        // 未开启时所有调用都走 Win32 / ntdll 标准路径（Syscall.Ready=false 会自然回退），
        // 进程里既不解析系统调用号，也不申请任何可执行内存。
        bool advanced = AppSettings.AdvancedMode ||
                        e.Args.Any(a => a.Equals("--advanced", StringComparison.OrdinalIgnoreCase));
        AppSettings.AdvancedActive = advanced;
        if (advanced) Syscall.Initialize();
        else Syscall.Disable("高级终止未开启（走标准系统调用）");

        // 主题要在窗口构造前就位，否则首帧会先按浅色布局再跳色
        ThemeManager.Apply(AppSettings.Dark);

        if (e.Args.Any(a => a.Equals("--probe", StringComparison.OrdinalIgnoreCase)))
        {
            string outPath = "probe.json";
            int idx = Array.FindIndex(e.Args, a => a.Equals("--out", StringComparison.OrdinalIgnoreCase));
            if (idx >= 0 && idx + 1 < e.Args.Length) outPath = e.Args[idx + 1];
            try { RunProbe(outPath); }
            catch (Exception ex) { try { File.WriteAllText(outPath + ".error", ex.ToString()); } catch { } }
            Shutdown(0);
            return;
        }

        // 无界面提取模式：MemScope.exe --dump <pid> <模块名> [--dir <输出目录>]
        int dumpIdx = Array.FindIndex(e.Args, a => a.Equals("--dump", StringComparison.OrdinalIgnoreCase));
        if (dumpIdx >= 0)
        {
            string pidText = dumpIdx + 1 < e.Args.Length ? e.Args[dumpIdx + 1] : "";
            string moduleName = dumpIdx + 2 < e.Args.Length ? e.Args[dumpIdx + 2] : "";
            int dirIdx = Array.FindIndex(e.Args, a => a.Equals("--dir", StringComparison.OrdinalIgnoreCase));
            string outDir = dirIdx >= 0 && dirIdx + 1 < e.Args.Length
                ? e.Args[dirIdx + 1]
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MemScope_Export", "modules");
            try { RunDump(pidText, moduleName, outDir); }
            catch (Exception ex) { try { File.WriteAllText("dump.error.txt", ex.ToString()); } catch { } }
            Shutdown(0);
            return;
        }

        var win = new MainWindow();
        MainWindow = win;
        win.Show();
    }

    /// <summary>无界面提取：把指定进程的某个模块从内存还原成文件，结果写入控制台日志与 dump.log。</summary>
    private static void RunDump(string pidText, string moduleName, string outDir)
    {
        var sb = new StringBuilder();
        void W(string s) { sb.AppendLine(s); }

        if (!int.TryParse(pidText, out int pid) || pid <= 0)
        {
            W("PID 无效：" + pidText);
            File.WriteAllText("dump.log", sb.ToString(), new UTF8Encoding(true));
            return;
        }

        var mods = MemoryMapScanner.Modules(pid);
        var mod = mods.FirstOrDefault(m => m.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                  ?? mods.FirstOrDefault(m => m.Name.Contains(moduleName, StringComparison.OrdinalIgnoreCase));

        if (mod == null)
        {
            W($"PID {pid} 的模块列表里没有匹配 \"{moduleName}\" 的项。已加载模块：");
            foreach (var m in mods.Take(40)) W($"  {m.Name,-32} {m.BaseHex}");
            File.WriteAllText("dump.log", sb.ToString(), new UTF8Encoding(true));
            return;
        }

        string procName = ProcessSnapshot.Capture().Processes.FirstOrDefault(p => p.Pid == pid)?.Name ?? "process";
        var r = ModuleDumper.DumpModule(pid, procName, mod, outDir, freeze: false);

        // 命令行是一次性取证：落盘完就直接输出报告，所以这里把后台哈希等齐，
        // 保证报告里的 sha256 不是空的（UI 里不等，哈希算完再补一行日志）。
        double criticalMs = r.ElapsedMs;
        try { r.HashTask?.GetAwaiter().GetResult(); } catch { }

        W($"dump: {procName}({pid}) {mod.Name} @{mod.BaseHex}  ok={r.Ok}  {r.FileBytes} B  {criticalMs:F0} ms");
        if (r.Ok)
        {
            W($"  out    = {r.OutPath}");
            W($"  sha256 = {r.Sha256}");
            W($"  pe     = {r.PeValid}  {r.PeNote}");
            W($"  time   = 关键路径 {criticalMs:F0} ms（读 {r.ReadMs:F0} · 落盘 {r.WriteMs:F0} · PE校验 {r.VerifyMs:F0} · 比对 {r.CompareMs:F0}）｜后台哈希 {r.HashMs:F0} ms（取证归档用，不挡落盘）｜峰值内存 {r.PeakWorkingSetMb} MB");
            if (r.ChangedDuringRead) W("  ! 提取期间内容发生变化（未冻结），快照可能不一致");
            foreach (var s in r.Sections) W(s.Line);
        }
        foreach (var n in r.Notes) W("  " + n);

        File.WriteAllText("dump.log", sb.ToString(), new UTF8Encoding(true));
    }

    /// <summary>无界面自检：验证进程采样 / 内存扫描 / 句柄扫描 / 强制终止链路。</summary>
    private static void RunProbe(string outPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== MemScope probe ===");
        sb.AppendLine($"time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"elevated: {Win32.IsElevated()}");
        sb.AppendLine($"syscall: ready={Syscall.Ready} {Syscall.StatusMessage}");

        var sw = Stopwatch.StartNew();
        var snap = ProcessSnapshot.Capture();
        sb.AppendLine($"capture: {snap.Processes.Count} processes, threads={snap.ThreadTotal}, " +
                      $"wsTotal={snap.WorkingSetTotal / 1024 / 1024}MB, {sw.Elapsed.TotalMilliseconds:F1}ms");

        var sample = snap.Processes.OrderByDescending(p => p.WorkingSet).Take(12).ToList();
        foreach (var p in sample)
            sb.AppendLine($"  pid={p.Pid,-6} {p.Name,-28} ws={p.WorkingSet / 1024 / 1024,6}MB private={p.PrivateBytes / 1024 / 1024,6}MB th={p.Threads,-4} h={p.Handles}");

        int me = Environment.ProcessId;
        var myPath = ProcessSnapshot.GetImagePath(me, 0);
        sb.AppendLine($"ownPath: {(string.IsNullOrEmpty(myPath) ? "(空)" : myPath)}");

        sw.Restart();
        var regions = MemoryMapScanner.Scan(me);
        sb.AppendLine($"memoryRegions(self): {regions.Count} 条, {sw.Elapsed.TotalMilliseconds:F1}ms");
        foreach (var r in regions.Take(5))
            sb.AppendLine($"  {r.BaseHex,-14} {r.SizeDisplay,-10} {r.State} {r.Type} {r.Protect} {r.File}");

        sw.Restart();
        var mods = MemoryMapScanner.Modules(me);
        sb.AppendLine($"modules(self): {mods.Count} 个, {sw.Elapsed.TotalMilliseconds:F1}ms");
        foreach (var m in mods.Take(5)) sb.AppendLine($"  {m.Name,-28} {m.SizeDisplay,8} {m.BaseHex}");

        sw.Restart();
        var handles = HandleScanner.ScanFiles(me);
        sb.AppendLine($"fileHandles(self): {handles.Items.Count} 条 ({handles.Note}), {sw.Elapsed.TotalMilliseconds:F1}ms");
        sb.AppendLine($"fileTypeIndex: {HandleScanner.FileTypeDiagnostic}");
        foreach (var h in handles.Items.Take(5)) sb.AppendLine($"  {h.AccessHex} {h.Path}");

        // 强制终止链路实测：启动一个替身进程再把它做掉
        try
        {
            var proc = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 60 127.0.0.1 > nul")
            {
                UseShellExecute = false,
                CreateNoWindow = true
            });
            if (proc != null)
            {
                Thread.Sleep(400);
                sw.Restart();
                // 注意：RunProbe 跑在 UI 线程上，直接 .GetResult() 会与 WPF 同步上下文死锁，
                // 因此放到线程池执行后再阻塞等待。
                var stages = Task.Run(() => Killer.ForceKillAsync(proc.Id, "probe-victim"))
                    .GetAwaiter().GetResult();
                sb.AppendLine($"killTest(pid={proc.Id}): 耗时 {sw.Elapsed.TotalMilliseconds:F0}ms");
                foreach (var s in stages) sb.AppendLine("  " + s);
                sb.AppendLine($"killTest.aliveAfter: {Killer.IsAlive(proc.Id)}");
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine("killTest.error: " + ex.Message);
        }

        var json = JsonSerializer.Serialize(new
        {
            elevated = Win32.IsElevated(),
            syscallReady = Syscall.Ready,
            syscallStatus = Syscall.StatusMessage,
            processCount = snap.Processes.Count,
            captureMs = Math.Round(snap.ElapsedMs, 2),
            log = sb.ToString()
        }, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });

        File.WriteAllText(outPath, json, new UTF8Encoding(false));
        File.WriteAllText(outPath + ".log.txt", sb.ToString(), new UTF8Encoding(true));
    }
}
