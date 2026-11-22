using System.Diagnostics;
using System.Text;
using MemScope.Core;
using MemScope.Interop;

namespace MemScopeCli;

internal static class Program
{
    private static void Say(string s)
    {
        Console.WriteLine(s);
        Console.Out.Flush();
    }

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        // 提取引擎基准模式：--bench <pid> <模块> [次数]
        if (args.Any(a => a.Equals("--bench", StringComparison.OrdinalIgnoreCase)))
            return Bench.Run(args);

        string outPath = args.FirstOrDefault(a => !a.StartsWith('-')) ?? "cli_report.txt";
        var report = new StringBuilder();
        void Log(string s) { report.AppendLine(s); Say(s); }

        try
        {
            Log($"== MemScope 引擎自检 {DateTime.Now:yyyy-MM-dd HH:mm:ss} ==");
            Log($"elevated = {Win32.IsElevated()}  cores = {Environment.ProcessorCount}  x64 = {Environment.Is64BitProcess}");

            // 1. syscall 层
            Syscall.Initialize();
            Log($"[1] syscall: ready={Syscall.Ready}  {Syscall.StatusMessage}");
            foreach (var fn in new[] { "NtOpenProcess", "NtTerminateProcess", "NtQuerySystemInformation", "NtQueryObject", "NtCreateThreadEx", "NtQueueApcThread", "NtGetNextThread" })
            {
                var stub = Syscall.Resolve(fn);
                Log($"    {fn,-26} stub=0x{stub.ToInt64():X}");
            }

            // 2. 进程快照
            var sw = Stopwatch.StartNew();
            var snap = ProcessSnapshot.Capture();
            sw.Stop();
            Log($"[2] snapshot: {snap.Processes.Count} 进程 / {snap.ThreadTotal} 线程 / " +
                $"{snap.WorkingSetTotal / 1024 / 1024} MB 工作集 / {sw.Elapsed.TotalMilliseconds:F1} ms");
            foreach (var p in snap.Processes.OrderByDescending(x => x.WorkingSet).Take(8))
                Log($"    pid={p.Pid,-6} {p.Name,-24} ws={p.WorkingSet / 1024 / 1024,6} MB  priv={p.PrivateBytes / 1024 / 1024,6} MB  th={p.Threads,-4} h={p.Handles}");

            // 3. 路径
            int me = Environment.ProcessId;
            var self = snap.Processes.FirstOrDefault(p => p.Pid == me);
            Log($"[3] self pid={me} inSnapshot={self != null} path={ProcessSnapshot.GetImagePath(me, self?.CreateTime ?? 0)}");

            // 4. 内存区域
            sw.Restart();
            var regions = MemoryMapScanner.Scan(me);
            sw.Stop();
            Log($"[4] regions(self): {regions.Count} 条 / {sw.Elapsed.TotalMilliseconds:F1} ms");
            foreach (var r in regions.Take(6))
                Log($"    {r.BaseHex,-14} {r.SizeDisplay,-11} {r.State,-4} {r.Type,-4} {r.Protect,-8} {r.File}");

            // 5. 模块
            sw.Restart();
            var mods = MemoryMapScanner.Modules(me);
            sw.Stop();
            Log($"[5] modules(self): {mods.Count} 个 / {sw.Elapsed.TotalMilliseconds:F1} ms");
            foreach (var m in mods.Take(6)) Log($"    {m.Name,-26} {m.SizeDisplay,9}  {m.BaseHex}");

            // 6. 文件句柄
            sw.Restart();
            var hs = HandleScanner.ScanFiles(me);
            sw.Stop();
            Log($"[6] fileHandles(self): {hs.Items.Count} 条 / {sw.Elapsed.TotalMilliseconds:F1} ms  ({hs.Note})");
            Log($"    {HandleScanner.FileTypeDiagnostic}");
            foreach (var h in hs.Items.Take(6)) Log($"    {h.AccessHex}  {h.Path}");

            // 7. 强制终止链路
            try
            {
                var psi = new ProcessStartInfo("C:\\Windows\\System32\\cmd.exe", "/c ping -n 120 127.0.0.1 > nul")
                { UseShellExecute = false, CreateNoWindow = true };
                using var victim = Process.Start(psi);
                if (victim != null)
                {
                    Thread.Sleep(500);
                    Log($"[7] killTest: 启动替身 pid={victim.Id}, alive={Killer.IsAlive(victim.Id)}");
                    sw.Restart();
                    var stages = Killer.ForceKillAsync(victim.Id, "cmd").GetAwaiter().GetResult();
                    sw.Stop();
                    foreach (var s in stages) Log("    " + s);
                    Log($"    terminated={!Killer.IsAlive(victim.Id)}  耗时 {sw.Elapsed.TotalMilliseconds:F0} ms");
                }
            }
            catch (Exception ex)
            {
                Log("[7] killTest 异常: " + ex);
            }

            // 8. 导出
            try
            {
                var rows = snap.Processes.Select(p =>
                {
                    var r = new ProcessRow { Pid = p.Pid, CreateTime = p.CreateTime, Path = ProcessSnapshot.GetImagePath(p.Pid, p.CreateTime) };
                    r.Update(p, 1000, Environment.ProcessorCount, false);
                    return r;
                }).ToList();
                var (csv, json) = SnapshotExporter.WriteSnapshot(snap, rows, Path.Combine(AppContext.BaseDirectory, "export_test"));
                Log($"[8] export: {Path.GetFileName(csv)} ({new FileInfo(csv).Length} B) / {Path.GetFileName(json)} ({new FileInfo(json).Length} B)");
            }
            catch (Exception ex)
            {
                Log("[8] export 异常: " + ex.Message);
            }

            // 9. 从活进程提取模块二进制
            try
            {
                int targetPid = -1;
                ModuleInfo? targetMod = null;
                string targetName = "";
                foreach (var p in snap.Processes.OrderByDescending(x => x.WorkingSet).Take(40))
                {
                    if (p.Pid <= 4) continue;
                    var mm = MemoryMapScanner.Modules(p.Pid);
                    var m = mm.FirstOrDefault(x => x.Name.Equals("nsi.dll", StringComparison.OrdinalIgnoreCase));
                    if (m != null && m.Size > 0)
                    {
                        targetPid = p.Pid;
                        targetMod = m;
                        targetName = p.Name;
                        break;
                    }
                }

                if (targetMod == null)
                {
                    Log("[9] 未找到加载 nsi.dll 的进程，跳过");
                }
                else
                {
                    string dumpRoot = Path.Combine(AppContext.BaseDirectory, "dump_test");
                    sw.Restart();
                    var dr = ModuleDumper.DumpModule(targetPid, targetName, targetMod, dumpRoot, false);
                    sw.Stop();
                    Log($"[9] dump {targetName}({targetPid}) {targetMod.Name} @0x{targetMod.Base:X} " +
                        $": ok={dr.Ok} {dr.FileBytes} B / {sw.Elapsed.TotalMilliseconds:F0} ms");
                    Log($"    out    = {dr.OutPath}");
                    Log($"    sha256 = {dr.Sha256}");
                    Log($"    pe     = {dr.PeValid}  {dr.PeNote}");
                    foreach (var s in dr.Sections) Log(s.Line);
                    foreach (var n in dr.Notes) Log("    " + n);

                    // 独立校验：交给 Windows 加载器按 SEC_IMAGE 映射一次，结构不合法会直接失败
                    if (dr.Ok && dr.OutPath.Length > 0)
                    {
                        IntPtr hm = NativeProbe.LoadLibraryExW(dr.OutPath, IntPtr.Zero, 0x22);
                        if (hm != IntPtr.Zero) NativeProbe.FreeLibrary(hm);
                        Log($"    Windows 加载器映射: {(hm != IntPtr.Zero ? "成功" : $"失败 (err={System.Runtime.InteropServices.Marshal.GetLastWin32Error()})")}");

                        // 与磁盘原文件整体哈希对照
                        if (!string.IsNullOrEmpty(targetMod.Path) && File.Exists(targetMod.Path))
                        {
                            var disk = File.ReadAllBytes(targetMod.Path);
                            string dh = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(disk)).ToLowerInvariant();
                            Log($"    disk   = {targetMod.Path}  {disk.Length} B  sha256={dh}");
                            Log($"    整文件相同 = {dh == dr.Sha256}（false 属正常：内存映像含重定位/IAT 写入）");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log("[9] dump 异常: " + ex);
            }

            // 10. WOW64（32 位进程）提取：验证 PE32 头/节表分支
            try
            {
                var psi32 = new ProcessStartInfo("C:\\Windows\\SysWOW64\\cmd.exe", "/c ping -n 60 127.0.0.1 > nul")
                { UseShellExecute = false, CreateNoWindow = true };
                using var p32 = Process.Start(psi32);
                if (p32 != null)
                {
                    Thread.Sleep(400);
                    var mm32 = MemoryMapScanner.Modules(p32.Id);
                    var m32 = mm32.FirstOrDefault(x => x.Name.Equals("KERNEL32.DLL", StringComparison.OrdinalIgnoreCase))
                              ?? mm32.FirstOrDefault(x => x.Size > 0 && x.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
                    Log($"[10] wow64 pid={p32.Id} modules={mm32.Count} 首个目标={(m32?.Name ?? "无")}");
                    if (m32 != null)
                    {
                        var r32 = ModuleDumper.DumpModule(p32.Id, "cmd32", m32, Path.Combine(AppContext.BaseDirectory, "dump_test"), false);
                        Log($"    ok={r32.Ok} {r32.FileBytes} B  节 {r32.SectionCount}  pe={r32.PeValid}  {r32.PeNote}");
                        foreach (var n in r32.Notes) Log("    " + n);
                        if (r32.Ok)
                        {
                            using var fs = File.OpenRead(r32.OutPath);
                            using var pe = new System.Reflection.PortableExecutable.PEReader(fs);
                            Log($"    BCL 读回：machine={pe.PEHeaders.CoffHeader.Machine} 段={pe.PEHeaders.SectionHeaders.Length} 映像=0x{pe.PEHeaders.PEHeader!.SizeOfImage:X}");
                        }
                    }
                    try { p32.Kill(true); } catch { }
                }
            }
            catch (Exception ex)
            {
                Log("[10] wow64 提取异常: " + ex.Message);
            }

            // 11. 受保护进程的失败路径（必须干净失败，不能崩、不能挂）
            try
            {
                var proto = new ModuleInfo { Base = 0xFFFFF80000000000, Name = "ntoskrnl.exe", Path = "" };
                var r11 = ModuleDumper.DumpModule(4, "System", proto, Path.Combine(AppContext.BaseDirectory, "dump_test"), false);
                Log($"[11] PID 4 提取: ok={r11.Ok}  说明={string.Join(" / ", r11.Notes)}");
            }
            catch (Exception ex) { Log("[11] 异常(不应发生): " + ex); }

            Log("== 全部完成 ==");
            File.WriteAllText(outPath, report.ToString(), new UTF8Encoding(true));
            return 0;
        }
        catch (Exception ex)
        {
            Log("!! 致命异常: " + ex);
            try { File.WriteAllText(outPath, report.ToString(), new UTF8Encoding(true)); } catch { }
            return 1;
        }
    }
}

internal static class NativeProbe
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr module);
}
