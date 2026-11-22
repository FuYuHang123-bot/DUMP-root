using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using MemScope.Core;

namespace MemScopeCli;

/// <summary>
/// 提取引擎基准：同一模块重复提取 N 次，逐段计时并给出中位数。
/// 用法：memscope-cli --bench &lt;pid&gt; &lt;模块名&gt; [次数] [--dir 输出目录]
///
/// 两个总耗时分开报：
///   · 关键路径：调用返回、产物文件已落盘且通过 PE 校验的时刻（用户真正等待的时间）
///   · 完整墙钟：再把后台 sha256 收尾算进去（取证归档才需要等这个）
/// </summary>
internal static class Bench
{
    private sealed class Row
    {
        public ModuleDumpResult R = null!;
        public double CriticalMs;   // DumpModule 返回
        public double WallMs;       // 含后台哈希收尾
    }

    internal static int Run(string[] args)
    {
        int i = Array.IndexOf(args, "--bench");
        if (i < 0 || i + 2 >= args.Length)
        {
            Console.WriteLine("用法: --bench <pid> <模块名> [次数] [--dir 目录]");
            return 2;
        }

        if (!int.TryParse(args[i + 1], out int pid))
        {
            Console.WriteLine("PID 无效");
            return 2;
        }
        string module = args[i + 2];
        int iters = 3;
        if (i + 3 < args.Length && int.TryParse(args[i + 3], out int n) && n > 0) iters = n;

        int di = Array.IndexOf(args, "--dir");
        string root = di >= 0 && di + 1 < args.Length
            ? args[di + 1]
            : Path.Combine(Path.GetTempPath(), "memscope_bench");

        var mods = MemoryMapScanner.Modules(pid);
        var mod = mods.FirstOrDefault(m => m.Name.Equals(module, StringComparison.OrdinalIgnoreCase))
                  ?? mods.FirstOrDefault(m => m.Name.Contains(module, StringComparison.OrdinalIgnoreCase));
        if (mod == null)
        {
            Console.WriteLine($"PID {pid} 未加载 \"{module}\"。已加载模块：");
            foreach (var m in mods.Take(30)) Console.WriteLine($"  {m.Name,-32} {m.BaseHex}");
            return 3;
        }

        var sb = new StringBuilder();
        void W(string s) { Console.WriteLine(s); sb.AppendLine(s); }

        W($"== bench {mod.Name} @0x{mod.Base:X} pid={pid} 迭代 {iters} 次 ==");
        W($"输出目录 {root}   核心数 {Environment.ProcessorCount}   提权 {MemScope.Interop.Win32.IsElevated()}");
        W("");

        var rows = new List<Row>();
        string? firstSha = null;
        bool shaStable = true;

        for (int k = 0; k < iters; k++)
        {
            // 每轮都等上一轮的哈希收尾，避免后台线程和本轮读写抢核心，导致数字不可比
            var swAll = Stopwatch.StartNew();
            // 每轮独立子目录：360 实时防护会在产物写完后立刻扫描整个 PE（358 MB 要数秒），
            // 期间锁着文件。若各轮共用同一个文件名，测到的就是“等杀软”而不是引擎本身。
            var r = ModuleDumper.DumpModule(pid, $"bench{pid}", mod, Path.Combine(root, $"run{k}"), freeze: false);
            double critical = swAll.Elapsed.TotalMilliseconds;

            if (!r.Ok)
            {
                W($"#{k} 失败：{string.Join(" / ", r.Notes)}");
                return 4;
            }

            try { r.HashTask?.GetAwaiter().GetResult(); }
            catch (Exception ex) { W($"#{k} 后台哈希异常：{ex.Message}"); }

            double wall = swAll.Elapsed.TotalMilliseconds;

            // 自检：产物此刻不应再被本进程持有（验证所有写入/校验句柄都已释放）
            string probe;
            try
            {
                using var pf = File.Open(r.OutPath, FileMode.Open, FileAccess.Read, FileShare.None);
                probe = "可独占打开";
            }
            catch (Exception ex) { probe = "占用（本进程不该持有它）：" + ex.GetType().Name; }
            if (!probe.StartsWith("可独占"))
                W($"#{k} 自检异常 — 产物 {probe}");

            firstSha ??= r.Sha256;
            if (r.Sha256 != firstSha) shaStable = false;
            rows.Add(new Row { R = r, CriticalMs = critical, WallMs = wall });
        }

        W($"{"#",-3}{"关键ms",8}{"墙钟ms",8}{"读ms",8}{"写ms",8}{"校验ms",8}{"比对ms",9}{"哈希ms",9}{"峰值MB",8}{"字节",12}{"差异",12}");
        for (int k = 0; k < rows.Count; k++)
        {
            var x = rows[k];
            var r = x.R;
            W($"{k,-3}{x.CriticalMs,8:F0}{x.WallMs,8:F0}{r.ReadMs,8:F0}{r.WriteMs,8:F0}{r.VerifyMs,8:F0}" +
              $"{r.CompareMs,9:F0}{r.HashMs,9:F0}{r.PeakWorkingSetMb,8}{r.FileBytes,12:N0}{r.DiffBytes,12:N0}");
        }

        double Med(Func<Row, double> f)
        {
            var v = rows.Select(f).OrderBy(x => x).ToList();
            return v.Count % 2 == 1 ? v[v.Count / 2] : (v[v.Count / 2 - 1] + v[v.Count / 2]) / 2;
        }

        var r0 = rows[0].R;
        double mb = r0.FileBytes / 1024.0 / 1024.0;
        double readMs = Med(x => x.R.ReadMs);
        W("");
        W($"中位  关键 {Med(x => x.CriticalMs):F0} ms | 完整 {Med(x => x.WallMs):F0} ms " +
          $"({mb / Math.Max(1e-6, Med(x => x.CriticalMs) / 1000):F0} MB/s)");
        W($"      读 {readMs:F0} ({mb / Math.Max(1e-6, readMs / 1000):F0} MB/s) | 写 {Med(x => x.R.WriteMs):F0} | " +
          $"校验 {Med(x => x.R.VerifyMs):F0} | 比对 {Med(x => x.R.CompareMs):F0} | " +
          $"哈希(后台) {Med(x => x.R.HashMs):F0} | 峰值 {Med(x => x.R.PeakWorkingSetMb):F0} MB");
        W($"节数 {r0.SectionCount}  PE {r0.PeValid}  差异 {r0.DiffBytes:N0}/{r0.ComparedBytes:N0}  sha 可复现 {shaStable}");
        W($"sha256 {firstSha}");
        W($"磁盘 sha256 {(string.IsNullOrEmpty(r0.DiskSha256) ? "（未计算）" : r0.DiskSha256)}");
        foreach (var s in r0.Sections)
            W($"    {s.Name,-9} RVA {s.Rva:X8}  提取 {s.Copied,12:N0} B  差异 {s.DiskDiff,10:N0} B");

        // 产物自检：文件哈希必须与结果里的 sha256 一致（防止“报告说一套、文件是另一套”）
        string diskSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(r0.OutPath))).ToLowerInvariant();
        W($"产物文件回读 sha256 一致 = {diskSha == r0.Sha256}");

        try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "bench_report.txt"), sb.ToString(), new UTF8Encoding(true)); } catch { }
        return 0;
    }
}
