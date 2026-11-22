using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace MemScope.Core;

/// <summary>快照导出：CSV（Excel 友好，带 BOM）+ JSON（结构化，便于二次分析）。</summary>
internal static class SnapshotExporter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MemScope_Export");

    public static (string CsvPath, string JsonPath) WriteSnapshot(SystemSnapshot snap, IEnumerable<ProcessRow> rows,
        string directory, string tag = "")
    {
        Directory.CreateDirectory(directory);
        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
        string baseName = string.IsNullOrEmpty(tag) ? $"snapshot_{stamp}" : $"snapshot_{tag}_{stamp}";
        string csvPath = Path.Combine(directory, baseName + ".csv");
        string jsonPath = Path.Combine(directory, baseName + ".json");

        var rowList = rows.ToList();

        var sb = new StringBuilder(1024 * 64);
        sb.AppendLine("PID,进程名,CPU%,工作集MB,私有内存MB,虚拟内存MB,线程数,句柄数,会话,父PID,路径");
        foreach (var r in rowList)
        {
            sb.Append(r.Pid).Append(',')
              .Append(Csv(r.Name)).Append(',')
              .Append(r.Cpu.ToString("0.0")).Append(',')
              .Append(r.WorkingSetMb.ToString("0.0")).Append(',')
              .Append(r.PrivateMb.ToString("0.0")).Append(',')
              .Append(r.VirtualMb.ToString("0.0")).Append(',')
              .Append(r.Threads).Append(',')
              .Append(r.Handles).Append(',')
              .Append(r.SessionId).Append(',')
              .Append(r.ParentPid).Append(',')
              .Append(Csv(r.Path)).AppendLine();
        }
        File.WriteAllText(csvPath, sb.ToString(), new UTF8Encoding(true));

        var payload = new
        {
            tool = "MemScope",
            exportedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            processCount = rowList.Count,
            threadCount = snap.ThreadTotal,
            totalWorkingSetMB = Math.Round(snap.WorkingSetTotal / 1024.0 / 1024.0, 1),
            totalPrivateMB = Math.Round(snap.PrivateTotal / 1024.0 / 1024.0, 1),
            sampleCostMs = Math.Round(snap.ElapsedMs, 2),
            processes = rowList.Select(r => new
            {
                pid = r.Pid,
                name = r.Name,
                cpuPercent = r.Cpu,
                workingSetMB = r.WorkingSetMb,
                privateMB = r.PrivateMb,
                virtualMB = r.VirtualMb,
                threads = r.Threads,
                handles = r.Handles,
                session = r.SessionId,
                parentPid = r.ParentPid,
                path = r.Path
            })
        };
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(payload, JsonOpts), new UTF8Encoding(false));

        return (csvPath, jsonPath);
    }

    public static string WriteDetail(int pid, string name, List<ModuleInfo> modules,
        List<MemoryRegion> regions, List<FileHandleInfo> handles, string directory)
    {
        Directory.CreateDirectory(directory);
        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
        string path = Path.Combine(directory, $"detail_{Sanitize(name)}_{pid}_{stamp}.json");

        var payload = new
        {
            tool = "MemScope",
            exportedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff"),
            pid,
            name,
            modules = modules.Select(m => new { name = m.Name, baseAddress = m.BaseHex, sizeKB = m.Size / 1024, path = m.Path }),
            memoryRegions = regions.Select(r => new
            {
                baseAddress = r.BaseHex,
                sizeKB = (long)(r.Size / 1024),
                state = r.State,
                type = r.Type,
                protect = r.Protect,
                mappedFile = r.File
            }),
            openFiles = handles.Select(h => new { path = h.Path, handle = "0x" + h.Handle.ToString("X"), access = h.AccessHex })
        };
        File.WriteAllText(path, JsonSerializer.Serialize(payload, JsonOpts), new UTF8Encoding(false));
        return path;
    }

    /// <summary>环形裁剪：只保留最近 N 组 CSV/JSON。</summary>
    public static int Prune(string directory, int keepSets = 40)
    {
        try
        {
            var files = new DirectoryInfo(directory).GetFiles("snapshot_*.csv")
                .OrderByDescending(f => f.CreationTimeUtc).Skip(keepSets).ToList();
            int removed = 0;
            foreach (var f in files)
            {
                var json = Path.ChangeExtension(f.FullName, ".json");
                try { f.Delete(); removed++; } catch { }
                try { if (File.Exists(json)) File.Delete(json); } catch { }
            }
            return removed;
        }
        catch { return 0; }
    }

    private static string Csv(string v)
    {
        if (string.IsNullOrEmpty(v)) return "";
        if (v.Contains(',') || v.Contains('"') || v.Contains('\n') || v.Contains('\r'))
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        return v;
    }

    private static string Sanitize(string s)
    {
        foreach (char c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
        return s.Length > 40 ? s[..40] : s;
    }
}
