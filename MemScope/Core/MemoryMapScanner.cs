using System.Runtime.InteropServices;
using System.Text;
using MemScope.Interop;

namespace MemScope.Core;

/// <summary>把 \Device\HarddiskVolumeN\... 转成 C:\...</summary>
internal static class DosPath
{
    private static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase);
    private static long _lastRefresh;

    private static void Refresh()
    {
        Map.Clear();
        uint mask = Win32.GetLogicalDrives();
        var sb = new StringBuilder(1024);
        for (int i = 0; i < 26; i++)
        {
            if ((mask & (1u << i)) == 0) continue;
            string letter = ((char)('A' + i)) + ":";
            if (Win32.QueryDosDeviceW(letter, sb, sb.Capacity) && sb.Length > 0)
            {
                string target = sb.ToString();
                if (!Map.ContainsKey(target)) Map[target] = letter;
            }
            sb.Clear();
        }
        _lastRefresh = Environment.TickCount64;
    }

    public static string? FromDevicePath(string devicePath)
    {
        if (string.IsNullOrEmpty(devicePath)) return null;
        if (devicePath.Length > 1 && devicePath[1] == ':') return devicePath;

        if (Map.Count == 0 || Environment.TickCount64 - _lastRefresh > 60_000) Refresh();

        foreach (var kv in Map)
        {
            if (devicePath.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase))
                return kv.Value + devicePath[kv.Key.Length..];
        }
        return null;
    }
}


/// <summary>字节数→人类可读尺寸：大区域（已保留地址空间可达 TB 级）不再显示成 36864 MB。</summary>
internal static class SizeFmt
{
    public static string Bytes(double b)
    {
        if (b >= 1024.0 * 1024 * 1024 * 1024) return $"{b / (1024.0 * 1024 * 1024 * 1024):0.##} TB";
        if (b >= 1024.0 * 1024 * 1024) return $"{b / (1024.0 * 1024 * 1024):0.##} GB";
        if (b >= 1024.0 * 1024) return $"{b / (1024.0 * 1024):0.#} MB";
        return $"{b / 1024.0:0} KB";
    }
}

/// <summary>VirtualQueryEx 扫出的虚拟内存区域。</summary>
internal sealed class MemoryRegion
{
    public ulong Base { get; init; }
    public ulong Size { get; init; }
    public string State { get; init; } = "";
    public string Type { get; init; } = "";
    public string Protect { get; init; } = "";
    public string File { get; init; } = "";

    public string BaseHex => "0x" + Base.ToString("X");
    public string FileDisplay => string.IsNullOrEmpty(File) ? "—" : File;
    public string Summary => $"{State}·{Type}·{Protect}";
    public string SizeDisplay => SizeFmt.Bytes(Size);
}

internal static class MemoryMapScanner
{
    public static List<MemoryRegion> Scan(int pid, int maxRegions = 8000)
    {
        var list = new List<MemoryRegion>();
        IntPtr h = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero)
        {
            IntPtr oa = ProcessSnapshot.ObjectAttributes();
            IntPtr cid = ProcessSnapshot.ClientId(pid);
            try
            {
                if (Syscall.OpenProcess(out h, Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_READ, oa, cid) != 0)
                    return list;
            }
            finally
            {
                Marshal.FreeHGlobal(oa);
                Marshal.FreeHGlobal(cid);
            }
        }

        try
        {
            var sb = new StringBuilder(1024);
            ulong addr = 0;
            ulong limit = 0x7FFFFFFF0000UL;
            int guard = 0;

            while (addr < limit && list.Count < maxRegions && guard++ < 200000)
            {
                if (Win32.VirtualQueryEx(h, (IntPtr)(long)addr, out var mbi, (IntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == IntPtr.Zero)
                    break;

                ulong baseAddr = (ulong)mbi.BaseAddress.ToInt64();
                ulong size = (ulong)mbi.RegionSize.ToInt64();
                if (size == 0) break;

                if (mbi.State != Win32.MEM_FREE)
                {
                    string file = "";
                    if (mbi.Type == Win32.MEM_IMAGE || mbi.Type == Win32.MEM_MAPPED)
                    {
                        sb.Clear();
                        if (Win32.GetMappedFileNameW(h, (IntPtr)(long)baseAddr, sb, sb.Capacity) > 0)
                        {
                            string mapped = sb.ToString();
                            file = DosPath.FromDevicePath(mapped) ?? mapped;
                        }
                    }

                    list.Add(new MemoryRegion
                    {
                        Base = baseAddr,
                        Size = size,
                        State = mbi.State == Win32.MEM_COMMIT ? "已提交" : "已保留",
                        Type = mbi.Type switch
                        {
                            Win32.MEM_IMAGE => "映像",
                            Win32.MEM_MAPPED => "映射",
                            Win32.MEM_PRIVATE => "私有",
                            _ => "—"
                        },
                        Protect = DescribeProtect(mbi.Protect),
                        File = file
                    });
                }

                ulong next = baseAddr + size;
                if (next <= addr) break;
                addr = next;
            }
        }
        finally { Win32.CloseHandle(h); }

        return list;
    }

    public static string DescribeProtect(uint p)
    {
        if (p == 0) return "—";
        string s = (p & 0xFF) switch
        {
            Win32.PAGE_NOACCESS => "无访问",
            Win32.PAGE_READONLY => "R",
            Win32.PAGE_READWRITE => "RW",
            Win32.PAGE_WRITECOPY => "WC",
            Win32.PAGE_EXECUTE => "X",
            Win32.PAGE_EXECUTE_READ => "RX",
            Win32.PAGE_EXECUTE_READWRITE => "RWX",
            Win32.PAGE_EXECUTE_WRITECOPY => "WCX",
            _ => "0x" + (p & 0xFF).ToString("X2")
        };
        if ((p & Win32.PAGE_GUARD) != 0) s += "|Guard";
        if ((p & Win32.PAGE_NOCACHE) != 0) s += "|NoCache";
        return s;
    }

    /// <summary>进程加载的模块（= 进程占用的可执行文件/ DLL 文件）。</summary>
    public static List<ModuleInfo> Modules(int pid)
    {
        var result = new List<ModuleInfo>();
        IntPtr h = TargetProcess.Open(pid, Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_READ);
        if (h == IntPtr.Zero) return result;

        try
        {
            var mods = new IntPtr[1024];
            if (!Win32.EnumProcessModulesEx(h, mods, mods.Length * IntPtr.Size, out int needed, Win32.LIST_MODULES_ALL))
                return result;

            // WOW64 进程里 32 位模块的 LDR 路径写的是 "...\System32\xxx.dll"，
            // 那是 32 位视图下的 System32（实际等于 SysWOW64）。64 位视角要还原成 SysWOW64，
            // 否则拿到的会是不存在的/错误架构的文件。
            bool wow64 = Win32.IsWow64Process(h, out bool w) && w;

            int count = needed / IntPtr.Size;
            if (count > mods.Length) count = mods.Length;
            var sb = new StringBuilder(1024);
            for (int i = 0; i < count; i++)
            {
                sb.Clear();
                int len = Win32.GetModuleFileNameExW(h, mods[i], sb, sb.Capacity);
                if (len <= 0) continue;
                string path = sb.ToString();
                if (wow64 && mods[i].ToInt64() > 0 && mods[i].ToInt64() < 0x1_0000_0000L)
                    path = RedirectWow64(path);
                Win32.GetModuleInformation(h, mods[i], out var mi, Marshal.SizeOf<MODULEINFO>());
                result.Add(new ModuleInfo
                {
                    Base = (ulong)mods[i].ToInt64(),
                    Size = mi.SizeOfImage,
                    Path = path,
                    Name = System.IO.Path.GetFileName(path)
                });
            }
        }
        finally { Win32.CloseHandle(h); }

        return result;
    }

    /// <summary>把 32 位视图里的 System32 路径还原成 64 位视角下真实存在的路径。</summary>
    internal static string RedirectWow64(string path)
    {
        try
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string sys32 = System.IO.Path.Combine(win, "System32");
            string sysWow = System.IO.Path.Combine(win, "SysWOW64");
            if (!path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase)) return path;
            string alt = sysWow + path[sys32.Length..];
            if (System.IO.File.Exists(alt)) return alt;
            return path;
        }
        catch { return path; }
    }
}

internal sealed class ModuleInfo
{
    public ulong Base { get; init; }
    public uint Size { get; init; }
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public string BaseHex => "0x" + Base.ToString("X");
    public string SizeDisplay => SizeFmt.Bytes(Size);
}
