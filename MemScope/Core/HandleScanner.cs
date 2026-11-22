using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using MemScope.Interop;

namespace MemScope.Core;

internal sealed class FileHandleInfo
{
    public long Handle { get; init; }
    public uint Access { get; init; }
    public string Path { get; init; } = "";
    public string Name => System.IO.Path.GetFileName(Path);
    public string AccessHex => "0x" + Access.ToString("X8");
}

internal sealed class HandleScanResult
{
    public readonly List<FileHandleInfo> Items = new();
    public int TotalFileHandles;
    public int Unresolved;
    public bool Truncated;
    public string Note = "";
}

/// <summary>
/// 通过系统句柄表（SystemExtendedHandleInformation）反查进程真正打开的文件。
/// 流程：全表快照 → 按 PID + 文件对象类型索引过滤 → 复制句柄 → NtQueryObject 取名 → 设备路径转 DOS 路径。
/// </summary>
internal static class HandleScanner
{
    private const int SystemExtendedHandleInformation = 64;
    private const int ObjectNameInformation = 1;
    private const uint DuplicateSameAccess = 0x00000002;

    private static ushort _fileTypeIndex;
    private static string _fileTypeName = "";

    public static string FileTypeDiagnostic
    {
        get
        {
            if (_fileTypeIndex == 0) EnsureFileTypeIndex();
            return _fileTypeIndex == 0
                ? "未识别文件对象类型（" + _diag + "）"
                : $"文件对象类型索引 {_fileTypeIndex} ({_fileTypeName})";
        }
    }

    public static HandleScanResult ScanFiles(int pid, int timeoutMs = 6000)
    {
        var result = new HandleScanResult();
        var sw = Stopwatch.StartNew();

        ushort fileIdx = EnsureFileTypeIndex();
        if (fileIdx == 0)
        {
            result.Note = "无法识别文件对象类型：" + Diagnose();
            return result;
        }

        if (!QueryHandleTable(out IntPtr table, out long count, out string err))
        {
            result.Note = err;
            return result;
        }

        IntPtr hProc = Win32.OpenProcess(0x0040 /*PROCESS_DUP_HANDLE*/, false, pid);
        if (hProc == IntPtr.Zero)
        {
            result.Note = "无法打开进程（PROCESS_DUP_HANDLE 被拒绝），句柄不可枚举";
            Marshal.FreeHGlobal(table);
            return result;
        }

        try
        {
            for (long i = 0; i < count; i++)
            {
                if (sw.ElapsedMilliseconds > timeoutMs)
                {
                    result.Truncated = true;
                    break;
                }

                IntPtr p = table + 16 + (int)(i * 40);
                long entryPid = Marshal.ReadInt64(p, 8);
                if (entryPid != pid) continue;

                short typeIdx = Marshal.ReadInt16(p, 30);
                if (typeIdx != fileIdx) continue;

                long handleValue = Marshal.ReadInt64(p, 16);
                uint access = (uint)Marshal.ReadInt32(p, 24);
                result.TotalFileHandles++;

                // 已知会让 NtQueryObject 卡死的访问掩码组合（同步管道/匿名文件）
                if (access == 0x0012019F) { result.Unresolved++; continue; }

                if (!Win32.DuplicateHandle(hProc, (IntPtr)handleValue, Win32.GetCurrentProcess(),
                        out IntPtr local, 0, false, DuplicateSameAccess))
                {
                    result.Unresolved++;
                    continue;
                }

                string raw;
                try { raw = QueryObjectName(local); }
                finally { Win32.CloseHandle(local); }

                if (string.IsNullOrEmpty(raw)) { result.Unresolved++; continue; }

                string? dos = DosPath.FromDevicePath(raw);
                if (dos == null) { result.Unresolved++; continue; }

                result.Items.Add(new FileHandleInfo { Handle = handleValue, Access = access, Path = dos });
            }
        }
        finally
        {
            Win32.CloseHandle(hProc);
            Marshal.FreeHGlobal(table);
        }

        result.Items.Sort((a, b) => string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase));

        var note = new StringBuilder();
        note.Append($"文件句柄 {result.TotalFileHandles} 个，解析 {result.Items.Count} 个路径");
        if (result.Unresolved > 0) note.Append($"，{result.Unresolved} 个无法命名");
        if (result.Truncated) note.Append("（扫描超时，结果不完整）");
        result.Note = note.ToString();
        return result;
    }

    private static ushort EnsureFileTypeIndex()
    {
        if (_fileTypeIndex != 0) return _fileTypeIndex;
        try
        {
            string exe = Environment.ProcessPath ?? "";
            if (string.IsNullOrEmpty(exe)) { _diag = "取不到自身路径"; return 0; }
            IntPtr h = Win32.CreateFileW(exe, 0x80000000, 3, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) { _diag = "CreateFileW 失败"; return 0; }
            try
            {
                if (!QueryHandleTable(out IntPtr table, out long count, out string err)) { _diag = err; return 0; }
                try
                {
                    int me = Environment.ProcessId;
                    long target = h.ToInt64();
                    int mine = 0;
                    var types = new Dictionary<short, int>();
                    for (long i = 0; i < count; i++)
                    {
                        IntPtr p = table + 16 + (int)(i * 40);
                        if (Marshal.ReadInt64(p, 8) != me) continue;
                        mine++;
                        short idx = Marshal.ReadInt16(p, 30);
                        types[idx] = types.TryGetValue(idx, out int c) ? c + 1 : 1;

                        if (Marshal.ReadInt64(p, 16) != target) continue;

                        if (idx <= 0) { _diag = "自身文件句柄的类型索引为 0"; continue; }

                        string tname = QueryObjectTypeName(h);
                        _fileTypeIndex = (ushort)idx;
                        _fileTypeName = string.IsNullOrEmpty(tname) ? "File" : tname;
                        _diag = $"命中自身文件句柄，类型索引 {idx} ({_fileTypeName})";
                        return _fileTypeIndex;
                    }

                    _diag = $"句柄表 {count} 条，本进程 {mine} 条，未找到自身文件句柄 0x{target:X}；" +
                            "类型分布 " + string.Join(",", types.OrderByDescending(k => k.Value).Take(6).Select(k => $"{k.Key}:{k.Value}"));
                }
                finally { Marshal.FreeHGlobal(table); }
            }
            finally { Win32.CloseHandle(h); }
        }
        catch (Exception ex) { _diag = "异常：" + ex.Message; }
        return 0;
    }

    private static string _diag = "";

    /// <summary>句柄表自检，用于排查“文件对象类型识别失败”。</summary>
    public static string Diagnose()
    {
        EnsureFileTypeIndex();
        return _diag;
    }

    private static bool QueryHandleTable(out IntPtr buffer, out long count, out string error)
    {
        buffer = IntPtr.Zero;
        count = 0;
        error = "";
        int len = 8 * 1024 * 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            for (int attempt = 0; attempt < 4; attempt++)
            {
                int st = Syscall.QuerySystemInformation(SystemExtendedHandleInformation, buf, len, out int ret);
                if (st == NtStatus.InfoLengthMismatch || st == NtStatus.BufferTooSmall || st == NtStatus.BufferOverflow)
                {
                    if (ret <= 0) ret = len * 2;
                    len = ret + (1024 * 1024);
                    buf = Marshal.ReAllocHGlobal(buf, (IntPtr)len);
                    continue;
                }
                if (st != 0)
                {
                    error = "句柄表查询失败：" + NtStatus.Describe(st);
                    return false;
                }

                count = Marshal.ReadInt64(buf, 0);
                if (count <= 0 || count > 4_000_000) { error = "句柄表数据异常"; return false; }
                buffer = buf;
                return true;
            }
            error = "句柄表缓冲区不足";
            return false;
        }
        catch (Exception ex)
        {
            error = "句柄表查询异常：" + ex.Message;
            return false;
        }
        finally
        {
            if (buffer == IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static string QueryObjectName(IntPtr handle)
    {
        int len = 4096;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            int st = Syscall.QueryObject(handle, ObjectNameInformation, buf, len, out int ret);
            if (st == NtStatus.InfoLengthMismatch || st == NtStatus.BufferTooSmall || st == NtStatus.BufferOverflow)
            {
                if (ret <= 0) ret = len * 2;
                len = ret + 1024;
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal(len);
                st = Syscall.QueryObject(handle, ObjectNameInformation, buf, len, out _);
            }
            if (st != 0) return "";

            var us = Marshal.PtrToStructure<UNICODE_STRING>(buf);
            if (us.Buffer == IntPtr.Zero || us.Length == 0) return "";
            return Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? "";
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static string QueryObjectTypeName(IntPtr handle)
    {
        int len = 1024;
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            int st = Syscall.QueryObject(handle, 2 /*ObjectTypeInformation*/, buf, len, out int ret);
            if (st == NtStatus.InfoLengthMismatch || st == NtStatus.BufferTooSmall)
            {
                len = Math.Max(ret, 512) + 512;
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal(len);
                st = Syscall.QueryObject(handle, 2, buf, len, out _);
            }
            if (st != 0) return "";
            var us = Marshal.PtrToStructure<UNICODE_STRING>(buf);
            return us.Buffer == IntPtr.Zero ? "" : Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? "";
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
