using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MemScope.Interop;

namespace MemScope.Core;

/// <summary>单个节区的提取结果。</summary>
internal sealed class SectionDump
{
    public string Name { get; init; } = "";
    public uint Rva { get; init; }
    public uint VirtualSize { get; init; }
    public uint RawOffset { get; init; }
    public uint RawSize { get; init; }
    public long Copied { get; set; }
    public long Unreadable { get; set; }
    public long DiskDiff { get; set; }
    public bool DiskCompared { get; set; }
    public string? FirstDiffRva { get; set; }
    public uint Characteristics { get; init; }

    /// <summary>节属性 IMAGE_SCN_MEM_WRITE：运行时可写的数据节。</summary>
    public bool Writable => (Characteristics & 0x80000000) != 0;

    /// <summary>节属性 IMAGE_SCN_MEM_EXECUTE：可执行节（代码）。</summary>
    public bool Executable => (Characteristics & 0x20000000) != 0;

    public string Line => DiskCompared
        ? $"    {Name,-9} RVA {Rva:X8}  提取 {Copied,9:N0} B  不可读 {Unreadable,7:N0} B  与磁盘差异 {DiskDiff,9:N0} B"
        : $"    {Name,-9} RVA {Rva:X8}  提取 {Copied,9:N0} B  不可读 {Unreadable,7:N0} B";
}

internal sealed class ModuleDumpResult
{
    public bool Ok { get; set; }
    public string OutPath { get; set; } = "";
    public string OutDir { get; set; } = "";
    public string Module { get; set; } = "";
    public string Process { get; set; } = "";
    public int Pid { get; set; }
    public ulong Base { get; set; }
    public long FileBytes { get; set; }
    public long UnreadableBytes { get; set; }
    public int SectionCount { get; set; }
    public bool PeValid { get; set; }
    public string PeNote { get; set; } = "";
    /// <summary>提取完成的时刻（meta 里的 extractedAt）。后台重写 meta 时用它，避免时间戳被推迟。</summary>
    public string ExtractedAt { get; set; } = "";
    public string Sha256 { get; set; } = "";

    /// <summary>
    /// 后台收尾任务：产物 sha256 / 磁盘 sha256 落定，并重写 meta 文件。
    /// 提取返回时它通常还在跑——没有 SHA-NI 的机器上 SHA-256 只有约 460 MB/s，
    /// 343 MB 的模块要 0.7 s，不该挡在“文件已落盘且结构校验通过”这条路径上。
    /// 需要哈希值的调用方 await 它即可，其余场景可以完全不管。
    /// </summary>
    public Task? HashTask { get; set; }

    public string? DiskPath { get; set; }
    public bool DiskFound { get; set; }
    public string? DiskSha256 { get; set; }
    public long DiffBytes { get; set; }
    public long ComparedBytes { get; set; }
    public long DiskOverlayBytes { get; set; }
    public long RelocCoveredBytes { get; set; }

    // ---- 分段耗时（用于定位瓶颈，也便于对比优化效果）----
    public double ReadMs { get; set; }
    public double WriteMs { get; set; }
    public double HashMs { get; set; }
    public double CompareMs { get; set; }
    public double CompareSetupMs { get; set; }
    public double CompareLoopMs { get; set; }
    public double VerifyMs { get; set; }
    public int PeakWorkingSetMb { get; set; }
    public bool ChangedDuringRead { get; set; }

    // ---- 差异归属（与磁盘比对时逐字节归类，让“差异”不再是模糊描述）----
    public long HeaderImageBaseDiff { get; set; }   // PE 头里的 ImageBase 字段被加载器改写
    public long IatCoveredBytes { get; set; }       // 落在导入地址表区间内
    public long WritableDataBytes { get; set; }     // 落在可写数据节（.data/.didat 等）
    public long CodeUncoveredBytes { get; set; }    // 落在可执行节且既非重定位也非 IAT：真正可疑
    public string? FirstCodeUncoveredRva { get; set; }
    public List<string> CodeUncoveredSectionNames { get; } = new();
    public int IatRangeCount { get; set; }
    public long PaddingBytes { get; set; }
    public double ElapsedMs { get; set; }
    public List<SectionDump> Sections { get; } = new();
    public List<string> Notes { get; } = new();

    public string SizeText => FileBytes >= 1024 * 1024
        ? $"{FileBytes / 1024.0 / 1024.0:0.##} MB"
        : $"{FileBytes / 1024.0:0.#} KB";
}

/// <summary>
/// 从运行中的进程里把模块的 PE 映像提取成磁盘文件。
///
/// 做法（不是 dump 整片内存后硬凑）：
///   1. 读目标模块的 DOS/NT 头，拿到 SizeOfHeaders / FileAlignment / 节表；
///   2. 按节表逐个 ReadVirtualMemory 读取 SizeOfRawData（不超过 VirtualSize）字节；
///   3. 按原文件的 PointerToRawData 布局重排，写出的就是结构合法的 PE 文件；
///   4. 用 System.Reflection.PortableExecutable 独立解析一遍校验；
///   5. 若磁盘上存在同名原文件，逐节字节比对，报告差异（可暴露重定位 / IAT 写入 / 代码补丁）。
/// </summary>
internal static class ModuleDumper
{
    private const int Chunk = 4 << 20;          // 单次读取 4 MB
    private const int PageSize = 0x1000;
    private const long MaxFile = 512L * 1024 * 1024;
    /// <summary>超过这个尺寸的磁盘原件不再单独算 sha256（见 ResolveDiskPath 里的理由）。</summary>
    private const long DiskHashLimit = 64L * 1024 * 1024;

    // ---------------- 对外接口 ----------------

    public static unsafe ModuleDumpResult DumpModule(int pid, string processName, ModuleInfo mod, string outRoot, bool freeze)
    {
        var r = new ModuleDumpResult
        {
            Pid = pid,
            Process = processName,
            Module = string.IsNullOrWhiteSpace(mod.Name) ? $"module_{mod.Base:X}" : mod.Name,
            Base = mod.Base,
            DiskPath = string.IsNullOrWhiteSpace(mod.Path) ? null : mod.Path
        };
        var sw = Stopwatch.StartNew();
        IntPtr h = IntPtr.Zero, tmp = IntPtr.Zero;
        GCHandle gh = default;
        bool suspended = false;

        try
        {
            h = TargetProcess.Open(pid, Win32.PROCESS_VM_READ | Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_SUSPEND_RESUME);
            if (h == IntPtr.Zero)
            {
                r.Notes.Add("打不开目标进程句柄（需要 PROCESS_VM_READ；受内核保护或权限不足时用户态无解）");
                return r;
            }

            if (freeze)
            {
                int st = Syscall.SuspendProcess(h);
                suspended = st == 0;
                r.Notes.Add(suspended
                    ? "提取期间已冻结进程（NtSuspendProcess），完成后立即恢复"
                    : $"冻结失败 0x{st:X8}，改为运行态读取");
            }

            tmp = Marshal.AllocHGlobal(PageSize);

            // ---- 1. 头部 ----
            var layout = ParseHeaders(h, mod.Base);
            if (layout == null)
            {
                r.Notes.Add("模块基址处不是有效 PE 头（可能未映射、已被解映射，或基址已失效）");
                return r;
            }
            r.SectionCount = layout.Sections.Count;

            // 磁盘比对所需的路径与哈希提前到这里：哈希在后台线程跑，与读内存/落盘/比对并行
            var (resolvedPath, diskHashTask) = ResolveDiskPath(r.DiskPath, layout.Machine, r.Notes);
            r.DiskPath = resolvedPath;

            // ---- 2. 目标文件尺寸（保持原文件布局）----
            long fileSize = layout.SizeOfHeaders;
            foreach (var s in layout.Sections)
                if (s.RawOffset > 0 && s.RawSize > 0)
                    fileSize = Math.Max(fileSize, (long)s.RawOffset + s.RawSize);
            if (fileSize <= 0 || fileSize > MaxFile)
            {
                r.Notes.Add($"节表推算出的文件尺寸异常：{fileSize} 字节");
                return r;
            }

            var file = new byte[fileSize];

            // 整份缓冲只钉一次：所有读取直接落进这块内存（NtReadVirtualMemory 的目标就是产物本身），
            // 不再经过 AllocHGlobal 中转 + Marshal.Copy——省掉一次与模块等量的内存拷贝。
            gh = GCHandle.Alloc(file, GCHandleType.Pinned);
            IntPtr fbase = gh.AddrOfPinnedObject();

            // ---- 3. 头部 ----
            int hdrLen = (int)Math.Min(layout.SizeOfHeaders, fileSize);
            r.UnreadableBytes += ReadIntoPtr(h, mod.Base, fbase, hdrLen, PageSize);

            // ---- 4. 逐节读取：切成固定大小的块，块之间互不重叠，可整块并行 ----
            // 按“节”并行在超大 .text（msedge 290 MB）上只有一个线程在干活；
            // 切到 8 MB 一块后，单个巨型节也能被所有核心分摊。
            r.Sections.AddRange(layout.Sections);
            var swRead = Stopwatch.StartNew();

            const int PieceMax = 8 << 20;
            var jobs = new List<ReadJob>();
            foreach (var s in r.Sections)
            {
                if (s.RawSize == 0 || s.RawOffset == 0) continue;
                long room = fileSize - s.RawOffset;
                if (room <= 0) continue;

                long copyLen = Math.Min(s.RawSize, room);
                // 只读映像里真实存在的部分，避免越过本节末尾读到下一节
                if (s.VirtualSize > 0 && s.VirtualSize < copyLen) copyLen = s.VirtualSize;
                if (copyLen <= 0) continue;

                s.Copied = copyLen;
                long done = 0;
                while (done < copyLen)
                {
                    int len = (int)Math.Min(PieceMax, copyLen - done);
                    jobs.Add(new ReadJob(s, mod.Base + s.Rva + (ulong)done, (int)s.RawOffset + (int)done, len));
                    done += len;
                }
            }

            int workers = Math.Min(Environment.ProcessorCount, 16);
            if (workers < 1) workers = 1;
            if (jobs.Count <= 1 || !RawRangesDisjoint(jobs)) workers = 1;

            var bad = new int[jobs.Count];
            Parallel.For(0, jobs.Count, new ParallelOptions { MaxDegreeOfParallelism = workers }, idx =>
            {
                var j = jobs[idx];
                bad[idx] = ReadIntoPtr(h, j.SrcAddr, fbase + j.DstOff, j.Len, Chunk);
            });

            for (int k = 0; k < jobs.Count; k++)
            {
                jobs[k].Sec.Unreadable += bad[k];
                r.UnreadableBytes += bad[k];
            }
            r.ReadMs = swRead.Elapsed.TotalMilliseconds;

            // ---- 4b. 一致性自检：未冻结时模块可能正在被改写，抽样重读比对 ----
            r.ChangedDuringRead = VerifyStable(h, mod.Base, fbase, file, jobs);
            if (r.ChangedDuringRead)
                r.Notes.Add("注意：提取期间有节区内容再次读取时发生变化（进程未冻结），该次结果可能不是同一时刻的快照；需要严格一致请勾选“冻结提取”");

            // ---- 5. 落盘 / 产物哈希 / 磁盘比对：三条流水线同时跑 ----
            // 落盘是 IO、比对是 CPU、哈希各占一个核，三者只读同一块内存，互不干扰；
            // 关键路径从“读 → 写 → 比对 → 等哈希”压成 读 + max(写, 比对, 哈希)。
            string dir = Path.Combine(outRoot, Safe($"{pid}_{(string.IsNullOrWhiteSpace(processName) ? "process" : processName)}"));
            Directory.CreateDirectory(dir);
            string filePath = Path.Combine(dir, Safe($"{pid}_{r.Module}"));
            r.OutPath = filePath;
            r.OutDir = dir;
            r.FileBytes = fileSize;

            var writeTask = Task.Run(() =>
            {
                var sw = Stopwatch.StartNew();
                // 写临时扩展名：实时防护（本机是 360 杀毒）会逐个字节扫描落盘的 .dll/.exe，
                // 每次 WriteFile 都被它的文件过滤驱动拦一道，358 MB 要多花上百毫秒且写完还锁着文件。
                // 用 .part 落盘、写完再原子改名，扫描只会发生在改名之后（那时提取已经结束）。
                string tmp = filePath + ".part";
                try
                {
                    // 从钉住的原始内存直接写盘：RandomAccess.Write 走 WriteFile，不产生二次拷贝。
                    // 预分配长度避免边写边扩文件带来的元数据开销。
                    using (var fh = OpenForWrite(tmp, fileSize))
                    {
                        const int W = 8 << 20;
                        long off = 0;
                        while (off < fileSize)
                        {
                            int n = (int)Math.Min(W, fileSize - off);
                            RandomAccess.Write(fh, new ReadOnlySpan<byte>((void*)(fbase + (int)off), n), off);
                            off += n;
                        }
                    }
                    ReplaceWith(tmp, filePath);
                }
                finally
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                }
                return sw.Elapsed.TotalMilliseconds;
            });

            // 产物哈希在后台跑：只用于给文件打指纹，不参与“能不能用”的判断，
            // 因此不必挡在返回路径上（没有 SHA-NI 时 343 MB 要 0.7 s）。
            var dumpHashSw = Stopwatch.StartNew();
            var hashTask = Task.Run(() =>
            {
                try
                {
                    string s = Convert.ToHexString(SHA256.HashData(new ReadOnlySpan<byte>((void*)fbase, (int)fileSize)))
                                      .ToLowerInvariant();
                    r.Sha256 = s;
                    r.HashMs = dumpHashSw.Elapsed.TotalMilliseconds;
                }
                catch (Exception ex) { r.Notes.Add("产物哈希失败：" + ex.Message); }

                // 磁盘原件的哈希从读取前就在另一个线程跑，这里顺带收口
                if (diskHashTask != null)
                {
                    try { r.DiskSha256 = diskHashTask.GetAwaiter().GetResult(); }
                    catch (Exception ex) { r.DiskSha256 = null; r.Notes.Add("磁盘文件哈希失败：" + ex.Message); }
                }

                WriteMeta(r, force: true);   // 哈希落定后重写 meta，别让文件里的 sha256 停在空值
            });
            r.HashTask = hashTask;

            var cmpTask = Task.Run(() => CompareWithDisk(r, file, layout, hdrLen, resolvedPath ?? ""));

            r.WriteMs = writeTask.GetAwaiter().GetResult();

            // ---- 6. 独立校验（用 BCL 的 PE 解析器再读一遍写出的文件，必须等落盘完成）----
            var swVerify = Stopwatch.StartNew();
            try
            {
                using var fs = File.OpenRead(filePath);
                // 不预读整份文件：大模块下 PrefetchEntireImage 会再复制一份完整映像进内存
                using var pe = new PEReader(fs, PEStreamOptions.Default);
                var headers = pe.PEHeaders;
                bool ok = headers.PEHeader != null
                          && (ushort)headers.CoffHeader.Machine == layout.Machine
                          && headers.SectionHeaders.Length == layout.Sections.Count
                          && headers.PEHeader.SizeOfImage == layout.SizeOfImage;
                r.PeValid = ok;
                r.PeNote = ok
                    ? $"PE 校验通过：{MachineName(layout.Machine)} · {layout.Sections.Count} 节 · SizeOfImage 0x{layout.SizeOfImage:X}"
                    : "PE 结构可读但与内存头不一致（节数 / 机器类型 / SizeOfImage 对不上）";
            }
            catch (Exception ex)
            {
                r.PeValid = false;
                r.PeNote = "PE 校验失败：" + ex.GetType().Name + " — " + ex.Message;
            }
            r.VerifyMs = swVerify.Elapsed.TotalMilliseconds;

            // ---- 7. 收拢比对 / 哈希（哈希与比对在后台已并行跑完，这里只取结果）----
            var swCmp = Stopwatch.StartNew();
            cmpTask.GetAwaiter().GetResult();
            r.CompareMs = swCmp.Elapsed.TotalMilliseconds;

            // 哈希不在这里等：r.HashTask 会在后台把 sha256 与 meta 补齐

            r.PeakWorkingSetMb = (int)(Process.GetCurrentProcess().PeakWorkingSet64 / 1024 / 1024);

            r.Ok = true;
            r.ExtractedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            if (r.UnreadableBytes > 0)
                r.Notes.Add($"有 {r.UnreadableBytes:N0} 字节无法读取（对应页被保护或无提交），已按 0 填充，这些位置不代表真实内容");
            return r;
        }
        catch (Exception ex)
        {
            r.Notes.Add("提取异常：" + ex.GetType().Name + " — " + ex.Message);
            return r;
        }
        finally
        {
            if (suspended)
            {
                int st = Syscall.ResumeProcess(h);
                if (st != 0) r.Notes.Add($"恢复进程失败 0x{st:X8}");
            }
            if (tmp != IntPtr.Zero) Marshal.FreeHGlobal(tmp);
            if (gh.IsAllocated)
            {
                // 后台哈希还在直接读这块钉住的缓冲，现在解固定会让 GC 把它搬走；
                // 改为挂到哈希任务之后释放（任务已完成则立刻释放）。
                var handle = gh;
                var ht = r.HashTask;
                if (ht == null || ht.IsCompleted) handle.Free();
                else ht.ContinueWith(_ => handle.Free(), TaskScheduler.Default);
            }
            if (h != IntPtr.Zero) Win32.CloseHandle(h);
            r.ElapsedMs = sw.Elapsed.TotalMilliseconds;
            WriteMeta(r);   // 先写一份不含哈希的；哈希任务完成时会整体重写
        }
    }

    /// <summary>把一段虚拟内存区域原样转储为 .bin（无 PE 结构，纯字节）。</summary>
    public static ModuleDumpResult DumpRegion(int pid, string processName, MemoryRegion region, string outRoot, bool freeze)
    {
        var r = new ModuleDumpResult
        {
            Pid = pid,
            Process = processName,
            Module = $"region_{region.Base:X}_{region.Size:X}.bin",
            Base = region.Base,
            DiskPath = string.IsNullOrEmpty(region.File) ? null : region.File
        };
        var sw = Stopwatch.StartNew();
        IntPtr h = IntPtr.Zero, tmp = IntPtr.Zero;
        bool suspended = false;

        try
        {
            h = TargetProcess.Open(pid, Win32.PROCESS_VM_READ | Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_SUSPEND_RESUME);
            if (h == IntPtr.Zero)
            {
                r.Notes.Add("打不开目标进程句柄（需要 PROCESS_VM_READ）");
                return r;
            }

            if (freeze)
            {
                int st = Syscall.SuspendProcess(h);
                suspended = st == 0;
                r.Notes.Add(suspended ? "转储期间已冻结进程" : $"冻结失败 0x{st:X8}，改为运行态读取");
            }

            if (region.Size == 0 || region.Size > (ulong)MaxFile)
            {
                r.Notes.Add($"区域尺寸 {region.Size} 字节超出转储上限");
                return r;
            }

            tmp = Marshal.AllocHGlobal(Chunk);
            var buf = new byte[(int)region.Size];
            r.UnreadableBytes = ReadIntoArray(h, region.Base, buf, 0, buf.Length, Chunk);

            string dir = Path.Combine(outRoot, Safe($"{pid}_{(string.IsNullOrWhiteSpace(processName) ? "process" : processName)}"));
            Directory.CreateDirectory(dir);
            string path = Path.Combine(dir, Safe($"{pid}_{r.Module}"));
            File.WriteAllBytes(path, buf);

            r.OutPath = path;
            r.OutDir = dir;
            r.FileBytes = buf.Length;
            r.Sha256 = Sha256(buf);
            r.PeValid = false;
            r.PeNote = "原始内存区域（非 PE 镜像，未做重排）";
            r.Ok = true;
            r.ExtractedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            if (r.UnreadableBytes > 0)
                r.Notes.Add($"{r.UnreadableBytes:N0} 字节不可读，已按 0 填充");
            return r;
        }
        catch (Exception ex)
        {
            r.Notes.Add("转储异常：" + ex.GetType().Name + " — " + ex.Message);
            return r;
        }
        finally
        {
            if (suspended) Syscall.ResumeProcess(h);
            if (tmp != IntPtr.Zero) Marshal.FreeHGlobal(tmp);
            if (h != IntPtr.Zero) Win32.CloseHandle(h);
            r.ElapsedMs = sw.Elapsed.TotalMilliseconds;
            WriteMeta(r);
        }
    }

    // ---------------- PE 头解析 ----------------

    private sealed class PeLayout
    {
        public ushort Machine;
        public bool Pe32Plus;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint EntryPoint;
        public uint RelocRva;
        public uint RelocSize;
        public uint ImportRva;
        public uint ImportSize;
        public int PeOffset;
        public int ImageBaseOffset;          // 头部缓冲区中 ImageBase 字段的偏移
        public ulong PreferredImageBase;
        public List<SectionDump> Sections = new();
    }

    private static PeLayout? ParseHeaders(IntPtr h, ulong baseAddr)
    {
        byte[] head = new byte[PageSize];
        ReadIntoArray(h, baseAddr, head, 0, head.Length, PageSize);

        if (head[0] != (byte)'M' || head[1] != (byte)'Z') return null;

        int peOff = BitConverter.ToInt32(head, 0x3C);
        if (peOff < 0x40 || peOff > 0x10000) return null;

        // DOS stub 过长时补读一次
        if (peOff + 0x120 > head.Length)
        {
            head = new byte[peOff + 0x400];
            ReadIntoArray(h, baseAddr, head, 0, head.Length, PageSize);
        }

        if (peOff + 24 > head.Length) return null;
        if (BitConverter.ToUInt32(head, peOff) != 0x00004550) return null; // "PE\0\0"

        int coff = peOff + 4;
        ushort machine = BitConverter.ToUInt16(head, coff + 0);
        ushort numSec = BitConverter.ToUInt16(head, coff + 2);
        ushort optSize = BitConverter.ToUInt16(head, coff + 16);
        int opt = coff + 20;

        if (opt + optSize > head.Length) return null;
        if (numSec == 0 || numSec > 256) return null;
        if (optSize < 0xE0) return null;

        ushort magic = BitConverter.ToUInt16(head, opt);
        if (magic != 0x10B && magic != 0x20B) return null;

        var layout = new PeLayout
        {
            Machine = machine,
            Pe32Plus = magic == 0x20B,
            PeOffset = peOff,
            EntryPoint = BitConverter.ToUInt32(head, opt + 16),
            SizeOfImage = BitConverter.ToUInt32(head, opt + 56),
            SizeOfHeaders = BitConverter.ToUInt32(head, opt + 60),
            ImageBaseOffset = magic == 0x20B ? opt + 24 : opt + 28
        };
        layout.PreferredImageBase = magic == 0x20B
            ? BitConverter.ToUInt64(head, opt + 24)
            : BitConverter.ToUInt32(head, opt + 28);

        // 数据目录第 5 项 = 基址重定位表（PE32 在 opt+96，PE32+ 在 opt+112）
        int dd = opt + (layout.Pe32Plus ? 112 : 96);
        if (dd + 40 <= head.Length)
        {
            layout.RelocRva = BitConverter.ToUInt32(head, dd + 5 * 8);
            layout.RelocSize = BitConverter.ToUInt32(head, dd + 5 * 8 + 4);
            layout.ImportRva = BitConverter.ToUInt32(head, dd + 1 * 8);
            layout.ImportSize = BitConverter.ToUInt32(head, dd + 1 * 8 + 4);
        }

        int secTab = opt + optSize;
        for (int i = 0; i < numSec; i++)
        {
            int p = secTab + i * 40;
            if (p + 40 > head.Length) break;

            var nameBytes = new byte[8];
            Buffer.BlockCopy(head, p, nameBytes, 0, 8);
            int n = Array.IndexOf(nameBytes, (byte)0);
            if (n < 0) n = 8;
            string name = Encoding.ASCII.GetString(nameBytes, 0, n).Trim();
            if (name.Length == 0) name = $".sec{i}";

            layout.Sections.Add(new SectionDump
            {
                Name = name,
                VirtualSize = BitConverter.ToUInt32(head, p + 8),
                Rva = BitConverter.ToUInt32(head, p + 12),
                RawSize = BitConverter.ToUInt32(head, p + 16),
                RawOffset = BitConverter.ToUInt32(head, p + 20),
                Characteristics = BitConverter.ToUInt32(head, p + 36)
            });
        }

        return layout.Sections.Count > 0 ? layout : null;
    }

    private static string MachineName(ushort m) => m switch
    {
        0x8664 => "x64",
        0x14C => "x86",
        0xAA64 => "ARM64",
        0x1C4 => "ARM",
        _ => $"0x{m:X4}"
    };

    // ---------------- 读取 ----------------

    /// <summary>一个读取任务：把目标地址的一段连续内存直接落进产物缓冲的指定偏移。</summary>
    private readonly struct ReadJob
    {
        public readonly SectionDump Sec;
        public readonly ulong SrcAddr;
        public readonly int DstOff;
        public readonly int Len;

        public ReadJob(SectionDump sec, ulong srcAddr, int dstOff, int len)
        {
            Sec = sec;
            SrcAddr = srcAddr;
            DstOff = dstOff;
            Len = len;
        }
    }

    /// <summary>读取任务的文件区间是否两两不重叠——只有互不重叠才能并发写同一块缓冲区。</summary>
    private static bool RawRangesDisjoint(List<ReadJob> jobs)
    {
        if (jobs.Count <= 1) return true;
        var spans = new List<(long Start, long End)>(jobs.Count);
        foreach (var j in jobs)
            spans.Add((j.DstOff, j.DstOff + j.Len));
        spans.Sort((a, b) => a.Start.CompareTo(b.Start));
        for (int i = 1; i < spans.Count; i++)
            if (spans[i].Start < spans[i - 1].End) return false;
        return true;
    }

    /// <summary>
    /// 抽样重读：每节开头 64 字节 + 节内两处再读一次，与已抓取内容比对。
    /// 用于发现“未冻结时模块正在被改写”导致的撕裂快照，代价只有十几个小读。
    /// </summary>
    private static unsafe bool VerifyStable(IntPtr h, ulong baseAddr, IntPtr fbase, byte[] file, List<ReadJob> jobs)
    {
        const int sample = 64;
        byte* probe = stackalloc byte[sample];
        try
        {
            foreach (var j in jobs)
            {
                if (j.Len <= 0) continue;
                // 每个节只抽查第一块的首/中/尾，避免巨节被切成很多块后重复抽查
                if (j.DstOff != (int)j.Sec.RawOffset) continue;
                int copyLen = (int)j.Sec.Copied;
                if (copyLen <= 0) continue;

                int[] offsets = copyLen > sample * 2
                    ? new[] { 0, copyLen / 4, copyLen - sample }
                    : new[] { 0 };

                foreach (int rel in offsets)
                {
                    if (rel < 0 || rel + sample > copyLen) continue;
                    int got = TryReadPtr(h, baseAddr + j.Sec.Rva + (ulong)rel, (IntPtr)probe, sample);
                    if (got < sample) continue;   // 读不到就不作为“变化”证据

                    int at = (int)j.Sec.RawOffset + rel;
                    for (int i = 0; i < sample; i++)
                        if (probe[i] != file[at + i]) return true;
                }
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// 直接从目标进程读进指定地址（通常是产物缓冲的某个偏移），不经过中转缓冲。
    /// 返回“不可读字节数”（这些位置已被清零）。
    /// 先按 chunkSize 整块读，失败则退化到 4 KB 页，单页失败才记 0，
    /// 这样节内存在无提交页时不会整段放弃。
    /// </summary>
    private static unsafe int ReadIntoPtr(IntPtr h, ulong addr, IntPtr dst, int len, int chunkSize)
    {
        if (chunkSize <= 0) chunkSize = PageSize;
        int unreadable = 0, pos = 0;
        while (pos < len)
        {
            int chunk = Math.Min(len - pos, chunkSize);
            int got = TryReadPtr(h, addr + (ulong)pos, dst + pos, chunk);
            if (got == chunk)
            {
                pos += chunk;
                continue;
            }

            // 整块失败或只读到一部分：剩余部分退化为按 4 KB 页读
            pos += Math.Max(0, got);

            while (pos < len)
            {
                int page = Math.Min(len - pos, PageSize);
                int gotPage = TryReadPtr(h, addr + (ulong)pos, dst + pos, page);
                if (gotPage == page)
                {
                    pos += page;
                    continue;
                }

                pos += Math.Max(0, gotPage);
                int zero = page - Math.Max(0, gotPage);
                if (zero <= 0) break;

                new Span<byte>((void*)(dst + pos), zero).Clear();
                unreadable += zero;
                pos += zero;
            }
        }
        return unreadable;
    }

    /// <summary>读进托管数组（钉住后走同一套指针路径，供头部/小区域使用）。</summary>
    private static unsafe int ReadIntoArray(IntPtr h, ulong addr, byte[] dst, int dstOff, int len, int chunkSize)
    {
        if (dstOff < 0 || len <= 0 || dstOff + len > dst.Length) return 0;
        fixed (byte* p = dst)
            return ReadIntoPtr(h, addr, (IntPtr)(p + dstOff), len, chunkSize);
    }

    private static int TryReadPtr(IntPtr h, ulong addr, IntPtr dst, int len)    {
        if (len <= 0) return 0;

        if (Syscall.Ready)
        {
            int st = Syscall.ReadVirtualMemory(h, (IntPtr)(long)addr, dst, len, out long got);
            if (st == 0 && got == len) return len;
            return (int)Math.Clamp(got, 0, len);
        }

        if (Win32.ReadProcessMemory(h, (IntPtr)(long)addr, dst, (IntPtr)len, out IntPtr read))
            return (int)Math.Clamp((long)read, 0, len);
        return 0;
    }

    // ---------------- 与磁盘比对 ----------------

    private static void CompareWithDisk(ModuleDumpResult r, byte[] dump, PeLayout layout, int hdrLen,
                                        string diskPath)
    {
        if (string.IsNullOrEmpty(diskPath))   // 无磁盘原件（内存加载 / 已删除）：上面已记录原因
        {
            r.DiskFound = false;
            return;
        }

        FileStream fs;
        long diskLen;
        string diskSha;
        try
        {
            var fi = new FileInfo(diskPath);
            if (fi.Length <= 0 || fi.Length > MaxFile)
            {
                r.DiskFound = false;
                r.Notes.Add($"磁盘原文件尺寸异常（{fi.Length} 字节），跳过比对");
                return;
            }
            diskLen = fi.Length;
            // 流式比对：343 MB 的模块若整份 ReadAllBytes，会为比对再占一份等量内存
            fs = new FileStream(diskPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                                1 << 16, FileOptions.SequentialScan);
            diskSha = "";   // 磁盘哈希由调用方在后台并行计算
        }
        catch (Exception ex)
        {
            r.DiskFound = false;
            r.Notes.Add("读取磁盘原文件失败：" + ex.Message);
            return;
        }

        using (fs)
        {
            var swCmpSetup = Stopwatch.StartNew();
            try
            {
                r.DiskFound = true;
                _ = diskSha;

                // 磁盘文件在最后一个节之后可能还有附加数据（现代 Windows 的系统 DLL 常内嵌 PKCS#7 签名），
                // 这部分不属于映像、不会映射进内存，所以不可能被提取；这里如实说明，而不是假装是同一份文件。
                long extra = diskLen - dump.Length;
                if (extra > 0)
                {
                    bool signed = HasPkcs7Signature(fs, dump.Length, diskLen);
                    r.DiskOverlayBytes = extra;
                    r.Notes.Add($"磁盘原文件比内存映像多 {extra:N0} 字节：节表之外的附加数据" +
                                (signed ? "（识别到 PKCS#7 Authenticode 签名）" : "") +
                                "，不会被加载进进程，提取结果里没有这部分");
                }
                else if (extra < 0)
                {
                    r.Notes.Add($"提取结果比磁盘原文件长 {-extra:N0} 字节（磁盘文件可能已被裁剪或替换过）");
                }

                // 头部
                int hdrCmp = (int)Math.Min(Math.Min(hdrLen, diskLen), dump.Length);
                var diskHdr = new byte[Math.Max(1, hdrCmp)];
                if (hdrCmp > 0) ReadExact(fs, 0, diskHdr, 0, hdrCmp);

                long headerDiff = 0;
                int ibLen = layout.Pe32Plus ? 8 : 4;
                for (int i = 0; i < hdrCmp; i++)
                {
                    if (dump[i] == diskHdr[i]) continue;
                    headerDiff++;
                    if (i >= layout.ImageBaseOffset && i < layout.ImageBaseOffset + ibLen)
                        r.HeaderImageBaseDiff++;
                }
                r.DiffBytes += headerDiff;
                r.ComparedBytes += hdrCmp;

                foreach (var s in r.Sections)
                {
                    if (s.RawSize == 0 || s.VirtualSize == 0) continue;
                    if (s.RawSize > s.VirtualSize)
                        r.PaddingBytes += s.RawSize - s.VirtualSize;
                }
                if (r.PaddingBytes > 0)
                    r.Notes.Add($"有 {r.PaddingBytes:N0} 字节属于节的尾部填充（RawSize > VirtualSize）：不会被映射进内存，不参与提取与比对，输出文件中为 0");

                // 覆盖判定改成“有序区间 + 单调游标”，O(1) 摊销；原来每个差异字节都查一次字典并线性扫列表
                long[] relocSpans = BuildRelocSpans(dump, layout);
                long[] iatSpans = BuildIatSpans(dump, layout);
                r.IatRangeCount = iatSpans.Length / 2;

                const int CmpChunkMax = 1 << 23;   // 8 MB 一块：顺序读、摊薄 syscall 开销
                long maxSec = PageSize;
                foreach (var s0 in r.Sections)
                    if (s0.RawSize > 0) maxSec = Math.Max(maxSec, Math.Min(s0.RawSize, s0.VirtualSize > 0 ? s0.VirtualSize : s0.RawSize));
                int CmpChunk = (int)Math.Min(CmpChunkMax, maxSec);
                var diskBuf = new byte[CmpChunk];
                r.CompareSetupMs = swCmpSetup.Elapsed.TotalMilliseconds;
                var swLoop = Stopwatch.StartNew();

                foreach (var s in r.Sections)
                {
                    if (s.RawSize == 0 || s.RawOffset == 0) continue;

                    // 只比映射进内存的部分：RawSize 超过 VirtualSize 的尾部是文件填充，不在进程里，
                    // 拿它比对会把垫片字节误判成"代码被改写"
                    long mapped = s.VirtualSize > 0 ? Math.Min(s.RawSize, s.VirtualSize) : s.RawSize;
                    long len = Math.Min(mapped, Math.Min((long)dump.Length - s.RawOffset, diskLen - s.RawOffset));
                    if (len <= 0) continue;
                    if (len > int.MaxValue - 64) len = int.MaxValue - 64;

                    int dOff = (int)s.RawOffset;
                    int first = -1;
                    long diff = 0, covered = 0;
                    int rc = 0, ic = 0;                 // 两个单调游标

                    void Classify(long local)
                    {
                        uint rva = s.Rva + (uint)local;
                        rc = Advance(relocSpans, rc, rva, out bool inReloc);
                        if (inReloc) { covered++; return; }
                        ic = Advance(iatSpans, ic, rva, out bool inIat);
                        if (inIat) { r.IatCoveredBytes++; return; }
                        if (s.Writable) { r.WritableDataBytes++; return; }
                        if (s.Executable)
                        {
                            r.CodeUncoveredBytes++;
                            r.FirstCodeUncoveredRva ??= $"0x{rva:X}";
                            if (!r.CodeUncoveredSectionNames.Contains(s.Name)) r.CodeUncoveredSectionNames.Add(s.Name);
                            return;
                        }
                        r.WritableDataBytes++;   // 只读数据节里的零散差异，归入“非代码”，不谎报为代码补丁
                    }

                    long done = 0;
                    while (done < len)
                    {
                        int c = (int)Math.Min(CmpChunk, len - done);
                        ReadExact(fs, s.RawOffset + done, diskBuf, 0, c);
                        int baseOff = dOff + (int)done;

                        // 整块先走向量化比较（内部是 memcmp/AVX2，约 10 GB/s）：
                        // 加载器映像里绝大多数块与磁盘完全一致，这一步能省掉后面 8 字节一轮的扫描。
                        if (dump.AsSpan(baseOff, c).SequenceEqual(diskBuf.AsSpan(0, c)))
                        {
                            done += c;
                            continue;
                        }

                        // 先按 8 字节粗筛，只有整字不同才回落逐字节判定（差异通常 <2%，省掉绝大多数循环）
                        int words = c >> 3;
                        if (words > 0)
                        {
                            var a = MemoryMarshal.Cast<byte, ulong>(dump.AsSpan(baseOff, words * 8));
                            var b = MemoryMarshal.Cast<byte, ulong>(diskBuf.AsSpan(0, words * 8));
                            for (int k = 0; k < words; k++)
                            {
                                if (a[k] == b[k]) continue;
                                int bo = baseOff + (k << 3), so = k << 3;
                                for (int j = 0; j < 8; j++)
                                {
                                    if (dump[bo + j] == diskBuf[so + j]) continue;
                                    diff++;
                                    int local = (int)done + so + j;
                                    if (first < 0) first = local;
                                    Classify(local);
                                }
                            }
                        }
                        for (int j = words * 8; j < c; j++)
                        {
                            if (dump[baseOff + j] == diskBuf[j]) continue;
                            diff++;
                            int local = (int)done + j;
                            if (first < 0) first = local;
                            Classify(local);
                        }

                        done += c;
                    }

                    s.DiskCompared = true;
                    s.DiskDiff = diff;
                    if (first >= 0) s.FirstDiffRva = $"0x{s.Rva + (uint)first:X}";
                    r.DiffBytes += diff;
                    r.RelocCoveredBytes += covered;
                    r.ComparedBytes += len;
                }

                r.CompareLoopMs = swLoop.Elapsed.TotalMilliseconds;
            }
            catch (Exception ex)
            {
                r.DiskFound = false;
                r.Notes.Add("与磁盘原文件比对中断：" + ex.GetType().Name + " — " + ex.Message);
            }
        }

        if (r.ComparedBytes == 0)
        {
            r.Notes.Add("磁盘原文件布局与内存映像不匹配，未能比对");
            return;
        }

        double pct = r.DiffBytes * 100.0 / r.ComparedBytes;
        if (r.DiffBytes == 0)
        {
            r.Notes.Add($"与磁盘原文件逐字节一致（比对 {r.ComparedBytes:N0} 字节，0 处差异）：该模块在内存中未被改写、也未做基址重定位");
            return;
        }

        var hot = r.Sections.Where(x => x.DiskCompared && x.DiskDiff > 0)
                            .OrderByDescending(x => x.DiskDiff)
                            .Take(4)
                            .Select(x => $"{x.Name}({x.DiskDiff:N0} B@{(x.FirstDiffRva ?? "?")})");
        r.Notes.Add($"与磁盘原文件有 {r.DiffBytes:N0} 字节差异（{pct:0.###}%），集中在 {string.Join("、", hot)}");

        // 逐字节归类，把每个差异字节归到具体结构上，不留“可能是什么”的模糊地带
        var parts = new List<string>();
        if (r.RelocCoveredBytes > 0) parts.Add($"基址重定位项内 {r.RelocCoveredBytes:N0} B");
        if (r.IatCoveredBytes > 0) parts.Add($"导入表 IAT {r.IatCoveredBytes:N0} B（{r.IatRangeCount} 段）");
        if (r.HeaderImageBaseDiff > 0) parts.Add($"PE 头 ImageBase 字段 {r.HeaderImageBaseDiff:N0} B");
        long writableOnly = r.WritableDataBytes;
        if (writableOnly > 0) parts.Add($"可写/数据节 {writableOnly:N0} B");
        if (r.CodeUncoveredBytes > 0) parts.Add($"可执行节内非重定位 {r.CodeUncoveredBytes:N0} B");
        if (parts.Count > 0) r.Notes.Add("差异构成：" + string.Join(" · ", parts));

        if (r.CodeUncoveredBytes == 0)
            r.Notes.Add("可执行节（代码）内没有任何非重定位差异：代码段未被改写，不存在内存补丁 / Hook 迹象");
        else
            r.Notes.Add($"可执行节内有 {r.CodeUncoveredBytes:N0} B 既不在重定位表也不在 IAT 内" +
                        $"（节 {string.Join("/", r.CodeUncoveredSectionNames)}，首个 @RVA {r.FirstCodeUncoveredRva}）：" +
                        (r.CodeUncoveredSectionNames.Any(n => n.Equals(".text", StringComparison.OrdinalIgnoreCase))
                            ? "其中包含 .text 主代码段，需重点核查"
                            : "不在 .text 主代码段，属于桩/跳板节，可能是运行时重定向"));
    }

    /// <summary>RVA → 文件偏移（按节表换算），越界返回 -1。</summary>
    private static int RvaToOffset(PeLayout layout, uint rva, int fileLen)
    {
        foreach (var s in layout.Sections)
        {
            uint span = Math.Max(s.VirtualSize, s.RawSize);
            if (span == 0) continue;
            if (rva >= s.Rva && rva - s.Rva < span)
            {
                long off = (long)s.RawOffset + (rva - s.Rva);
                if (off >= 0 && off < fileLen) return (int)off;
                return -1;
            }
        }
        return -1;
    }

    /// <summary>从导入描述符算出每个模块的 IAT 区间（加载器把函数地址写进去的地方，不在重定位表内）。</summary>
    private static List<(uint Start, uint End)> BuildIatRanges(byte[] img, PeLayout layout)
    {
        var list = new List<(uint, uint)>();
        if (layout.ImportRva == 0 || layout.ImportSize == 0) return list;

        int ptr = layout.Pe32Plus ? 8 : 4;
        int off = RvaToOffset(layout, layout.ImportRva, img.Length);
        if (off < 0) return list;

        int guard = 0;
        while (off + 20 <= img.Length && guard++ < 4096)
        {
            uint oft = BitConverter.ToUInt32(img, off + 0);
            uint nameRva = BitConverter.ToUInt32(img, off + 12);
            uint ft = BitConverter.ToUInt32(img, off + 16);
            if (oft == 0 && nameRva == 0 && ft == 0) break;

            uint walk = oft != 0 ? oft : ft;
            int woff = RvaToOffset(layout, walk, img.Length);
            int count = 0;
            if (woff >= 0)
            {
                while (count < 8192 && woff + (count + 1) * ptr <= img.Length)
                {
                    long val = ptr == 8
                        ? BitConverter.ToInt64(img, woff + count * 8)
                        : BitConverter.ToUInt32(img, woff + count * 4);
                    if (val == 0) break;
                    count++;
                }
            }

            if (ft != 0 && count > 0)
                list.Add((ft, ft + (uint)((count + 1) * ptr)));

            off += 20;
        }

        list.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        return list;
    }

    private static bool InAnyRange(List<(uint Start, uint End)> ranges, uint rva)
    {
        if (ranges.Count == 0) return false;
        int lo = 0, hi = ranges.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            var (s, e) = ranges[mid];
            if (rva < s) hi = mid - 1;
            else if (rva >= e) lo = mid + 1;
            else return true;
        }
        return false;
    }

    /// <summary>
    /// 解析磁盘原文件路径（含 WOW64 视图修正），并提前启动哈希任务：
    /// 哈希在后台跑，与“读内存 → 落盘 → 比对”整条链路重叠，不再占用关键路径。
    /// </summary>
    private static (string? Path, Task<string>? HashTask) ResolveDiskPath(string? path, ushort machine, List<string> notes)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            notes.Add("磁盘上找不到该模块的原始文件（可能是内存加载 / 已删除），提取结果即唯一副本");
            return (null, null);
        }

        ushort? diskMachine = ReadMachine(path);
        if (diskMachine.HasValue && diskMachine.Value != machine)
        {
            string alt = AltArchPath(path);
            if (alt != path && File.Exists(alt) && ReadMachine(alt) == machine)
            {
                notes.Add($"磁盘路径按模块位数修正：{path} → {alt}");
                path = alt;
            }
            else
            {
                notes.Add($"磁盘文件架构（0x{diskMachine.Value:X4}）与内存模块（0x{machine:X4}）不一致，跳过比对");
                return (null, null);
            }
        }

        string p = path;

        // 磁盘原件的 sha256 只在小文件上顺带算。
        // 系统 DLL 普遍带 Authenticode 签名（末尾附加数据不映射进内存），它的整文件哈希
        // 与产物的哈希本来就不会相等，信息量很低；而每次重算一遍几百 MB 的 SHA-256
        // 会与产物哈希抢同一个后台核心和内存带宽。内容是否一致，逐字节比对已经给了答案。
        long len = 0;
        try { len = new FileInfo(p).Length; } catch { }
        if (len > DiskHashLimit)
        {
            notes.Add($"磁盘原件 {len / 1024.0 / 1024.0:N0} MB，未单独计算其 sha256（内容一致性见逐字节比对）");
            return (p, null);
        }

        var task = Task.Run(() =>
        {
            using var hs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.Read,
                                          1 << 16, FileOptions.SequentialScan);
            return Convert.ToHexString(SHA256.HashData(hs)).ToLowerInvariant();
        });
        return (p, task);
    }

    /// <summary>读磁盘文件 PE 头里的 Machine 字段（用于确认架构，读不到返回 null）。</summary>
    private static ushort? ReadMachine(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var buf = new byte[0x400];
            int n = fs.Read(buf, 0, buf.Length);
            if (n < 0x40 || buf[0] != (byte)'M' || buf[1] != (byte)'Z') return null;
            int peOff = BitConverter.ToInt32(buf, 0x3C);
            if (peOff < 0x40 || peOff + 6 > n) return null;
            if (BitConverter.ToUInt32(buf, peOff) != 0x00004550) return null;
            return BitConverter.ToUInt16(buf, peOff + 4);
        }
        catch { return null; }
    }

    /// <summary>System32 ↔ SysWOW64 互换，用于纠正 WOW64 视图下的路径。</summary>
    private static string AltArchPath(string path)
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string sys32 = Path.Combine(win, "System32");
        string sysWow = Path.Combine(win, "SysWOW64");
        try
        {
            if (path.StartsWith(sysWow, StringComparison.OrdinalIgnoreCase))
                return sys32 + path[sysWow.Length..];
            if (path.StartsWith(sys32, StringComparison.OrdinalIgnoreCase))
                return sysWow + path[sys32.Length..];
        }
        catch { }
        return path;
    }

    /// <summary>在附加数据开头找 PKCS#7 SignedData 的 DER OID（1.2.840.113549.1.7.2），用于判断是不是 Authenticode 签名。</summary>
    private static bool HasPkcs7Signature(FileStream fs, long offset, long fileLen)
    {
        if (offset < 0 || offset >= fileLen) return false;
        int len = (int)Math.Min(0x2000, fileLen - offset);
        if (len < 8) return false;

        var buf = new byte[len];
        ReadExact(fs, offset, buf, 0, len);
        for (int i = 0; i + 7 < len; i++)
        {
            // OID 1.2.840.113549.1.7.2 = signedData
            if (buf[i] == 0x06 && buf[i + 1] == 0x09 &&
                buf[i + 2] == 0x2A && buf[i + 3] == 0x86 && buf[i + 4] == 0x48 &&
                buf[i + 5] == 0x86 && buf[i + 6] == 0xF7 && buf[i + 7] == 0x0D)
                return true;
        }
        return false;
    }

    /// <summary>解析基址重定位表，得到“页 RVA → (页内偏移, 宽度)”的映射，用来判断差异是否由重定位置成。</summary>
    /// <summary>把 .reloc 展开成按起始 RVA 排序的区间数组（偶数位=起点，奇数位=终点）。</summary>
    private static long[] BuildRelocSpans(byte[] dump, PeLayout layout)
    {
        if (layout.RelocRva == 0 || layout.RelocSize < 8) return Array.Empty<long>();
        int start = OffsetOfRva(layout, layout.RelocRva) ?? -1;
        if (start < 0 || start + 8 > dump.Length) return Array.Empty<long>();

        int end = (int)Math.Min(dump.Length, (long)start + layout.RelocSize);
        var flat = new List<long>(4096);
        bool ascending = true;
        long prevStart = -1;
        int p = start;
        while (p + 8 <= end)
        {
            uint page = BitConverter.ToUInt32(dump, p);
            int blockSize = BitConverter.ToInt32(dump, p + 4);
            if (blockSize < 8 || p + blockSize > end) break;

            for (int q = p + 8; q + 2 <= p + blockSize; q += 2)
            {
                ushort e = BitConverter.ToUInt16(dump, q);
                int width = (e >> 12) switch { 3 => 4, 10 => 8, 1 or 2 => 2, _ => 0 };
                if (width == 0) continue;
                long rva = page + (e & 0xFFF);
                if (rva < prevStart) ascending = false;
                prevStart = rva;
                flat.Add(rva);
                flat.Add(rva + width);
            }
            p += blockSize;
        }

        if (!ascending)
        {
            int n = flat.Count >> 1;
            var keys = new long[n];
            var vals = new long[n];
            for (int i = 0; i < n; i++) { keys[i] = flat[i * 2]; vals[i] = flat[i * 2 + 1]; }
            Array.Sort(keys, vals);
            flat.Clear();
            for (int i = 0; i < n; i++) { flat.Add(keys[i]); flat.Add(vals[i]); }
        }
        return flat.ToArray();
    }

    /// <summary>导入表 IAT 区间，同样展开成有序区间数组。</summary>
    private static long[] BuildIatSpans(byte[] dump, PeLayout layout)
    {
        var ranges = BuildIatRanges(dump, layout);
        var list = new List<(uint S, uint E)>(ranges.Count);
        foreach (var (a, b) in ranges) list.Add((a, b));
        return Pack(list);
    }

    private static long[] Pack(List<(uint S, uint E)> list)
    {
        if (list.Count == 0) return Array.Empty<long>();
        list.Sort((a, b) => a.S.CompareTo(b.S));
        var spans = new long[list.Count * 2];
        for (int i = 0; i < list.Count; i++)
        {
            spans[i * 2] = list[i].S;
            spans[i * 2 + 1] = list[i].E;
        }
        return spans;
    }

    /// <summary>
    /// 单调游标：rva 在节内递增，因此游标只前进不回退，均摊 O(1)。
    /// 返回新的游标位置，hit 表示 rva 落在某个区间内。
    /// </summary>
    private static int Advance(long[] spans, int cur, uint rva, out bool hit)
    {
        int n = spans.Length >> 1;
        while (cur < n && spans[cur * 2 + 1] <= rva) cur++;
        hit = cur < n && spans[cur * 2] <= rva && rva < spans[cur * 2 + 1];
        return cur;
    }

    /// <summary>按绝对偏移从磁盘文件精确读取 len 字节（跨块读，短读即报错）。</summary>
    private static void ReadExact(FileStream fs, long offset, byte[] buf, int bufOff, int len)
    {
        fs.Seek(offset, SeekOrigin.Begin);
        while (len > 0)
        {
            int n = fs.Read(buf, bufOff, len);
            if (n <= 0) throw new IOException($"磁盘文件在偏移 0x{offset:X} 处提前结束");
            bufOff += n;
            len -= n;
        }
    }

    private static int? OffsetOfRva(PeLayout layout, long rva)
    {
        foreach (var s in layout.Sections)
        {
            long size = Math.Max(s.VirtualSize, s.RawSize);
            if (rva >= s.Rva && rva < s.Rva + size)
                return (int)(s.RawOffset + (rva - s.Rva));
        }
        return null;
    }

    private static long CountDiff(byte[] a, int aOff, byte[] b, int bOff, int len, ref int firstIndex)
    {
        long diff = 0;
        var sa = a.AsSpan(aOff, len);
        var sb = b.AsSpan(bOff, len);
        for (int i = 0; i < len; i++)
        {
            if (sa[i] == sb[i]) continue;
            diff++;
            if (firstIndex < 0) firstIndex = i;
        }
        return diff;
    }

    private static long CountDiff(byte[] a, int aOff, byte[] b, int bOff, int len)
    {
        int ignored = -1;
        return CountDiff(a, aOff, b, bOff, len, ref ignored);
    }

    // ---------------- 辅助 ----------------

    private static string Sha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private static readonly char[] Invalid =
        Path.GetInvalidFileNameChars().Concat(new[] { '\\', '/', ':', '*', '?', '"', '<', '>', '|' }).Distinct().ToArray();

    /// <summary>
    /// 独占写打开产物文件。刚写出的大 PE 有时会被系统组件（索引 / 应用兼容性检查）短时抓住，
    /// 表现就是“文件正被另一个进程使用”；这里按指数退避重试，最长约 8 秒。
    /// </summary>
    private static Microsoft.Win32.SafeHandles.SafeFileHandle OpenForWrite(string path, long size)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return File.OpenHandle(path, FileMode.Create, FileAccess.Write, FileShare.None,
                                       FileOptions.None, size);
            }
            catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) && attempt < 14)
            {
                Thread.Sleep(attempt < 6 ? 60 * (attempt + 1) : 800);
            }
        }
    }

    /// <summary>
    /// 把临时文件替换成最终产物。MoveFileEx(REPLACE_EXISTING) 是原子的：
    /// 旁观者要么看到旧文件、要么看到新文件，不会读到半截产物。
    /// 目标若被实时防护短暂占住则退避重试（最长约 8 秒）。
    /// </summary>
    private static void ReplaceWith(string tmp, string dest)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                File.Move(tmp, dest, overwrite: true);
                return;
            }
            catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) && attempt < 14)
            {
                Thread.Sleep(attempt < 6 ? 60 * (attempt + 1) : 800);
            }
        }
    }

    private static string Safe(string name)
    {        var sb = new StringBuilder(name.Length);
        foreach (char c in name) sb.Append(Array.IndexOf(Invalid, c) >= 0 ? '_' : c);
        string s = sb.ToString().Trim();
        if (s.Length == 0) s = "item";
        if (s.Length > 120) s = s[..120];
        return s;
    }

    /// <summary>
    /// 写 &lt;产物&gt;.meta.json。
    /// force=true 时不检查 Ok，供后台哈希任务在哈希落定后整体重写（此时文件里 sha256 才是真的）。
    /// </summary>
    private static void WriteMeta(ModuleDumpResult r, bool force = false)
    {
        if (string.IsNullOrEmpty(r.OutPath)) return;
        if (!r.Ok && !force) return;
        try
        {
          lock (r)   // 首次写入与哈希后的重写可能撞车
          {
            var meta = new
            {
                kind = r.SectionCount > 0 ? "module-image" : "memory-region",
                process = r.Process,
                pid = r.Pid,
                module = r.Module,
                baseAddress = "0x" + r.Base.ToString("X"),
                extractedAt = r.ExtractedAt,
                file = Path.GetFileName(r.OutPath),
                bytes = r.FileBytes,
                sha256 = r.Sha256,
                peValid = r.PeValid,
                peNote = r.PeNote,
                unreadableBytes = r.UnreadableBytes,
                diskPath = r.DiskPath,
                diskSha256 = r.DiskSha256,
                diskDiffBytes = r.DiffBytes,
                comparedBytes = r.ComparedBytes,
                diskOverlayBytes = r.DiskOverlayBytes,
                diffBreakdown = new
                {
                    relocCovered = r.RelocCoveredBytes,
                    importIat = r.IatCoveredBytes,
                    headerImageBase = r.HeaderImageBaseDiff,
                    writableData = r.WritableDataBytes,
                    codeUncovered = r.CodeUncoveredBytes,
                    firstCodeUncoveredRva = r.FirstCodeUncoveredRva
                },
                sections = r.Sections.Select(s => new
                {
                    name = s.Name,
                    rva = "0x" + s.Rva.ToString("X"),
                    rawOffset = "0x" + s.RawOffset.ToString("X"),
                    virtualSize = s.VirtualSize,
                    rawSize = s.RawSize,
                    copied = s.Copied,
                    unreadable = s.Unreadable,
                    diskDiff = s.DiskDiff
                }),
                notes = r.Notes
            };
            File.WriteAllText(r.OutPath + ".meta.json",
                JsonSerializer.Serialize(meta, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                }),
                new UTF8Encoding(false));
          }
        }
        catch { /* 元数据写失败不影响提取结果 */ }
    }
}
