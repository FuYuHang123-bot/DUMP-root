using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using MemScope.Core;

namespace MemScope;

/// <summary>模块二进制提取（从活进程内存还原 PE 文件）与内存区域转储。</summary>
public partial class MainWindow
{
    private ModuleInfo? SelectedModule => ModuleGrid.SelectedItem as ModuleInfo;

    /// <summary>最近一次提取结果，拼在模块页签的信息行里（每秒刷新会用采样数据重写这行，所以单独记住）。</summary>
    private string? _lastDumpText;
    private int _lastDumpPid = -1;

    private string DumpRoot => Path.Combine(_exportDir, "modules");

    // ==================== 入口 ====================

    private async void BtnDumpModule_Click(object sender, RoutedEventArgs e) => await DumpSelectedModuleAsync();

    private async void MenuDumpModule_Click(object sender, RoutedEventArgs e) => await DumpSelectedModuleAsync();

    private async void ModuleGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => await DumpSelectedModuleAsync();

    private async void BtnDumpAll_Click(object sender, RoutedEventArgs e)
    {
        var proc = Selected;
        if (proc == null) { Log("请先在左侧选择一个进程。"); return; }

        var mods = (ModuleGrid.ItemsSource as IEnumerable<ModuleInfo>)?.ToList() ?? new List<ModuleInfo>();
        if (mods.Count == 0) { Log("该进程没有可提取的模块（模块枚举为空）。"); return; }

        var ok = MessageBox.Show(this,
            $"将从 PID {proc.Pid}（{proc.Name}）提取全部 {mods.Count} 个模块。\n" +
            $"输出目录：{Path.Combine(DumpRoot, $"{proc.Pid}_{proc.Name}")}\n\n继续？",
            "提取全部模块", MessageBoxButton.OKCancel, MessageBoxImage.Question);
        if (ok != MessageBoxResult.OK) return;

        await DumpModulesAsync(proc, mods);
    }

    private async Task DumpSelectedModuleAsync()
    {
        var proc = Selected;
        var mod = SelectedModule;
        if (proc == null) { Log("请先在左侧选择一个进程。"); return; }
        if (mod == null)
        {
            Log("请先在“文件与模块”页签选中一个模块（提示：右键也可提取，双击行直接提取）。");
            return;
        }
        await DumpModulesAsync(proc, new List<ModuleInfo> { mod });
    }

    private async Task DumpModulesAsync(ProcessRow proc, List<ModuleInfo> mods)
    {
        bool freeze = ChkFreeze.IsChecked == true;
        string root = DumpRoot;

        BtnDumpModule.IsEnabled = false;
        BtnDumpAll.IsEnabled = false;
        try
        {
            Log($"—— 从 PID {proc.Pid}（{proc.Name}）提取 {mods.Count} 个模块的二进制{(freeze ? "，提取时冻结进程" : "")} ——");

            var results = await Task.Run(() =>
                mods.Select(m => ModuleDumper.DumpModule(proc.Pid, proc.Name, m, root, freeze)).ToList());

            int succeed = 0;
            foreach (var r in results)
            {
                if (r.Ok) succeed++;
                LogDumpResult(r, verbose: results.Count == 1);
            }

            var last = results.LastOrDefault(r => r.Ok);
            if (last != null)
            {
                _lastDumpText = results.Count == 1
                    ? $"已提取 {Path.GetFileName(last.OutPath)}"
                    : $"已提取 {succeed}/{results.Count} 个模块";
                _lastDumpPid = proc.Pid;
                LblModuleInfo.Text = _lastDumpText;
                LblModuleInfo.ToolTip = $"{_lastDumpText}\n大小 {last.SizeText}\n输出 {last.OutPath}";
                LblExportStatus.Text = $"最后提取 {DateTime.Now:HH:mm:ss}";
            }
            Log($"—— 提取结束：成功 {succeed} / {results.Count} ——");
        }
        catch (Exception ex)
        {
            Log("提取失败：" + ex.GetType().Name + " — " + ex.Message);
        }
        finally
        {
            BtnDumpModule.IsEnabled = true;
            BtnDumpAll.IsEnabled = true;
        }
    }

    private void LogDumpResult(ModuleDumpResult r, bool verbose)
    {
        if (!r.Ok)
        {
            Log($"× {r.Module} @0x{r.Base:X}：提取失败");
            foreach (var n in r.Notes) Log("    " + n);
            return;
        }

        Log($"√ {Path.GetFileName(r.OutPath)}  {r.SizeText}  节 {r.SectionCount}  {r.ElapsedMs:F0} ms  " +
            $"(读 {r.ReadMs:F0} · 落盘 {r.WriteMs:F0} · 比对 {r.CompareMs:F0})  " +
            $"{(r.PeValid ? "PE 校验通过" : "PE 校验未通过")}" +
            (r.UnreadableBytes > 0 ? $"，不可读 {r.UnreadableBytes:N0} B" : ""));
        if (r.ChangedDuringRead)
            Log("    ! 提取期间内容发生变化（进程未冻结），快照可能不一致——建议勾选“冻结提取”");
        if (r.Sha256.Length > 0)
            Log($"    sha256 {r.Sha256}");
        else if (r.HashTask != null)
        {
            // 哈希在后台算（没有 SHA-NI 的机器上 343 MB 要 0.7 s），不挡提取结果
            Log("    sha256 计算中…");
            _ = AppendHashAsync(r);
        }
        if (verbose)
        {
            Log("    " + r.PeNote);
            if (r.DiskFound)
                Log($"    磁盘原文件 {r.DiskPath}");
            foreach (var s in r.Sections) Log(s.Line);
            foreach (var n in r.Notes) Log("    " + n);
            Log($"    输出 {r.OutPath}");
        }
        else if (r.DiffBytes > 0 || r.UnreadableBytes > 0)
        {
            foreach (var n in r.Notes) Log("    " + n);
        }
    }

    /// <summary>后台哈希算完后补一行日志（Log 内部已做线程封送）。</summary>
    private async Task AppendHashAsync(ModuleDumpResult r)
    {
        try
        {
            await r.HashTask!;
            Log(r.Sha256.Length > 0 ? $"    sha256 {r.Sha256}" : "    sha256 计算失败");
        }
        catch (Exception ex) { Log("    sha256 计算失败：" + ex.Message); }
    }

    // ==================== 内存区域转储 ====================
    private async void MenuDumpRegion_Click(object sender, RoutedEventArgs e)
    {
        var proc = Selected;
        var region = RegionGrid.SelectedItem as MemoryRegion;
        if (proc == null || region == null) { Log("请先选中一个内存区域。"); return; }
        if (region.State != "已提交")
        {
            Log("该区域尚未提交（保留状态），没有可读取的物理内容，已跳过。");
            return;
        }

        bool freeze = ChkFreeze.IsChecked == true;
        try
        {
            Log($"—— 转储区域 0x{region.Base:X}（{region.SizeDisplay}）——");
            var r = await Task.Run(() => ModuleDumper.DumpRegion(proc.Pid, proc.Name, region, DumpRoot, freeze));
            LogDumpResult(r, verbose: true);
            if (r.Ok)
            {
                LblRegionInfo.Text = $"已转储 {Path.GetFileName(r.OutPath)}（{r.SizeText}）→ {r.OutDir}";
                LblExportStatus.Text = $"最后转储 {DateTime.Now:HH:mm:ss}";
            }
        }
        catch (Exception ex)
        {
            Log("转储失败：" + ex.Message);
        }
    }

    // ==================== 右键辅助 ====================

    private void ModuleGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        => SelectRowUnderMouse(ModuleGrid, e);

    private void RegionGrid_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
        => SelectRowUnderMouse(RegionGrid, e);

    private static void SelectRowUnderMouse(DataGrid grid, MouseButtonEventArgs e)
    {
        var row = FindAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row != null) row.IsSelected = true;
        else grid.SelectedItem = null;
    }

    private static T? FindAncestor<T>(DependencyObject? d) where T : DependencyObject
    {
        while (d != null)
        {
            if (d is T t) return t;
            d = d is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(d)
                : LogicalTreeHelper.GetParent(d);
        }
        return null;
    }

    private void MenuCopyModulePath_Click(object sender, RoutedEventArgs e)
    {
        var mod = SelectedModule;
        if (mod == null) return;
        try
        {
            Clipboard.SetText(string.IsNullOrEmpty(mod.Path) ? mod.Name : mod.Path);
            Log("已复制模块路径：" + (string.IsNullOrEmpty(mod.Path) ? mod.Name : mod.Path));
        }
        catch (Exception ex) { Log("复制失败：" + ex.Message); }
    }

    private void MenuLocateModule_Click(object sender, RoutedEventArgs e)
    {
        var mod = SelectedModule;
        if (mod == null || string.IsNullOrEmpty(mod.Path) || !File.Exists(mod.Path)) { Log("该模块没有可定位的磁盘路径。"); return; }
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{mod.Path}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { Log("定位失败：" + ex.Message); }
    }
}
