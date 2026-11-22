using System.IO;
using System.Windows;
using System.Windows.Controls;
using MemScope.Core;

namespace MemScope;

public partial class MainWindow
{
    private bool _detailBusy;
    private int _detailPid = -1;
    private int _lastSelectedPid = -1;

    private ProcessRow? Selected => ProcessGrid.SelectedItem as ProcessRow;

    private void ProcessGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var sel = Selected;
        if (sel == null)
        {
            LblProcTitle.Text = "未选择进程";
            SetStats(null);
            ModuleGrid.ItemsSource = new List<ModuleInfo>();
            RegionGrid.ItemsSource = new List<MemoryRegion>();
            HandleGrid.ItemsSource = new List<FileHandleInfo>();
            LblModuleInfo.Text = LblRegionInfo.Text = LblHandleInfo.Text = "—";
            _detailPid = -1;
            return;
        }

        if (sel.Pid != _lastDumpPid) _lastDumpText = null;
        _detailPid = sel.Pid;
        _lastSelectedPid = sel.Pid;
        LblProcTitle.Text = sel.Name;
        SetStats(sel);
        _ = LoadDetailsAsync(sel.Pid, sel.Name, withRegions: true, withHandles: true);
    }

    /// <summary>把选中进程的关键指标填进标题下的指标条；null 表示无选中。</summary>
    private void SetStats(ProcessRow? row)
    {
        if (row == null)
        {
            LblStatPid.Text = LblStatWs.Text = LblStatPriv.Text = LblStatThreads.Text = LblStatHandles.Text = "—";
            LblStatPath.Text = "在左侧选择一行以查看其内存与已加载文件";
            LblStatPath.ToolTip = null;
            return;
        }

        LblStatPid.Text = row.Pid.ToString();
        LblStatWs.Text = $"{row.WorkingSetMb:N1} MB";
        LblStatPriv.Text = $"{row.PrivateMb:N1} MB";
        LblStatThreads.Text = row.Threads.ToString();
        LblStatHandles.Text = row.Handles.ToString();
        LblStatPath.Text = string.IsNullOrEmpty(row.Path) ? "（路径未知：进程可能已退出或无权限查询）" : row.Path;
        LblStatPath.ToolTip = row.Path;
    }

    private async Task LoadDetailsAsync(int pid, string name, bool withRegions, bool withHandles)
    {
        if (_detailBusy) return;
        _detailBusy = true;
        try
        {
            if (pid != _detailPid) return;

            var mods = await Task.Run(() => MemoryMapScanner.Modules(pid));
            if (pid != _detailPid) return;
            ModuleGrid.ItemsSource = mods;
            string moduleInfo = mods.Count == 0
                ? "无法枚举模块（进程可能已退出，或句柄被保护）"
                : $"{mods.Count} 个模块 · {mods.Sum(m => (long)m.Size) / 1024.0 / 1024.0:N1} MB";
            // 刚提取过模块时，这一行改为显示提取结果（更贴近刚才的操作），否则显示模块统计
            LblModuleInfo.Text = _lastDumpText ?? moduleInfo;
            LblModuleInfo.ToolTip = _lastDumpText == null ? moduleInfo : $"{moduleInfo} · {_lastDumpText}";
            var sel = Selected;
            if (sel != null && sel.Pid == pid && withRegions == false)
                SetStats(sel);

            if (withRegions)
            {
                var regions = await Task.Run(() => MemoryMapScanner.Scan(pid));
                if (pid != _detailPid) return;
                RegionGrid.ItemsSource = regions;
                long committed = regions.Where(r => r.State == "已提交").Sum(r => (long)r.Size);
                LblRegionInfo.Text = regions.Count == 0
                    ? "无法读取虚拟内存布局"
                    : $"{regions.Count} 个区域 · 已提交合计 {committed / 1024.0 / 1024.0:N1} MB";
            }

            if (withHandles)
            {
                var hs = await Task.Run(() => HandleScanner.ScanFiles(pid));
                if (pid != _detailPid) return;
                HandleGrid.ItemsSource = hs.Items;
                LblHandleInfo.Text = hs.Items.Count == 0 ? hs.Note : $"{hs.Note} · 打开的文件 {hs.Items.Select(i => i.Path).Distinct().Count()} 个";
            }
        }
        catch (Exception ex)
        {
            Log($"详情载入失败：{ex.Message}");
        }
        finally
        {
            _detailBusy = false;
        }
    }

    // ==================== 导出 ====================

    private async void BtnExport_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_lastSnap.Processes.Count == 0) await RefreshAsync(force: true);
            var snap = _lastSnap;
            var copy = _rows.ToList();
            var dir = _exportDir;
            var (csv, json) = await Task.Run(() => SnapshotExporter.WriteSnapshot(snap, copy, dir));
            Log($"已导出快照：{Path.GetFileName(csv)} / {Path.GetFileName(json)}（{copy.Count} 进程）→ {dir}");
            LblExportStatus.Text = $"最后导出 {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex)
        {
            Log("导出失败：" + ex.Message);
        }
    }

    private void TglAutoExport_Click(object sender, RoutedEventArgs e)
    {
        _autoExport = TglAutoExport.IsChecked == true;
        if (_autoExport)
        {
            Directory.CreateDirectory(_exportDir);
            _autoExportTimer.Start();
            TglAutoExport.Content = "实时导出 · 开";
            Log($"实时导出已开启：每 5 秒写入 {_exportDir}（仅保留最近 40 组）");
        }
        else
        {
            _autoExportTimer.Stop();
            TglAutoExport.Content = "实时导出 · 关";
            Log("实时导出已关闭");
        }
    }

    private async Task AutoExportAsync()
    {
        if (!_autoExport || _paused) return;
        try
        {
            var snap = _lastSnap;
            if (snap.Processes.Count == 0) return;
            var copy = _rows.ToList();
            var dir = _exportDir;
            var (csv, _) = await Task.Run(() =>
            {
                var r = SnapshotExporter.WriteSnapshot(snap, copy, dir, "auto");
                SnapshotExporter.Prune(dir, 40);
                return r;
            });
            LblExportStatus.Text = $"最后导出 {DateTime.Now:HH:mm:ss} · {Path.GetFileName(csv)}";
        }
        catch (Exception ex)
        {
            Log("实时导出失败：" + ex.Message);
            _autoExport = false;
            _autoExportTimer.Stop();
            TglAutoExport.IsChecked = false;
            TglAutoExport.Content = "实时导出 · 关";
        }
    }

    // ==================== 强制终止 ====================

    private async void BtnKill_Click(object sender, RoutedEventArgs e)
    {
        var sel = Selected;
        if (sel == null)
        {
            Log("请先在列表中选择一个进程。");
            return;
        }

        if (Killer.IsCritical(sel.Name))
        {
            Log($"已拒绝：{sel.Name}({sel.Pid}) 是 Windows 关键进程，终止会导致系统崩溃。");
            MessageBox.Show(this,
                $"“{sel.Name}” 属于 Windows 关键进程（如 csrss / winlogon / services / lsass）。\n" +
                "终止它会立即导致系统蓝屏或强制重启，因此本程序拒绝执行。",
                "安全保护", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var choice = MessageBox.Show(this,
            $"目标：{sel.Name}  (PID {sel.Pid})\n" +
            $"内存：{sel.WorkingSetMb:N1} MB 工作集 / {sel.PrivateMb:N1} MB 私有\n" +
            $"文件：{sel.PathDisplay}\n\n" +
            "是 = 连同子进程一起结束\n否 = 只结束该进程\n取消 = 放弃",
            "强制终止确认", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);

        if (choice == MessageBoxResult.Cancel) return;
        bool tree = choice == MessageBoxResult.Yes;

        BtnKill.IsEnabled = false;
        try
        {
            Killer.EnableDebugPrivilege();
            Log($"—— 开始强制终止 {sel.Name}({sel.Pid}){(tree ? " 及子进程" : "")} ——");

            if (tree)
            {
                var results = await Killer.ForceKillTreeAsync(sel.Pid, NameOf, Log);
                Log("进程树结果：" + string.Join(" | ", results));
            }
            else
            {
                var stages = await Killer.ForceKillAsync(sel.Pid, sel.Name);
                foreach (var s in stages) Log("  " + s);
            }

            if (!Killer.IsAlive(sel.Pid))
            {
                Log($"√ {sel.Name}({sel.Pid}) 已终止");
                if (_map.TryGetValue(sel.Pid, out var row))
                {
                    _rows.Remove(row);
                    _map.Remove(sel.Pid);
                }
            }
            else
            {
                Log($"× {sel.Name}({sel.Pid}) 仍在运行");
            }

            await RefreshAsync(force: true);
        }
        catch (Exception ex)
        {
            Log("终止过程异常：" + ex.Message);
        }
        finally
        {
            BtnKill.IsEnabled = true;
        }
    }

    private string NameOf(int pid) => _map.TryGetValue(pid, out var r) ? r.Name : $"pid{pid}";
}
