using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;
using MemScope.Core;
using MemScope.Interop;

namespace MemScope;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<ProcessRow> _rows = new();
    private readonly Dictionary<int, ProcessRow> _map = new();
    private readonly ObservableCollection<LogEntry> _logs = new();
    private readonly DispatcherTimer _timer = new();
    private readonly DispatcherTimer _autoExportTimer = new();

    private ICollectionView _view = null!;
    private SystemSnapshot _lastSnap = new();
    private int _cores = Environment.ProcessorCount;

    private readonly double[] _intervals = { 0.5, 1.0, 2.0, 5.0 };
    private int _intervalIndex = 1;
    private bool _busy;
    private bool _paused;
    private bool _autoExport;
    private int _tickCount;
    private string _exportDir = SnapshotExporter.DefaultDirectory;

    public MainWindow()
    {
        InitializeComponent();

        LogList.ItemsSource = _logs;
        ModuleGrid.ItemsSource = new List<ModuleInfo>();
        RegionGrid.ItemsSource = new List<MemoryRegion>();
        HandleGrid.ItemsSource = new List<FileHandleInfo>();

        ProcessGrid.ItemsSource = _rows;
        _view = CollectionViewSource.GetDefaultView(_rows);
        _view.Filter = FilterRow;
        _view.SortDescriptions.Add(new SortDescription(nameof(ProcessRow.WorkingSetMb), ListSortDirection.Descending));

        _timer.Interval = TimeSpan.FromSeconds(_intervals[_intervalIndex]);
        _timer.Tick += async (_, _) => await TickAsync();

        _autoExportTimer.Interval = TimeSpan.FromSeconds(5);
        _autoExportTimer.Tick += async (_, _) => await AutoExportAsync();

        BtnTheme.Content = ThemeManager.Dark ? "浅色" : "深色";
        ApplySettings();
        Loaded += OnLoaded;
        Closing += (_, _) => { _timer.Stop(); _autoExportTimer.Stop(); };
    }

    /// <summary>把 AppSettings 的当前值同步到界面控件（构造时与设置窗口保存后各调一次）。</summary>
    internal void ApplySettings()
    {
        ChkFreeze.IsChecked = AppSettings.FreezeOnDump;
        _exportDir = string.IsNullOrWhiteSpace(AppSettings.OutputDir)
            ? SnapshotExporter.DefaultDirectory
            : AppSettings.OutputDir;
        BtnTheme.Content = ThemeManager.Dark ? "浅色" : "深色";
    }

    private bool _loadedOnce;

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_loadedOnce) return;
        _loadedOnce = true;

        Log($"MemScope 启动 · {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        Log($"系统调用层：{(Syscall.Ready ? Syscall.StatusMessage : Syscall.StatusMessage + "（回退到常规 ntdll）")}");
        Log($"对象类型：{HandleScanner.FileTypeDiagnostic}");
        LblHandleDiag.Text = Syscall.Ready
            ? $"直连系统调用就绪 · {HandleScanner.FileTypeDiagnostic}"
            : $"标准模式 · {HandleScanner.FileTypeDiagnostic}";

        bool elevated = Win32.IsElevated();
        UpdatePrivilegeChip(elevated);
        if (elevated)
            Log("已提权：SeDebugPrivilege 生效，可操作绝大多数进程。");
        else
            Log("当前非管理员：部分系统进程无法打开句柄，建议点击右上角“普通权限”一键提权。");

        _timer.Start();
        await RefreshAsync(force: true);
    }

    private void UpdatePrivilegeChip(bool elevated)
    {
        if (elevated)
        {
            ChipPrivilege.Background = (System.Windows.Media.Brush)FindResource("AccentSoftBrush");
            LblPrivilege.Text = "管理员 · 已就绪";
            LblPrivilege.Foreground = (System.Windows.Media.Brush)FindResource("AccentBrush");
        }
        else
        {
            ChipPrivilege.Background = (System.Windows.Media.Brush)FindResource("DangerSoftBrush");
            LblPrivilege.Text = "普通权限 · 点击提权";
            LblPrivilege.Foreground = (System.Windows.Media.Brush)FindResource("DangerBrush");
        }
    }

    // ==================== 采样 ====================

    private async Task TickAsync()
    {
        if (_paused) return;
        await RefreshAsync();
        _tickCount++;

        var sel = ProcessGrid.SelectedItem as ProcessRow;
        if (sel != null && TglFollow.IsChecked == true)
        {
            bool withHandles = _tickCount % Math.Max(1, (int)(5.0 / _intervals[_intervalIndex])) == 0;
            await LoadDetailsAsync(sel.Pid, sel.Name, withRegions: false, withHandles: withHandles);
        }
    }

    private async Task RefreshAsync(bool force = false)
    {
        if (_busy && !force) return;
        _busy = true;
        try
        {
            var snap = await Task.Run(() =>
            {
                var s = ProcessSnapshot.Capture();
                foreach (var p in s.Processes)
                    p.ImagePath = ProcessSnapshot.GetImagePath(p.Pid, p.CreateTime);
                return s;
            });

            ApplySnapshot(snap);

            LblStatus.Text = $"采样 {snap.ElapsedMs:F1} ms · {DateTime.Now:HH:mm:ss}";
            LblProcCount.Text = $"{_rows.Count} 个";
            LblProcSummary.Text = $"总工作集 {snap.WorkingSetTotal / 1024.0 / 1024.0 / 1024.0:F2} GB · " +
                                  $"线程 {snap.ThreadTotal:N0}";
        }
        catch (Exception ex)
        {
            Log("采样异常：" + ex.Message);
        }
        finally
        {
            _busy = false;
        }
    }

    private void ApplySnapshot(SystemSnapshot snap)
    {
        double elapsedMs = _lastSnap.TakenAtTicks == 0
            ? 0
            : (snap.TakenAtTicks - _lastSnap.TakenAtTicks) / 10000.0;

        var seen = new HashSet<int>(snap.Processes.Count);
        foreach (var s in snap.Processes)
        {
            seen.Add(s.Pid);
            if (!_map.TryGetValue(s.Pid, out var row))
            {
                row = new ProcessRow { Pid = s.Pid, CreateTime = s.CreateTime, Path = s.ImagePath };
                _map[s.Pid] = row;
                row.Update(s, elapsedMs, _cores, true);
                _rows.Add(row);
            }
            else
            {
                row.Update(s, elapsedMs, _cores, elapsedMs <= 0);
                if (string.IsNullOrEmpty(row.Path) && !string.IsNullOrEmpty(s.ImagePath))
                    row.Path = s.ImagePath;
            }
        }

        for (int i = _rows.Count - 1; i >= 0; i--)
        {
            var r = _rows[i];
            if (seen.Contains(r.Pid)) continue;
            _rows.RemoveAt(i);
            _map.Remove(r.Pid);
        }

        _lastSnap = snap;
    }

    private bool FilterRow(object obj)
    {
        string q = TxtSearch.Text.Trim();
        if (q.Length == 0) return true;
        if (obj is not ProcessRow r) return false;
        return r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
               || r.Pid.ToString().Contains(q)
               || r.Path.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    // ==================== 交互 ====================

    private void TxtSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        // 过滤会重排视图并清掉选中，过滤后若原来的进程仍在结果里就还原，避免右侧详情被清空
        _view.Refresh();
        if (_lastSelectedPid > 0 && _map.TryGetValue(_lastSelectedPid, out var row)
            && _view.Contains(row) && !ReferenceEquals(ProcessGrid.SelectedItem, row))
        {
            ProcessGrid.SelectedItem = row;
        }
    }

    private void BtnInterval_Click(object sender, RoutedEventArgs e)
    {
        _intervalIndex = (_intervalIndex + 1) % _intervals.Length;
        _timer.Interval = TimeSpan.FromSeconds(_intervals[_intervalIndex]);
        BtnInterval.Content = $"{_intervals[_intervalIndex]:0.0} s";
    }

    private void BtnPause_Click(object sender, RoutedEventArgs e)
    {
        _paused = !_paused;
        BtnPause.Content = _paused ? "继续" : "暂停";
        Log(_paused ? "实时采样已暂停" : "实时采样已恢复");
    }

    private void ChipPrivilege_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (Win32.IsElevated()) { Log("当前已是管理员权限。"); return; }
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return;
            Process.Start(new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.CurrentDirectory
            });
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            Log("提权失败（用户取消或被策略阻止）：" + ex.Message);
        }
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e)
    {
        _logs.Clear();
        LblLogCount.Text = "0 条";
    }

    private void BtnOpenFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(_exportDir);
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{_exportDir}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { Log("打开目录失败：" + ex.Message); }
    }

    private void ProcessGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (ProcessGrid.SelectedItem is not ProcessRow r || string.IsNullOrEmpty(r.Path)) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{r.Path}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { Log("定位文件失败：" + ex.Message); }
    }

    // ==================== 日志 ====================

    /// <summary>日志分级：只看语气词，不做猜测。失败/异常/拒绝 → 红，成功 → 绿。</summary>
    private static string Classify(string m)
    {
        if (m.Contains("失败") || m.Contains("异常") || m.Contains("拒绝") || m.Contains("错误") || m.StartsWith("×"))
            return "err";
        if (m.StartsWith("√") || m.Contains("已终止") || m.Contains("校验通过"))
            return "ok";
        return "";
    }

    private void ChkFreeze_Changed(object sender, RoutedEventArgs e)
    {
        // 就地勾选也记进设置，下次启动沿用
        AppSettings.FreezeOnDump = ChkFreeze.IsChecked == true;
        AppSettings.Save();
    }

    private void BtnSettings_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SettingsWindow { Owner = this };
        if (dlg.ShowDialog() != true) return;

        ApplySettings();
        UpdatePrivilegeChip(Win32.IsElevated());   // 芯片底色是本地值，换主题后要重新取色
        Log($"设置已保存 · 高级终止 {(AppSettings.AdvancedMode ? "已开启" : "关闭")} · 输出目录 {_exportDir}");
        if (AppSettings.AdvancedMode)
            Log("  提示：高级终止会准备直连系统调用，部分安全软件可能因此提高关注度");
    }

    private void BtnTheme_Click(object sender, RoutedEventArgs e)
    {
        ThemeManager.Apply(!ThemeManager.Dark);
        BtnTheme.Content = ThemeManager.Dark ? "浅色" : "深色";
        UpdatePrivilegeChip(Win32.IsElevated());   // 芯片底色是本地值，换主题后要重新取色
        Log(ThemeManager.Dark ? "已切换到深色主题" : "已切换到浅色主题");
    }

    internal void Log(string message)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(() => Log(message));
            return;
        }
        _logs.Add(new LogEntry(DateTime.Now.ToString("HH:mm:ss"), message, Classify(message)));
        while (_logs.Count > 500) _logs.RemoveAt(0);
        LblLogCount.Text = $"{_logs.Count} 条";
        LogScroll.ScrollToBottom();   // 只滚到底：ScrollToEnd 会顺带把水平偏移推满，导致时间列被裁
    }
}

/// <summary>一条日志：时间 / 正文 / 级别（err=失败, ok=成功, 空=普通）。</summary>
internal sealed class LogEntry
{
    public string Time { get; }
    public string Text { get; }
    public string Kind { get; }

    public LogEntry(string time, string text, string kind)
    {
        Time = time;
        Text = text;
        Kind = kind;
    }
}
