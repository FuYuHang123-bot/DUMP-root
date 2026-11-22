using System.IO;
using System.Reflection;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace MemScopeUiTest;

/// <summary>
/// 无窗口渲染验证：加载 App 资源 → 构造 MainWindow → 让实时采样跑一会儿 →
/// 把界面渲染成 PNG，用于人工核对视觉与数据链路（不创建可见窗口，避免干扰）。
/// </summary>
internal static class Program
{
    private const int W = 1360;
    private const int H = 860;

    [STAThread]
    private static int Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        string dir = AppContext.BaseDirectory;

        // 模拟真实 WPF 应用的 UI 线程同步上下文
        SynchronizationContext.SetSynchronizationContext(
            new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));

        var app = new MemScope.App();
        app.InitializeComponent();
        Say("App 资源加载成功");

        var win = new MemScope.MainWindow();
        Say("MainWindow 构造成功（XAML 解析 + StaticResource 全部命中）");

        if (win.Content is not Grid root)
        {
            Say("根元素不是 Grid：" + win.Content?.GetType().Name);
            return 2;
        }
        root.SetResourceReference(Panel.BackgroundProperty, "BgBrush");

        // 触发 Loaded 逻辑（启动采样与定时器）
        bool shown = false;
        try
        {
            // 显示在屏幕外：视觉树是真实布局（星号列不会塌），但不会挡住用户正在看的画面
            win.WindowStartupLocation = WindowStartupLocation.Manual;
            win.ShowInTaskbar = false;
            win.Left = -20000;
            win.Top = -20000;
            win.Width = W;
            win.Height = H;
            win.Show();
            shown = true;
            Pump(120);
            Say($"窗口已离屏显示：Left={win.Left:F0} Top={win.Top:F0} ActualClient={root.ActualWidth:F0}x{root.ActualHeight:F0}");
        }
        catch (Exception ex)
        {
            Say("显示窗口失败：" + ex.Message);
        }
        // 基准固定为浅色，避免上一次运行留下的主题影响截图
        MemScope.ThemeManager.Apply(false);
        Pump(200);
        Say("基准主题：" + (MemScope.ThemeManager.IsDarkNow() ? "深色" : "浅色"));

        win.RaiseEvent(new RoutedEventArgs(FrameworkElement.LoadedEvent, win));
        Pump(2500);
        Say("采样已运行 2.5s");

        var grid = (DataGrid?)Field(win, "ProcessGrid");
        int rowCount = (Field(win, "_rows") as System.Collections.ICollection)?.Count ?? -1;
        Say($"进程行数 = {rowCount}");
        Say("状态栏：" + ((TextBlock?)Field(win, "LblStatus"))?.Text);
        Say("进程计数：" + ((TextBlock?)Field(win, "LblProcCount"))?.Text);
        Say("权限标识：" + ((TextBlock?)Field(win, "LblPrivilege"))?.Text);
        Say("syscall：" + ((TextBlock?)Field(win, "LblHandleDiag"))?.Text);

        if (grid != null && grid.Items.Count > 0)
        {
            grid.SelectedIndex = 0;
            Pump(2200);
        }
        Say("选中：" + ((TextBlock?)Field(win, "LblProcTitle"))?.Text +
            " | PID=" + ((TextBlock?)Field(win, "LblStatPid"))?.Text +
            " 工作集=" + ((TextBlock?)Field(win, "LblStatWs"))?.Text +
            " 私有=" + ((TextBlock?)Field(win, "LblStatPriv"))?.Text +
            " 线程=" + ((TextBlock?)Field(win, "LblStatThreads"))?.Text +
            " 句柄=" + ((TextBlock?)Field(win, "LblStatHandles"))?.Text);
        Say("路径：" + ((TextBlock?)Field(win, "LblStatPath"))?.Text);
        Say("模块：" + ((TextBlock?)Field(win, "LblModuleInfo"))?.Text);
        Say("内存：" + ((TextBlock?)Field(win, "LblRegionInfo"))?.Text);
        Say("文件：" + ((TextBlock?)Field(win, "LblHandleInfo"))?.Text);

        // 模块二进制提取链路：选中一个模块 → 点“提取所选”
        var mgrid = (DataGrid?)Field(win, "ModuleGrid");
        if (mgrid != null && mgrid.Items.Count > 0)
        {
            var mods = mgrid.Items.Cast<object>().ToList();
            int idx = mods.FindIndex(m =>
                string.Equals(m.GetType().GetProperty("Name")?.GetValue(m) as string, "NSI.dll",
                    StringComparison.OrdinalIgnoreCase));
            if (idx < 0) idx = 0;
            mgrid.SelectedIndex = idx;
            Pump(200);
            Say($"选中模块 = {mods[idx].GetType().GetProperty("Name")?.GetValue(mods[idx])} " +
                $"基址 {mods[idx].GetType().GetProperty("BaseHex")?.GetValue(mods[idx])}");

            var btnDump = (Button?)Field(win, "BtnDumpModule");
            btnDump?.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
            Pump(8000);
            Say("提取后提示：" + ((TextBlock?)Field(win, "LblModuleInfo"))?.Text);
            Say("状态栏：" + ((TextBlock?)Field(win, "LblExportStatus"))?.Text);

            // 后台哈希补行：提取返回时 sha256 还没算完，等它把日志补上
            var logColl = Field(win, "_logs") as System.Collections.IEnumerable;
            bool hashLogged = false;
            for (int t = 0; t < 60 && !hashLogged; t++)
            {
                Pump(100);
                if (logColl == null) break;
                hashLogged = logColl.Cast<object>().Any(o =>
                {
                    string txt = o.GetType().GetProperty("Text")?.GetValue(o) as string ?? "";
                    return txt.StartsWith("    sha256 ") && txt.Length > 20;
                });
            }
            Say("后台哈希补行：" + (hashLogged ? "已补上" : "未出现"));
        }
        else Say("模块列表为空，跳过提取测试");

        // 内存区域转储链路（右键菜单等效调用）
        var rgrid = (DataGrid?)Field(win, "RegionGrid");
        if (rgrid != null && rgrid.Items.Count > 0)
        {
            rgrid.SelectedIndex = 0;
            Pump(200);
            var mi = typeof(MemScope.MainWindow).GetMethod("MenuDumpRegion_Click",
                BindingFlags.Instance | BindingFlags.NonPublic);
            mi?.Invoke(win, new object[] { win, new RoutedEventArgs() });
            Pump(2500);
            Say("区域转储提示：" + ((TextBlock?)Field(win, "LblRegionInfo"))?.Text);
            var rgItems = rgrid.Items.Cast<object>().ToList();
            foreach (var it in rgItems.Where(o => {
                var sz = o.GetType().GetProperty("Size")?.GetValue(o);
                return sz is ulong u && u > 1UL << 30; }).Take(4))
            {
                var t = it.GetType();
                Say($"  region| Size={t.GetProperty("Size")?.GetValue(it)} 显示={t.GetProperty("SizeDisplay")?.GetValue(it)} " +
                    $"保护={t.GetProperty("Protect")?.GetValue(it)} 状态={t.GetProperty("State")?.GetValue(it)}");
            }
        }
        else Say("内存区域列表为空，跳过区域转储测试");

        root.Measure(new Size(W, H));
        root.Arrange(new Rect(0, 0, W, H));
        root.UpdateLayout();

        if (grid != null)
        {
            Say($"ProcessGrid 实际尺寸 = {grid.ActualWidth:F0} x {grid.ActualHeight:F0}");
            Say("列宽: " + string.Join("  ", grid.Columns.Select(c => $"{c.Header}:{c.ActualWidth:F0}")));
            foreach (var c in grid.Columns.Take(2))
                Say($"  {c.Header}: Width={c.Width} DisplayValue={c.Width.DisplayValue} Unit={c.Width.UnitType} " +
                    $"Min={c.MinWidth} Max={c.MaxWidth}");
            var sv = FindChild<ScrollViewer>(grid);
            if (sv != null)
                Say($"ScrollViewer viewport={sv.ViewportWidth:F0} extent={sv.ExtentWidth:F0} vpHeight={sv.ViewportHeight:F0} extentH={sv.ExtentHeight:F0}");
            if (grid.ItemContainerGenerator.ContainerFromIndex(0) is DataGridRow r0)
            {
                var cell = FindChild<DataGridCell>(r0);
                Say($"首行 = {r0.ActualWidth:F0} x {r0.ActualHeight:F0}, 首个 cell 宽 = {cell?.ActualWidth:F0}");
                Say($"SelectedIndex={grid.SelectedIndex} IsSelected={r0.IsSelected} " +
                    $"RowBg={(r0.Background as SolidColorBrush)?.Color.ToString() ?? "null"} " +
                    $"cellBg={(cell?.Background as SolidColorBrush)?.Color.ToString() ?? "null"}");
            }
        }

        // 对照实验：脱离样式的裸 DataGrid，看列宽是否正常
        var probe = new DataGrid { AutoGenerateColumns = false, IsReadOnly = true };
        probe.Columns.Add(new DataGridTextColumn { Header = "A", Width = 120, Binding = new System.Windows.Data.Binding(".") });
        probe.Columns.Add(new DataGridTextColumn { Header = "B", Width = new DataGridLength(1, DataGridLengthUnitType.Star), Binding = new System.Windows.Data.Binding(".") });
        probe.ItemsSource = new[] { "x", "y" };
        var host = new Border { Width = 600, Height = 200, Child = probe };
        host.Measure(new Size(600, 200));
        host.Arrange(new Rect(0, 0, 600, 200));
        host.UpdateLayout();
        Say($"对照 DataGrid: 列宽 {probe.Columns[0].ActualWidth:F0} / {probe.Columns[1].ActualWidth:F0}");

        // 交互链路：搜索过滤 + 导出按钮 + 实时导出开关
        var txt = (TextBox?)Field(win, "TxtSearch");
        if (txt != null)
        {
            txt.Text = "explorer";
            Pump(400);
            Say($"搜索 'explorer' → 列表 {grid?.Items.Count} 行");
            txt.Text = "";
            Pump(400);
            Say($"清空搜索 → 列表 {grid?.Items.Count} 行, SelectedIndex={grid?.SelectedIndex}");
        }

        var btnExport = (Button?)Field(win, "BtnExport");
        btnExport?.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        Pump(1500);
        string expDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "MemScope_Export");
        if (Directory.Exists(expDir))
        {
            var files = new DirectoryInfo(expDir).GetFiles().OrderByDescending(f => f.LastWriteTime).Take(4).ToList();
            Say("导出目录文件：" + string.Join(", ", files.Select(f => $"{f.Name}({f.Length}B)")));
        }
        else Say("导出目录不存在！");

        Say($"导出后 SelectedIndex={grid?.SelectedIndex}");
        var tgl = (System.Windows.Controls.Primitives.ToggleButton?)Field(win, "TglAutoExport");
        if (tgl != null)
        {
            tgl.IsChecked = true;
            tgl.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
            Pump(6000);
            Say("实时导出状态：" + tgl.Content + " / 状态栏：" + ((TextBlock?)Field(win, "LblExportStatus"))?.Text);
            int autoFiles = Directory.Exists(expDir) ? Directory.GetFiles(expDir, "snapshot_auto_*.csv").Length : 0;
            Say("自动导出 CSV 数量 = " + autoFiles);
            tgl.IsChecked = false;
            tgl.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        }

        Say($"渲染前 SelectedIndex={grid?.SelectedIndex} 标题={((TextBlock?)Field(win, "LblProcTitle"))?.Text}");
        var tab = FindChild<TabControl>(root);        string[] names = { "ui_tab0.png", "ui_tab1.png", "ui_tab2.png" };
        for (int i = 0; i < names.Length; i++)
        {
            if (tab != null) { tab.SelectedIndex = i; Pump(700); }
            Render(root, Path.Combine(dir, names[i]));
            Say("已渲染 " + names[i]);
        }

        // 深色主题：点工具栏“主题”按钮后重渲染，验证 DynamicResource 热替换
        var btnTheme = (Button?)Field(win, "BtnTheme");
        btnTheme?.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        Pump(500);
        Say("主题按钮 = " + btnTheme?.Content + " / 资源 BgBrush = " +
            ((SolidColorBrush)app.Resources["BgBrush"]).Color.ToString());
        Say("窗口实际 Backdrop = " + (win.Background is SolidColorBrush wbg ? wbg.Color.ToString() : "n/a") +
            " / 根元素 = " + (root.Background is SolidColorBrush rbg ? rbg.Color.ToString() : "n/a"));
        var firstCard = FindChild<Border>(root);
        Say("首个 Border 底色 = " + (firstCard?.Background is SolidColorBrush cbg ? cbg.Color.ToString() : "n/a"));
        Say("正文色 = " + (win.Foreground is SolidColorBrush fg ? fg.Color.ToString() : "n/a"));
        if (Field(win, "_logs") is System.Collections.IEnumerable lg)
        {
            var tail = lg.Cast<object>().Select(o => o.GetType().GetProperty("Text")?.GetValue(o) as string).ToList();
            foreach (var t in tail.Where(t => t != null && t.Contains("[theme]"))) Say("  theme| " + t);
        }
        if (tab != null) { tab.SelectedIndex = 0; Pump(400); }
        Render(root, Path.Combine(dir, "ui_dark_tab0.png"));
        Say("已渲染 ui_dark_tab0.png");

        // 日志面板文本（看有没有异常）
        var logs = Field(win, "_logs") as System.Collections.IEnumerable;
        int n = 0;
        var all = new List<string>();
        if (logs != null)
            foreach (var l in logs)
            {
                string t = l?.GetType().GetProperty("Time")?.GetValue(l) as string ?? "";
                string x = l?.GetType().GetProperty("Text")?.GetValue(l) as string ?? "";
                all.Add(t + "  " + x);
                n++;
            }
        foreach (var l in all.Take(12)) Say("  log| " + l);
        foreach (var l in all.Where(x => x.Contains("提取") || x.Contains("sha256") || x.Contains("磁盘原文件") || x.Contains("差异") || x.Contains("PE 校验")))
            Say("  dump| " + l);
        Say($"日志条数 = {n}");

        // 提取产物落盘检查
        string dumpDir = Path.Combine(expDir, "modules");
        if (Directory.Exists(dumpDir))
        {
            var files = Directory.GetFiles(dumpDir, "*", SearchOption.AllDirectories)
                .Select(f => new FileInfo(f)).OrderByDescending(f => f.LastWriteTime).Take(6).ToList();
            Say("提取目录：" + string.Join(", ", files.Select(f => $"{f.Name}({f.Length}B)")));
        }
        else Say("提取目录不存在！");

        // ---- 设置窗口（独立面板）：离屏渲染两套主题 ----
        MemScope.ThemeManager.Apply(false);
        Pump(200);
        var sw = new MemScope.SettingsWindow
        {
            WindowStartupLocation = WindowStartupLocation.Manual,
            ShowInTaskbar = false,
            Left = -20000,
            Top = -20000
        };
        sw.Show();
        Pump(500);

        var sroot = (FrameworkElement)sw.Content;
        sroot.SetResourceReference(Panel.BackgroundProperty, "BgBrush");

        Say("设置窗口 高级终止=" + (Field(sw, "ChkAdvanced") as CheckBox)?.IsChecked +
            " 冻结=" + (Field(sw, "ChkFreeze") as CheckBox)?.IsChecked +
            " 深色=" + (Field(sw, "ChkDark") as CheckBox)?.IsChecked);
        Say("  系统调用行 = " + (Field(sw, "LblSyscallStatus") as TextBlock)?.Text);
        Say("  输出目录 = " + (Field(sw, "TxtOutputDir") as TextBox)?.Text);
        RenderAt(sroot, Path.Combine(dir, "ui_settings_light.png"));
        Say($"已渲染 ui_settings_light.png ({sroot.ActualWidth:F0}x{sroot.ActualHeight:F0})");

        if (Field(sw, "ChkDark") is CheckBox chkDark)
        {
            chkDark.IsChecked = true;
            Pump(450);
        }
        RenderAt(sroot, Path.Combine(dir, "ui_settings_dark.png"));
        Say("已渲染 ui_settings_dark.png");

        if (Field(sw, "ChkAdvanced") is CheckBox chkAdv)
        {
            chkAdv.IsChecked = true;
            Pump(350);
            Say("  开启后提示可见 = " + ((Field(sw, "WarningAdvanced") as FrameworkElement)?.Visibility));
            Say("  系统调用行 = " + (Field(sw, "LblSyscallStatus") as TextBlock)?.Text);
        }
        RenderAt(sroot, Path.Combine(dir, "ui_settings_dark_adv.png"));
        Say("已渲染 ui_settings_dark_adv.png");

        var ssv = FindChild<ScrollViewer>(sroot);
        Say($"  设置滚动区 视口={ssv?.ViewportHeight:F0} 内容={ssv?.ExtentHeight:F0} 滚动条={ssv?.ComputedVerticalScrollBarVisibility} " +
            $"关于文字高={(Field(sw, "LblAbout") as FrameworkElement)?.ActualHeight:F0}");

        sw.Close();
        Pump(200);

        win.Close();
        app.Shutdown();
        return 0;
    }

    private static void Say(string s)
    {
        Console.WriteLine(s);
        Console.Out.Flush();
    }

    private static object? Field(object o, string name) =>
        o.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public)?.GetValue(o);

    private static T? FindChild<T>(DependencyObject parent) where T : DependencyObject
    {
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T t) return t;
            var found = FindChild<T>(child);
            if (found != null) return found;
        }
        return null;
    }

    private static void Pump(int ms)
    {
        var frame = new DispatcherFrame();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(ms) };
        timer.Tick += (_, _) => { timer.Stop(); frame.Continue = false; };
        timer.Start();
        Dispatcher.PushFrame(frame);
    }

    /// <summary>按元素自身尺寸渲染（用于独立窗口，避免被主窗口的 1360x860 强排布带偏）。</summary>
    private static void RenderAt(FrameworkElement el, string path)
    {
        el.UpdateLayout();
        int w = Math.Max(1, (int)Math.Ceiling(el.ActualWidth));
        int h = Math.Max(1, (int)Math.Ceiling(el.ActualHeight));

        var rtb = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(el);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(path);
        encoder.Save(fs);
    }

    private static void Render(FrameworkElement el, string path)
    {
        el.Measure(new Size(W, H));
        el.Arrange(new Rect(0, 0, W, H));
        el.UpdateLayout();

        var rtb = new RenderTargetBitmap(W, H, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(el);

        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(rtb));
        using var fs = File.Create(path);
        encoder.Save(fs);
    }
}
