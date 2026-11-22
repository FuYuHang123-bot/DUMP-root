using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Media;
using MemScope.Interop;

namespace MemScope;

/// <summary>
/// 独立设置面板。核心是「高级终止」开关：
/// 默认关闭时程序只使用标准 Windows 调用，行为与常规进程浏览器一致；
/// 开启后才准备直连系统调用与注入路径，并在界面上明确提示代价。
/// </summary>
public partial class SettingsWindow : Window
{
    private readonly bool _origDark;
    private bool _saved;

    public SettingsWindow()
    {
        InitializeComponent();
        _origDark = ThemeManager.Dark;

        ChkAdvanced.IsChecked = AppSettings.AdvancedMode;
        ChkFreeze.IsChecked = AppSettings.FreezeOnDump;
        ChkDark.IsChecked = AppSettings.Dark;
        TxtOutputDir.Text = string.IsNullOrWhiteSpace(AppSettings.OutputDir)
            ? Core.SnapshotExporter.DefaultDirectory
            : AppSettings.OutputDir;

        var ver = typeof(SettingsWindow).Assembly.GetName().Version;
        LblAbout.Text = $"MemScope {ver?.ToString(3) ?? "1.0.0"} · 进程内存与文件句柄实时观测、模块二进制提取\n" +
                        "默认以标准系统调用运行；提取产物与其 sha256 一并写入导出目录。";
        LblSettingsPath.Text = "设置文件：" + AppSettings.FilePath;

        UpdateAdvancedStatus();
    }

    private void UpdateAdvancedStatus()
    {
        bool on = ChkAdvanced.IsChecked == true;

        WarningAdvanced.Visibility = on ? Visibility.Visible : Visibility.Collapsed;

        if (on && !Syscall.Ready) Syscall.Initialize();

        LblSyscallStatus.Text = on
            ? "系统调用层：" + Syscall.StatusMessage
            : "系统调用层：未加载（标准模式下不会解析系统调用号，也不会申请可执行内存）";

        if (TryFindResource(on && Syscall.Ready ? "OkBrush" : "TextFaintBrush") is Brush b)
            LblSyscallStatus.Foreground = b;
    }

    private void ChkAdvanced_Changed(object sender, RoutedEventArgs e) => UpdateAdvancedStatus();

    private void ChkDark_Changed(object sender, RoutedEventArgs e)
    {
        // 即时预览；取消时在 OnClosing 里还原
        ThemeManager.Apply(ChkDark.IsChecked == true, persist: false);
    }

    private void BtnBrowse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "选择导出目录", Multiselect = false };
        try
        {
            string cur = TxtOutputDir.Text?.Trim() ?? "";
            if (Directory.Exists(cur)) dlg.InitialDirectory = cur;
        }
        catch { }

        if (dlg.ShowDialog(this) == true && !string.IsNullOrWhiteSpace(dlg.FolderName))
            TxtOutputDir.Text = dlg.FolderName;
    }

    private void BtnReset_Click(object sender, RoutedEventArgs e)
    {
        ChkAdvanced.IsChecked = false;
        ChkFreeze.IsChecked = false;
        ChkDark.IsChecked = false;
        TxtOutputDir.Text = Core.SnapshotExporter.DefaultDirectory;
        UpdateAdvancedStatus();
    }

    private void BtnSave_Click(object sender, RoutedEventArgs e)
    {
        bool advanced = ChkAdvanced.IsChecked == true;

        AppSettings.AdvancedMode = advanced;
        AppSettings.AdvancedActive = advanced;   // 本次运行立即生效，无需重启
        AppSettings.FreezeOnDump = ChkFreeze.IsChecked == true;
        AppSettings.Dark = ChkDark.IsChecked == true;

        string dir = TxtOutputDir.Text?.Trim() ?? "";
        // 与默认值相同就存空，这样以后换机器仍然落到各自的桌面目录
        AppSettings.OutputDir = string.IsNullOrEmpty(dir) ||
                                dir.Equals(Core.SnapshotExporter.DefaultDirectory, StringComparison.OrdinalIgnoreCase)
            ? ""
            : dir;

        // 保存时才开始准备（或彻底不准备）系统调用层
        if (advanced && !Syscall.Ready)
        {
            Syscall.Initialize();
            if (!Syscall.Ready)
            {
                MessageBox.Show(this,
                    "高级终止已保存，但系统调用层准备失败：\n\n" + Syscall.StatusMessage +
                    "\n\n程序仍可正常使用，终止时只会走标准路径。",
                    "高级终止", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        else if (!advanced && Syscall.Ready)
        {
            Syscall.Disable("高级终止已关闭（重新开启需重启程序）");
        }

        _saved = true;
        AppSettings.Save();
        DialogResult = true;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // 取消 / 直接关窗：还原主题预览。用字段而不是读 DialogResult，
        // 这样以 Show() 方式打开（自动化渲染测试）时也不会抛异常。
        if (!_saved) ThemeManager.Apply(_origDark, persist: false);
        base.OnClosing(e);
    }
}
