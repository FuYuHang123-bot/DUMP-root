using System.Windows;
using System.Windows.Threading;

namespace MemScope;

/// <summary>
/// 自定义入口：把启动期异常（XAML 资源解析、P/Invoke 初始化等）落盘，
/// 避免 WinExe 静默退出时完全查不到原因。
/// </summary>
internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        try
        {
            var app = new App();
            app.InitializeComponent();
            app.DispatcherUnhandledException += OnDispatcherException;
            AppDomain.CurrentDomain.UnhandledException += (_, e) => Dump(e.ExceptionObject as Exception);
            app.Run();
            return 0;
        }
        catch (Exception ex)
        {
            Dump(ex);
            if (args.Any(a => a.Equals("--probe", StringComparison.OrdinalIgnoreCase)))
            {
                // 探针模式下把崩溃信息也写进 probe.json 旁边
                try
                {
                    int i = Array.FindIndex(args, a => a.Equals("--out", StringComparison.OrdinalIgnoreCase));
                    string outPath = i >= 0 && i + 1 < args.Length ? args[i + 1] : "probe.json";
                    File.WriteAllText(outPath + ".crash.txt", ex.ToString());
                }
                catch { }
            }
            return 1;
        }
    }

    private static void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Dump(e.Exception);
        e.Handled = true;
        MessageBox.Show("发生未处理异常，已记录到 memscope_error.log：\n" + e.Exception.Message,
            "MemScope", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static void Dump(Exception? ex)
    {
        if (ex == null) return;
        try
        {
            string path = Path.Combine(AppContext.BaseDirectory, "memscope_error.log");
            File.AppendAllText(path, $"==== {DateTime.Now:yyyy-MM-dd HH:mm:ss} ====\n{ex}\n\n");
        }
        catch { }
    }
}
