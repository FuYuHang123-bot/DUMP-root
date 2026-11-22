using System.IO;
using System.Text.Json;

namespace MemScope;

/// <summary>
/// 全局设置的唯一存放点：外观、高级终止开关、提取默认值。
///
/// 之所以集中到一处：这些值都落在 %LOCALAPPDATA%\MemScope\settings.json，
/// 若各模块各自序列化自己那一份，后写的会覆盖先写的（主题和高级模式会互相冲掉）。
/// </summary>
public static class AppSettings
{
    /// <summary>深色主题。</summary>
    public static bool Dark { get; set; }

    /// <summary>
    /// 高级终止模式：允许直连系统调用、远程线程、APC 投递。
    /// 默认关闭——关闭时全部走 Win32 / ntdll 标准调用，程序行为与普通进程浏览器一致。
    /// </summary>
    public static bool AdvancedMode { get; set; }

    /// <summary>
    /// 本次运行实际生效的值。平时等于 <see cref="AdvancedMode"/>，
    /// 命令行 --advanced 可以让它临时为 true 而不写入设置文件。
    /// 执行路径一律判断这个值，不再直接读 AdvancedMode，避免两处不一致。
    /// </summary>
    public static bool AdvancedActive { get; set; }

    /// <summary>提取模块时是否先冻结目标进程（拿到一致快照）。</summary>
    public static bool FreezeOnDump { get; set; }

    /// <summary>导出根目录；空表示用桌面上的 MemScope_Export。</summary>
    public static string OutputDir { get; set; } = "";

    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MemScope", "settings.json");

    private sealed class Model
    {
        public bool dark { get; set; }
        public bool advancedMode { get; set; }
        public bool freezeOnDump { get; set; }
        public string outputDir { get; set; } = "";
    }

    public static void Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return;
            var m = JsonSerializer.Deserialize<Model>(File.ReadAllText(FilePath));
            if (m == null) return;
            Dark = m.dark;
            AdvancedMode = m.advancedMode;
            FreezeOnDump = m.freezeOnDump;
            OutputDir = string.IsNullOrWhiteSpace(m.outputDir) ? "" : m.outputDir;
        }
        catch { /* 设置文件损坏就按默认值跑，不影响启动 */ }
    }

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(new Model
            {
                dark = Dark,
                advancedMode = AdvancedMode,
                freezeOnDump = FreezeOnDump,
                outputDir = OutputDir
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* 记不住设置不影响使用 */ }
    }

    public static void ResetToDefaults()
    {
        Dark = false;
        AdvancedMode = false;
        FreezeOnDump = false;
        OutputDir = "";
        Save();
    }
}
