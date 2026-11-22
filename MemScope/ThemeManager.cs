using System.Windows;

namespace MemScope;

/// <summary>
/// 主题切换：把所有颜色令牌从对应的字典逐键覆盖到常驻 holder 里。
/// 所有颜色都是 DynamicResource，逐键赋值会各自触发变更通知，界面立即重取色，控件树不重建。
/// 选择持久化在 AppSettings（与其它设置同一个文件）。
/// </summary>
public static class ThemeManager
{
    public static bool Dark
    {
        get => AppSettings.Dark;
        private set => AppSettings.Dark = value;
    }

    /// <summary>以资源里的实际颜色为准（静态字段只反映本进程最后一次调用）。</summary>
    public static bool IsDarkNow()
    {
        if (Application.Current?.Resources["BgBrush"] is System.Windows.Media.SolidColorBrush b)
            return b.Color.R < 128;
        return Dark;
    }

    /// <summary>
    /// 主题载体：一个常驻在 MergedDictionaries 里的空字典。
    /// 换主题时逐键覆盖它，而不是替换整个字典——替换字典在某些宿主下不会刷新已有的 DynamicResource。
    /// </summary>
    private static ResourceDictionary? _holder;

    public static void Apply(bool dark, bool persist = true)
    {
        var app = Application.Current;
        if (app == null) return;

        if (_holder != null && Dark == dark && _holder.Contains("BgBrush")) return;   // 已是该主题

        var uri = new Uri(dark ? "/MemScope;component/Assets/Theme.Dark.xaml"
                               : "/MemScope;component/Assets/Theme.Light.xaml", UriKind.Relative);
        var fresh = new ResourceDictionary { Source = uri };

        if (_holder == null || !app.Resources.MergedDictionaries.Contains(_holder))
        {
            _holder = new ResourceDictionary();
            app.Resources.MergedDictionaries.Add(_holder);
        }

        foreach (var key in fresh.Keys)
            _holder[key] = fresh[key];

        Dark = dark;
        if (persist) AppSettings.Save();
    }
}
