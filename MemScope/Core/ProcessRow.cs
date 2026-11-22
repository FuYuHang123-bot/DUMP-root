using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace MemScope.Core;

internal abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }
}

internal sealed class ProcessRow : ObservableObject
{
    public int Pid { get; init; }
    public int ParentPid { get; set; }
    public long CreateTime { get; set; }

    private string _name = "";
    public string Name { get => _name; set => Set(ref _name, value); }

    private string _path = "";
    public string Path { get => _path; set { if (Set(ref _path, value)) Raise(nameof(PathDisplay)); } }

    public string PathDisplay => string.IsNullOrEmpty(_path) ? "—" : _path;

    private double _cpu;
    public double Cpu { get => _cpu; set => Set(ref _cpu, value); }

    private double _workingSetMb;
    public double WorkingSetMb { get => _workingSetMb; set => Set(ref _workingSetMb, value); }

    private double _privateMb;
    public double PrivateMb { get => _privateMb; set => Set(ref _privateMb, value); }

    private double _virtualMb;
    public double VirtualMb { get => _virtualMb; set => Set(ref _virtualMb, value); }

    private uint _threads;
    public uint Threads { get => _threads; set => Set(ref _threads, value); }

    private uint _handles;
    public uint Handles { get => _handles; set => Set(ref _handles, value); }

    private int _sessionId;
    public int SessionId { get => _sessionId; set => Set(ref _sessionId, value); }

    private string _trend = "";
    public string Trend { get => _trend; set => Set(ref _trend, value); }

    // 内部：CPU 增量计算
    internal long LastKernel;
    internal long LastUser;

    public void Update(ProcSample s, double elapsedMs, int cpuCount, bool firstSample)
    {
        Name = s.Name;
        ParentPid = s.ParentPid;
        Threads = s.Threads;
        Handles = s.Handles;
        SessionId = (int)s.SessionId;

        double wsMb = s.WorkingSet / 1024.0 / 1024.0;
        double pvMb = s.PrivateBytes / 1024.0 / 1024.0;
        double virtMb = s.VirtualBytes / 1024.0 / 1024.0;

        if (!firstSample && elapsedMs > 1)
        {
            long delta = s.KernelTime + s.UserTime - LastKernel - LastUser;
            if (delta > 0)
            {
                double pct = delta / (elapsedMs * 10000.0) * 100.0 / cpuCount;
                Cpu = Math.Round(Math.Min(pct, 100.0 * cpuCount), 1);
            }
            else Cpu = 0;

            double diff = wsMb - WorkingSetMb;
            Trend = diff > 1 ? "▲" : diff < -1 ? "▼" : "";
        }

        WorkingSetMb = Math.Round(wsMb, 1);
        PrivateMb = Math.Round(pvMb, 1);
        VirtualMb = Math.Round(virtMb, 1);

        LastKernel = s.KernelTime;
        LastUser = s.UserTime;
    }

    public override string ToString() => $"{Name} ({Pid})";
}
