namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>端口集合，支持 80、443、8000-9000 混合写法。</summary>
public sealed class PortSet
{
    private readonly List<(int Start, int End)> _ranges;

    private PortSet(List<(int Start, int End)> ranges)
    {
        _ranges = ranges;
    }

    public static bool TryCreate(IEnumerable<string> entries, out PortSet? set, out string? error)
    {
        set = null;
        error = null;
        var ranges = new List<(int, int)>();
        foreach (var entry in entries)
        {
            foreach (var part in entry.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var dash = part.IndexOf('-');
                if (dash < 0)
                {
                    if (!int.TryParse(part, out var port) || port is < 1 or > 65535)
                    {
                        error = $"端口无效：{part}";
                        return false;
                    }

                    ranges.Add((port, port));
                    continue;
                }

                if (!int.TryParse(part[..dash], out var start) || !int.TryParse(part[(dash + 1)..], out var end)
                    || start is < 1 or > 65535 || end is < 1 or > 65535 || start > end)
                {
                    error = $"端口范围无效：{part}";
                    return false;
                }

                ranges.Add((start, end));
            }
        }

        if (ranges.Count == 0)
        {
            error = "端口集合为空。";
            return false;
        }

        set = new PortSet(ranges);
        return true;
    }

    public bool Contains(int port)
    {
        foreach (var (start, end) in _ranges)
        {
            if (port >= start && port <= end)
            {
                return true;
            }
        }

        return false;
    }
}
