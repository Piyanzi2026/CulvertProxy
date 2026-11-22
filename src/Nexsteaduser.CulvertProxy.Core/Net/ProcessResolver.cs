using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>通过 TCP 连接表把本地入口连接归属到发起进程。</summary>
public sealed record ProcessIdentity(int Pid, string? Name, string? Path);

/// <summary>端口到进程的映射，带短周期快照以控制高并发下的系统调用开销。</summary>
public sealed class ProcessResolver
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 4;
    private static readonly TimeSpan SnapshotLifetime = TimeSpan.FromMilliseconds(300);
    private static readonly TimeSpan ProcessCacheLifetime = TimeSpan.FromMinutes(2);

    private readonly object _sync = new();
    private readonly ConcurrentDictionary<int, CachedProcess> _processCache = new();
    private Dictionary<int, int> _table = new();
    private DateTime _tableTimestamp = DateTime.MinValue;

    /// <summary>根据客户端端点与本地监听端点找到发起进程；失败返回 null。</summary>
    public ProcessIdentity? Resolve(IPEndPoint clientEndpoint, IPEndPoint serverEndpoint)
    {
        try
        {
            var pid = FindPid(clientEndpoint.Port, serverEndpoint.Port);
            return pid > 0 ? GetProcess(pid) : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>按 PID 直接查询进程信息；用于校验注入端上报的身份。</summary>
    public ProcessIdentity? Lookup(int pid)
    {
        if (pid <= 0)
        {
            return null;
        }

        try
        {
            return GetProcess(pid);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>清空进程名称缓存。</summary>
    public void ClearCache()
    {
        _processCache.Clear();
        lock (_sync)
        {
            _table = new Dictionary<int, int>();
            _tableTimestamp = DateTime.MinValue;
        }
    }

    private int FindPid(int localPort, int remotePort)
    {
        lock (_sync)
        {
            var now = DateTime.UtcNow;
            if (now - _tableTimestamp > SnapshotLifetime)
            {
                var fresh = BuildTable();
                if (fresh is not null)
                {
                    _table = fresh;
                }

                _tableTimestamp = now;
            }

            return _table.GetValueOrDefault(Key(localPort, remotePort));
        }
    }

    private ProcessIdentity GetProcess(int pid)
    {
        var now = DateTimeOffset.UtcNow;
        if (_processCache.TryGetValue(pid, out var cached) && cached.ExpiresAt > now)
        {
            return new ProcessIdentity(pid, cached.Name, cached.Path);
        }

        using var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle.IsInvalid)
        {
            return new ProcessIdentity(pid, null, null);
        }

        var buffer = new char[1024];
        var size = buffer.Length;
        string? path = null;
        if (QueryFullProcessImageName(handle, 0, buffer, ref size))
        {
            path = new string(buffer, 0, size);
        }

        var name = path is null ? null : Path.GetFileName(path);
        _processCache[pid] = new CachedProcess(name, path, now.Add(ProcessCacheLifetime));
        if (_processCache.Count > 2048)
        {
            foreach (var entry in _processCache.Where(kv => kv.Value.ExpiresAt <= now).Take(256))
            {
                _processCache.TryRemove(entry.Key, out _);
            }
        }

        return new ProcessIdentity(pid, name, path);
    }

    private static Dictionary<int, int>? BuildTable()
    {
        var result = new Dictionary<int, int>(256);
        try
        {
            ReadTable(AfInet, isV6: false, result);
        }
        catch
        {
            // IPv4 表失败仍可尝试 IPv6。
        }

        try
        {
            ReadTable(AfInet6, isV6: true, result);
        }
        catch
        {
            // IPv6 不可用时忽略。
        }

        return result;
    }

    private static void ReadTable(int addressFamily, bool isV6, Dictionary<int, int> output)
    {
        var size = 0;
        var first = GetExtendedTcpTable(IntPtr.Zero, ref size, false, addressFamily, TcpTableOwnerPidAll, 0);
        if (first != ErrorInsufficientBuffer || size == 0)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = GetExtendedTcpTable(buffer, ref size, false, addressFamily, TcpTableOwnerPidAll, 0);
            if (status != 0)
            {
                return;
            }

            var count = Marshal.ReadInt32(buffer);
            var rowSize = isV6 ? 56 : 24;
            var ptr = IntPtr.Add(buffer, 4);
            for (var i = 0; i < count; i++)
            {
                var row = IntPtr.Add(ptr, i * rowSize);
                int localPort;
                int remotePort;
                int pid;
                if (isV6)
                {
                    localPort = NetOrderPort((uint)Marshal.ReadInt32(row, 20));
                    remotePort = NetOrderPort((uint)Marshal.ReadInt32(row, 44));
                    pid = Marshal.ReadInt32(row, 52);
                }
                else
                {
                    localPort = NetOrderPort((uint)Marshal.ReadInt32(row, 8));
                    remotePort = NetOrderPort((uint)Marshal.ReadInt32(row, 16));
                    pid = Marshal.ReadInt32(row, 20);
                }

                if (localPort > 0 && remotePort > 0 && pid > 0)
                {
                    output[Key(localPort, remotePort)] = pid;
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int Key(int localPort, int remotePort) => (localPort << 16) | (remotePort & 0xFFFF);

    private static int NetOrderPort(uint value) =>
        (ushort)IPAddress.NetworkToHostOrder((short)(value & 0xFFFF));

    private const int ErrorInsufficientBuffer = 122;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private sealed record CachedProcess(string? Name, string? Path, DateTimeOffset ExpiresAt);

    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(
            IntPtr table,
            ref int size,
            [MarshalAs(UnmanagedType.Bool)] bool sort,
            int addressFamily,
            int tableClass,
            uint reserved);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint access,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            int flags,
            [Out] char[] exeName,
            ref int size);
    }

    private static uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved)
        => NativeMethods.GetExtendedTcpTable(table, ref size, sort, family, tableClass, reserved);

    private static SafeProcessHandle OpenProcess(uint access, bool inherit, int pid)
        => NativeMethods.OpenProcess(access, inherit, pid);

    private static bool QueryFullProcessImageName(SafeProcessHandle handle, int flags, char[] buffer, ref int size)
        => NativeMethods.QueryFullProcessImageName(handle, flags, buffer, ref size);
}
