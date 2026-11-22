using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Nexsteaduser.CulvertProxy.Core.Diagnostics;

namespace Nexsteaduser.CulvertProxy.Core.Interception;

/// <summary>把 CulvertHook.dll 注入当前会话的 64 位用户进程，并持续接管新进程。</summary>
internal sealed class ProcessInjector : IAsyncDisposable
{
    private const uint ProcessCreateThread = 0x0002;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessVmRead = 0x0010;
    private const uint MemCommit = 0x1000;
    private const uint MemReserve = 0x2000;
    private const uint MemRelease = 0x8000;
    private const uint PageReadWrite = 0x04;
    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 0x102;
    private const ushort ImageFileMachineUnknown = 0;

    private static readonly HashSet<string> BuiltInExclusions = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
        "WUDFHost.exe", "MemCompression", "SecurityHealthService.exe", "SecurityHealthSystray.exe",
        "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe", "SgrmBroker.exe", "SppExtComObj.exe",
        "WmiPrvSE.exe", "dllhost.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe",
        "StartMenuExperienceHost.exe", "TextInputHost.exe", "ApplicationFrameHost.exe",
        "LockApp.exe", "LogonUI.exe", "taskhostw.exe", "ctfmon.exe", "audiodg.exe",
        "conhost.exe", "OpenConsole.exe", "explorer.exe", "SearchHost.exe", "SearchIndexer.exe",
        "devenv.exe", "MSBuild.exe", "VBCSCompiler.exe", "dotnet.exe", "testhost.exe",
        "vstest.console.exe", "git.exe", "cl.exe", "link.exe", "culvert.exe",
        "WerFault.exe", "GameBar.exe", "Widgets.exe", "backgroundTaskHost.exe",
        "TrustedInstaller.exe", "TiWorker.exe", "MoUsoCoreWorker.exe", "smartscreen.exe",
        "SecurityHealthHost.exe", "WsaClient.exe", "WsaService.exe",
        "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe", "avp.exe", "avastui.exe", "AvastSvc.exe",
        "avgnt.exe", "ccSvcHst.exe", "ekrn.exe", "egui.exe", "mcshield.exe", "mfemms.exe",
        "CSFalconService.exe", "CSFalconContainer.exe", "SentinelAgent.exe", "CylanceSvc.exe",
        "bdservicehost.exe", "vsserv.exe", "SavService.exe", "SEDservice.exe",
        "BEService.exe", "BEService_x64.exe", "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe",
        "FaceitAC.exe", "vgc.exe", "vgtray.exe",
    };

    private readonly LogHub _log;
    private readonly string _hookPath;
    private readonly int _sessionId;
    private readonly bool _elevated;
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private readonly ConcurrentDictionary<int, InjectedProcess> _injected = new();
    private readonly ConcurrentDictionary<int, FailedProcess> _failed = new();
    private readonly CancellationTokenSource _cts = new();
    private volatile string[] _userExcludes = [];
    private volatile bool _autoInject = true;
    private Task? _loop;
    private long _scanCount;
    private string? _lastError;

    public ProcessInjector(LogHub log, string hookPath)
    {
        _log = log;
        _hookPath = hookPath;
        using var current = Process.GetCurrentProcess();
        _sessionId = current.SessionId;
        _elevated = CheckElevated();
    }

    public bool IsElevated => _elevated;

    public int InjectedCount => _injected.Count;

    public int FailedCount => _failed.Count;

    public string? LastError => _lastError;

    public IReadOnlyList<InjectedProcessInfo> InjectedProcesses => _injected.Values
        .OrderBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase)
        .Select(item => new InjectedProcessInfo(item.ProcessId, item.Name, item.Path, item.InjectedAt))
        .ToArray();

    /// <summary>启动后台扫描；首次扫描可立即接管已在运行的进程。</summary>
    public void Start(bool injectExisting, bool autoInject, IReadOnlyList<string> excludes)
    {
        _autoInject = autoInject;
        _userExcludes = excludes.ToArray();
        _loop = Task.Run(() => LoopAsync(injectExisting, _cts.Token));
    }

    /// <summary>热更新排除列表与自动接管开关。</summary>
    public void UpdateOptions(bool autoInject, IReadOnlyList<string> excludes)
    {
        _autoInject = autoInject;
        _userExcludes = excludes.ToArray();
    }

    /// <summary>立即扫描一次；用于界面上的“接管当前进程”。</summary>
    public async Task<InjectionReport> InjectNowAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await ScanAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return InjectionReport.Empty;
        }
    }

    /// <summary>向指定 PID 注入；供启动器与端到端诊断使用。</summary>
    public async Task<InjectionReport> InjectProcessAsync(int processId)
    {
        await _scanLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_injected.ContainsKey(processId))
            {
                return new InjectionReport(1, 0, 1, 0, 0, null);
            }

            using var process = Process.GetProcessById(processId);
            var name = process.ProcessName + ".exe";
            if (processId == Environment.ProcessId
                || process.SessionId != _sessionId
                || IsBuiltInExcluded(name)
                || IsUserExcluded(name, null, _userExcludes))
            {
                return new InjectionReport(1, 0, 0, 1, 0, "进程被排除或不属于当前会话。");
            }

            var startTime = process.StartTime;
            return TryInject(processId, name, startTime, _userExcludes) switch
            {
                InjectionOutcome.Success => new InjectionReport(1, 1, 0, 0, 0, null),
                InjectionOutcome.AlreadyLoaded => new InjectionReport(1, 0, 1, 0, 0, null),
                InjectionOutcome.Skipped => new InjectionReport(1, 0, 0, 1, 0, _lastError),
                _ => new InjectionReport(1, 0, 0, 0, 1, _lastError),
            };
        }
        catch (Exception ex)
        {
            return new InjectionReport(1, 0, 0, 0, 1, ex.Message);
        }
        finally
        {
            _scanLock.Release();
        }
    }

    private async Task LoopAsync(bool injectExisting, CancellationToken cancellationToken)
    {
        var first = injectExisting;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (first || _autoInject)
                {
                    first = false;
                    await ScanAsync(cancellationToken).ConfigureAwait(false);
                }

                await Task.Delay(_autoInject ? 1200 : 500, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                _log.Warn("Intercept", $"进程扫描失败：{ex.Message}");
                try
                {
                    await Task.Delay(2000, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }
    }

    private async Task<InjectionReport> ScanAsync(CancellationToken cancellationToken)
    {
        await _scanLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var scanned = 0;
            var injected = 0;
            var already = 0;
            var skipped = 0;
            var failed = 0;
            var now = DateTimeOffset.UtcNow;
            var excludes = _userExcludes;

            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (process.Id <= 4 || process.Id == Environment.ProcessId)
                    {
                        continue;
                    }

                    scanned++;
                    string name;
                    int session;
                    try
                    {
                        name = process.ProcessName + ".exe";
                        session = process.SessionId;
                    }
                    catch
                    {
                        skipped++;
                        continue;
                    }

                    if (session != _sessionId || IsBuiltInExcluded(name) || IsUserExcluded(name, null, excludes))
                    {
                        skipped++;
                        continue;
                    }

                    if (_injected.ContainsKey(process.Id))
                    {
                        already++;
                        continue;
                    }

                    if (_failed.TryGetValue(process.Id, out var failure))
                    {
                        if (failure.Until > now)
                        {
                            skipped++;
                            continue;
                        }

                        _failed.TryRemove(process.Id, out _);
                    }

                    DateTime startTime;
                    try
                    {
                        startTime = process.StartTime;
                    }
                    catch
                    {
                        startTime = DateTime.MinValue;
                    }

                    switch (TryInject(process.Id, name, startTime, excludes))
                    {
                        case InjectionOutcome.Success:
                            injected++;
                            _log.Debug("Intercept", $"已注入 {name} (PID {process.Id})。");
                            break;
                        case InjectionOutcome.AlreadyLoaded:
                            already++;
                            break;
                        case InjectionOutcome.Skipped:
                            skipped++;
                            break;
                        default:
                            failed++;
                            _failed[process.Id] = new FailedProcess(now.AddSeconds(30), _lastError);
                            break;
                    }
                }
            }

            Interlocked.Increment(ref _scanCount);
            CleanupStale(now);
            if (injected > 0)
            {
                _log.Info("Intercept", $"本轮已接管 {injected} 个进程，当前共 {_injected.Count} 个。");
            }

            return new InjectionReport(scanned, injected, already, skipped, failed, _lastError);
        }
        finally
        {
            _scanLock.Release();
        }
    }

    private InjectionOutcome TryInject(int processId, string name, DateTime startTime, IReadOnlyList<string> excludes)
    {
        using var handle = OpenProcess(
            ProcessCreateThread | ProcessQueryInformation | ProcessQueryLimitedInformation
            | ProcessVmOperation | ProcessVmWrite | ProcessVmRead,
            false,
            processId);
        if (handle.IsInvalid)
        {
            _lastError = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message;
            return InjectionOutcome.Skipped;
        }

        var path = QueryImagePath(handle);
        if (path is not null && IsUserExcluded(name, path, excludes))
        {
            return InjectionOutcome.Skipped;
        }

        if (Is32Bit(handle))
        {
            return InjectionOutcome.Skipped;
        }

        var modulePath = _hookPath;
        var moduleBytes = Encoding.Unicode.GetBytes(modulePath + "\0");
        var remote = VirtualAllocEx(handle, IntPtr.Zero, (nuint)moduleBytes.Length, MemCommit | MemReserve, PageReadWrite);
        if (remote == IntPtr.Zero)
        {
            _lastError = "VirtualAllocEx 失败。";
            return InjectionOutcome.Failed;
        }

        var safeToFree = true;
        try
        {
            if (!WriteProcessMemory(handle, remote, moduleBytes, (nuint)moduleBytes.Length, out _))
            {
                _lastError = "写入远程进程内存失败。";
                return InjectionOutcome.Failed;
            }

            var loadLibrary = GetProcAddress(GetModuleHandleW("kernel32.dll"), "LoadLibraryW");
            if (loadLibrary == IntPtr.Zero)
            {
                _lastError = "找不到 LoadLibraryW。";
                return InjectionOutcome.Failed;
            }

            using var thread = CreateRemoteThread(handle, IntPtr.Zero, 0, loadLibrary, remote, 0, out _);
            if (thread.IsInvalid)
            {
                _lastError = "创建远程线程失败。";
                return InjectionOutcome.Failed;
            }

            var wait = WaitForSingleObject(thread, 5000);
            if (wait == WaitTimeout)
            {
                // 远程线程仍可能读取该路径，宁可不释放也不要制造悬空指针。
                safeToFree = false;
                _lastError = "远程 LoadLibrary 超时。";
                return InjectionOutcome.Failed;
            }

            if (!GetExitCodeThread(thread, out var exitCode) || exitCode == 0)
            {
                _lastError = "远程 LoadLibrary 返回 0。";
                return InjectionOutcome.Failed;
            }

            // 新编译或被安全软件扫描的 DLL 首次加载可能明显变慢，等待窗口放宽到 2 秒。
            if (!WaitForHookReady(processId, TimeSpan.FromSeconds(2), out var readyError))
            {
                _log.Debug("Intercept", $"{name} 已加载 Hook，但未在 2 秒内收到就绪事件：{readyError ?? "未创建"}。");
            }

            _injected[processId] = new InjectedProcess(processId, name, path, startTime, DateTimeOffset.Now);
            _lastError = null;
            return InjectionOutcome.Success;
        }
        finally
        {
            if (safeToFree)
            {
                VirtualFreeEx(handle, remote, 0, MemRelease);
            }
        }
    }

    private static bool WaitForHookReady(int processId, TimeSpan timeout, out string? error)
    {
        var eventName = $@"Local\Nexsteaduser.CulvertProxy.HookReady.{processId}";
        var deadline = DateTime.UtcNow + timeout;
        error = null;
        while (DateTime.UtcNow < deadline)
        {
            using var ready = OpenEventW(0x00100000 /* SYNCHRONIZE */, false, eventName);
            if (!ready.IsInvalid)
            {
                if (WaitForSingleObject(ready, 0) == WaitObject0)
                {
                    return true;
                }

                error = "事件未置位";
            }
            else
            {
                var code = Marshal.GetLastWin32Error();
                error = $"OpenEvent {code}";
            }

            Thread.Sleep(20);
        }

        return false;
    }

    private void CleanupStale(DateTimeOffset now)
    {
        foreach (var entry in _failed.ToArray())
        {
            if (entry.Value.Until <= now)
            {
                _failed.TryRemove(entry.Key, out _);
            }
        }

        // 每十轮核对一次 PID 是否仍然存在，PID 复用时重新注入。
        if (Interlocked.Read(ref _scanCount) % 10 != 0)
        {
            return;
        }

        foreach (var entry in _injected.ToArray())
        {
            try
            {
                using var process = Process.GetProcessById(entry.Key);
                if (process.StartTime != entry.Value.StartTime)
                {
                    _injected.TryRemove(entry.Key, out _);
                }
            }
            catch
            {
                _injected.TryRemove(entry.Key, out _);
            }
        }
    }

    private static string? QueryImagePath(SafeProcessHandle process)
    {
        try
        {
            var buffer = new char[1024];
            var size = buffer.Length;
            return QueryFullProcessImageName(process, 0, buffer, ref size)
                ? new string(buffer, 0, size)
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool IsBuiltInExcluded(string name)
    {
        if (BuiltInExclusions.Contains(name))
        {
            return true;
        }

        return name.Equals("CulvertProxy.exe", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Nexsteaduser.CulvertProxy.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUserExcluded(string name, string? path, IReadOnlyList<string> excludes)
    {
        foreach (var pattern in excludes)
        {
            if (pattern.Length == 0)
            {
                continue;
            }

            if (pattern.Contains('\\') || pattern.Contains('/'))
            {
                if (path is not null && MatchWildcard(pattern, path))
                {
                    return true;
                }
            }
            else if (MatchWildcard(pattern, name))
            {
                return true;
            }
        }

        return false;
    }

    private static bool MatchWildcard(string pattern, string text)
    {
        var patternIndex = 0;
        var textIndex = 0;
        var starIndex = -1;
        var matchIndex = 0;
        while (textIndex < text.Length)
        {
            if (patternIndex < pattern.Length
                && (pattern[patternIndex] == '?' || char.ToLowerInvariant(pattern[patternIndex]) == char.ToLowerInvariant(text[textIndex])))
            {
                patternIndex++;
                textIndex++;
            }
            else if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            {
                starIndex = patternIndex++;
                matchIndex = textIndex;
            }
            else if (starIndex >= 0)
            {
                patternIndex = starIndex + 1;
                textIndex = ++matchIndex;
            }
            else
            {
                return false;
            }
        }

        while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
        {
            patternIndex++;
        }

        return patternIndex == pattern.Length;
    }

    private static bool CheckElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static bool Is32Bit(SafeProcessHandle process)
    {
        try
        {
            if (IsWow64Process2(process.DangerousGetHandle(), out var processMachine, out _))
            {
                return processMachine != ImageFileMachineUnknown;
            }
        }
        catch
        {
            // 旧系统回退到 IsWow64Process。
        }

        try
        {
            return IsWow64Process(process.DangerousGetHandle(), out var wow64) && wow64;
        }
        catch
        {
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        var stopped = true;
        if (_loop is not null)
        {
            try
            {
                await _loop.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            }
            catch
            {
                stopped = false;
            }
        }

        // 扫描卡在系统调用上时不要释放它仍在使用的同步对象，交给进程退出回收。
        if (stopped)
        {
            _cts.Dispose();
            _scanLock.Dispose();
        }
    }

    private enum InjectionOutcome
    {
        Success,
        AlreadyLoaded,
        Skipped,
        Failed,
    }

    private sealed record InjectedProcess(
        int ProcessId,
        string Name,
        string? Path,
        DateTime StartTime,
        DateTimeOffset InjectedAt);

    private sealed record FailedProcess(DateTimeOffset Until, string? Error);

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint access,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr VirtualAllocEx(
            SafeProcessHandle process,
            IntPtr address,
            nuint size,
            uint allocationType,
            uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool VirtualFreeEx(
            SafeProcessHandle process,
            IntPtr address,
            nuint size,
            uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool WriteProcessMemory(
            SafeProcessHandle process,
            IntPtr address,
            byte[] buffer,
            nuint size,
            out nuint written);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern SafeWaitHandle CreateRemoteThread(
            SafeProcessHandle process,
            IntPtr attributes,
            nuint stackSize,
            IntPtr startAddress,
            IntPtr parameter,
            uint creationFlags,
            out uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint WaitForSingleObject(SafeWaitHandle handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetExitCodeThread(SafeWaitHandle thread, out uint exitCode);

        [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr GetModuleHandleW(string? moduleName);

        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress", SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", EntryPoint = "OpenEventW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafeWaitHandle OpenEventW(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process(IntPtr process, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryFullProcessImageName(
            SafeProcessHandle process,
            uint flags,
            [Out] char[] name,
            ref int size);
    }

    private static SafeProcessHandle OpenProcess(uint access, bool inherit, int processId)
        => NativeMethods.OpenProcess(access, inherit, processId);

    private static IntPtr VirtualAllocEx(SafeProcessHandle process, IntPtr address, nuint size, uint allocationType, uint protect)
        => NativeMethods.VirtualAllocEx(process, address, size, allocationType, protect);

    private static bool VirtualFreeEx(SafeProcessHandle process, IntPtr address, nuint size, uint freeType)
        => NativeMethods.VirtualFreeEx(process, address, size, freeType);

    private static bool WriteProcessMemory(SafeProcessHandle process, IntPtr address, byte[] buffer, nuint size, out nuint written)
        => NativeMethods.WriteProcessMemory(process, address, buffer, size, out written);

    private static SafeWaitHandle CreateRemoteThread(SafeProcessHandle process, IntPtr attributes, nuint stackSize, IntPtr startAddress, IntPtr parameter, uint creationFlags, out uint threadId)
        => NativeMethods.CreateRemoteThread(process, attributes, stackSize, startAddress, parameter, creationFlags, out threadId);

    private static uint WaitForSingleObject(SafeWaitHandle handle, uint milliseconds)
        => NativeMethods.WaitForSingleObject(handle, milliseconds);

    private static bool GetExitCodeThread(SafeWaitHandle thread, out uint exitCode)
        => NativeMethods.GetExitCodeThread(thread, out exitCode);

    private static IntPtr GetModuleHandleW(string? moduleName)
        => NativeMethods.GetModuleHandleW(moduleName);

    private static IntPtr GetProcAddress(IntPtr module, string procName)
        => NativeMethods.GetProcAddress(module, procName);

    private static SafeWaitHandle OpenEventW(uint desiredAccess, bool inherit, string name)
        => NativeMethods.OpenEventW(desiredAccess, inherit, name);

    private static bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine)
        => NativeMethods.IsWow64Process2(process, out processMachine, out nativeMachine);

    private static bool IsWow64Process(IntPtr process, out bool wow64Process)
        => NativeMethods.IsWow64Process(process, out wow64Process);

    private static bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, char[] name, ref int size)
        => NativeMethods.QueryFullProcessImageName(process, flags, name, ref size);
}
