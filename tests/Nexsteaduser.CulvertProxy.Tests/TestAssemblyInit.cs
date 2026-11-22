using System.Runtime.CompilerServices;
using Nexsteaduser.CulvertProxy.Core.Interception;

namespace Nexsteaduser.CulvertProxy.Tests;

/// <summary>把测试期间的 Hook 配置重定向到临时目录，避免影响真实运行中的应用。</summary>
internal static class TestAssemblyInit
{
    internal static readonly string DirectoryPath = Path.Combine(
        Path.GetTempPath(),
        $"culvert-tests-{Environment.ProcessId}");

    internal static readonly string HookConfigPath = Path.Combine(DirectoryPath, "hook.conf");

    [ModuleInitializer]
    internal static void Initialize()
    {
        Directory.CreateDirectory(DirectoryPath);
        HookConfig.FilePathOverride = HookConfigPath;
    }
}
