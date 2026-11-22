using System.Text.Json;
using System.Text.Json.Serialization;
using Nexsteaduser.CulvertProxy.Core.Configuration;

namespace Nexsteaduser.CulvertProxy.App.Services;

/// <summary>通过 JSON 深拷贝配置，避免界面编辑影响运行中的引擎。</summary>
public static class ConfigCloner
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static AppConfig Clone(AppConfig config)
    {
        var json = JsonSerializer.Serialize(config, Options);
        return JsonSerializer.Deserialize<AppConfig>(json, Options) ?? AppConfig.CreateDefault();
    }
}
