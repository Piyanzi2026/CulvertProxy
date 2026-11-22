using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Nexsteaduser.CulvertProxy.Core.Routing;

/// <summary>域名模式：精确、通配、后缀与正则四种形态。</summary>
public sealed class HostPattern
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(80);
    private readonly PatternKind _kind;
    private readonly string _value;
    private readonly Regex? _regex;

    private HostPattern(string source, PatternKind kind, string value, Regex? regex = null)
    {
        Source = source;
        _kind = kind;
        _value = value;
        _regex = regex;
    }

    public string Source { get; }

    public static bool TryCreate(string source, out HostPattern? pattern, out string? error)
    {
        pattern = null;
        error = null;
        if (string.IsNullOrWhiteSpace(source))
        {
            error = "域名模式为空。";
            return false;
        }

        var text = source.Trim();
        if (text == "*")
        {
            pattern = new HostPattern(source, PatternKind.Any, string.Empty);
            return true;
        }

        if (text.StartsWith("re:", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var regex = new Regex(text[3..], RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
                pattern = new HostPattern(source, PatternKind.Regex, text[3..], regex);
                return true;
            }
            catch (ArgumentException ex)
            {
                error = $"正则无效：{ex.Message}";
                return false;
            }
        }

        if (text.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = Normalize(text[2..]);
            if (suffix.Length == 0)
            {
                error = "通配域名缺少主体。";
                return false;
            }

            pattern = new HostPattern(source, PatternKind.SubdomainOnly, suffix);
            return true;
        }

        if (text.StartsWith('.'))
        {
            var suffix = Normalize(text[1..]);
            if (suffix.Length == 0)
            {
                error = "后缀域名缺少主体。";
                return false;
            }

            pattern = new HostPattern(source, PatternKind.Suffix, suffix);
            return true;
        }

        if (text.Contains('*') || text.Contains('?'))
        {
            var regex = new Regex(GlobToRegex(Normalize(text)), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
            pattern = new HostPattern(source, PatternKind.Regex, text, regex);
            return true;
        }

        pattern = new HostPattern(source, PatternKind.Exact, Normalize(text));
        return true;
    }

    public bool IsMatch(string host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return false;
        }

        var normalized = Normalize(host);
        return _kind switch
        {
            PatternKind.Any => true,
            PatternKind.Exact => normalized.Equals(_value, StringComparison.OrdinalIgnoreCase),
            PatternKind.SubdomainOnly => normalized.EndsWith("." + _value, StringComparison.OrdinalIgnoreCase),
            PatternKind.Suffix => normalized.Equals(_value, StringComparison.OrdinalIgnoreCase)
                || normalized.EndsWith("." + _value, StringComparison.OrdinalIgnoreCase),
            PatternKind.Regex => _regex!.IsMatch(host) || _regex.IsMatch(normalized),
            _ => false,
        };
    }

    private static string Normalize(string host)
    {
        var trimmed = host.Trim().TrimEnd('.');
        if (trimmed.Any(c => c > 127))
        {
            try
            {
                trimmed = new IdnMapping().GetAscii(trimmed);
            }
            catch
            {
                // 保留原始值参与比较。
            }
        }

        return trimmed;
    }

    private static string GlobToRegex(string glob)
    {
        var builder = new StringBuilder(glob.Length + 16);
        builder.Append('^');
        foreach (var ch in glob)
        {
            switch (ch)
            {
                case '*':
                    builder.Append(".*");
                    break;
                case '?':
                    builder.Append('.');
                    break;
                default:
                    builder.Append(Regex.Escape(ch.ToString()));
                    break;
            }
        }

        builder.Append('$');
        return builder.ToString();
    }

    private enum PatternKind
    {
        Exact,
        SubdomainOnly,
        Suffix,
        Regex,
        Any,
    }
}
