using System.Buffers;
using System.Text;

namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>读取 HTTP 响应/请求头块，并保留可能被多读的隧道数据。</summary>
public static class HttpHeaderReader
{
    /// <summary>读到空行为止，返回头部文本与残余字节。</summary>
    public static async ValueTask<HeaderBlock> ReadAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(8192);
        var total = 0;
        try
        {
            while (true)
            {
                if (total == buffer.Length)
                {
                    if (buffer.Length >= maxBytes)
                    {
                        throw new IOException($"HTTP 头超过 {maxBytes} 字节限制。");
                    }

                    var larger = ArrayPool<byte>.Shared.Rent(Math.Min(buffer.Length * 2, maxBytes));
                    buffer.AsSpan(0, total).CopyTo(larger);
                    ArrayPool<byte>.Shared.Return(buffer);
                    buffer = larger;
                }

                var read = await stream.ReadAsync(buffer.AsMemory(total, Math.Min(8192, buffer.Length - total)), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new IOException("对端在 HTTP 头结束前关闭了连接。");
                }

                total += read;
                var headerLength = FindHeaderEnd(buffer.AsSpan(0, total));
                if (headerLength > 0)
                {
                    var text = Encoding.ASCII.GetString(buffer, 0, headerLength);
                    var leftoverLength = total - headerLength;
                    var leftover = leftoverLength > 0 ? buffer.AsSpan(headerLength, leftoverLength).ToArray() : [];
                    return new HeaderBlock(text, leftover);
                }

                if (total >= maxBytes)
                {
                    throw new IOException($"HTTP 头超过 {maxBytes} 字节限制。");
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static int FindHeaderEnd(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
        {
            if (data[i] != (byte)'\n')
            {
                continue;
            }

            if (i + 1 < data.Length && data[i + 1] == (byte)'\n')
            {
                return i + 2;
            }

            if (i >= 2 && data[i - 1] == (byte)'\r' && i + 1 < data.Length && data[i + 1] == (byte)'\r')
            {
                if (i + 2 < data.Length && data[i + 2] == (byte)'\n')
                {
                    return i + 3;
                }
            }
        }

        return -1;
    }

    /// <summary>从头部文本中查找某字段的值，大小写不敏感。</summary>
    public static string? FindHeaderValue(string headerText, string name)
    {
        var span = headerText.AsSpan();
        var lineStart = span.IndexOf('\n');
        while (lineStart >= 0)
        {
            lineStart++;
            if (lineStart >= span.Length)
            {
                break;
            }

            var lineEnd = span[lineStart..].IndexOf('\n');
            var line = lineEnd < 0 ? span[lineStart..] : span.Slice(lineStart, lineEnd);
            line = line.TrimEnd('\r');
            var colon = line.IndexOf(':');
            if (colon > 0 && line[..colon].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return line[(colon + 1)..].Trim().ToString();
            }

            if (lineEnd < 0)
            {
                break;
            }

            lineStart += lineEnd;
        }

        return null;
    }

    /// <summary>解析状态行，返回状态码；非 HTTP 响应返回 0。</summary>
    public static int ParseStatusCode(string headerText)
    {
        var lineEnd = headerText.IndexOf('\n');
        var line = lineEnd < 0 ? headerText : headerText[..lineEnd];
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2 || !parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        return int.TryParse(parts[1], out var code) ? code : 0;
    }

    public readonly record struct HeaderBlock(string Text, byte[] Leftover);
}
