using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DotnetProbe;

/// <summary>用于验证 .NET Socket 路径（含 ConnectEx）是否被接管。</summary>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (args.Length < 4)
        {
            Console.Error.WriteLine("usage: DotnetProbe <ip> <port> <wait-ms> <sync|async>");
            return 64;
        }

        var address = IPAddress.Parse(args[0]);
        var port = int.Parse(args[1]);
        var wait = int.Parse(args[2]);
        var mode = args[3];
        await Task.Delay(wait);

        using var client = new TcpClient();
        if (mode.Equals("async", StringComparison.OrdinalIgnoreCase))
        {
            await client.ConnectAsync(address, port);
        }
        else
        {
            client.Connect(address, port);
        }

        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.UTF8.GetBytes("dotnet-ping"));
        var buffer = new byte[64];
        var read = await stream.ReadAsync(buffer);
        if (read <= 0)
        {
            Console.WriteLine("READ_FAIL");
            return 3;
        }

        Console.WriteLine($"OK {Encoding.UTF8.GetString(buffer, 0, read)}");
        return 0;
    }
}
