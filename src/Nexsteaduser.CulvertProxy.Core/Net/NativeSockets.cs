using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Nexsteaduser.CulvertProxy.Core.Net;

/// <summary>WinSock 扩展调用的薄封装，全部失败即静默忽略。</summary>
internal static partial class NativeSockets
{
    private const int SioLoopbackFastPath = unchecked((int)0x9800000C);
    private const int SioTcpKeepAliveValues = unchecked((int)0x98000004);

    /// <summary>尽可能启用回环快速路径，仅对监听/连接建立前生效。</summary>
    public static void TryEnableLoopbackFastPath(Socket socket)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var enabled = 1;
            var buffer = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                Marshal.WriteInt32(buffer, enabled);
                _ = WsaIoctl(socket.SafeHandle, SioLoopbackFastPath, buffer, sizeof(int), IntPtr.Zero, 0, out _, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            // 老系统或受限环境不支持时保持默认路径。
        }
    }

    /// <summary>设置 TCP keep-alive 空闲与探测间隔（Windows 专用结构体）。</summary>
    public static void TrySetKeepAlive(Socket socket, uint idleSeconds, uint intervalSeconds)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            var values = new TcpKeepAlive
            {
                OnOff = 1,
                KeepAliveTime = idleSeconds * 1000,
                KeepAliveInterval = intervalSeconds * 1000,
            };
            var buffer = Marshal.AllocHGlobal(Marshal.SizeOf<TcpKeepAlive>());
            try
            {
                Marshal.StructureToPtr(values, buffer, false);
                _ = WsaIoctl(socket.SafeHandle, SioTcpKeepAliveValues, buffer, Marshal.SizeOf<TcpKeepAlive>(), IntPtr.Zero, 0, out _, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            // 忽略不支持的情况。
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpKeepAlive
    {
        public uint OnOff;
        public uint KeepAliveTime;
        public uint KeepAliveInterval;
    }

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int WsaIoctl(
        SafeSocketHandle socket,
        int ioControlCode,
        IntPtr inBuffer,
        int inBufferSize,
        IntPtr outBuffer,
        int outBufferSize,
        out int bytesReturned,
        IntPtr overlapped,
        IntPtr completionRoutine);
}
