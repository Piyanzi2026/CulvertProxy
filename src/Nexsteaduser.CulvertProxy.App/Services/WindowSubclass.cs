using System.Runtime.InteropServices;

namespace Nexsteaduser.CulvertProxy.App.Services;

/// <summary>订阅窗口消息的轻量子类，用于捕获最小化。</summary>
internal sealed class WindowSubclass : IDisposable
{
    private const uint WmSize = 0x0005;
    private const int SizeMinimized = 1;
    private readonly IntPtr _hwnd;
    private readonly SubclassProc _proc;
    private readonly Action _onMinimized;
    private bool _installed;
    private bool _disposed;

    public WindowSubclass(IntPtr hwnd, Action onMinimized)
    {
        _hwnd = hwnd;
        _onMinimized = onMinimized;
        _proc = WindowProc;
        _installed = SetWindowSubclass(hwnd, _proc, new UIntPtr(1), IntPtr.Zero);
    }

    public bool Installed => _installed;

    private IntPtr WindowProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam, UIntPtr id, IntPtr data)
    {
        if (message == WmSize && ((long)wParam & 0xFFFF) == SizeMinimized)
        {
            _onMinimized();
        }

        return DefSubclassProc(hwnd, message, wParam, lParam);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_installed)
        {
            RemoveWindowSubclass(_hwnd, _proc, new UIntPtr(1));
            _installed = false;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr SubclassProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam, UIntPtr id, IntPtr data);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(IntPtr hwnd, SubclassProc proc, UIntPtr id, IntPtr data);

    [DllImport("comctl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(IntPtr hwnd, SubclassProc proc, UIntPtr id);

    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
}
