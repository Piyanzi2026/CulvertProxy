using System.Runtime.InteropServices;

namespace Nexsteaduser.CulvertProxy.App.Services;

/// <summary>Win32 托盘图标：双击还原窗口，右键菜单可退出。</summary>
public sealed class TrayIcon : IDisposable
{
    private const int WmApp = 0x8000;
    private const int WmCommand = 0x0111;
    private const int WmContextMenu = 0x007B;
    private const int WmLeftButtonDoubleClick = 0x0203;
    private const int WmRightButtonUp = 0x0205;
    private const int NifMessage = 0x1;
    private const int NifIcon = 0x2;
    private const int NifTip = 0x4;
    private const int NimAdd = 0x0;
    private const int NimModify = 0x1;
    private const int NimDelete = 0x2;
    private const int ImageIcon = 1;
    private const int LrLoadFromFile = 0x10;
    private const uint MfString = 0x0;
    private const uint MfSeparator = 0x800;
    private const uint TpmRightButton = 0x0002;
    private const uint TpmReturnCmd = 0x0100;
    private static readonly IntPtr HwndMessage = new(-3);
    private static readonly IntPtr IdiApplication = new(32512);
    private const uint CommandOpen = 1;
    private const uint CommandExit = 2;
    private const string ClassName = "NexsteaduserCulvertProxyTrayWindow";
    private static readonly uint TaskbarCreated = RegisterWindowMessageW("TaskbarCreated");

    private readonly WndProcDelegate _wndProc;
    private readonly IntPtr _hwnd;
    private readonly IntPtr _icon;
    private readonly uint _callbackMessage = WmApp + 42;
    private readonly string _iconPath;
    private bool _visible;
    private bool _disposed;
    private string _tooltip = "CulvertProxy";

    public TrayIcon(string iconPath)
    {
        _iconPath = iconPath;
        _wndProc = WindowProc;
        var instance = GetModuleHandleW(null);
        var windowClass = new WndClassEx
        {
            Size = (uint)Marshal.SizeOf<WndClassEx>(),
            WndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            Instance = instance,
            ClassName = ClassName,
        };
        _ = RegisterClassExW(ref windowClass);
        _hwnd = CreateWindowExW(0, ClassName, "CulvertProxy", 0, 0, 0, 0, 0, HwndMessage, IntPtr.Zero, instance, IntPtr.Zero);
        if (_hwnd == IntPtr.Zero)
        {
            throw new InvalidOperationException("无法创建托盘消息窗口。");
        }

        _icon = LoadIcon();
        Show();
    }

    public event Action? OpenRequested;

    public event Action? ExitRequested;

    public void SetTooltip(string text)
    {
        _tooltip = text;
        if (_visible)
        {
            UpdateIcon();
        }
    }

    private void Show()
    {
        var data = CreateData(NifMessage | NifIcon | NifTip);
        _visible = Shell_NotifyIconW(NimAdd, ref data);
    }

    private void UpdateIcon()
    {
        var data = CreateData(NifTip);
        _ = Shell_NotifyIconW(NimModify, ref data);
    }

    private NotifyIconData CreateData(int flags)
    {
        return new NotifyIconData
        {
            Size = Marshal.SizeOf<NotifyIconData>(),
            Window = _hwnd,
            Id = 1,
            Flags = (uint)flags,
            CallbackMessage = _callbackMessage,
            Icon = _icon,
            Tip = _tooltip.Length > 120 ? _tooltip[..120] : _tooltip,
            Info = string.Empty,
            InfoTitle = string.Empty,
        };
    }

    private IntPtr LoadIcon()
    {
        if (File.Exists(_iconPath))
        {
            var icon = LoadImageW(IntPtr.Zero, _iconPath, ImageIcon, 32, 32, LrLoadFromFile);
            if (icon != IntPtr.Zero)
            {
                return icon;
            }
        }

        return LoadIconW(IntPtr.Zero, IdiApplication);
    }

    private IntPtr WindowProc(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
    {
        if (message == _callbackMessage)
        {
            var code = (int)(lParam.ToInt64() & 0xFFFF);
            if (code == WmLeftButtonDoubleClick)
            {
                OpenRequested?.Invoke();
            }
            else if (code == WmRightButtonUp || code == WmContextMenu)
            {
                ShowMenu();
            }

            return IntPtr.Zero;
        }

        if (message == WmCommand)
        {
            var command = (uint)(wParam.ToInt64() & 0xFFFF);
            if (command == CommandOpen)
            {
                OpenRequested?.Invoke();
            }
            else if (command == CommandExit)
            {
                ExitRequested?.Invoke();
            }

            return IntPtr.Zero;
        }

        if (message == TaskbarCreated)
        {
            _visible = false;
            Show();
            return IntPtr.Zero;
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }

    private void ShowMenu()
    {
        var menu = CreatePopupMenu();
        if (menu == IntPtr.Zero)
        {
            return;
        }

        _ = AppendMenuW(menu, MfString, CommandOpen, "打开 CulvertProxy");
        _ = AppendMenuW(menu, MfSeparator, 0, null);
        _ = AppendMenuW(menu, MfString, CommandExit, "退出");
        GetCursorPos(out var point);
        _ = SetForegroundWindow(_hwnd);
        var command = TrackPopupMenu(menu, TpmRightButton | TpmReturnCmd, point.X, point.Y, 0, _hwnd, IntPtr.Zero);
        _ = DestroyMenu(menu);
        _ = PostMessageW(_hwnd, 0, IntPtr.Zero, IntPtr.Zero);
        if (command == CommandOpen)
        {
            OpenRequested?.Invoke();
        }
        else if (command == CommandExit)
        {
            ExitRequested?.Invoke();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_visible)
        {
            var data = CreateData(0);
            _ = Shell_NotifyIconW(NimDelete, ref data);
            _visible = false;
        }

        if (_icon != IntPtr.Zero)
        {
            _ = DestroyIcon(_icon);
        }

        if (_hwnd != IntPtr.Zero)
        {
            _ = DestroyWindow(_hwnd);
        }

        _ = UnregisterClassW(ClassName, GetModuleHandleW(null));
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr WndProcDelegate(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WndClassEx
    {
        public uint Size;
        public uint Style;
        public IntPtr WndProc;
        public int ClassExtra;
        public int WindowExtra;
        public IntPtr Instance;
        public IntPtr Icon;
        public IntPtr Cursor;
        public IntPtr Background;
        public string? MenuName;
        public string ClassName;
        public IntPtr SmallIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public int Size;
        public IntPtr Window;
        public uint Id;
        public uint Flags;
        public uint CallbackMessage;
        public IntPtr Icon;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string Tip;

        public uint State;
        public uint StateMask;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Info;

        public uint Version;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string InfoTitle;

        public uint InfoFlags;
        public Guid Guid;
        public IntPtr BalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassExW(ref WndClassEx windowClass);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(
        uint extendedStyle,
        string className,
        string windowName,
        uint style,
        int x,
        int y,
        int width,
        int height,
        IntPtr parent,
        IntPtr menu,
        IntPtr instance,
        IntPtr param);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool DestroyWindow(IntPtr hwnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool UnregisterClassW(string className, IntPtr instance);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessageW(string message);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string? moduleName);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIconW(uint message, ref NotifyIconData data);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadImageW(IntPtr instance, string name, int type, int cx, int cy, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadIconW(IntPtr instance, IntPtr name);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    [DllImport("user32.dll")]
    private static extern IntPtr CreatePopupMenu();

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool AppendMenuW(IntPtr menu, uint flags, uint itemId, string? text);

    [DllImport("user32.dll")]
    private static extern bool DestroyMenu(IntPtr menu);

    [DllImport("user32.dll")]
    private static extern uint TrackPopupMenu(IntPtr menu, uint flags, int x, int y, int reserved, IntPtr hwnd, IntPtr rect);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out Point point);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
}
