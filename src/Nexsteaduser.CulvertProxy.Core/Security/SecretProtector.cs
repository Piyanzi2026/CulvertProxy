using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Nexsteaduser.CulvertProxy.Core.Security;

/// <summary>使用 Windows DPAPI 保护配置中的代理密码。</summary>
public static class SecretProtector
{
    private const string DpapiPrefix = "dpapi:";
    private const string PlainPrefix = "plain:";
    private const int CryptProtectUiForbidden = 0x1;
    private static readonly byte[] Entropy = "Nexsteaduser.CulvertProxy.v1"u8.ToArray();

    /// <summary>加密明文；DPAPI 不可用时退化为显式 plain 前缀。</summary>
    public static string Protect(string plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        try
        {
            var data = Encoding.UTF8.GetBytes(plaintext);
            var cipher = ProtectCore(data);
            return DpapiPrefix + Convert.ToBase64String(cipher);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or CryptographicException or PlatformNotSupportedException)
        {
            return PlainPrefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        }
    }

    /// <summary>解密存储值，兼容 dpapi、plain 和未加前缀的明文。</summary>
    public static string? Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
        {
            return null;
        }

        if (stored.StartsWith(DpapiPrefix, StringComparison.Ordinal))
        {
            try
            {
                var cipher = Convert.FromBase64String(stored[DpapiPrefix.Length..]);
                return Encoding.UTF8.GetString(UnprotectCore(cipher));
            }
            catch (Exception ex) when (ex is FormatException or CryptographicException or DllNotFoundException or EntryPointNotFoundException)
            {
                return null;
            }
        }

        if (stored.StartsWith(PlainPrefix, StringComparison.Ordinal))
        {
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(stored[PlainPrefix.Length..]));
            }
            catch (FormatException)
            {
                return null;
            }
        }

        return stored;
    }

    private static byte[] ProtectCore(byte[] data)
    {
        var inBlob = new DataBlob();
        var outBlob = new DataBlob();
        var entropyBlob = new DataBlob();
        var inHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        try
        {
            inBlob.Size = data.Length;
            inBlob.Data = inHandle.AddrOfPinnedObject();
            entropyBlob.Size = Entropy.Length;
            entropyBlob.Data = entropyHandle.AddrOfPinnedObject();
            if (!NativeMethods.CryptProtectData(ref inBlob, "CulvertProxy", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outBlob))
            {
                throw new CryptographicException(Marshal.GetLastPInvokeError());
            }

            var result = new byte[outBlob.Size];
            Marshal.Copy(outBlob.Data, result, 0, outBlob.Size);
            return result;
        }
        finally
        {
            if (outBlob.Data != IntPtr.Zero)
            {
                NativeMethods.LocalFree(outBlob.Data);
            }

            inHandle.Free();
            entropyHandle.Free();
        }
    }

    private static byte[] UnprotectCore(byte[] cipher)
    {
        var inBlob = new DataBlob();
        var outBlob = new DataBlob();
        var entropyBlob = new DataBlob();
        var inHandle = GCHandle.Alloc(cipher, GCHandleType.Pinned);
        var entropyHandle = GCHandle.Alloc(Entropy, GCHandleType.Pinned);
        try
        {
            inBlob.Size = cipher.Length;
            inBlob.Data = inHandle.AddrOfPinnedObject();
            entropyBlob.Size = Entropy.Length;
            entropyBlob.Data = entropyHandle.AddrOfPinnedObject();
            if (!NativeMethods.CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out outBlob))
            {
                throw new CryptographicException(Marshal.GetLastPInvokeError());
            }

            var result = new byte[outBlob.Size];
            Marshal.Copy(outBlob.Data, result, 0, outBlob.Size);
            return result;
        }
        finally
        {
            if (outBlob.Data != IntPtr.Zero)
            {
                NativeMethods.LocalFree(outBlob.Data);
            }

            inHandle.Free();
            entropyHandle.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Size;
        public IntPtr Data;
    }

    private static class NativeMethods
    {
        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptProtectData(
            ref DataBlob dataIn,
            string? description,
            ref DataBlob optionalEntropy,
            IntPtr reserved,
            IntPtr promptStruct,
            int flags,
            out DataBlob dataOut);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptUnprotectData(
            ref DataBlob dataIn,
            IntPtr description,
            ref DataBlob optionalEntropy,
            IntPtr reserved,
            IntPtr promptStruct,
            int flags,
            out DataBlob dataOut);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr LocalFree(IntPtr handle);
    }
}
