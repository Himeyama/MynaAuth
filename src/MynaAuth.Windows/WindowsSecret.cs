using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace MynaAuth.Windows;

public sealed record WindowsAccountValidation(string? Sid, int ErrorCode)
{
    public bool IsSuccess => Sid is not null;
}

public static class WindowsSecret
{
    public static string ValidateAccount(string qualifiedName, SecureString password)
    {
        WindowsAccountValidation result = TryValidateAccount(qualifiedName, password);
        return result.Sid ?? throw new InvalidOperationException("Windows authentication failed.");
    }

    public static WindowsAccountValidation TryValidateAccount(string qualifiedName, SecureString password)
    {
        IntPtr plain = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            int separator = qualifiedName.IndexOf('\\');
            string user = separator >= 0 ? qualifiedName[(separator + 1)..] : qualifiedName;
            string? domain = separator >= 0 ? qualifiedName[..separator] : null;
            if (!LogonUser(user, domain, plain, 2, 0, out SafeAccessTokenHandle token))
                return new(null, Marshal.GetLastWin32Error());
            using (token)
            using (WindowsIdentity identity = new(token.DangerousGetHandle()))
                return new(identity.User?.Value, identity.User is null ? 1332 : 0);
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(plain); }
    }

    public static void Store(string sid, SecureString password)
    {
        _ = new SecurityIdentifier(sid);
        byte[] encrypted = Protect(password);
        try
        {
            using RegistryKey root = AccountStore.OpenProtectedRoot();
            using RegistryKey key = root.CreateSubKey($@"Accounts\{sid}", true);
            key.SetValue("ProtectedPassword", encrypted, RegistryValueKind.Binary);
        }
        finally { CryptographicOperations.ZeroMemory(encrypted); }
    }

    public static byte[] Pack(string sid, string qualifiedName)
    {
        _ = new SecurityIdentifier(sid);
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"{AccountStore.RegistryPath}\{sid}");
        byte[] encrypted = key?.GetValue("ProtectedPassword") as byte[] ?? throw new InvalidOperationException("Missing protected credential.");
        try { return PackEncrypted(encrypted, qualifiedName); }
        finally { CryptographicOperations.ZeroMemory(encrypted); }
    }

    public static void Delete(string sid)
    {
        _ = new SecurityIdentifier(sid);
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"{AccountStore.RegistryPath}\{sid}", true);
        key?.DeleteValue("ProtectedPassword", false);
    }

    internal static byte[] Protect(SecureString password)
    {
        if (password.Length is 0 or > 512) throw new ArgumentException("Invalid password length.");
        IntPtr plain = Marshal.SecureStringToGlobalAllocUnicode(password);
        DataBlob output = new();
        try
        {
            DataBlob input = new() { Length = password.Length * 2, Data = plain };
            // Machine scope is required before logon. Registry ACLs, not DPAPI alone,
            // restrict access to the ciphertext to SYSTEM and administrators.
            if (!CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1 | 4, out output))
                throw new CryptographicException("Credential protection failed.");
            byte[] encrypted = new byte[output.Length];
            Marshal.Copy(output.Data, encrypted, 0, encrypted.Length);
            return encrypted;
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(plain);
            if (output.Data != IntPtr.Zero) _ = LocalFree(output.Data);
        }
    }

    internal static byte[] PackEncrypted(byte[] encrypted, string qualifiedName)
    {
        if (encrypted.Length is 0 or > 65536) throw new CryptographicException("Invalid protected credential.");
        GCHandle pinned = GCHandle.Alloc(encrypted, GCHandleType.Pinned);
        DataBlob plain = new();
        IntPtr terminated = IntPtr.Zero;
        byte[]? packed = null;
        try
        {
            DataBlob input = new() { Length = encrypted.Length, Data = pinned.AddrOfPinnedObject() };
            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out plain))
                throw new CryptographicException("Credential decryption failed.");
            if (plain.Length is <= 0 or > 1024 || plain.Length % 2 != 0) throw new CryptographicException("Invalid protected credential.");
            terminated = Marshal.AllocHGlobal(plain.Length + 2);
            for (int index = 0; index < plain.Length; index++) Marshal.WriteByte(terminated, index, Marshal.ReadByte(plain.Data, index));
            Marshal.WriteInt16(terminated, plain.Length, 0);
            uint size = 0;
            uint flags = qualifiedName.StartsWith("MicrosoftAccount\\", StringComparison.OrdinalIgnoreCase) ? 1u | 8u : 1u;
            _ = CredPackAuthenticationBuffer(flags, qualifiedName, terminated, null, ref size);
            if (Marshal.GetLastWin32Error() != 122 || size is 0 or > 65536) throw new CryptographicException("Credential packing failed.");
            packed = new byte[size];
            if (!CredPackAuthenticationBuffer(flags, qualifiedName, terminated, packed, ref size))
                throw new CryptographicException("Credential packing failed.");
            return packed;
        }
        catch
        {
            if (packed is not null) CryptographicOperations.ZeroMemory(packed);
            throw;
        }
        finally
        {
            if (terminated != IntPtr.Zero)
            {
                for (int index = 0; index < plain.Length + 2; index++) Marshal.WriteByte(terminated, index, 0);
                Marshal.FreeHGlobal(terminated);
            }
            if (plain.Data != IntPtr.Zero)
            {
                for (int index = 0; index < plain.Length; index++) Marshal.WriteByte(plain.Data, index, 0);
                _ = LocalFree(plain.Data);
            }
            pinned.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Length; public IntPtr Data; }
    [DllImport("advapi32.dll", EntryPoint = "LogonUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool LogonUser(string user, string? domain, IntPtr password, uint type, uint provider, out SafeAccessTokenHandle token);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref DataBlob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("credui.dll", EntryPoint = "CredPackAuthenticationBufferW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CredPackAuthenticationBuffer(uint flags, string user, IntPtr password, [Out] byte[]? buffer, ref uint length);
}
