using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32;
using MynaAuth.Jpki;
using MynaAuth.Windows;

namespace MynaAuth.Setup;

internal enum SetupStage { WindowsAccount, Card, Save, Install }

internal interface ISetupBackend
{
    string FindEmail();
    Task<WindowsAccountValidation> ValidateAsync(string account, SecureString password);
    Task<CardAuthenticationResult> AuthenticateAsync(byte[] pin, CancellationToken token);
    void Save(string sid, string account, SecureString password, string credentialId);
    Task<bool> InstallAsync();
    void RecordFailure(SetupStage stage, int code);
}

internal sealed class SetupBackend : ISetupBackend
{
    public string FindEmail()
    {
        uint code = NetUserGetInfo(null, Environment.UserName, 24, out IntPtr buffer);
        if (code != 0) throw new InvalidOperationException("Account discovery failed.");
        try
        {
            UserInfo24 info = Marshal.PtrToStructure<UserInfo24>(buffer);
            if (info.InternetIdentity == 0)
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                return identity.Name;
            }
            if (!string.Equals(Marshal.PtrToStringUni(info.Provider), "MicrosoftAccount", StringComparison.OrdinalIgnoreCase)) return "";
            return Marshal.PtrToStringUni(info.Principal) ?? "";
        }
        finally { _ = NetApiBufferFree(buffer); }
    }

    public Task<WindowsAccountValidation> ValidateAsync(string account, SecureString password) =>
        Task.Run(() => WindowsSecret.TryValidateAccount(account, password));
    public Task<CardAuthenticationResult> AuthenticateAsync(byte[] pin, CancellationToken token) =>
        new CardAuthentication(CardDevice.Automatic).AuthenticateAsync(pin, token);
    public void Save(string sid, string account, SecureString password, string credentialId)
    {
        WindowsSecret.Store(sid, password);
        AccountStore.Write(sid, account, credentialId);
    }

    public async Task<bool> InstallAsync()
    {
        ValidateInstallBundle(AppContext.BaseDirectory);
        using RegistryKey? provider = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{37167329-B6D8-4379-90A9-0D350F82F31A}");
        ProcessStartInfo start = CreateInstallStartInfo(provider is not null, AppContext.BaseDirectory);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException();
        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode == 0;
    }

    internal static void ValidateInstallBundle(string bundlePath)
    {
        foreach (string name in new[] { "Install-LogonProvider.ps1", "Update-LogonProvider.ps1", "bundle-manifest.json", "MynaAuthCredentialProvider.dll", "MynaAuth.LogonHost.exe" })
            if (!File.Exists(Path.Combine(bundlePath, name)))
                throw new FileNotFoundException("Installation bundle is incomplete.");
    }

    internal static ProcessStartInfo CreateInstallStartInfo(bool providerInstalled, string bundlePath)
    {
        string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        ProcessStartInfo start = new(powershell) { UseShellExecute = false, CreateNoWindow = true };
        string script = providerInstalled ? "Update-LogonProvider.ps1" : "Install-LogonProvider.ps1";
        foreach (string argument in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(bundlePath, script) })
            start.ArgumentList.Add(argument);
        if (providerInstalled)
        {
            start.ArgumentList.Add("-BundlePath");
            start.ArgumentList.Add(bundlePath);
        }
        return start;
    }

    public void RecordFailure(SetupStage stage, int code)
    {
        try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "setup-diagnostics.log"), $"{DateTimeOffset.UtcNow:O} Stage={stage} Code={code}{Environment.NewLine}"); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct UserInfo24
    { public int InternetIdentity; public uint Flags; public IntPtr Provider; public IntPtr Principal; public IntPtr Sid; }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserGetInfo(string? server, string user, uint level, out IntPtr buffer);
    [DllImport("netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr buffer);
}
