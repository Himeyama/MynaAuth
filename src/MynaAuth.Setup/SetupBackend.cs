using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32;
using MynaAuth.Jpki;
using MynaAuth.Windows;

namespace MynaAuth.Setup;

internal enum SetupStage { Recovery, WindowsAccount, Card, Save, Install }
internal sealed record RecoveryCheck(bool Ready, string? Sid, int Code);

internal interface ISetupBackend
{
    string FindEmail();
    RecoveryCheck CheckRecovery();
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

    public RecoveryCheck CheckRecovery()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) return new(false, null, 5);
        using RegistryKey? marker = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\MynaAuth");
        if (marker?.GetValue("RecoverySid") is not string sid || marker.GetValue("RecoveryVerifiedUtc") is not string)
            return new(false, null, 2);
        _ = new SecurityIdentifier(sid);
        return new(true, sid, 0);
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
        ProcessStartInfo start = new("powershell.exe") { UseShellExecute = false, CreateNoWindow = true };
        foreach (string argument in new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", Path.Combine(AppContext.BaseDirectory, "Install-LogonProvider.ps1"), "-RecoverySignInConfirmed" })
            start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException();
        await process.WaitForExitAsync().ConfigureAwait(false);
        return process.ExitCode == 0;
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
