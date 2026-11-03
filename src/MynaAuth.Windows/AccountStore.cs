using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace MynaAuth.Windows;

public sealed record EnrolledAccount(string Sid, string QualifiedName, string[] CredentialIds);

public static class AccountStore
{
    public const string RegistryPath = @"SOFTWARE\MynaAuth\Accounts";
    public const string ProviderId = "{37167329-B6D8-4379-90A9-0D350F82F31A}";

    public static EnrolledAccount? Read(string sid)
    {
        _ = new SecurityIdentifier(sid);
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey($@"{RegistryPath}\{sid}");
        if (key?.GetValue("QualifiedName") is not string name || key.GetValue("CredentialIds") is not string[] ids)
            return null;
        return new(sid, name, ids);
    }

    public static bool Matches(EnrolledAccount account, string? credentialId)
    {
        if (credentialId is null || credentialId.Length != 64 || !credentialId.All(Uri.IsHexDigit)) return false;
        byte[] candidate = Convert.FromHexString(credentialId);
        return account.CredentialIds.Any(id => id.Length == 64 && id.All(Uri.IsHexDigit) &&
            CryptographicOperations.FixedTimeEquals(candidate, Convert.FromHexString(id)));
    }

    public static void Write(string sid, string name, string credentialId)
    {
        if (credentialId.Length != 64 || !credentialId.All(Uri.IsHexDigit)) throw new ArgumentException("Invalid credential identifier.");
        _ = new SecurityIdentifier(sid);
        using RegistryKey root = OpenProtectedRoot();
        EnrolledAccount? previous = Read(sid);
        if (previous is not null && !StringComparer.OrdinalIgnoreCase.Equals(previous.QualifiedName, name))
            throw new InvalidOperationException("Account identity differs.");
        using RegistryKey key = root.CreateSubKey($@"Accounts\{sid}", true);
        string[] ids = previous is null ? [credentialId] : previous.CredentialIds.Append(credentialId).Distinct(StringComparer.Ordinal).ToArray();
        key.SetValue("QualifiedName", name, RegistryValueKind.String);
        key.SetValue("CredentialIds", ids, RegistryValueKind.MultiString);
    }

    internal static RegistryKey OpenProtectedRoot()
    {
        RegistryKey root = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\MynaAuth", true);
        RegistrySecurity security = new();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        root.SetAccessControl(security);
        return root;
    }
}
