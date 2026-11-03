using System.Security;
using System.Security.Cryptography;
using System.Text;
using MynaAuth.Windows;

// Synthetic values only. No account creation, registry write, real password or Windows logon.
string allowed = new('A', 64);
EnrolledAccount account = new("S-1-5-21-1-2-3-1001", "MicrosoftAccount\\synthetic@example.invalid", [allowed]);
Check(AccountStore.Matches(account, allowed), "Accept registered credential identifier");
Check(!AccountStore.Matches(account, new string('B', 64)), "Reject another card's key");
Check(!AccountStore.Matches(account, null) && !AccountStore.Matches(account, "not-a-key"), "Reject missing and malformed identifiers");

using SecureString secret = new();
foreach (char value in "Synthetic password for API check only!") secret.AppendChar(value);
secret.MakeReadOnly();
byte[] encrypted = WindowsSecret.Protect(secret);
byte[] plaintext = Encoding.Unicode.GetBytes("Synthetic password for API check only!");
try
{
    Check(encrypted.Length > 0 && encrypted.AsSpan().IndexOf(plaintext) < 0, "DPAPI payload does not contain plaintext password");
    byte[] packed = WindowsSecret.PackEncrypted(encrypted, account.QualifiedName);
    try { Check(packed.Length > 0 && packed.AsSpan().IndexOf(plaintext) < 0, "Windows serialization contains session-protected credentials"); }
    finally { CryptographicOperations.ZeroMemory(packed); }
    byte[] localPacked = WindowsSecret.PackEncrypted(encrypted, Environment.MachineName + @"\SyntheticLocal");
    try { Check(localPacked.Length > 0 && localPacked.AsSpan().IndexOf(plaintext) < 0, "Pack local credentials with protected password without online identity flag"); }
    finally { CryptographicOperations.ZeroMemory(localPacked); }
    encrypted[^1] ^= 0x80;
    bool rejected = false;
    try { WindowsSecret.PackEncrypted(encrypted, account.QualifiedName); }
    catch (CryptographicException) { rejected = true; }
    Check(rejected, "Reject tampered encrypted credential");
}
finally { CryptographicOperations.ZeroMemory(encrypted); CryptographicOperations.ZeroMemory(plaintext); }
Console.WriteLine("Windows credential checks passed. No real credential or registry configuration used.");

static void Check(bool condition, string description)
{
    if (!condition) throw new InvalidOperationException(description);
    Console.WriteLine($"PASS: {description}");
}
