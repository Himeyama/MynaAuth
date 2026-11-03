using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Principal;
using MynaAuth.Jpki;
using MynaAuth.Windows;

byte[] pin = new byte[4];
byte[] payload = [];
uint status = 1;
try
{
    using WindowsIdentity identity = WindowsIdentity.GetCurrent();
    if (args is not ["--authenticate", string sid] || !identity.IsSystem) return;
    EnrolledAccount? account = AccountStore.Read(sid);
    if (account is null) return;
    using Stream input = Console.OpenStandardInput();
    await input.ReadExactlyAsync(pin);
    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(60));
    CardAuthenticationResult result = await new CardAuthentication(CardDevice.Automatic).AuthenticateAsync(pin, timeout.Token);
    status = result.Status switch
    {
        CardAuthenticationStatus.InvalidPin => 2,
        CardAuthenticationStatus.PinLocked => 3,
        CardAuthenticationStatus.Cancelled or CardAuthenticationStatus.TimedOut => 5,
        CardAuthenticationStatus.InvalidCertificate or CardAuthenticationStatus.InvalidSignature => 7,
        CardAuthenticationStatus.CardUnavailable or CardAuthenticationStatus.CardNotRecognized => 8,
        _ => 1
    };
    if (result.Status == CardAuthenticationStatus.Success && !AccountStore.Matches(account, result.CredentialId)) status = 4;
    if (result.Status == CardAuthenticationStatus.Success && AccountStore.Matches(account, result.CredentialId))
    {
        payload = WindowsSecret.Pack(sid, account.QualifiedName);
        status = 0;
    }
}
catch (Exception) { status = 1; }
finally
{
    CryptographicOperations.ZeroMemory(pin);
    byte[] header = new byte[12];
    "MYL1"u8.CopyTo(header);
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), status);
    BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), (uint)payload.Length);
    try
    {
        using Stream output = Console.OpenStandardOutput();
        output.Write(header);
        if (status == 0) output.Write(payload);
        output.Flush();
    }
    catch (IOException) { }
    finally { CryptographicOperations.ZeroMemory(payload); }
}
