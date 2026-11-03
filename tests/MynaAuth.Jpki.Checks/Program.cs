using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MynaAuth.Jpki;
using MynaAuth.Jpki.Checks;

if (args is ["--auto-preflight"])
{
    try
    {
        using AutoCardModule module = new();
        DateTimeOffset until = DateTimeOffset.UtcNow.AddSeconds(15);
        while (module.GetSlots().Length == 0 && DateTimeOffset.UtcNow < until) await Task.Delay(250);
        module.Open(0);
        Console.WriteLine($"Automatic detection: {module.DetectedDevice}. No PIN or certificate requested.");
    }
    catch (Pkcs11Exception error)
    {
        Console.WriteLine(new JpkiFailure(error.Operation, error.Code).Summary);
        Environment.ExitCode = 1;
    }
    return;
}

if (args is ["--android-preflight"] or ["--android-certificate-check"])
{
    try
    {
        using AndroidCardModule module = new();
        DateTimeOffset until = DateTimeOffset.UtcNow.AddSeconds(30);
        while (module.GetSlots().Length == 0 && DateTimeOffset.UtcNow < until) await Task.Delay(250);
        module.Open(0);
        Console.WriteLine("Android JPKI application and token type: OK. No PIN or certificate requested.");
        if (args is ["--android-certificate-check"])
        {
            byte[] cardCertificate = module.Certificate();
            try
            {
                using X509Certificate2 parsed = new(cardCertificate);
                bool trusted = CertificateTrust.IsTrusted(parsed);
                Console.WriteLine(trusted ? "Android authentication certificate trust and validity: OK. No PIN submitted; certificate not saved."
                    : "Android certificate validation: FAILED. No PIN submitted; certificate not saved.");
                if (!trusted) Environment.ExitCode = 1;
            }
            finally { CryptographicOperations.ZeroMemory(cardCertificate); }
        }
    }
    catch (Pkcs11Exception error)
    {
        Console.WriteLine(new JpkiFailure(error.Operation, error.Code).Summary);
        Environment.ExitCode = 1;
    }
    return;
}

if (args is ["--pcsc-link"])
{
    PcscLinkDiagnostic.Run();
    return;
}

if (args is ["--native-preflight"] or ["--native-watch"])
{
    string operation = "Initialize";
    try
    {
        using Pkcs11Module module = new();
        Console.WriteLine("Initialize: OK");
        operation = "GetSlots";
        uint[] slots = module.GetSlots();
        if (args is ["--native-watch"])
        {
            Console.WriteLine("Waiting up to 45 seconds for a card. No PIN will be submitted.");
            DateTimeOffset end = DateTimeOffset.UtcNow.AddSeconds(45);
            while (slots.Length == 0 && DateTimeOffset.UtcNow < end)
            {
                await Task.Delay(250);
                slots = module.GetSlots();
            }
        }
        Console.WriteLine($"GetSlots: OK, present count={slots.Length}");
        if (slots.Length == 1)
        {
            operation = "OpenSession";
            module.Open(slots[0]);
            Console.WriteLine("OpenSession: OK");
        }
    }
    catch (Pkcs11Exception error)
    {
        Console.WriteLine($"{operation}: {new JpkiFailure(error.Operation, error.Code).Summary}");
        Environment.ExitCode = 1;
    }
    Console.WriteLine("No PIN submitted. No certificate or signature read.");
    return;
}

using RSA testKey = RSA.Create(2048);
CertificateRequest request = new("CN=Synthetic test only", testKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
byte[] raw = certificate.Export(X509ContentType.Cert);
Check(!CertificateTrust.IsTrusted(certificate), "Reject synthetic certificate under official JPKI anchors");

FakeModule success = new(testKey, raw);
byte[] successPin = DemoPin();
CardAuthenticationResult successResult = await new CardAuthentication(() => success, _ => true)
    .AuthenticateAsync(successPin, CancellationToken.None);
Check(successResult.Status == CardAuthenticationStatus.Success, "Verify a fresh card signature");
Check(success.LoginCount == 1 && success.SignCount == 1 && success.Disposed, "Single PIN submission and module cleanup");
Check(IsZero(successPin) && IsZero(success.ReturnedCertificate!) && IsZero(success.ReturnedSignature!),
    "Erase PIN, certificate buffer and signature buffer");

FakeModule wrong = new(testKey, raw) { LoginStatus = 0xA0 };
byte[] wrongPin = DemoPin();
CardAuthenticationResult wrongResult = await new CardAuthentication(() => wrong, _ => true)
    .AuthenticateAsync(wrongPin, CancellationToken.None);
Check(wrongResult.Status == CardAuthenticationStatus.InvalidPin && wrong.LoginCount == 1 && wrong.SignCount == 0,
    "Wrong PIN is never retried or used to sign");
Check(wrongResult.Failure is { Operation: JpkiOperation.Login, Code: 0xA0 },
    "Preserve failure stage and numeric code without PIN data");
Check(IsZero(wrongPin) && wrong.Disposed, "Erase PIN on failed login");

FakeModule locked = new(testKey, raw) { LoginStatus = 0xA4 };
Check((await new CardAuthentication(() => locked, _ => true).AuthenticateAsync(DemoPin(), CancellationToken.None))
    .Status == CardAuthenticationStatus.PinLocked && locked.LoginCount == 1, "Report locked PIN without retry");

FakeModule alreadyLoggedIn = new(testKey, raw) { LoginStatus = 0x100 };
Check((await new CardAuthentication(() => alreadyLoggedIn, _ => true).AuthenticateAsync(DemoPin(), CancellationToken.None))
    .Status == CardAuthenticationStatus.Failed, "Existing login is not accepted as a fresh PIN check");

FakeModule untrusted = new(testKey, raw);
Check((await new CardAuthentication(() => untrusted, _ => false).AuthenticateAsync(DemoPin(), CancellationToken.None))
    .Status == CardAuthenticationStatus.InvalidCertificate && untrusted.SignCount == 0, "Reject untrusted certificate before signing");

FakeModule tampered = new(testKey, raw) { Tamper = true };
Check((await new CardAuthentication(() => tampered, _ => true).AuthenticateAsync(DemoPin(), CancellationToken.None))
    .Status == CardAuthenticationStatus.InvalidSignature, "Reject tampered proof");

FakeModule captured = new(testKey, raw);
await new CardAuthentication(() => captured, _ => true).AuthenticateAsync(DemoPin(), CancellationToken.None);
FakeModule replay = new(testKey, raw) { ReplaySignature = captured.CapturedSignature };
Check((await new CardAuthentication(() => replay, _ => true).AuthenticateAsync(DemoPin(), CancellationToken.None))
    .Status == CardAuthenticationStatus.InvalidSignature, "Reject proof replayed in a new session");

using CancellationTokenSource midLoginCancellation = new();
FakeModule cancelDuringLogin = new(testKey, raw) { OnLogin = midLoginCancellation.Cancel };
byte[] midLoginPin = DemoPin();
Check((await new CardAuthentication(() => cancelDuringLogin, _ => true)
    .AuthenticateAsync(midLoginPin, midLoginCancellation.Token)).Status == CardAuthenticationStatus.Cancelled &&
    cancelDuringLogin.SignCount == 0 && IsZero(midLoginPin) && cancelDuringLogin.Disposed,
    "Cancellation during PIN verification prevents signing and clears PIN");

FakeModule multiple = new(testKey, raw) { Slots = [0, 1] };
Check((await new CardAuthentication(() => multiple, _ => true).AuthenticateAsync(DemoPin(), CancellationToken.None))
    .Status == CardAuthenticationStatus.MultipleCards && multiple.LoginCount == 0, "No PIN sent with multiple cards");

using CancellationTokenSource cancelled = new();
cancelled.Cancel();
byte[] cancelledPin = DemoPin();
Check((await new CardAuthentication(() => throw new InvalidOperationException(), _ => true)
    .AuthenticateAsync(cancelledPin, cancelled.Token)).Status == CardAuthenticationStatus.Cancelled && IsZero(cancelledPin),
    "Cancellation clears PIN before native access");

byte[] missingLibraryPin = DemoPin();
Check((await new CardAuthentication(() => throw new DllNotFoundException(), _ => true)
    .AuthenticateAsync(missingLibraryPin, CancellationToken.None)).Status == CardAuthenticationStatus.LibraryUnavailable && IsZero(missingLibraryPin),
    "Missing library fails closed and clears PIN");

FakeModule removed = new(testKey, raw) { ThrowOnSign = true };
byte[] removedPin = DemoPin();
Check((await new CardAuthentication(() => removed, _ => true).AuthenticateAsync(removedPin, CancellationToken.None))
    .Status == CardAuthenticationStatus.CardUnavailable && IsZero(removedPin) && removed.Disposed,
    "Card removal fails closed and releases resources");
Check(CardAuthentication.MapStatus(0xE1) == CardAuthenticationStatus.CardNotRecognized,
    "Distinguish unsupported-card recognition from card removal");
Console.WriteLine("JPKI checks passed. All credentials in these checks are synthetic.");
await AndroidChecks.RunAsync();

static byte[] DemoPin() => [(byte)'2', (byte)'4', (byte)'6', (byte)'8'];
static bool IsZero(byte[] bytes) => bytes.All(value => value == 0);
static void Check(bool condition, string description)
{
    if (!condition) throw new InvalidOperationException(description);
    Console.WriteLine($"PASS: {description}");
}

internal sealed class FakeModule(RSA key, byte[] certificate) : IPkcs11Module
{
    public uint LoginStatus { get; init; }
    public uint[] Slots { get; init; } = [0];
    public bool Tamper { get; init; }
    public bool ThrowOnSign { get; init; }
    public Action? OnLogin { get; init; }
    public byte[]? ReplaySignature { get; init; }
    public byte[]? CapturedSignature { get; private set; }
    public bool Disposed { get; private set; }
    public int LoginCount { get; private set; }
    public int SignCount { get; private set; }
    public byte[]? ReturnedCertificate { get; private set; }
    public byte[]? ReturnedSignature { get; private set; }
    public uint[] GetSlots() => Slots;
    public void Open(uint slot) { }
    public uint Login(byte[] pin) { LoginCount++; OnLogin?.Invoke(); return LoginStatus; }
    public byte[] Certificate() { ReturnedCertificate = certificate.ToArray(); return ReturnedCertificate; }
    public byte[] Sign(byte[] digestInfo)
    {
        SignCount++;
        if (ThrowOnSign) throw new Pkcs11Exception(0x32);
        if (digestInfo.Length != 51 || !digestInfo.AsSpan(0, 19).SequenceEqual(Convert.FromHexString("3031300D060960864801650304020105000420")))
            throw new InvalidOperationException("DigestInfo framing mismatch.");
        ReturnedSignature = ReplaySignature?.ToArray() ?? key.SignHash(digestInfo.AsSpan(19), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        CapturedSignature = ReturnedSignature.ToArray();
        if (Tamper) ReturnedSignature[0] ^= 0x80;
        return ReturnedSignature;
    }
    public void Dispose() => Disposed = true;
}
