using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using MynaAuth.Jpki;

namespace MynaAuth.Jpki.Checks;

internal static class AndroidChecks
{
    public static async Task RunAsync()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=Synthetic Android test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] raw = certificate.Export(X509ContentType.Cert);

        ScriptedPhone phone = new(key, raw);
        byte[] pin = SyntheticPin();
        CardAuthenticationResult result = await Authenticate(phone, pin);
        Check(result.Status == CardAuthenticationStatus.Success && phone.PinCount == 1 && phone.SignCount == 1,
            "Android proof verifies, including chained signature response");
        Check(pin.All(value => value == 0) && phone.PinCommand!.All(value => value == 0) && phone.Disposed,
            "Android PIN command and caller buffer are erased; connection released");

        ScriptedPhone wrong = new(key, raw) { WrongPin = true };
        result = await Authenticate(wrong, SyntheticPin());
        Check(result.Status == CardAuthenticationStatus.InvalidPin && wrong.PinCount == 1 && wrong.SignCount == 0,
            "Android wrong PIN consumes only one submission and never signs");

        ScriptedPhone unknown = new(key, raw) { UnknownToken = true };
        result = await Authenticate(unknown, SyntheticPin());
        Check(result.Status == CardAuthenticationStatus.CardNotRecognized && unknown.PinCount == 0,
            "Unrecognized phone never receives PIN");

        ScriptedPhone untrusted = new(key, raw);
        result = await new CardAuthentication(() => new AndroidCardModule(() => untrusted), _ => false)
            .AuthenticateAsync(SyntheticPin(), CancellationToken.None);
        Check(result.Status == CardAuthenticationStatus.InvalidCertificate && untrusted.PinCount == 1 && untrusted.SignCount == 0,
            "Untrusted Android certificate is rejected before signing");

        ScriptedPhone direct = new(key, raw) { WrongPin = true };
        using AndroidCardModule module = new(() => direct);
        module.GetSlots();
        module.Open(0);
        byte[] directPin = SyntheticPin();
        try { module.Login(directPin); module.Login(directPin); }
        finally { CryptographicOperations.ZeroMemory(directPin); }
        Check(direct.PinCount == 1, "Android adapter refuses a second VERIFY command");

        ScriptedPhone autoPhone = new(key, raw);
        result = await new CardAuthentication(() => new AutoCardModule(new AndroidCardModule(() => autoPhone, null),
            () => throw new InvalidOperationException("Physical path must not run for Android.")), _ => true)
            .AuthenticateAsync(SyntheticPin(), CancellationToken.None);
        Check(result.Status == CardAuthenticationStatus.Success && result.DetectedDevice == CardDevice.Android && autoPhone.PinCount == 1,
            "Automatic mode selects Android without invoking physical-card provider");

        ScriptedPhone physicalProbe = new(key, raw) { PhysicalToken = true };
        FakeModule physical = new(key, raw);
        result = await new CardAuthentication(() => new AutoCardModule(new AndroidCardModule(() => physicalProbe, null), () =>
        {
            if (!physicalProbe.Disposed) throw new InvalidOperationException("Probe must release NFC before opening JPKI.");
            return physical;
        }), _ => true).AuthenticateAsync(SyntheticPin(), CancellationToken.None);
        Check(result.Status == CardAuthenticationStatus.Success && result.DetectedDevice == CardDevice.PhysicalCard &&
            physicalProbe.PinCount == 0 && physical.LoginCount == 1 && physical.Disposed,
            "Automatic mode releases detection session and uses existing physical-card path");

        ScriptedPhone unknownAuto = new(key, raw) { UnknownToken = true };
        result = await new CardAuthentication(() => new AutoCardModule(new AndroidCardModule(() => unknownAuto, null),
            () => throw new InvalidOperationException("Unknown type must not select a provider.")), _ => true)
            .AuthenticateAsync(SyntheticPin(), CancellationToken.None);
        Check(result.Status == CardAuthenticationStatus.CardNotRecognized && unknownAuto.PinCount == 0,
            "Automatic mode sends no PIN to unknown token");

        ScriptedPhone badAutoPin = new(key, raw) { WrongPin = true };
        result = await new CardAuthentication(() => new AutoCardModule(new AndroidCardModule(() => badAutoPin, null),
            () => throw new InvalidOperationException("Wrong PIN must never trigger physical-card fallback.")), _ => true)
            .AuthenticateAsync(SyntheticPin(), CancellationToken.None);
        Check(result.Status == CardAuthenticationStatus.InvalidPin && badAutoPin.PinCount == 1 && badAutoPin.SignCount == 0,
            "Automatic mode never switches providers after wrong PIN");
    }

    private static byte[] SyntheticPin() => [(byte)'2', (byte)'4', (byte)'6', (byte)'8'];
    private static Task<CardAuthenticationResult> Authenticate(ScriptedPhone phone, byte[] pin) =>
        new CardAuthentication(() => new AndroidCardModule(() => phone), _ => true).AuthenticateAsync(pin, CancellationToken.None);
    private static void Check(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException(description);
        Console.WriteLine($"PASS: {description}");
    }

    private sealed class ScriptedPhone(RSA key, byte[] certificate) : IApduConnection
    {
        private ushort _file;
        private byte[]? _remaining;
        private bool _verified;
        public bool WrongPin { get; init; }
        public bool UnknownToken { get; init; }
        public bool PhysicalToken { get; init; }
        public int PinCount { get; private set; }
        public int SignCount { get; private set; }
        public byte[]? PinCommand { get; private set; }
        public bool Disposed { get; private set; }

        public byte[] Exchange(byte[] command, JpkiOperation operation)
        {
            if (command[1] == 0xA4)
            {
                if (command[2] == 2) _file = (ushort)((command[5] << 8) | command[6]);
                return [0x90, 0];
            }
            if (command[1] == 0xB0)
            {
                if (_file == 6) return UnknownToken ? [.. new byte[32], 0x90, 0] : PhysicalToken
                    ? [.. "JPKIAPICCTOKEN2                 "u8, 0x90, 0] : [.. "JPKIAPGPSETOKEN                 "u8, 0x90, 0];
                if (_file != 0xA) throw new InvalidOperationException("Unexpected file.");
                if (!_verified) return [0x69, 0x82];
                int offset = (command[2] << 8) | command[3];
                return [.. certificate.AsSpan(offset, command[4]), 0x90, 0];
            }
            if (command[1] == 0x20)
            {
                PinCount++;
                PinCommand = command;
                _verified = !WrongPin;
                return WrongPin ? [0x63, 0xC2] : [0x90, 0];
            }
            if (command[1] == 0x2A)
            {
                SignCount++;
                byte[] signature = key.SignHash(command.AsSpan(24, 32), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                _remaining = signature.AsSpan(128).ToArray();
                byte[] first = [.. signature.AsSpan(0, 128), 0x61, 0x80];
                CryptographicOperations.ZeroMemory(signature);
                return first;
            }
            if (command[1] == 0xC0 && _remaining is not null)
            {
                byte[] final = [.. _remaining, 0x90, 0];
                CryptographicOperations.ZeroMemory(_remaining);
                _remaining = null;
                return final;
            }
            throw new InvalidOperationException("Unexpected command.");
        }

        public void Dispose()
        {
            if (_remaining is not null) CryptographicOperations.ZeroMemory(_remaining);
            Disposed = true;
        }
    }
}
