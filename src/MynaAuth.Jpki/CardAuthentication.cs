using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MynaAuth.Jpki;

public enum CardAuthenticationStatus
{
    Success, InvalidPin, PinLocked, Cancelled, TimedOut, CardUnavailable,
    MultipleCards, LibraryUnavailable, InvalidCertificate, InvalidSignature, Failed, CardNotRecognized
}

// Intentionally excludes PIN, certificate, serial, public key, and signature.
public enum JpkiOperation
{
    Unknown, Initialize, GetSlots, GetSlotInfo, GetTokenInfo, OpenSession, Login, FindObjects, ReadCertificate, Sign,
    PcscConnect, AndroidSelectApplication, AndroidReadToken, AndroidVerifyPin, AndroidReadCertificate, AndroidSign
}

public enum CardDevice { PhysicalCard, Android, Automatic }

public sealed record JpkiFailure(JpkiOperation Operation, uint Code)
{
    public string Summary => $"{Operation}: {Code switch
    {
        0x32 => "CKR_DEVICE_REMOVED",
        0xE0 => "CKR_TOKEN_NOT_PRESENT",
        0xE1 => "CKR_TOKEN_NOT_RECOGNIZED",
        0xA0 => "CKR_PIN_INCORRECT",
        0xA4 => "CKR_PIN_LOCKED",
        _ => "CK_RV"
    }} (0x{Code:X8})";
}

public sealed record CardAuthenticationResult(CardAuthenticationStatus Status, JpkiFailure? Failure = null, CardDevice? DetectedDevice = null, string? CredentialId = null);

public sealed class CardAuthentication
{
    private static readonly SemaphoreSlim LibraryGate = new(1, 1);
    private readonly Func<IPkcs11Module> _factory;
    private readonly Func<X509Certificate2, bool> _trust;

    public CardAuthentication() : this(() => new Pkcs11Module(), CertificateTrust.IsTrusted) { }

    public CardAuthentication(CardDevice device) : this(device switch
    {
        CardDevice.PhysicalCard => () => new Pkcs11Module(),
        CardDevice.Android => () => new AndroidCardModule(),
        CardDevice.Automatic => () => new AutoCardModule(),
        _ => throw new ArgumentOutOfRangeException(nameof(device))
    }, CertificateTrust.IsTrusted) { }

    internal CardAuthentication(Func<IPkcs11Module> factory, Func<X509Certificate2, bool> trust)
    {
        _factory = factory;
        _trust = trust;
    }

    /// <summary>Takes ownership of pin, erasing it on every completion path. Never logs or persists data.</summary>
    public async Task<CardAuthenticationResult> AuthenticateAsync(byte[] pin, CancellationToken cancellationToken, IProgress<CardDevice>? detected = null)
    {
        bool entered = false;
        try
        {
            if (pin.Length != 4 || pin.Any(digit => digit is < (byte)'0' or > (byte)'9'))
                return new(CardAuthenticationStatus.InvalidPin);
            await LibraryGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            return await Task.Run(() => Authenticate(pin, cancellationToken, detected), cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { return new(CardAuthenticationStatus.Cancelled); }
        catch (DllNotFoundException) { return new(CardAuthenticationStatus.LibraryUnavailable); }
        catch (EntryPointNotFoundException) { return new(CardAuthenticationStatus.LibraryUnavailable); }
        catch (BadImageFormatException) { return new(CardAuthenticationStatus.LibraryUnavailable); }
        catch (Pkcs11Exception error) { return new(MapStatus(error.Code), new(error.Operation, error.Code)); }
        catch (CryptographicException) { return new(CardAuthenticationStatus.InvalidCertificate); }
        finally
        {
            CryptographicOperations.ZeroMemory(pin);
            if (entered)
                LibraryGate.Release();
        }
    }

    private CardAuthenticationResult Authenticate(byte[] pin, CancellationToken cancellationToken, IProgress<CardDevice>? detected)
    {
        using IPkcs11Module module = _factory();
        DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddSeconds(60);
        uint[] slots;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= expiresAt)
                return new(CardAuthenticationStatus.TimedOut);
            slots = module.GetSlots();
            if (slots.Length > 0)
                break;
            cancellationToken.WaitHandle.WaitOne(200);
        }
        if (slots.Length != 1)
            return new(CardAuthenticationStatus.MultipleCards);
        module.Open(slots[0]);
        if (module.DetectedDevice is CardDevice device) detected?.Report(device);
        cancellationToken.ThrowIfCancellationRequested();
        if (DateTimeOffset.UtcNow >= expiresAt)
            return new(CardAuthenticationStatus.TimedOut);
        byte[] certificateBytes = [];
        byte[] challenge = [];
        byte[]? digestInfo = null;
        byte[]? signature = null;
        try
        {
            // The S25 requires PIN verification before it permits reading the certificate.
            // AndroidCardModule.Open identifies the Android token without submitting a PIN.
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= expiresAt) return new(CardAuthenticationStatus.TimedOut);
            // Exactly one PIN submission per explicitly initiated attempt. Never retry on failure.
            uint login;
            try { login = module.Login(pin); }
            finally { CryptographicOperations.ZeroMemory(pin); }
            if (login != 0) return new(MapStatus(login), new(JpkiOperation.Login, login), module.DetectedDevice);
            cancellationToken.ThrowIfCancellationRequested();
            if (certificateBytes.Length == 0) certificateBytes = module.Certificate();
            challenge = RandomNumberGenerator.GetBytes(32);
            using X509Certificate2 certificate = new(certificateBytes);
            if (!_trust(certificate))
                return new(CardAuthenticationStatus.InvalidCertificate);
            using RSA? rsa = certificate.GetRSAPublicKey();
            if (rsa is null || rsa.KeySize != 2048)
                return new(CardAuthenticationStatus.InvalidCertificate);
            digestInfo = CreateDigestInfo(challenge);
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= expiresAt)
                return new(CardAuthenticationStatus.TimedOut);
            signature = module.Sign(digestInfo);
            cancellationToken.ThrowIfCancellationRequested();
            if (DateTimeOffset.UtcNow >= expiresAt)
                return new(CardAuthenticationStatus.TimedOut);
            bool valid = rsa.VerifyData(challenge, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            byte[] publicKey = rsa.ExportSubjectPublicKeyInfo();
            try
            {
                return new(valid ? CardAuthenticationStatus.Success : CardAuthenticationStatus.InvalidSignature,
                    DetectedDevice: module.DetectedDevice, CredentialId: valid ? Convert.ToHexString(SHA256.HashData(publicKey)) : null);
            }
            finally { CryptographicOperations.ZeroMemory(publicKey); }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(certificateBytes);
            CryptographicOperations.ZeroMemory(challenge);
            if (digestInfo is not null) CryptographicOperations.ZeroMemory(digestInfo);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
        }
    }

    internal static byte[] CreateDigestInfo(byte[] challenge)
    {
        byte[] hash = SHA256.HashData(challenge);
        try { return [.. Convert.FromHexString("3031300D060960864801650304020105000420"), .. hash]; }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }

    internal static CardAuthenticationStatus MapStatus(uint code) => code switch
    {
        0xA0 or 0xA1 or 0xA2 => CardAuthenticationStatus.InvalidPin,
        0xA4 => CardAuthenticationStatus.PinLocked,
        0x32 or 0xE0 or 0x80100069 or 0x8010000C or 0x80100017 => CardAuthenticationStatus.CardUnavailable,
        0xE1 => CardAuthenticationStatus.CardNotRecognized,
        // CKR_USER_ALREADY_LOGGED_IN is not accepted as evidence that this PIN was checked.
        _ => CardAuthenticationStatus.Failed
    };
}

internal static class CertificateTrust
{
    // Public trust anchors only. Fingerprints published by J-LIS, not cardholder certificates.
    private static readonly (string Resource, string Hash)[] Roots =
    [
        ("authca02.cer", "0D98DE47FC11B7F67126874B7028B6026A803D2638D6EDFE53176953961FADE6"),
        ("authca03.cer", "64114F29620C24ED2631D46476A040E7EE740D956089C00B036A6A8118C322B5")
    ];

    public static bool IsTrusted(X509Certificate2 certificate)
    {
        DateTime now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime())
            return false;
        X509BasicConstraintsExtension? constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        X509KeyUsageExtension? usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (constraints?.CertificateAuthority == true || usage is null ||
            (usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
            return false;

        using X509Chain chain = new();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        List<X509Certificate2> roots = [];
        try
        {
            foreach ((string resource, string hash) in Roots)
            {
                using Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream($"MynaAuth.Jpki.Roots.{resource}")
                    ?? throw new CryptographicException();
                using MemoryStream bytes = new();
                stream.CopyTo(bytes);
                byte[] raw = bytes.ToArray();
                if (!Convert.ToHexString(SHA256.HashData(raw)).Equals(hash, StringComparison.Ordinal))
                    return false;
                X509Certificate2 root = new(raw);
                roots.Add(root);
                chain.ChainPolicy.CustomTrustStore.Add(root);
            }
            return chain.Build(certificate);
        }
        finally { foreach (X509Certificate2 root in roots) root.Dispose(); }
    }
}
