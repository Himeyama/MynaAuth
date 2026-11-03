using MynaAuth.Core;
using System.Security.Cryptography;

using RSA enrolled = RSA.Create(2048);
using RSA foreign = RSA.Create(2048);
byte[] publicKey = enrolled.ExportSubjectPublicKeyInfo();

using (AuthenticationSession session = new(new SigningCard(enrolled), publicKey))
{
    Check(!session.SubmitPin("１２３４"), "Reject non-ASCII PIN");
    Check(!session.SubmitPin("123"), "Reject short PIN");
    Check(session.SubmitPin("1234"), "Accept four digits");
    Check(await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None) == ProofStatus.Success,
        "Verify enrolled key");
    Check(await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None) == ProofStatus.Failed,
        "Prevent reuse");
}
using (AuthenticationSession session = new(new SigningCard(foreign), publicKey))
{
    session.SubmitPin("1234");
    Check(await session.AuthenticateAsync(CredentialMedium.AndroidCertificate, CancellationToken.None) == ProofStatus.Failed,
        "Reject unregistered key");
}
FailingCard failing = new();
using (AuthenticationSession session = new(failing, publicKey))
{
    session.SubmitPin("1234");
    Check(await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None) == ProofStatus.InvalidPin,
        "Report invalid PIN");
    await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None);
    Check(failing.Attempts == 1, "Never retry PIN");
    Check(failing.PinView.Span.ToArray().All(value => value == 0), "Erase PIN after adapter returns");
}
using (AuthenticationSession first = new(new SigningCard(enrolled), publicKey))
{
    first.SubmitPin("1234");
    CapturingCard capture = new(enrolled);
    using AuthenticationSession captured = new(capture, publicKey);
    captured.SubmitPin("1234");
    await captured.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None);
    using AuthenticationSession replay = new(new ReplayCard(capture.Signature!), publicKey);
    replay.SubmitPin("1234");
    Check(await replay.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None) == ProofStatus.Failed,
        "Reject proof from a different session");
}
using (AuthenticationSession session = new(new SigningCard(enrolled), publicKey))
{
    session.SubmitPin("1234");
    using CancellationTokenSource cancelled = new();
    cancelled.Cancel();
    Check(await session.AuthenticateAsync(CredentialMedium.PhysicalCard, cancelled.Token) == ProofStatus.Failed &&
        session.State == AuthenticationState.Cancelled, "Fail closed on cancellation");
}
ManualClock clock = new();
FailingCard expiredCard = new();
using (AuthenticationSession session = new(expiredCard, publicKey, clock))
{
    session.SubmitPin("1234");
    clock.Now = clock.Now.AddMinutes(2);
    Check(await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None) == ProofStatus.Failed &&
        expiredCard.Attempts == 0, "Do not submit PIN after expiration");
}
Console.WriteLine("All authentication checks passed.");

static void Check(bool condition, string description)
{
    if (!condition)
        throw new InvalidOperationException(description);
    Console.WriteLine($"PASS: {description}");
}

internal sealed class SigningCard(RSA key) : ICardAuthenticator
{
    public Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new CardProof(ProofStatus.Success,
            key.SignData(challenge.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
    }
}
internal sealed class FailingCard : ICardAuthenticator
{
    public int Attempts { get; private set; }
    public ReadOnlyMemory<byte> PinView { get; private set; }
    public Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        Attempts++;
        PinView = pin;
        return Task.FromResult(new CardProof(ProofStatus.InvalidPin));
    }
}
internal sealed class CapturingCard(RSA key) : ICardAuthenticator
{
    public byte[]? Signature { get; private set; }
    public Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        Signature = key.SignData(challenge.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Task.FromResult(new CardProof(ProofStatus.Success, Signature));
    }
}
internal sealed class ReplayCard(byte[] signature) : ICardAuthenticator
{
    public Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken) =>
        Task.FromResult(new CardProof(ProofStatus.Success, signature));
}
internal sealed class ManualClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
    public override DateTimeOffset GetUtcNow() => Now;
}
