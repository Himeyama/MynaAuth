using System.Security.Cryptography;

namespace MynaAuth.Core;

public enum AuthenticationState { AwaitingPin, AwaitingCard, Verifying, Verified, Failed, Cancelled }
public enum CredentialMedium { PhysicalCard, AndroidCertificate }
public enum ProofStatus { Success, InvalidPin, PinLocked, Unavailable, Failed }

// An SDK adapter must verify PIN on the card and return a signature made by
// the authentication private key. A PIN match in application code is insufficient.
public interface ICardAuthenticator
{
    Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken);
}

public sealed record CardProof(ProofStatus Status, byte[]? Signature = null);

/// <summary>One attempt, bound to a previously enrolled public key. Never performs Windows logon.</summary>
public sealed class AuthenticationSession(ICardAuthenticator authenticator, byte[] enrolledPublicKey,
    TimeProvider? timeProvider = null) : IDisposable
{
    private readonly byte[] _publicKey = enrolledPublicKey.ToArray();
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly byte[] _challenge = RandomNumberGenerator.GetBytes(32);
    private byte[]? _pin;
    private DateTimeOffset _expiresAt;
    private bool _disposed;

    public AuthenticationState State { get; private set; } = AuthenticationState.AwaitingPin;

    public bool SubmitPin(ReadOnlySpan<char> pin)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (State != AuthenticationState.AwaitingPin || pin.Length != 4)
            return false;
        foreach (char digit in pin)
        {
            if (digit is < '0' or > '9')
                return false;
        }

        _pin = new byte[4];
        for (int index = 0; index < pin.Length; index++)
            _pin[index] = (byte)pin[index];
        _expiresAt = _clock.GetUtcNow().AddSeconds(60);
        State = AuthenticationState.AwaitingCard;
        return true;
    }

    public async Task<ProofStatus> AuthenticateAsync(CredentialMedium medium, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (State != AuthenticationState.AwaitingCard || _pin is null)
            return ProofStatus.Failed;

        State = AuthenticationState.Verifying;
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        TimeSpan remaining = _expiresAt - _clock.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
        {
            ClearPin();
            State = AuthenticationState.Failed;
            return ProofStatus.Failed;
        }
        timeout.CancelAfter(remaining);

        try
        {
            // No automatic retry: a wrong JPKI PIN consumes a card-side attempt.
            CardProof proof = await authenticator.AuthenticateAsync(medium, _pin, _challenge, timeout.Token)
                .ConfigureAwait(false);
            timeout.Token.ThrowIfCancellationRequested();
            if (_disposed || _clock.GetUtcNow() >= _expiresAt)
            {
                State = AuthenticationState.Failed;
                return ProofStatus.Failed;
            }
            if (proof.Status != ProofStatus.Success)
            {
                State = AuthenticationState.Failed;
                return proof.Status;
            }

            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(_publicKey, out int bytesRead);
            bool valid = bytesRead == _publicKey.Length && proof.Signature is not null &&
                rsa.VerifyData(_challenge, proof.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            State = valid ? AuthenticationState.Verified : AuthenticationState.Failed;
            return valid ? ProofStatus.Success : ProofStatus.Failed;
        }
        catch (OperationCanceledException)
        {
            State = AuthenticationState.Cancelled;
            return ProofStatus.Failed;
        }
        catch (CryptographicException)
        {
            State = AuthenticationState.Failed;
            return ProofStatus.Failed;
        }
        catch
        {
            State = AuthenticationState.Failed;
            throw;
        }
        finally
        {
            ClearPin();
        }
    }

    private void ClearPin()
    {
        if (_pin is not null)
            CryptographicOperations.ZeroMemory(_pin);
        _pin = null;
    }

    public void Dispose()
    {
        _disposed = true;
        // Call after the asynchronous operation completes; the adapter may still own the PIN view.
        ClearPin();
        CryptographicOperations.ZeroMemory(_challenge);
        if (State is AuthenticationState.AwaitingPin or AuthenticationState.AwaitingCard)
            State = AuthenticationState.Cancelled;
    }
}
