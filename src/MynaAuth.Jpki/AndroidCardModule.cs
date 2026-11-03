using System.Security.Cryptography;

namespace MynaAuth.Jpki;

// A separate, explicit transport: never falls back after submitting a PIN.
internal sealed class AndroidCardModule : IPkcs11Module
{
    private readonly Func<IApduConnection> _factory;
    private readonly CardDevice? _expectedDevice;
    private IApduConnection? _connection;
    private bool _identified;
    private bool _pinSubmitted;
    private bool _authenticated;
    private bool _signatureRequested;

    public AndroidCardModule() : this(() => new PcscConnection()) { }
    internal AndroidCardModule(Func<IApduConnection> factory, CardDevice? expectedDevice = CardDevice.Android)
    {
        _factory = factory;
        _expectedDevice = expectedDevice;
    }
    public CardDevice? DetectedDevice { get; private set; }

    public uint[] GetSlots()
    {
        if (_connection is not null) return [0];
        try { _connection = _factory(); return [0]; }
        catch (Pkcs11Exception error) when (error.Code is 0x8010000C or 0x80100069 or 0x80100010 or 0x80100017 or 0x8010002E)
        { return []; }
    }

    public void Open(uint slot)
    {
        Check([0x00, 0xA4, 0x04, 0x0C, 0x0A, 0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01], JpkiOperation.AndroidSelectApplication);
        Select(0x0006, JpkiOperation.AndroidReadToken);
        byte[] token = Call([0x00, 0xB0, 0x00, 0x00, 0x20], JpkiOperation.AndroidReadToken);
        try
        {
            // Only the public 32-byte type name is read, not serial numbers or certificate data.
            DetectedDevice = IdentifyDevice(token);
            if (DetectedDevice is null || (_expectedDevice is not null && DetectedDevice != _expectedDevice))
                throw new Pkcs11Exception(0xE1, JpkiOperation.AndroidReadToken);
            _identified = true;
        }
        finally { CryptographicOperations.ZeroMemory(token); }
    }

    internal static CardDevice? IdentifyDevice(ReadOnlySpan<byte> token) => token switch
    {
        _ when token.SequenceEqual("JPKIAPGPSETOKEN                 "u8) => CardDevice.Android,
        _ when token.SequenceEqual("JPKIAPICCTOKEN2                 "u8) => CardDevice.PhysicalCard,
        _ => null
    };

    public uint Login(byte[] pin)
    {
        if (!_identified || _pinSubmitted || pin.Length != 4 || pin.Any(digit => digit is < (byte)'0' or > (byte)'9'))
            return 0x6;
        Select(0x0018, JpkiOperation.AndroidVerifyPin);
        byte[] command = new byte[9];
        command[0] = 0; command[1] = 0x20; command[2] = 0; command[3] = 0x80; command[4] = 4;
        pin.CopyTo(command, 5);
        _pinSubmitted = true;
        try
        {
            byte[] data = Call(command, JpkiOperation.AndroidVerifyPin);
            CryptographicOperations.ZeroMemory(data);
            _authenticated = true;
            return 0;
        }
        catch (Pkcs11Exception error) when ((error.Code & 0xFFF0) == 0x63C0 || error.Code == 0x6983)
        { return error.Code is 0x63C0 or 0x6983 ? 0xA4u : 0xA0u; }
        finally { CryptographicOperations.ZeroMemory(command); }
    }

    public byte[] Certificate()
    {
        Select(0x000A, JpkiOperation.AndroidReadCertificate);
        byte[] header = Read(0, 4);
        int size;
        try
        {
            if (header.Length != 4 || header[0] != 0x30 || header[1] != 0x82)
                throw new Pkcs11Exception(0x6, JpkiOperation.AndroidReadCertificate);
            size = 4 + (header[2] << 8) + header[3];
            if (size is < 256 or > 8192) throw new Pkcs11Exception(0x6, JpkiOperation.AndroidReadCertificate);
        }
        finally { CryptographicOperations.ZeroMemory(header); }
        byte[] certificate = new byte[size];
        try
        {
            for (int offset = 0; offset < size;)
            {
                int count = Math.Min(240, size - offset);
                byte[] part = Read(offset, count);
                try
                {
                    if (part.Length != count) throw new Pkcs11Exception(0x6, JpkiOperation.AndroidReadCertificate);
                    part.CopyTo(certificate, offset);
                    offset += part.Length;
                }
                finally { CryptographicOperations.ZeroMemory(part); }
            }
            return certificate;
        }
        catch { CryptographicOperations.ZeroMemory(certificate); throw; }
    }

    public byte[] Sign(byte[] digestInfo)
    {
        if (!_authenticated || _signatureRequested) throw new Pkcs11Exception(0x101, JpkiOperation.AndroidSign);
        _signatureRequested = true;
        Select(0x0017, JpkiOperation.AndroidSign);
        byte[] command = new byte[6 + digestInfo.Length];
        command[0] = 0x80; command[1] = 0x2A; command[2] = 0; command[3] = 0x80;
        command[4] = checked((byte)digestInfo.Length);
        digestInfo.CopyTo(command, 5);
        try { return Call(command, JpkiOperation.AndroidSign); }
        finally { CryptographicOperations.ZeroMemory(command); }
    }

    private byte[] Read(int offset, int count) => Call([0x00, 0xB0, (byte)(offset >> 8), (byte)offset, (byte)count], JpkiOperation.AndroidReadCertificate);
    private void Select(ushort id, JpkiOperation operation) => Check([0x00, 0xA4, 0x02, 0x0C, 0x02, (byte)(id >> 8), (byte)id], operation);
    private void Check(byte[] command, JpkiOperation operation)
    {
        byte[] data = Call(command, operation);
        CryptographicOperations.ZeroMemory(data);
    }

    private byte[] Call(byte[] command, JpkiOperation operation)
    {
        if (_connection is null) throw new Pkcs11Exception(0xE0, operation);
        byte[] collected = new byte[8192];
        int size = 0;
        byte[] request = command;
        try
        {
            for (int part = 0; part < 32; part++)
            {
                byte[] response = _connection.Exchange(request, operation);
                try
                {
                    if (response.Length < 2 || size + response.Length - 2 > collected.Length)
                        throw new Pkcs11Exception(0x6, operation);
                    uint status = (uint)((response[^2] << 8) | response[^1]);
                    if (status != 0x9000 && (status >> 8) != 0x61) throw new Pkcs11Exception(status, operation);
                    response.AsSpan(0, response.Length - 2).CopyTo(collected.AsSpan(size));
                    size += response.Length - 2;
                    if (status == 0x9000) return collected.AsSpan(0, size).ToArray();
                    // Continue the response, never repeat a VERIFY or SIGN command.
                    request = [0x00, 0xC0, 0x00, 0x00, (byte)status];
                }
                finally { CryptographicOperations.ZeroMemory(response); }
            }
            throw new Pkcs11Exception(0x6, operation);
        }
        finally { CryptographicOperations.ZeroMemory(collected); }
    }

    public void Dispose()
    {
        _identified = false;
        _authenticated = false;
        _connection?.Dispose();
        _connection = null;
    }
}
