using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace MynaAuth.Jpki;

internal interface IApduConnection : IDisposable
{
    byte[] Exchange(byte[] command, JpkiOperation operation);
}

internal sealed class PcscConnection : IApduConnection
{
    private IntPtr _context;
    private IntPtr _card;
    private uint _protocol;
    private bool _transaction;

    public PcscConnection()
    {
        Ensure(SCardEstablishContext(0, IntPtr.Zero, IntPtr.Zero, out _context));
        try
        {
            uint length = 0;
            Ensure(SCardListReaders(_context, null, null, ref length));
            if (length is 0 or > 65536) throw new Pkcs11Exception(0xE0, JpkiOperation.PcscConnect);
            char[] names = new char[length];
            Ensure(SCardListReaders(_context, null, names, ref length));
            string[] readers = new string(names).Split('\0', StringSplitOptions.RemoveEmptyEntries);
            if (readers.Length != 1) throw new Pkcs11Exception(0x6, JpkiOperation.PcscConnect);
            Ensure(SCardConnect(_context, readers[0], 2, 3, out _card, out _protocol));
            Ensure(SCardBeginTransaction(_card));
            _transaction = true;
        }
        catch { Dispose(); throw; }
    }

    public byte[] Exchange(byte[] command, JpkiOperation operation)
    {
        byte[] response = new byte[4096];
        uint length = (uint)response.Length;
        IoRequest request = new() { Protocol = _protocol, Length = 8 };
        try
        {
            int status = SCardTransmit(_card, ref request, command, (uint)command.Length,
                IntPtr.Zero, response, ref length);
            if (status != 0) throw new Pkcs11Exception(unchecked((uint)status), operation);
            if (length is < 2 or > 4096) throw new Pkcs11Exception(0x6, operation);
            return response.AsSpan(0, (int)length).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(response); }
    }

    private static void Ensure(int status)
    {
        if (status != 0) throw new Pkcs11Exception(unchecked((uint)status), JpkiOperation.PcscConnect);
    }

    public void Dispose()
    {
        if (_transaction) { _ = SCardEndTransaction(_card, 1); _transaction = false; }
        if (_card != IntPtr.Zero) { _ = SCardDisconnect(_card, 1); _card = IntPtr.Zero; }
        if (_context != IntPtr.Zero) { _ = SCardReleaseContext(_context); _context = IntPtr.Zero; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoRequest { public uint Protocol; public uint Length; }
    [DllImport("winscard.dll", ExactSpelling = true)] private static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);
    [DllImport("winscard.dll", EntryPoint = "SCardListReadersW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardListReaders(IntPtr context, string? groups, [Out] char[]? readers, ref uint length);
    [DllImport("winscard.dll", EntryPoint = "SCardConnectW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardConnect(IntPtr context, string reader, uint share, uint protocols, out IntPtr card, out uint protocol);
    [DllImport("winscard.dll", ExactSpelling = true)] private static extern int SCardBeginTransaction(IntPtr card);
    [DllImport("winscard.dll", ExactSpelling = true)] private static extern int SCardEndTransaction(IntPtr card, uint disposition);
    [DllImport("winscard.dll", ExactSpelling = true)] private static extern int SCardDisconnect(IntPtr card, uint disposition);
    [DllImport("winscard.dll", ExactSpelling = true)] private static extern int SCardReleaseContext(IntPtr context);
    [DllImport("winscard.dll", ExactSpelling = true)] private static extern int SCardTransmit(IntPtr card, ref IoRequest sendPci,
        [In] byte[] send, uint sendLength, IntPtr receivePci, [Out] byte[] receive, ref uint receiveLength);
}
