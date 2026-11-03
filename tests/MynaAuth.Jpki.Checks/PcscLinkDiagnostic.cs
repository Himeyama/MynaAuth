using System.Runtime.InteropServices;

namespace MynaAuth.Jpki.Checks;

internal static class PcscLinkDiagnostic
{
    public static void Run()
    {
        int result = SCardEstablishContext(0, IntPtr.Zero, IntPtr.Zero, out IntPtr context);
        Console.WriteLine($"PC/SC context: 0x{result:X8}");
        if (result != 0) return;
        try
        {
            uint length = 0;
            result = SCardListReaders(context, null, null, ref length);
            if (result != 0 || length is 0 or > 65536)
            {
                Console.WriteLine($"Reader enumeration: 0x{result:X8}");
                return;
            }
            char[] names = new char[length];
            result = SCardListReaders(context, null, names, ref length);
            if (result != 0) { Console.WriteLine($"Reader enumeration: 0x{result:X8}"); return; }
            string[] readers = new string(names).Split('\0', StringSplitOptions.RemoveEmptyEntries);
            Console.WriteLine($"PC/SC readers: {readers.Length}");
            foreach (string reader in readers)
            {
                result = SCardConnect(context, reader, 2, 3, out IntPtr card, out uint protocol);
                Console.WriteLine($"PC/SC connect: 0x{result:X8}; negotiated protocol={protocol}");
                if (result == 0) _ = SCardDisconnect(card, 0);
            }
        }
        finally { _ = SCardReleaseContext(context); }
        Console.WriteLine("No commands, PINs or certificate requests sent.");
    }

    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);
    [DllImport("winscard.dll", EntryPoint = "SCardListReadersW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardListReaders(IntPtr context, string? groups, [Out] char[]? readers, ref uint length);
    [DllImport("winscard.dll", EntryPoint = "SCardConnectW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardConnect(IntPtr context, string reader, uint share, uint protocols, out IntPtr card, out uint protocol);
    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardDisconnect(IntPtr card, uint disposition);
    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardReleaseContext(IntPtr context);
}
