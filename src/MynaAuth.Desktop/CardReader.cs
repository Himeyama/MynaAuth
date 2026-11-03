using System.Runtime.InteropServices;

namespace MynaAuth.Desktop;

internal sealed record ReaderSnapshot(string[] Names, string? Error);

internal static class CardReader
{
    public static ReaderSnapshot Discover()
    {
        int result = SCardEstablishContext(0, IntPtr.Zero, IntPtr.Zero, out IntPtr context);
        if (result != 0)
            return new([], Explain(result));
        try
        {
            uint length = 0;
            result = SCardListReaders(context, null, null, ref length);
            if (result != 0)
                return new([], Explain(result));
            if (length is 0 or > 65536)
                return new([], "リーダー一覧を取得できません。");
            char[] names = new char[length];
            result = SCardListReaders(context, null, names, ref length);
            return result == 0 ? new(new string(names).Split('\0', StringSplitOptions.RemoveEmptyEntries), null)
                : new([], Explain(result));
        }
        finally { _ = SCardReleaseContext(context); }
    }

    public static bool IsPresent(string reader)
    {
        int result = SCardEstablishContext(0, IntPtr.Zero, IntPtr.Zero, out IntPtr context);
        if (result != 0)
            return false;
        try
        {
            ReaderState[] states = [new() { Reader = reader, Atr = new byte[36] }];
            result = SCardGetStatusChange(context, 0, states, 1);
            return result == 0 && (states[0].EventState & 0x20) != 0 &&
                (states[0].EventState & (0x1 | 0x4 | 0x8 | 0x10)) == 0;
        }
        finally { _ = SCardReleaseContext(context); }
    }

    private static string Explain(int code) => unchecked((uint)code) switch
    {
        0x8010002E => "リーダー未接続。RC-S300 の接続を確認してください。",
        0x8010001D => "Smart Card サービスを利用できません。",
        _ => $"リーダー確認エラー (0x{code:X8})"
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ReaderState
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Reader;
        public IntPtr UserData;
        public uint CurrentState;
        public uint EventState;
        public uint AtrLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 36)] public byte[] Atr;
    }

    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);
    [DllImport("winscard.dll", EntryPoint = "SCardListReadersW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardListReaders(IntPtr context, string? groups, [Out] char[]? readers, ref uint length);
    [DllImport("winscard.dll", EntryPoint = "SCardGetStatusChangeW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardGetStatusChange(IntPtr context, uint timeout, [In, Out] ReaderState[] states, uint count);
    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardReleaseContext(IntPtr context);
}
