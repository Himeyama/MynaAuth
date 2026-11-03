using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace MynaAuth.Probe;

/// <summary>Lists PC/SC readers without connecting to a card or submitting a PIN.</summary>
[SupportedOSPlatform("windows")]
internal static class ReaderDiagnostics
{
    public static int Run()
    {
        int status = SCardEstablishContext(0, IntPtr.Zero, IntPtr.Zero, out IntPtr context);
        if (status != 0)
            return Report(status);
        try
        {
            uint length = 0;
            status = SCardListReaders(context, null, null, ref length);
            if (status != 0)
                return Report(status);
            if (length is 0 or > 65536)
            {
                Console.WriteLine("リーダー一覧のサイズが不正です。");
                return 1;
            }
            char[] buffer = new char[length];
            status = SCardListReaders(context, null, buffer, ref length);
            if (status != 0)
                return Report(status);
            string[] readers = new string(buffer).Split('\0', StringSplitOptions.RemoveEmptyEntries);
            Console.WriteLine($"PC/SC リーダー: {readers.Length} 台");
            foreach (string reader in readers)
                Console.WriteLine(reader);
            Console.WriteLine("機器名の列挙のみです。カード・スマホの認証対応を保証する結果ではありません。");
            return 0;
        }
        finally
        {
            _ = SCardReleaseContext(context);
        }
    }

    private static int Report(int status)
    {
        Console.WriteLine(unchecked((uint)status) switch
        {
            0x8010002E => "PC/SC リーダーがありません。RC-S300 の USB 接続と NFC ポートソフトウェアを確認してください。",
            0x8010001D => "Smart Card サービスが利用できません。Windows のサービス状態を確認してください。",
            _ => $"PC/SC の確認に失敗しました (0x{status:X8})。"
        });
        return 1;
    }

    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr context);

    [DllImport("winscard.dll", EntryPoint = "SCardListReadersW", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int SCardListReaders(IntPtr context, string? groups, [Out] char[]? readers, ref uint length);

    [DllImport("winscard.dll", ExactSpelling = true)]
    private static extern int SCardReleaseContext(IntPtr context);
}
