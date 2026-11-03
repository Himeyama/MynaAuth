using MynaAuth.Core;
using MynaAuth.Probe;
using System.Security.Cryptography;

Console.OutputEncoding = System.Text.Encoding.UTF8;
if (args is ["--readers"])
{
    if (!OperatingSystem.IsWindows())
    {
        Console.WriteLine("リーダー診断は Windows 専用です。");
        Environment.ExitCode = 1;
        return;
    }
    Environment.ExitCode = ReaderDiagnostics.Run();
    return;
}
if (args is not ["--simulate"])
{
    Console.WriteLine("MynaAuth 検証アプリ。実カード・Android・Windows ログイン接続は未実装です。");
    Console.WriteLine("画面遷移の検証: dotnet run --project src/MynaAuth.Probe -- --simulate");
    Console.WriteLine("リーダー接続確認: dotnet run --project src/MynaAuth.Probe -- --readers");
    return;
}

Console.WriteLine("シミュレーション専用：実カードの PIN は入力しないでください。");
Console.WriteLine("任意の数字4桁を入力してください（保存されません）。");
char[] pin = new char[4];
int length = 0;
while (true)
{
    ConsoleKeyInfo key = Console.ReadKey(true);
    if (key.Key == ConsoleKey.Escape)
    {
        Array.Clear(pin);
        return;
    }
    if (key.Key == ConsoleKey.Enter && length == 4)
        break;
    if (key.Key == ConsoleKey.Backspace && length > 0)
        pin[--length] = '\0';
    else if (key.KeyChar is >= '0' and <= '9' && length < 4)
        pin[length++] = key.KeyChar;
}

using RSA simulatedCard = RSA.Create(2048);
using AuthenticationSession session = new(new SimulationAuthenticator(simulatedCard), simulatedCard.ExportSubjectPublicKeyInfo());
bool accepted = session.SubmitPin(pin);
Array.Clear(pin);
if (!accepted)
    return;
Console.WriteLine("カードをかざしてください（シミュレーションでは Enter、Esc で終了）。");
if (Console.ReadKey(true).Key != ConsoleKey.Enter)
    return;
ProofStatus result = await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None);
Console.WriteLine(result == ProofStatus.Success
    ? "模擬署名の検証成功。Windows ログインは行いません。"
    : "検証失敗。");

internal sealed class SimulationAuthenticator(RSA key) : ICardAuthenticator
{
    public Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new CardProof(ProofStatus.Success,
            key.SignData(challenge.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
    }
}
