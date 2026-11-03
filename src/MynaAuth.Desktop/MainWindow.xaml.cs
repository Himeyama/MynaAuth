using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using MynaAuth.Core;
using MynaAuth.Jpki;

namespace MynaAuth.Desktop;

public partial class MainWindow : Window
{
    private readonly RSA _demoKey = RSA.Create(2048);
    private readonly DispatcherTimer _expiryTimer = new() { Interval = TimeSpan.FromSeconds(1) };
    private AuthenticationSession? _session;
    private CancellationTokenSource? _pending;
    private string[] _readers = [];
    private bool _waiting;
    private bool _busy;
    private bool _closed;
    private DateTimeOffset _expiresAt;

    public MainWindow()
    {
        InitializeComponent();
        _expiryTimer.Tick += ExpiryTimer_Tick;
        Reset();
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e) => await RefreshReadersAsync();

    private void Reset()
    {
        _expiryTimer.Stop();
        _pending?.Cancel();
        _waiting = false;
        _session?.Dispose();
        _session = null;
        Pin.Clear();
        Pin.Visibility = Visibility.Visible;
        Heading.Text = "4桁の PIN を入力";
        Description.Text = Mode.SelectedIndex == 4
            ? "かざすカードまたはスマホの利用者証明用 PIN（数字4桁）を入力してください。両者の PIN は異なる場合があります。3回連続の誤入力でロックされます。"
            : Mode.SelectedIndex == 3
            ? "スマホ用の利用者証明用 PIN（数字4桁）を入力してください。カード用と異なる場合があります。3回連続の誤入力でロックされます。"
            : Mode.SelectedIndex == 2
            ? "利用者証明用の数字4桁を入力してください。\n3回連続の誤入力でロックされます。自動再試行はしません。"
            : "操作確認用の数字4桁を入力してください。\n実際のカードの PIN は使わないでください。";
        ModeDescription.Text = Mode.SelectedIndex switch
        {
            0 => "カードなしで入力から認証結果まで試せます。起動ごとに作る模擬鍵で署名を検証します。",
            2 => "実物カードの PIN と秘密鍵の所持を確認します。証明書の発行元・期限も検証します。オンライン失効確認は対象外です。",
            3 => "Android 内の電子証明書を使います。スマホの種類を確認して PIN を1回照合し、証明書と署名を検証します。オンライン失効確認は対象外です。",
            4 => "実物カードか Android かを PIN 送信前に自動判別します。認識できない媒体には PIN を送らず、別の方式で再試行もしません。",
            _ => "RC-S300 への提示だけを検出します。PIN 送信・カードの種類の判別・本人認証は行いません。"
        };
        Symbol.Text = "◇";
        Status.Text = "";
        Next.Content = "カード提示へ";
        Next.IsEnabled = false;
        SetStep(1);
        StepTwo.Text = Mode.SelectedIndex == 3 ? "02  スマホ提示" : "02  カード提示";
    }

    private void SetStep(int step)
    {
        StepOne.Foreground = step == 1 ? Brushes.SeaGreen : Brushes.Gray;
        StepTwo.Foreground = step == 2 ? Brushes.SeaGreen : Brushes.Gray;
        StepThree.Foreground = step == 3 ? Brushes.SeaGreen : Brushes.Gray;
    }

    private async Task RefreshReadersAsync()
    {
        ReaderSnapshot snapshot = await Task.Run(CardReader.Discover);
        if (_closed)
            return;
        _readers = snapshot.Names;
        ReaderName.Text = snapshot.Error ?? string.Join("\n", snapshot.Names);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshReadersAsync();

    private void Mode_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Pin is not null && !_busy)
            Reset();
    }

    private void Pin_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (Next is not null && !_waiting && !_busy)
            Next.IsEnabled = Pin.SecurePassword.Length == 4;
    }

    private void Pin_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Next.IsEnabled)
            Next_Click(sender, e);
    }

    private static char[] ReadPin(PasswordBox input)
    {
        using SecureString password = input.SecurePassword;
        IntPtr buffer = Marshal.SecureStringToGlobalAllocUnicode(password);
        try
        {
            char[] digits = new char[password.Length];
            Marshal.Copy(buffer, digits, 0, digits.Length);
            return digits;
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(buffer); }
    }

    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;
        if (!_waiting)
        {
            char[] digits = ReadPin(Pin);
            byte[]? realPin = null;
            try
            {
                if (digits.Length != 4 || digits.Any(digit => digit is < '0' or > '9'))
                {
                    Status.Text = "半角の数字4桁を入力してください。";
                    Pin.Clear();
                    return;
                }
                if (Mode.SelectedIndex == 0)
                {
                    _session = new(new DemoAuthenticator(_demoKey), _demoKey.ExportSubjectPublicKeyInfo());
                    _session.SubmitPin(digits);
                }
                else if (Mode.SelectedIndex is 2 or 3 or 4)
                {
                    realPin = new byte[4];
                    for (int index = 0; index < digits.Length; index++)
                        realPin[index] = (byte)digits[index];
                }
            }
            finally
            {
                Array.Clear(digits);
                Pin.Clear();
            }
            _waiting = true;
            Pin.Visibility = Visibility.Collapsed;
            Heading.Text = "カードをかざしてください";
            Symbol.Text = "▱";
            SetStep(2);
            _expiresAt = DateTimeOffset.UtcNow.AddSeconds(60);
            _expiryTimer.Start();
            if (realPin is not null)
            {
                await AuthenticateRealCardAsync(realPin);
                return;
            }
            if (Mode.SelectedIndex == 0)
            {
                Description.Text = "模擬カードを提示して、署名の検証を試します。\nカードリーダーは必要ありません。";
                Next.Content = "模擬カードをかざす";
                Next.IsEnabled = true;
                return;
            }
            await DetectCardAsync();
            return;
        }

        if (_session is null)
            return;
        _busy = true;
        Mode.IsEnabled = false;
        Cancel.IsEnabled = false;
        Next.IsEnabled = false;
        AuthenticationSession session = _session;
        _session = null;
        try
        {
            ProofStatus status = await session.AuthenticateAsync(CredentialMedium.PhysicalCard, CancellationToken.None);
            if (!_closed)
                Finish(status == ProofStatus.Success ? "模擬認証が完了しました" : "模擬認証に失敗しました",
                    "模擬鍵による署名の検証結果です。実物カードや Android の本人認証ではありません。Windows へのサインインは行いません。",
                    status == ProofStatus.Success);
        }
        finally
        {
            session.Dispose();
            _busy = false;
            Mode.IsEnabled = true;
            Cancel.IsEnabled = true;
        }
    }

    private async Task AuthenticateRealCardAsync(byte[] pin)
    {
        _busy = true;
        Mode.IsEnabled = false;
        Next.IsEnabled = false;
        bool android = Mode.SelectedIndex == 3;
        bool automatic = Mode.SelectedIndex == 4;
        CardDevice? detectedDevice = null;
        if (android) Heading.Text = "S25 をかざしてください";
        if (automatic) Heading.Text = "カードかスマホをかざす";
        Description.Text = automatic
            ? "実物カードまたはロック解除済みの Android を1つだけかざしてください。PIN を送る前に種類を確認します。"
            : android
            ? "実物カードを離し、NFC 有効・ロック解除済みの S25 を RC-S300 にかざしてください。結果が出るまで動かさずにお待ちください。"
            : "実物のマイナンバーカードを RC-S300 に置き、\n結果が出るまで動かさずにお待ちください。";
        Status.Text = "最大60秒待機します。PIN・証明書は記録しません。";
        using CancellationTokenSource pending = new(TimeSpan.FromSeconds(60));
        _pending = pending;
        try
        {
            CardAuthentication authentication = new(automatic ? CardDevice.Automatic : android ? CardDevice.Android : CardDevice.PhysicalCard);
            Progress<CardDevice> detected = new(device =>
            {
                detectedDevice = device;
                if (!_closed && _busy && _waiting)
                    Status.Text = device == CardDevice.Android ? "Android を検出しました。スマホ用 PIN で認証中…" : "マイナカードを検出しました。カード用 PIN で認証中…";
            });
            CardAuthenticationResult result = await authentication.AuthenticateAsync(pin, pending.Token, detected);
            android = (result.DetectedDevice ?? detectedDevice) == CardDevice.Android;
            if (_closed)
                return;
            (string title, string detail) = result.Status switch
            {
                CardAuthenticationStatus.Success => ("カード認証に成功しました", "PIN と、カード内の秘密鍵による署名を確認しました。証明書の発行元・有効期限も確認済みです。オンラインの失効状態は未確認です。"),
                CardAuthenticationStatus.InvalidPin => ("PIN を確認してください", "PIN が一致しないか、形式が正しくありません。自動再試行は行っていません。3回連続で誤るとロックされるため、正しい番号を確認してからやり直してください。"),
                CardAuthenticationStatus.PinLocked => ("PIN がロックされています", "このカードの利用者証明用 PIN はロックされています。再入力せず、公式の解除手続きを確認してください。"),
                CardAuthenticationStatus.LibraryUnavailable => ("JPKI ソフトを利用できません", "64-bit 版 JPKI 利用者ソフトの導入状態を確認してください。このアプリは利用者証明用 PKCS#11 ライブラリを使用します。"),
                CardAuthenticationStatus.MultipleCards => ("カードを1枚にしてください", "複数のカードが認識されています。対象以外のカードやリーダーを外し、やり直してください。PIN は送信していません。"),
                CardAuthenticationStatus.InvalidCertificate => ("証明書を確認できません", "有効期限・利用目的・JPKI の発行元の確認に失敗しました。認証成功として扱いません。"),
                CardAuthenticationStatus.InvalidSignature => ("署名の検証に失敗しました", "カードの応答が今回の認証要求と一致しませんでした。認証成功として扱いません。"),
                CardAuthenticationStatus.Cancelled or CardAuthenticationStatus.TimedOut => ("認証を終了しました", "キャンセル、または60秒の待ち時間を過ぎました。PIN は消去しました。"),
                CardAuthenticationStatus.CardUnavailable => ("カードと通信できません", "カードが外れたか、利用できないカードです。置き直してからやり直してください。自動再試行は行いません。"),
                CardAuthenticationStatus.CardNotRecognized => ("カードを認識できません", "JPKI ソフトが対応するカードとして認識できませんでした。カードを置き直し、改善しなければリーダーの USB 接続と JPKI ソフトの設定・版を確認してください。PIN 誤入力とは別の認識エラーです。"),
                _ => ("認証できませんでした", "JPKI ソフトのリーダー設定、カードの置き方、ほかのカードアプリが動作中でないかを確認してください。自動再試行は行いません。")
            };
            if (android && result.Status == CardAuthenticationStatus.Success)
            {
                title = "Android の認証に成功しました";
                detail = "スマホ用 PIN と、スマホ内の秘密鍵による署名を確認しました。証明書の発行元・有効期限も確認済みです。オンラインの失効状態は未確認です。";
            }
            if (android && result.Status == CardAuthenticationStatus.CardNotRecognized)
                detail = "Android 搭載の JPKI 電子証明書を識別できません。実物カードを離し、S25 の NFC・ロック解除・電子証明書の搭載状態を確認してください。認識できない状態では PIN を送信しません。";
            Finish(title, detail, result.Status == CardAuthenticationStatus.Success);
            if (result.Failure is JpkiFailure failure)
            {
                bool saved = DiagnosticLog.Write(failure);
                Status.Text = $"診断: {failure.Summary}" + (saved ? "" : "（ログ保存不可）");
            }
        }
        catch (Exception)
        {
            // Do not persist exception details: native-library errors must not create secret-bearing logs.
            if (!_closed)
                Finish("認証を終了しました", "処理を完了できませんでした。PIN は消去しました。自動再試行は行いません。", false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pin);
            _pending = null;
            _busy = false;
            Mode.IsEnabled = true;
        }
    }

    private async Task DetectCardAsync()
    {
        _busy = true;
        Mode.IsEnabled = false;
        Next.IsEnabled = false;
        Description.Text = "リーダー上を空にしてからカードをかざしてください。\n提示を検出しても本人認証の成功にはなりません。";
        using CancellationTokenSource pending = new(TimeSpan.FromSeconds(60));
        _pending = pending;
        try
        {
            await RefreshReadersAsync();
            string? reader = _readers.FirstOrDefault(name => name.Contains("PaSoRi", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("FeliCa", StringComparison.OrdinalIgnoreCase));
            if (reader is null)
            {
                Finish("PaSoRi が見つかりません", "RC-S300 を接続し、接続を再確認してからやり直してください。", false);
                return;
            }
            bool armed = false;
            while (true)
            {
                pending.Token.ThrowIfCancellationRequested();
                bool present = await Task.Run(() => CardReader.IsPresent(reader), pending.Token);
                pending.Token.ThrowIfCancellationRequested();
                if (!present)
                    armed = true;
                if (armed && present)
                {
                    Finish("カードの提示を検出しました", "リーダーが IC カードの存在を報告しました。カードの種類・PIN・証明書は確認していません。本人認証は未実施です。", false);
                    return;
                }
                Status.Text = armed ? "カードの提示を待っています…" : "一度カードをリーダーから離してください。";
                await Task.Delay(250, pending.Token);
            }
        }
        catch (OperationCanceledException)
        {
            if (!_closed)
                Finish("検出を終了しました", "キャンセル、または60秒の待ち時間を過ぎました。もう一度やり直せます。", false);
        }
        finally
        {
            _pending = null;
            _busy = false;
            Mode.IsEnabled = true;
        }
    }

    private void Finish(string heading, string description, bool success)
    {
        _expiryTimer.Stop();
        _waiting = false;
        Heading.Text = heading;
        Description.Text = description;
        Pin.Visibility = Visibility.Collapsed;
        Symbol.Text = success ? "✓" : "◇";
        Status.Text = "";
        Next.IsEnabled = false;
        SetStep(3);
    }

    private void ExpiryTimer_Tick(object? sender, EventArgs e)
    {
        int seconds = Math.Max(0, (int)(_expiresAt - DateTimeOffset.UtcNow).TotalSeconds);
        if (seconds == 0 && !_busy)
        {
            _session?.Dispose();
            _session = null;
            Finish("待ち時間を過ぎました", "PIN を入力するところからやり直してください。", false);
        }
        else if (Mode.SelectedIndex == 0)
            Status.Text = $"残り {seconds} 秒";
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            _pending?.Cancel();
        else
            Reset();
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _closed = true;
        _expiryTimer.Stop();
        _pending?.Cancel();
        _session?.Dispose();
        Pin.Clear();
        _demoKey.Dispose();
    }
}

internal sealed class DemoAuthenticator(RSA key) : ICardAuthenticator
{
    public Task<CardProof> AuthenticateAsync(CredentialMedium medium, ReadOnlyMemory<byte> pin,
        ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new CardProof(ProofStatus.Success,
            key.SignData(challenge.Span, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
    }
}
