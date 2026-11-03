using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MynaAuth.Jpki;
using MynaAuth.Windows;

namespace MynaAuth.Setup;

public partial class SetupWindow : Window
{
    private readonly ISetupBackend _backend;
    private readonly HashSet<string> _registered = [];
    private readonly HashSet<string> _mediaNames = [];
    private SecureString? _password;
    private string? _recoverySid;
    private string? _sid;
    private string _account = "";
    private int _step;
    private bool _busy;
    private CancellationTokenSource? _pending;

    public SetupWindow() : this(new SetupBackend()) { }
    internal SetupWindow(ISetupBackend backend)
    {
        _backend = backend;
        InitializeComponent();
        try { Email.Text = _backend.FindEmail(); } catch (Exception) { Email.Text = ""; }
        ShowStep(0);
    }

    private void ShowStep(int step)
    {
        _step = step;
        FrameworkElement[] panels = [RecoveryPanel, WindowsPanel, CardPanel, ReviewPanel];
        TextBlock[] labels = [StepLabel0, StepLabel1, StepLabel2, StepLabel3];
        for (int index = 0; index < panels.Length; index++)
        {
            panels[index].Visibility = index == step ? Visibility.Visible : Visibility.Collapsed;
            labels[index].Foreground = index == step ? new SolidColorBrush(Color.FromRgb(23, 107, 87)) : Brushes.Gray;
            labels[index].FontWeight = index == step ? FontWeights.SemiBold : FontWeights.Normal;
        }
        Next.Content = step switch { 0 => "確認して次へ", 1 => "パスワードを確認して次へ", 2 => "登録完了 → 次へ", _ => "ログイン画面へ追加" };
        Next.IsEnabled = step != 2 || _registered.Count > 0;
        Back.IsEnabled = step > 0 && (step == 3 || _registered.Count == 0);
    }

    private void Message(string text, bool error = false)
    {
        Status.Text = text;
        StatusSurface.Background = new SolidColorBrush(error ? Color.FromRgb(253, 235, 230) : Color.FromRgb(232, 238, 232));
    }
    private void Busy(bool busy)
    {
        _busy = busy;
        Next.IsEnabled = !busy && (_step != 2 || _registered.Count > 0);
        Back.IsEnabled = !busy && _step > 0 && (_step == 3 || _registered.Count == 0);
        Enroll.IsEnabled = !busy;
        Email.IsEnabled = !busy;
        WindowsPassword.IsEnabled = !busy;
    }

    private async void Next_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetupStage stage = _step switch { 0 => SetupStage.Recovery, 1 => SetupStage.WindowsAccount, _ => SetupStage.Install };
        try
        {
            if (_step == 0)
            {
                if (RecoveryConfirmed.IsChecked != true) { Message("復旧用ユーザーで実際にサインインできることを確認し、チェックを入れてください。", true); return; }
                RecoveryCheck recovery = _backend.CheckRecovery();
                if (!recovery.Ready)
                {
                    _backend.RecordFailure(stage, recovery.Code);
                    Message(recovery.Code == 5 ? "管理者権限で起動できていません。設定アプリを右クリックし「管理者として実行」を選んでください。"
                        : "復旧ユーザーの確認記録が見つかりません。復旧スクリプトを -VerifyOnly 付きで実行してください。", true);
                    return;
                }
                _recoverySid = recovery.Sid;
                ShowStep(1);
                Message("次は Windows パスワードだけを確認します。カードの PIN はまだ入力しません。");
                return;
            }
            if (_step == 1)
            {
                string email = Email.Text.Trim();
                const string Prefix = "MicrosoftAccount\\";
                if (email.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) email = email[Prefix.Length..];
                string account;
                string localPrefix = Environment.MachineName + "\\";
                if (email.StartsWith(@".\", StringComparison.Ordinal) || email.StartsWith(localPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    string user = email[(email.IndexOf('\\') + 1)..];
                    if (user.Length == 0 || user.Contains('\\') || user.Any(char.IsControl))
                    { Message("この PC の Windows ユーザー名を確認してください。", true); return; }
                    account = localPrefix + user;
                }
                else
                {
                    if (email.Length is 0 or > 254 || !email.Contains('@') || email.Any(value => char.IsWhiteSpace(value) || value == '\\'))
                    { Message("Microsoft アカウントのメールアドレス、または この PC の名前\\ユーザー名を入力してください。", true); return; }
                    account = Prefix + email;
                }
                using SecureString entered = WindowsPassword.SecurePassword;
                if (entered.Length == 0) { Message("この PC の Windows サインイン用パスワードを入力してください。Windows Hello の PIN ではありません。", true); return; }
                Busy(true);
                WindowsPassword.Clear();
                Message("Windows パスワードを確認しています…");
                WindowsAccountValidation validation = await _backend.ValidateAsync(account, entered);
                if (!validation.IsSuccess)
                {
                    _backend.RecordFailure(stage, validation.ErrorCode);
                    Message(DescribeWindowsFailure(validation.ErrorCode), true);
                    return;
                }
                if (validation.Sid == _recoverySid) { Message("復旧用ユーザーは登録対象にできません。普段の Windows ユーザーを指定してください。", true); return; }
                _password?.Dispose(); _password = entered.Copy();
                _sid = validation.Sid; _account = account;
                ShowStep(2);
                Message("Windows の確認が完了しました。次は登録したいカードかスマホの PIN を入力してください。");
                return;
            }
            if (_step == 2)
            {
                if (_registered.Count == 0) { Message("先にカードまたは Android を1つ登録してください。", true); return; }
                ReviewSummary.Text = $"登録先：{Email.Text.Trim()}\n登録済み：{string.Join("、", _mediaNames)}";
                ShowStep(3);
                Message("内容を確認してください。次のボタンで初めてログイン画面へ追加します。");
                return;
            }
            if (_registered.Count == 0 || _sid is null) return;
            Busy(true); Message("ログイン画面へ追加しています…");
            if (await _backend.InstallAsync())
            {
                _password?.Dispose(); _password = null;
                ReviewTitle.Text = "追加が完了しました";
                Message("Windows のサインイン オプションから MynaAuth を選べます。実際のログインは初回の確認が必要です。");
                Next.Visibility = Visibility.Collapsed; Back.Visibility = Visibility.Collapsed;
            }
            else { _backend.RecordFailure(stage, 1); Message("ログイン画面への追加に失敗しました。カード登録とは別の導入段階のエラーです。標準のログイン方法を使えます。", true); }
        }
        catch (Exception error)
        {
            _backend.RecordFailure(stage, error.HResult);
            Message($"{StageName(stage)}の処理を完了できませんでした（{error.HResult:X8}）。この段階で停止しました。", true);
        }
        finally { Busy(false); }
    }

    private async void Enroll_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _step != 2 || _password is null || _sid is null) return;
        byte[] pin = ReadPin();
        SetupStage stage = SetupStage.Card;
        try
        {
            if (pin.Length != 4 || pin.Any(value => value is < (byte)'0' or > (byte)'9'))
            { Message("カードまたはスマホの利用者証明用 PIN を半角数字4桁で入力してください。", true); return; }
            Busy(true); CardPin.Clear();
            CancelCard.Visibility = Visibility.Visible;
            using CancellationTokenSource pending = new(TimeSpan.FromSeconds(60));
            _pending = pending;
            Message("いま、カードか Android を1つだけかざしてください。種類は自動判別します。");
            CardAuthenticationResult result = await _backend.AuthenticateAsync(pin, pending.Token);
            if (result.Status != CardAuthenticationStatus.Success || result.CredentialId is null)
            {
                _backend.RecordFailure(stage, (int)result.Status);
                Message(result.Status switch
                {
                    CardAuthenticationStatus.InvalidPin => "カード／スマホの PIN が一致しません。自動再試行はしていません。正しい番号を確認してください。",
                    CardAuthenticationStatus.PinLocked => "カード／スマホの PIN がロックされています。繰り返し入力せず、解除手続きを確認してください。",
                    CardAuthenticationStatus.Cancelled or CardAuthenticationStatus.TimedOut => "カードの登録を中止したか、待ち時間を過ぎました。Windows の確認は完了したままです。",
                    _ => $"カードの確認に失敗しました（{result.Status}）。Windows パスワードの確認はすでに完了しています。"
                }, true);
                return;
            }
            stage = SetupStage.Save;
            Message("確認できたカードを保護領域に登録しています…");
            await Task.Run(() => _backend.Save(_sid, _account, _password, result.CredentialId));
            _registered.Add(result.CredentialId);
            _mediaNames.Add(result.DetectedDevice == CardDevice.Android ? "Android" : "マイナカード");
            Registered.Text = "登録済み：" + string.Join("、", _mediaNames);
            Enroll.Content = "別の媒体も登録する";
            Message("登録できました。両方使う場合はもう一方を登録できます。準備できたら「次へ」を押してください。");
        }
        catch (Exception error)
        {
            _backend.RecordFailure(stage, error.HResult);
            Message(stage == SetupStage.Save ? "カード認証は成功しましたが、保護領域への登録に失敗しました。管理者権限を確認してください。"
                : $"カードとの処理を完了できませんでした（{error.HResult:X8}）。Windows の確認とは別の段階です。", true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pin); CardPin.Clear();
            _pending = null; CancelCard.Visibility = Visibility.Collapsed; Busy(false);
        }
    }

    private byte[] ReadPin()
    {
        using SecureString secure = CardPin.SecurePassword;
        IntPtr pointer = Marshal.SecureStringToGlobalAllocUnicode(secure);
        try
        {
            byte[] pin = new byte[secure.Length];
            for (int index = 0; index < pin.Length; index++)
            {
                short value = Marshal.ReadInt16(pointer, index * 2);
                pin[index] = value is >= 48 and <= 57 ? (byte)value : (byte)0;
            }
            return pin;
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(pointer); }
    }

    internal static string DescribeWindowsFailure(int code) => code switch
    {
        1326 => "Windows の確認に失敗しました（エラー1326）。指定した Windows ユーザーと、そのユーザーのパスワードが一致するか確認してください。Windows Hello の PIN は使えません。カードにはまだアクセスしていません。",
        1909 => "Windows アカウントが一時的にロックされています（エラー1909）。繰り返し試さず、標準のサインイン方法で確認してください。",
        1327 or 1385 => $"Windows がこの方法でのパスワード認証を許可していません（エラー{code}）。標準画面でパスワードによるサインインが可能か確認してください。",
        1330 => "Windows パスワードの有効期限が切れています（エラー1330）。標準の方法で更新してから設定してください。",
        1331 => "対象の Windows アカウントが無効になっています（エラー1331）。",
        _ => $"Windows パスワードの確認に失敗しました（エラー{code}）。カードの確認にはまだ進んでいません。"
    };
    private static string StageName(SetupStage stage) => stage switch { SetupStage.Recovery => "復旧確認", SetupStage.WindowsAccount => "Windows パスワード確認", SetupStage.Save => "保護領域への保存", SetupStage.Install => "ログイン画面への追加", _ => "カード確認" };

    private void Back_Click(object sender, RoutedEventArgs e)
    {
        if (_busy || _step == 0) return;
        if (_step <= 2) { _password?.Dispose(); _password = null; _sid = null; WindowsPassword.Clear(); }
        ShowStep(_step - 1); Message("表示中の手順を確認してください。");
    }
    private void CancelCard_Click(object sender, RoutedEventArgs e) => _pending?.Cancel();
    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_busy) { e.Cancel = true; _pending?.Cancel(); Message("処理を終了しています。完了後に閉じてください。"); return; }
        _password?.Dispose(); _password = null; WindowsPassword.Clear(); CardPin.Clear();
    }
}
