using System.Diagnostics;
using System.IO;
using System.Security;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using MynaAuth.Jpki;
using MynaAuth.Setup;
using MynaAuth.Windows;

namespace MynaAuth.Setup.Checks;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application app = new();
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        FakeBackend backend = new();
        SetupWindow window = new(backend) { ShowActivated = false };
        window.Show(); Pump();
        Button next = (Button)window.FindName("Next");
        Button back = (Button)window.FindName("Back");
        Button enroll = (Button)window.FindName("Enroll");
        PasswordBox password = (PasswordBox)window.FindName("WindowsPassword");
        PasswordBox pin = (PasswordBox)window.FindName("CardPin");
        TextBlock status = (TextBlock)window.FindName("Status");
        FrameworkElement windowsPanel = (FrameworkElement)window.FindName("WindowsPanel");
        FrameworkElement cardPanel = (FrameworkElement)window.FindName("CardPanel");
        Check(window.FindName("RecoveryPanel") is null && windowsPanel.Visibility == Visibility.Visible,
            "Start with Windows verification without a recovery step");
        Check(window.WindowStyle == WindowStyle.None && System.Windows.Shell.WindowChrome.GetWindowChrome(window) is not null,
            "Use custom window chrome");
        Check(((TextBlock)window.FindName("StepLabel0")).Text == "Windows の確認",
            "Show step names without numbers");
        ProcessStartInfo fresh = SetupBackend.CreateInstallStartInfo(false, @"C:\Synthetic Folder\app");
        ProcessStartInfo update = SetupBackend.CreateInstallStartInfo(true, @"C:\Synthetic Folder\app");
        Check(fresh.ArgumentList.Contains(@"C:\Synthetic Folder\app\Install-LogonProvider.ps1") && !fresh.ArgumentList.Contains("-RecoverySignInConfirmed"),
            "Fresh install has no recovery-confirmation requirement");
        Check(update.ArgumentList.Contains(@"C:\Synthetic Folder\app\Update-LogonProvider.ps1") && update.ArgumentList[^2] == "-BundlePath" && update.ArgumentList[^1] == @"C:\Synthetic Folder\app",
            "Existing provider uses the safe update path and preserves a bundle path with spaces");
        Check(windowsPanel.Visibility == Visibility.Visible && cardPanel.Visibility == Visibility.Collapsed, "Show only Windows verification before card entry");
        Capture(window, "setup-v2-windows");
        password.Password = "Synthetic test only!";
        Click(next);
        Check(status.Text.Contains("1326") && backend.CardCalls == 0 && password.SecurePassword.Length == 0,
            "Report Windows error without requesting card PIN, and clear password field");
        Check(backend.LastStage == SetupStage.WindowsAccount && backend.LastCode == 1326, "Record only failure stage and numeric Windows code");
        backend.WindowsError = 0;
        ((TextBox)window.FindName("Email")).Text = @".\SyntheticLocal";
        password.Password = "Synthetic test only!";
        Click(next);
        Check(cardPanel.Visibility == Visibility.Visible && !next.IsEnabled, "Enter card step only after Windows verification");
        Check(backend.LastAccount == Environment.MachineName + @"\SyntheticLocal", "Validate local account without substituting MicrosoftAccount identity");
        Check((string)next.Content == "登録完了", "Use the requested registration completion label");
        Capture(window, "setup-v2-card");
        pin.Password = "2468";
        backend.CardStatus = CardAuthenticationStatus.InvalidPin;
        Click(enroll);
        Check(status.Text.Contains("PIN が一致") && backend.SaveCalls == 0 && backend.LastPin!.All(value => value == 0),
            "Wrong card PIN is isolated from Windows verification and erased");
        backend.CardStatus = CardAuthenticationStatus.Success;
        pin.Password = "2468";
        Click(enroll);
        WaitFor(() => next.IsEnabled);
        Check(backend.SaveCalls == 1 && backend.LastPin!.All(value => value == 0), "Save verified card after successful proof and erase PIN");
        Click(next);
        Check(((FrameworkElement)window.FindName("ReviewPanel")).Visibility == Visibility.Visible && backend.InstallCalls == 0,
            "Require a separate review step before installation");
        Capture(window, "setup-v2-review");
        Click(back);
        Check(cardPanel.Visibility == Visibility.Visible, "Allow adding another medium from review");
        Click(next);
        backend.InstallSucceeds = false;
        Click(next);
        Check(status.Text.Contains("導入段階") && backend.LastStage == SetupStage.Install, "Distinguish installation failure from enrollment failure");
        backend.InstallSucceeds = true;
        Click(next);
        Check(status.Text.Contains("サインイン オプション") && next.Visibility == Visibility.Collapsed, "Show installation completion without locking Windows");
        window.Close(); app.Shutdown();
        Console.WriteLine("Wizard checks passed. All account data is synthetic; no Windows login, enrollment, registry write or installation occurred.");
    }

    private static void Click(Button button) { button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent)); Pump(); }
    private static void Pump()
    {
        DispatcherFrame frame = new();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }
    private static void WaitFor(Func<bool> condition)
    {
        Stopwatch clock = Stopwatch.StartNew();
        while (!condition() && clock.Elapsed < TimeSpan.FromSeconds(5)) { Pump(); Thread.Sleep(5); }
        if (!condition()) throw new InvalidOperationException("UI operation did not finish.");
    }
    private static void Check(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException(description);
        Console.WriteLine($"PASS: {description}");
    }
    private static void Capture(Window window, string name)
    {
        window.UpdateLayout(); Directory.CreateDirectory("artifacts");
        RenderTargetBitmap bitmap = new((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        PngBitmapEncoder encoder = new(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream output = File.Create($"artifacts/{name}.png"); encoder.Save(output);
    }

    private sealed class FakeBackend : ISetupBackend
    {
        public int WindowsError { get; set; } = 1326;
        public CardAuthenticationStatus CardStatus { get; set; }
        public bool InstallSucceeds { get; set; }
        public int ValidateCalls { get; private set; }
        public string? LastAccount { get; private set; }
        public int CardCalls { get; private set; }
        public int SaveCalls { get; private set; }
        public int InstallCalls { get; private set; }
        public byte[]? LastPin { get; private set; }
        public SetupStage LastStage { get; private set; }
        public int LastCode { get; private set; }
        public string FindEmail() => "synthetic@example.invalid";
        public Task<WindowsAccountValidation> ValidateAsync(string account, SecureString password)
        {
            ValidateCalls++;
            LastAccount = account;
            return Task.FromResult(new WindowsAccountValidation(WindowsError == 0 ? "S-1-5-21-1-2-3-1001" : null, WindowsError));
        }
        public Task<CardAuthenticationResult> AuthenticateAsync(byte[] pin, CancellationToken token)
        {
            CardCalls++; LastPin = pin;
            return Task.FromResult(new CardAuthenticationResult(CardStatus, DetectedDevice: CardDevice.Android,
                CredentialId: CardStatus == CardAuthenticationStatus.Success ? new string('A', 64) : null));
        }
        public void Save(string sid, string account, SecureString password, string credentialId) => SaveCalls++;
        public Task<bool> InstallAsync() { InstallCalls++; return Task.FromResult(InstallSucceeds); }
        public void RecordFailure(SetupStage stage, int code) { LastStage = stage; LastCode = code; }
    }
}
