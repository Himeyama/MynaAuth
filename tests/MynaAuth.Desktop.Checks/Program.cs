using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using MynaAuth.Desktop;

namespace MynaAuth.Desktop.Checks;

internal static class Program
{
    [STAThread]
    private static int Main()
    {
        App app = new();
        app.InitializeComponent();
        // Test window is shown without activating it, so it does not interrupt typing.
        MainWindow window = new() { ShowActivated = false };
        window.Show();
        Pump();
        ComboBox mode = (ComboBox)window.FindName("Mode");
        Check(mode.SelectedIndex == 4, "Automatic detection is the default");
        Check(((TextBlock)window.FindName("ModeDescription")).Text.Contains("PIN 送信前"), "Explain detection before PIN transmission");
        Capture(window, "auto-initial");
        mode.SelectedIndex = 3;
        Check(((TextBlock)window.FindName("Description")).Text.Contains("3回連続"), "Warn about card PIN lockout");
        Check(((TextBlock)window.FindName("Description")).Text.Contains("スマホ用"), "Android requires its own authentication PIN");
        Capture(window, "android-initial");
        mode.SelectedIndex = 2;
        Capture(window, "real-initial");
        mode.SelectedIndex = 0;
        PasswordBox pin = (PasswordBox)window.FindName("Pin");
        Button next = (Button)window.FindName("Next");
        Button cancel = (Button)window.FindName("Cancel");
        TextBlock heading = (TextBlock)window.FindName("Heading");
        Check(!next.IsEnabled, "Empty PIN cannot advance");
        Capture(window, "initial");
        pin.Password = "12ab";
        Click(next);
        Check(pin.SecurePassword.Length == 0 && !next.IsEnabled, "Reject non-digit PIN and clear input");
        pin.Password = "2468";
        Click(next);
        Check(heading.Text == "カードをかざしてください" && pin.Visibility == Visibility.Collapsed,
            "PIN first, then card prompt");
        Capture(window, "waiting");
        Click(next);
        Check(heading.Text == "模擬認証が完了しました", "Simulated proof completes");
        Check(!next.IsEnabled && pin.SecurePassword.Length == 0, "Result cannot resubmit PIN");
        Capture(window, "success");
        Click(cancel);
        Check(pin.Visibility == Visibility.Visible && !next.IsEnabled, "Restart clears session");
        mode.SelectedIndex = 1;
        Check(((TextBlock)window.FindName("ModeDescription")).Text.Contains("本人認証は行いません"),
            "Hardware mode discloses detection only");
        window.Close();
        app.Shutdown();
        Console.WriteLine("Desktop checks passed.");
        return 0;
    }

    private static void Check(bool condition, string description)
    {
        if (!condition)
            throw new InvalidOperationException(description);
        Console.WriteLine($"PASS: {description}");
    }

    private static void Click(Button button)
    {
        button.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Pump();
    }

    private static void Pump()
    {
        DispatcherFrame frame = new();
        Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle,
            new Action(() => frame.Continue = false));
        Dispatcher.PushFrame(frame);
    }

    private static void Capture(Window window, string name)
    {
        window.UpdateLayout();
        Directory.CreateDirectory("artifacts");
        RenderTargetBitmap bitmap = new((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        PngBitmapEncoder encoder = new();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using FileStream output = File.Create(Path.Combine("artifacts", $"desktop-{name}.png"));
        encoder.Save(output);
    }
}
