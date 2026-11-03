using System.Windows;
using Microsoft.Win32;
using MynaAuth.Windows;

namespace MynaAuth.Setup;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args is ["--check-startup"])
        {
            // Load the real WPF window without showing it or changing enrollment.
            SetupWindow window = new();
            window.Close();
            Shutdown(0);
            return;
        }
        if (e.Args is ["--remove-enrollment"])
        {
            int result = 0;
            try
            {
                using RegistryKey? accounts = Registry.LocalMachine.OpenSubKey(AccountStore.RegistryPath, true);
                if (accounts is not null)
                {
                    foreach (string sid in accounts.GetSubKeyNames())
                    {
                        WindowsSecret.Delete(sid);
                        accounts.DeleteSubKeyTree(sid);
                    }
                }
            }
            catch (Exception) { result = 1; }
            Shutdown(result);
            return;
        }
        base.OnStartup(e);
    }
}
