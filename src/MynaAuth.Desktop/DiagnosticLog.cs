using System.IO;
using MynaAuth.Jpki;

namespace MynaAuth.Desktop;

// Only a typed operation, numeric return code and timestamp can enter this file.
// Never accepts exception messages, arbitrary strings, PINs or card data.
internal static class DiagnosticLog
{
    public static bool Write(JpkiFailure failure)
    {
        try
        {
            string entry = $"{DateTimeOffset.UtcNow:O} {failure.Summary}{Environment.NewLine}";
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "diagnostics.log"), entry);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}
