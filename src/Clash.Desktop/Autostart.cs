using Microsoft.Win32;

namespace Clash.Desktop;

/// <summary>
/// "Run at startup" support, implemented as a value under
/// <c>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</c>.
/// <para>
/// A per-user Run entry needs no elevation and is visible to the user in Task
/// Manager's startup tab, which is what a tray application should use. The value
/// is compared against the current executable so a stale entry pointing at a
/// deleted build reads as "off" rather than "on".
/// </para>
/// </summary>
internal static class Autostart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Clash for .NET";

    /// <summary>The path recorded in the Run entry.</summary>
    public static string ExecutablePath
    {
        get
        {
            var path = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(path)) return path;

            // A framework-dependent launch through `dotnet run` has no apphost.
            return Path.ChangeExtension(typeof(Autostart).Assembly.Location, ".exe");
        }
    }

    /// <summary>True when the Run entry exists and still points at this executable.</summary>
    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: false);
            var value = key?.GetValue(ValueName) as string;
            if (string.IsNullOrWhiteSpace(value)) return false;

            var recorded = Unquote(value!);
            return string.Equals(recorded, ExecutablePath, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Adds or removes the Run entry. Returns false when the registry refused the change.</summary>
    public static bool TrySet(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
            if (key is null) return false;

            if (enabled)
            {
                key.SetValue(ValueName, $"\"{ExecutablePath}\"", RegistryValueKind.String);
            }
            else
            {
                key.DeleteValue(ValueName, throwOnMissingValue: false);
            }

            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string Unquote(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2 && trimmed[0] == '"' && trimmed[^1] == '"') return trimmed[1..^1];
        return trimmed;
    }
}
