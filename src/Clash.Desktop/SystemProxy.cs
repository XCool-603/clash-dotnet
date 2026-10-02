using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace Clash.Desktop;

/// <summary>
/// Windows system-proxy integration.
/// <para>
/// The live setting is changed through WinINet's <c>INTERNET_PER_CONN_OPTION_LIST</c>,
/// which is what already-running applications observe, and mirrored into
/// <c>HKCU\...\Internet Settings</c> so the state survives a logon. The user's
/// original settings are snapshotted to disk before the first change so
/// <see cref="Disable"/> restores what was actually there — including across a
/// crash, which a purely in-memory snapshot would not survive.
/// </para>
/// </summary>
internal static class SystemProxy
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const int InternetOptionPerConnectionOption = 75;
    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    private const int PerConnFlags = 1;
    private const int PerConnProxyServer = 2;
    private const int PerConnProxyBypass = 3;

    private const int ProxyTypeDirect = 0x00000001;
    private const int ProxyTypeProxy = 0x00000002;

    private static readonly string SnapshotPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ClashForDotNet",
        "system-proxy-snapshot.json");

    private static readonly Lock Gate = new();

    /// <summary>The default bypass list: loopback and local names must never be proxied.</summary>
    public const string DefaultBypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;" +
                                        "172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;" +
                                        "172.29.*;172.30.*;172.31.*;192.168.*;<local>";

    /// <summary>Points the system proxy at <paramref name="host"/>:<paramref name="port"/>.</summary>
    public static void Enable(string host, int port, string? bypass = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        lock (Gate)
        {
            SaveSnapshotOnce();

            var server = $"{host}:{port}";
            var bypassList = string.IsNullOrWhiteSpace(bypass) ? DefaultBypass : bypass!;

            if (!ApplyPerConnection(server, bypassList))
            {
                // WinINet is unavailable (some server SKUs); the registry is the
                // only lever left, and it still takes effect at next logon.
                WriteRegistry(server, bypassList);
            }
            else
            {
                WriteRegistry(server, bypassList);
            }

            NotifySettingsChanged();
        }
    }

    /// <summary>Restores the settings captured before the first <see cref="Enable"/>.</summary>
    public static void Disable()
    {
        lock (Gate)
        {
            var snapshot = LoadSnapshot();

            if (snapshot is not null)
            {
                ApplyPerConnection(snapshot.ProxyServer, snapshot.ProxyBypass, snapshot.Enabled);
                WriteRegistry(snapshot.Enabled ? snapshot.ProxyServer : null, snapshot.ProxyBypass);
            }
            else
            {
                ApplyPerConnection(string.Empty, DefaultBypass, enabled: false);
                WriteRegistry(null, DefaultBypass);
            }

            NotifySettingsChanged();
        }
    }

    /// <summary>Reads the current system-proxy state from the registry.</summary>
    public static bool IsEnabled(out string server)
    {
        server = string.Empty;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false);
            if (key is null) return false;

            var enabled = key.GetValue("ProxyEnable") is int value && value != 0;
            server = key.GetValue("ProxyServer") as string ?? string.Empty;
            return enabled && server.Length > 0;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>True when the system proxy currently points at this instance.</summary>
    public static bool IsPointingAt(int port)
        => IsEnabled(out var server) && server.EndsWith($":{port}", StringComparison.Ordinal);

    // ── WinINet ──────────────────────────────────────────────────────────────

    private static bool ApplyPerConnection(string proxyServer, string proxyBypass, bool enabled = true)
    {
        var optionCount = 3;
        var optionSize = Marshal.SizeOf<InternetPerConnOption>();
        var optionsPtr = Marshal.AllocHGlobal(optionSize * optionCount);
        var serverPtr = IntPtr.Zero;
        var bypassPtr = IntPtr.Zero;
        var listPtr = IntPtr.Zero;

        try
        {
            serverPtr = Marshal.StringToHGlobalUni(proxyServer ?? string.Empty);
            bypassPtr = Marshal.StringToHGlobalUni(proxyBypass ?? string.Empty);

            var flags = enabled && !string.IsNullOrEmpty(proxyServer)
                ? ProxyTypeProxy | ProxyTypeDirect
                : ProxyTypeDirect;

            var options = new[]
            {
                new InternetPerConnOption { Option = PerConnFlags, Value = new InternetPerConnOptionValue { IntValue = flags } },
                new InternetPerConnOption { Option = PerConnProxyServer, Value = new InternetPerConnOptionValue { PointerValue = serverPtr } },
                new InternetPerConnOption { Option = PerConnProxyBypass, Value = new InternetPerConnOptionValue { PointerValue = bypassPtr } },
            };

            for (var i = 0; i < optionCount; i++)
            {
                Marshal.StructureToPtr(options[i], optionsPtr + (i * optionSize), fDeleteOld: false);
            }

            var list = new InternetPerConnOptionList
            {
                Size = Marshal.SizeOf<InternetPerConnOptionList>(),
                Connection = IntPtr.Zero, // NULL == the LAN/default connection
                OptionCount = optionCount,
                OptionError = 0,
                Options = optionsPtr,
            };

            listPtr = Marshal.AllocHGlobal(list.Size);
            Marshal.StructureToPtr(list, listPtr, fDeleteOld: false);

            var session = InternetOpen("ClashForDotNet", 0, null, null, 0);
            if (session == IntPtr.Zero) return false;

            try
            {
                return InternetSetOption(session, InternetOptionPerConnectionOption, listPtr, list.Size);
            }
            finally
            {
                InternetCloseHandle(session);
            }
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (listPtr != IntPtr.Zero) Marshal.FreeHGlobal(listPtr);
            if (optionsPtr != IntPtr.Zero) Marshal.FreeHGlobal(optionsPtr);
            if (serverPtr != IntPtr.Zero) Marshal.FreeHGlobal(serverPtr);
            if (bypassPtr != IntPtr.Zero) Marshal.FreeHGlobal(bypassPtr);
        }
    }

    private static void NotifySettingsChanged()
    {
        var session = InternetOpen("ClashForDotNet", 0, null, null, 0);
        if (session != IntPtr.Zero)
        {
            try
            {
                InternetSetOption(session, InternetOptionSettingsChanged, IntPtr.Zero, 0);
                InternetSetOption(session, InternetOptionRefresh, IntPtr.Zero, 0);
            }
            finally
            {
                InternetCloseHandle(session);
            }
        }

        // Tell running applications to re-read the settings.
        SendMessageTimeout(
            new IntPtr(0xFFFF), // HWND_BROADCAST
            0x001A,             // WM_SETTINGCHANGE
            IntPtr.Zero,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            0x0002,             // SMTO_ABORTIFHUNG
            1000,
            out _);
    }

    // ── Registry mirror + snapshot ───────────────────────────────────────────

    private static void WriteRegistry(string? proxyServer, string proxyBypass)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(InternetSettingsKey, writable: true);
            if (key is null) return;

            if (proxyServer is null)
            {
                key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            }
            else
            {
                key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
            }

            key.SetValue("ProxyOverride", proxyBypass, RegistryValueKind.String);
        }
        catch (Exception)
        {
            // A locked-down registry is not fatal: the WinINet path already applied.
        }
    }

    private static void SaveSnapshotOnce()
    {
        try
        {
            if (File.Exists(SnapshotPath)) return;

            var directory = Path.GetDirectoryName(SnapshotPath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            var snapshot = new ProxySnapshot
            {
                Enabled = IsEnabled(out var server),
                ProxyServer = server,
                ProxyBypass = ReadBypass(),
            };

            File.WriteAllText(SnapshotPath, JsonSerializer.Serialize(snapshot));
        }
        catch (Exception)
        {
            // Without a snapshot Disable() falls back to a clean direct state.
        }
    }

    private static ProxySnapshot? LoadSnapshot()
    {
        try
        {
            if (!File.Exists(SnapshotPath)) return null;
            return JsonSerializer.Deserialize<ProxySnapshot>(File.ReadAllText(SnapshotPath));
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string ReadBypass()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: false);
            return key?.GetValue("ProxyOverride") as string ?? DefaultBypass;
        }
        catch (Exception)
        {
            return DefaultBypass;
        }
    }

    private sealed class ProxySnapshot
    {
        public bool Enabled { get; set; }
        public string ProxyServer { get; set; } = string.Empty;
        public string ProxyBypass { get; set; } = DefaultBypass;
    }

    // ── P/Invoke ─────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct InternetPerConnOptionList
    {
        public int Size;
        public IntPtr Connection;
        public int OptionCount;
        public int OptionError;
        public IntPtr Options;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct InternetPerConnOption
    {
        public int Option;
        public InternetPerConnOptionValue Value;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InternetPerConnOptionValue
    {
        [FieldOffset(0)] public int IntValue;

        [FieldOffset(0)] public IntPtr PointerValue;

        [FieldOffset(0)] public long FileTimeValue;
    }

    [DllImport("wininet.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr InternetOpen(string agent, int accessType, string? proxyName, string? proxyBypass, int flags);

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetSetOption(IntPtr session, int option, IntPtr buffer, int bufferLength);

    [DllImport("wininet.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InternetCloseHandle(IntPtr handle);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr window,
        uint message,
        IntPtr wParam,
        string lParam,
        uint flags,
        uint timeout,
        out IntPtr result);
}
