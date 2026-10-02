using System.Globalization;
using Microsoft.Win32;

namespace Clash.Desktop;

/// <summary>The languages the tray menu is available in.</summary>
internal enum TrayLanguage
{
    English,
    Chinese,
}

/// <summary>
/// The tray menu's own strings.
/// <para>
/// The dashboard has its own catalogue in the browser; this is the shell's, and
/// it is deliberately separate — the tray is a Win32 menu that exists before any
/// page loads, and it must render even when the embedded core never starts.
/// </para>
/// <para>
/// The first run follows the Windows display language, and an explicit choice is
/// remembered in <c>HKCU\Software\Clash for .NET</c> (the same hive the startup
/// entry uses, so nothing here needs elevation).
/// </para>
/// </summary>
internal static class TrayStrings
{
    private const string KeyPath = @"Software\Clash for .NET";
    private const string ValueName = "Language";

    private static readonly Dictionary<string, string> English = new(StringComparer.Ordinal)
    {
        ["app.name"] = "Clash for .NET",
        ["status.starting"] = "Starting…",
        ["status.restarting"] = "Restarting…",
        ["status.stopped"] = "Stopped",
        ["status.runningMixed"] = "Running — mixed port {0}",
        ["status.runningNoPort"] = "Running — no mixed port configured",
        ["status.apiNotAnswering"] = "Started, but the control API is not answering",
        ["status.restartedApiNotAnswering"] = "Restarted, but the control API is not answering",

        ["menu.dashboard"] = "Open Dashboard",
        ["menu.mode"] = "Mode",
        ["menu.mode.rule"] = "Rule",
        ["menu.mode.global"] = "Global",
        ["menu.mode.direct"] = "Direct",
        ["menu.systemProxy"] = "System Proxy",
        ["menu.restart"] = "Restart Core",
        ["menu.autostart"] = "Run at Startup",
        ["menu.language"] = "Language",
        ["menu.exit"] = "Exit",

        ["notify.coreStartFailed.title"] = "The core could not start",
        ["notify.coreRestartFailed.title"] = "The core could not be restarted",
        ["notify.dashboardFailed.title"] = "The dashboard could not be opened",
        ["notify.modeFailed.title"] = "The mode could not be changed",
        ["notify.modeFailed.message"] = "The core did not accept `mode: {0}`.",
        ["notify.noProxyPort.title"] = "No proxy port",
        ["notify.noProxyPort.message"] =
            "The configuration has no `mixed-port` (or `port`), so there is nothing to point the system proxy at.",
        ["notify.systemProxyFailed.title"] = "The system proxy could not be enabled",
        ["notify.systemProxyRestoreFailed.title"] = "The system proxy could not be restored",
        ["notify.autostartFailed.title"] = "Startup could not be changed",
        ["notify.autostartFailed.message"] = "Windows refused the change to the per-user Run key.",
    };

    private static readonly Dictionary<string, string> Chinese = new(StringComparer.Ordinal)
    {
        ["app.name"] = "Clash for .NET",
        ["status.starting"] = "正在启动…",
        ["status.restarting"] = "正在重启…",
        ["status.stopped"] = "已停止",
        ["status.runningMixed"] = "运行中 — 混合端口 {0}",
        ["status.runningNoPort"] = "运行中 — 未配置混合端口",
        ["status.apiNotAnswering"] = "已启动，但控制 API 无响应",
        ["status.restartedApiNotAnswering"] = "已重启，但控制 API 无响应",

        ["menu.dashboard"] = "打开控制面板",
        ["menu.mode"] = "模式",
        ["menu.mode.rule"] = "规则",
        ["menu.mode.global"] = "全局",
        ["menu.mode.direct"] = "直连",
        ["menu.systemProxy"] = "系统代理",
        ["menu.restart"] = "重启内核",
        ["menu.autostart"] = "开机自启",
        ["menu.language"] = "语言",
        ["menu.exit"] = "退出",

        ["notify.coreStartFailed.title"] = "内核启动失败",
        ["notify.coreRestartFailed.title"] = "内核重启失败",
        ["notify.dashboardFailed.title"] = "无法打开控制面板",
        ["notify.modeFailed.title"] = "无法切换模式",
        ["notify.modeFailed.message"] = "内核未接受 `mode: {0}`。",
        ["notify.noProxyPort.title"] = "没有可用的代理端口",
        ["notify.noProxyPort.message"] = "配置中没有 `mixed-port`（或 `port`），无法设置系统代理。",
        ["notify.systemProxyFailed.title"] = "系统代理设置失败",
        ["notify.systemProxyRestoreFailed.title"] = "系统代理还原失败",
        ["notify.autostartFailed.title"] = "开机自启设置失败",
        ["notify.autostartFailed.message"] = "Windows 拒绝修改当前用户的启动项。",
    };

    /// <summary>The active language. Changing it is a menu action, not a hot reload.</summary>
    public static TrayLanguage Current { get; private set; } = Detect();

    /// <summary>Raised after <see cref="Set"/> so the menu can re-render itself.</summary>
    public static event Action? Changed;

    /// <summary>True when the active language is Chinese.</summary>
    public static bool IsChinese => Current == TrayLanguage.Chinese;

    /// <summary>
    /// Looks up a message and fills <c>{0}</c>-style placeholders. An unknown key
    /// returns the key itself, which is loud enough to notice in a screenshot and
    /// harmless in production.
    /// </summary>
    public static string T(string key, params object?[] args)
    {
        var table = IsChinese ? Chinese : English;
        if (!table.TryGetValue(key, out var value)) return key;
        return args.Length == 0 ? value : string.Format(CultureInfo.CurrentCulture, value, args);
    }

    /// <summary>The label for a language entry, written in its own language.</summary>
    public static string Label(TrayLanguage language)
        => language == TrayLanguage.Chinese ? "简体中文" : "English";

    /// <summary>Switches language and remembers the choice.</summary>
    public static void Set(TrayLanguage language)
    {
        if (Current == language) return;
        Current = language;
        Persist(language);
        Changed?.Invoke();
    }

    /// <summary>
    /// The remembered choice, or — on a first run — the Windows display language:
    /// a Chinese Windows gets a Chinese tray without anyone having to find the
    /// setting.
    /// </summary>
    private static TrayLanguage Detect()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(KeyPath, writable: false);
            if (key?.GetValue(ValueName) as string is { Length: > 0 } saved)
            {
                if (string.Equals(saved, nameof(TrayLanguage.Chinese), StringComparison.OrdinalIgnoreCase))
                {
                    return TrayLanguage.Chinese;
                }

                if (string.Equals(saved, nameof(TrayLanguage.English), StringComparison.OrdinalIgnoreCase))
                {
                    return TrayLanguage.English;
                }
            }
        }
        catch (Exception)
        {
            // An unreadable registry falls through to the display language.
        }

        return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName
            .Equals("zh", StringComparison.OrdinalIgnoreCase)
            ? TrayLanguage.Chinese
            : TrayLanguage.English;
    }

    private static void Persist(TrayLanguage language)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(KeyPath, writable: true);
            key?.SetValue(ValueName, language.ToString(), RegistryValueKind.String);
        }
        catch (Exception)
        {
            // A refused write only costs the choice at the next launch.
        }
    }
}
