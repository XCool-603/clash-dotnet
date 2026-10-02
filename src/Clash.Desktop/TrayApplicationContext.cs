using System.Diagnostics;

namespace Clash.Desktop;

/// <summary>
/// The tray shell: it owns the embedded core (<see cref="CoreController"/>), the
/// system-proxy toggle (<see cref="SystemProxy"/>) and the startup entry
/// (<see cref="Autostart"/>), and exposes them as a notify-icon menu.
/// <para>
/// Every menu handler is an <c>async void</c> event handler, so each one funnels
/// its failures into a balloon tip instead of tearing the message pump down; a
/// tray application that dies on a failed HTTP call is worse than one that
/// reports it.
/// </para>
/// </summary>
internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly CoreController _core;
    private readonly SingleInstance _singleInstance;
    private readonly NotifyIcon _tray;
    private readonly ContextMenuStrip _menu;
    private readonly SynchronizationContext _ui;

    private readonly ToolStripMenuItem _statusItem = new() { Enabled = false };
    private readonly ToolStripMenuItem _dashboardItem = new();
    private readonly ToolStripMenuItem _ruleModeItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _globalModeItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _directModeItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _systemProxyItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _restartItem = new();
    private readonly ToolStripMenuItem _autostartItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _modeMenu = new();
    private readonly ToolStripMenuItem _languageMenu = new();
    private readonly ToolStripMenuItem _englishItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _chineseItem = new() { CheckOnClick = false };
    private readonly ToolStripMenuItem _exitItem = new();

    private bool _shuttingDown;

    /// <summary>
    /// The status line is kept as a message key rather than rendered text, so a
    /// language switch can re-render the current state instead of leaving the
    /// previous language's sentence on screen.
    /// </summary>
    private string _statusKey = "status.starting";
    private object?[] _statusArgs = [];

    public TrayApplicationContext(string[] args, SingleInstance singleInstance)
    {
        _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _singleInstance = singleInstance;
        _core = new CoreController(args);

        _menu = BuildMenu();
        _tray = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = TrayStrings.T("app.name"),
            ContextMenuStrip = _menu,
            Visible = true,
        };

        // After _tray exists: ApplyLanguage renders the status, which writes the
        // tray tooltip as well as the menu caption.
        ApplyLanguage();
        TrayStrings.Changed += OnLanguageChanged;

        _tray.DoubleClick += (_, _) => OpenDashboard();

        _singleInstance.ShowRequested += OnShowRequested;
        _core.Faulted += message => RunOnUi(() => Notify(TrayStrings.T("app.name"), message, ToolTipIcon.Warning));
        _ = StartCoreAsync();
    }

    private ContextMenuStrip BuildMenu()
    {
        _dashboardItem.Click += (_, _) => OpenDashboard();
        _ruleModeItem.Click += async (_, _) => await SetModeAsync("rule");
        _globalModeItem.Click += async (_, _) => await SetModeAsync("global");
        _directModeItem.Click += async (_, _) => await SetModeAsync("direct");
        _systemProxyItem.Click += async (_, _) => await ToggleSystemProxyAsync();
        _restartItem.Click += async (_, _) => await RestartCoreAsync();
        _autostartItem.Click += (_, _) => ToggleAutostart();
        _englishItem.Click += (_, _) => TrayStrings.Set(TrayLanguage.English);
        _chineseItem.Click += (_, _) => TrayStrings.Set(TrayLanguage.Chinese);
        _exitItem.Click += async (_, _) => await ExitAsync();

        _modeMenu.DropDownItems.AddRange([_ruleModeItem, _globalModeItem, _directModeItem]);
        _languageMenu.DropDownItems.AddRange([_englishItem, _chineseItem]);

        var menu = new ContextMenuStrip();
        menu.Items.AddRange(
        [
            _statusItem,
            new ToolStripSeparator(),
            _dashboardItem,
            _modeMenu,
            _systemProxyItem,
            new ToolStripSeparator(),
            _restartItem,
            _autostartItem,
            _languageMenu,
            new ToolStripSeparator(),
            _exitItem,
        ]);

        return menu;
    }

    /// <summary>
    /// Writes every caption in the active language. Called once at startup and
    /// again whenever the language changes, which is why the captions are not set
    /// where the items are constructed.
    /// </summary>
    private void ApplyLanguage()
    {
        _dashboardItem.Text = TrayStrings.T("menu.dashboard");
        _modeMenu.Text = TrayStrings.T("menu.mode");
        _ruleModeItem.Text = TrayStrings.T("menu.mode.rule");
        _globalModeItem.Text = TrayStrings.T("menu.mode.global");
        _directModeItem.Text = TrayStrings.T("menu.mode.direct");
        _systemProxyItem.Text = TrayStrings.T("menu.systemProxy");
        _restartItem.Text = TrayStrings.T("menu.restart");
        _autostartItem.Text = TrayStrings.T("menu.autostart");
        _languageMenu.Text = TrayStrings.T("menu.language");
        _exitItem.Text = TrayStrings.T("menu.exit");

        _englishItem.Text = TrayStrings.Label(TrayLanguage.English);
        _chineseItem.Text = TrayStrings.Label(TrayLanguage.Chinese);
        _englishItem.Checked = !TrayStrings.IsChinese;
        _chineseItem.Checked = TrayStrings.IsChinese;

        RenderStatus();
    }

    private void OnLanguageChanged() => RunOnUi(ApplyLanguage);

    // ── Core lifecycle ───────────────────────────────────────────────────────

    private async Task StartCoreAsync()
    {
        SetStatus("status.starting");

        try
        {
            await _core.StartAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetStatus("status.stopped");
            Notify(TrayStrings.T("notify.coreStartFailed.title"), ex.Message, ToolTipIcon.Error);
            return;
        }

        if (!await _core.WaitUntilReadyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(true))
        {
            SetStatus("status.apiNotAnswering");
        }
        else
        {
            SetRunningState();
        }

        // Adopt whatever state the machine is already in rather than assuming.
        _autostartItem.Checked = Autostart.IsEnabled();
        _systemProxyItem.Checked = _core.MixedPort != 0 && SystemProxy.IsPointingAt(_core.MixedPort);

        await RefreshModeAsync().ConfigureAwait(true);
    }

    private async Task RestartCoreAsync()
    {
        SetStatus("status.restarting");
        try
        {
            await _core.RestartAsync().ConfigureAwait(true);
            if (!await _core.WaitUntilReadyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(true))
            {
                SetStatus("status.restartedApiNotAnswering");
            }
            else
            {
                SetRunningState();
            }

            await RefreshModeAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetStatus("status.stopped");
            Notify(TrayStrings.T("notify.coreRestartFailed.title"), ex.Message, ToolTipIcon.Error);
        }
    }

    private async Task ExitAsync()
    {
        if (_shuttingDown) return;
        _shuttingDown = true;

        _tray.Visible = false;

        // Leaving the machine pointed at a proxy that is about to disappear would
        // break every application until the user noticed.
        if (_systemProxyItem.Checked)
        {
            try
            {
                SystemProxy.Disable();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"restoring the system proxy failed: {ex.Message}");
            }
        }

        try
        {
            await _core.DisposeAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"stopping the core failed: {ex.Message}");
        }

        _tray.Dispose();
        _menu.Dispose();
        ExitThread();
    }

    // ── Menu actions ─────────────────────────────────────────────────────────

    private void OpenDashboard()
    {
        try
        {
            Process.Start(new ProcessStartInfo(_core.DashboardUrl) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Notify(TrayStrings.T("notify.dashboardFailed.title"), ex.Message, ToolTipIcon.Error);
        }
    }

    private async Task SetModeAsync(string mode)
    {
        if (!await _core.SetModeAsync(mode).ConfigureAwait(true))
        {
            Notify(TrayStrings.T("notify.modeFailed.title"), TrayStrings.T("notify.modeFailed.message", mode), ToolTipIcon.Warning);
            await RefreshModeAsync().ConfigureAwait(true);
            return;
        }

        ApplyMode(mode);
    }

    private async Task RefreshModeAsync()
    {
        var mode = await _core.GetModeAsync().ConfigureAwait(true);
        if (!string.IsNullOrEmpty(mode)) ApplyMode(mode!);
    }

    private void ApplyMode(string mode)
    {
        _ruleModeItem.Checked = string.Equals(mode, "rule", StringComparison.OrdinalIgnoreCase);
        _globalModeItem.Checked = string.Equals(mode, "global", StringComparison.OrdinalIgnoreCase);
        _directModeItem.Checked = string.Equals(mode, "direct", StringComparison.OrdinalIgnoreCase);
    }

    private async Task ToggleSystemProxyAsync()
    {
        var wanted = !_systemProxyItem.Checked;

        if (wanted)
        {
            var port = _core.MixedPort;
            if (port == 0)
            {
                Notify(TrayStrings.T("notify.noProxyPort.title"), TrayStrings.T("notify.noProxyPort.message"), ToolTipIcon.Warning);
                return;
            }

            try
            {
                SystemProxy.Enable("127.0.0.1", port);
            }
            catch (Exception ex)
            {
                Notify(TrayStrings.T("notify.systemProxyFailed.title"), ex.Message, ToolTipIcon.Error);
                return;
            }

            _systemProxyItem.Checked = SystemProxy.IsPointingAt(port);
        }
        else
        {
            try
            {
                SystemProxy.Disable();
            }
            catch (Exception ex)
            {
                Notify(TrayStrings.T("notify.systemProxyRestoreFailed.title"), ex.Message, ToolTipIcon.Error);
                return;
            }

            _systemProxyItem.Checked = SystemProxy.IsPointingAt(_core.MixedPort);
        }
    }

    private void ToggleAutostart()
    {
        var wanted = !_autostartItem.Checked;
        if (!Autostart.TrySet(wanted))
        {
            Notify(TrayStrings.T("notify.autostartFailed.title"), TrayStrings.T("notify.autostartFailed.message"), ToolTipIcon.Warning);
            return;
        }

        _autostartItem.Checked = Autostart.IsEnabled();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// The "running" status is described by a key plus its argument rather than a
    /// finished sentence, so a language switch re-renders it.
    /// </summary>
    private void SetRunningState() => SetStatus(_core.MixedPort != 0 ? "status.runningMixed" : "status.runningNoPort", _core.MixedPort);

    private void SetStatus(string key, params object?[] args)
    {
        _statusKey = key;
        _statusArgs = args;
        RenderStatus();
    }

    /// <summary>Renders the remembered status in the active language.</summary>
    private void RenderStatus()
    {
        var text = TrayStrings.T(_statusKey, _statusArgs);
        _statusItem.Text = text;

        // The shell caps a tray tooltip at 63 characters.
        var app = TrayStrings.T("app.name");
        _tray.Text = app.Length + 3 + text.Length <= 63 ? $"{app} — {text}" : app;
    }

    private void Notify(string title, string message, ToolTipIcon icon)
    {
        try
        {
            _tray.BalloonTipTitle = title;
            _tray.BalloonTipText = message;
            _tray.BalloonTipIcon = icon;
            _tray.ShowBalloonTip(5000);
        }
        catch (Exception)
        {
            // Notifications are best-effort.
        }
    }

    private void RunOnUi(Action action)
    {
        if (_shuttingDown) return;
        _ui.Post(static state => ((Action)state!)(), action);
    }

    private void OnShowRequested() => RunOnUi(OpenDashboard);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _singleInstance.ShowRequested -= OnShowRequested;
            _tray.Dispose();
            _menu.Dispose();
        }

        base.Dispose(disposing);
    }
}
