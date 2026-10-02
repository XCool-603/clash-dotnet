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

    private readonly ToolStripMenuItem _statusItem = new("Starting…") { Enabled = false };
    private readonly ToolStripMenuItem _dashboardItem = new("Open Dashboard");
    private readonly ToolStripMenuItem _ruleModeItem = new("Rule") { CheckOnClick = false };
    private readonly ToolStripMenuItem _globalModeItem = new("Global") { CheckOnClick = false };
    private readonly ToolStripMenuItem _directModeItem = new("Direct") { CheckOnClick = false };
    private readonly ToolStripMenuItem _systemProxyItem = new("System Proxy") { CheckOnClick = false };
    private readonly ToolStripMenuItem _restartItem = new("Restart Core");
    private readonly ToolStripMenuItem _autostartItem = new("Run at Startup") { CheckOnClick = false };
    private readonly ToolStripMenuItem _exitItem = new("Exit");

    private bool _shuttingDown;

    public TrayApplicationContext(string[] args, SingleInstance singleInstance)
    {
        _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _singleInstance = singleInstance;
        _core = new CoreController(args);

        _menu = BuildMenu();
        _tray = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "Clash for .NET",
            ContextMenuStrip = _menu,
            Visible = true,
        };
        _tray.DoubleClick += (_, _) => OpenDashboard();

        _singleInstance.ShowRequested += OnShowRequested;
        _core.Faulted += message => RunOnUi(() => Notify("Clash for .NET", message, ToolTipIcon.Warning));

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
        _exitItem.Click += async (_, _) => await ExitAsync();

        var modeMenu = new ToolStripMenuItem("Mode");
        modeMenu.DropDownItems.AddRange([_ruleModeItem, _globalModeItem, _directModeItem]);

        var menu = new ContextMenuStrip();
        menu.Items.AddRange(
        [
            _statusItem,
            new ToolStripSeparator(),
            _dashboardItem,
            modeMenu,
            _systemProxyItem,
            new ToolStripSeparator(),
            _restartItem,
            _autostartItem,
            new ToolStripSeparator(),
            _exitItem,
        ]);

        return menu;
    }

    // ── Core lifecycle ───────────────────────────────────────────────────────

    private async Task StartCoreAsync()
    {
        SetStatus("Starting…");

        try
        {
            await _core.StartAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetStatus("Stopped");
            Notify("The core could not start", ex.Message, ToolTipIcon.Error);
            return;
        }

        if (!await _core.WaitUntilReadyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(true))
        {
            SetStatus("Started, but the control API is not answering");
        }
        else
        {
            SetStatus(DescribeRunningState());
        }

        // Adopt whatever state the machine is already in rather than assuming.
        _autostartItem.Checked = Autostart.IsEnabled();
        _systemProxyItem.Checked = _core.MixedPort != 0 && SystemProxy.IsPointingAt(_core.MixedPort);

        await RefreshModeAsync().ConfigureAwait(true);
    }

    private async Task RestartCoreAsync()
    {
        SetStatus("Restarting…");
        try
        {
            await _core.RestartAsync().ConfigureAwait(true);
            if (!await _core.WaitUntilReadyAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(true))
            {
                SetStatus("Restarted, but the control API is not answering");
            }
            else
            {
                SetStatus(DescribeRunningState());
            }

            await RefreshModeAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            SetStatus("Stopped");
            Notify("The core could not be restarted", ex.Message, ToolTipIcon.Error);
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
            Notify("The dashboard could not be opened", ex.Message, ToolTipIcon.Error);
        }
    }

    private async Task SetModeAsync(string mode)
    {
        if (!await _core.SetModeAsync(mode).ConfigureAwait(true))
        {
            Notify("The mode could not be changed", $"The core did not accept `mode: {mode}`.", ToolTipIcon.Warning);
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
                Notify("No proxy port", "The configuration has no `mixed-port` (or `port`), so there is nothing to point the system proxy at.", ToolTipIcon.Warning);
                return;
            }

            try
            {
                SystemProxy.Enable("127.0.0.1", port);
            }
            catch (Exception ex)
            {
                Notify("The system proxy could not be enabled", ex.Message, ToolTipIcon.Error);
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
                Notify("The system proxy could not be restored", ex.Message, ToolTipIcon.Error);
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
            Notify("Startup could not be changed", "Windows refused the change to the per-user Run key.", ToolTipIcon.Warning);
            return;
        }

        _autostartItem.Checked = Autostart.IsEnabled();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private string DescribeRunningState()
        => _core.MixedPort != 0
            ? $"Running — mixed port {_core.MixedPort}"
            : "Running — no mixed port configured";

    private void SetStatus(string text)
    {
        _statusItem.Text = text;
        _tray.Text = text.Length <= 63 ? $"Clash for .NET — {text}" : "Clash for .NET";
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
