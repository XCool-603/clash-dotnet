namespace Clash.Desktop;

/// <summary>
/// Placeholder tray context; replaced by the full tray shell (start/stop the
/// embedded server, switch mode, toggle the system proxy, autostart).
/// </summary>
internal sealed class TrayApplicationContext : ApplicationContext
{
    public TrayApplicationContext(string[] args)
    {
        var exit = new ToolStripMenuItem("Exit", null, (_, _) => ExitThread());
        var menu = new ContextMenuStrip();
        menu.Items.Add(exit);

        var notifyIcon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "Clash for .NET",
            ContextMenuStrip = menu,
            Visible = true,
        };

        _notifyIcon = notifyIcon;
    }

    private readonly NotifyIcon _notifyIcon;

    protected override void Dispose(bool disposing)
    {
        if (disposing) _notifyIcon.Dispose();
        base.Dispose(disposing);
    }
}
