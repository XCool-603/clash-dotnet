namespace Clash.Desktop;

/// <summary>
/// Entry point of the Windows tray shell.
/// <para>
/// A second launch never reaches <see cref="Application.Run"/>: it signals the
/// already-running instance through <see cref="SingleInstance"/> and returns.
/// Every unhandled exception - UI thread, background thread or fire-and-forget
/// task - is funnelled into a message box instead of a silent process death.
/// </para>
/// </summary>
internal static class Program
{
    private static int _reportingFatal;

    /// <summary>Runs the tray shell.</summary>
    [STAThread]
    private static void Main(string[] args)
    {
        using var singleInstance = SingleInstance.Acquire();
        if (!singleInstance.IsOwner)
        {
            singleInstance.SignalExistingInstance();
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => ReportFatal("Unexpected error", e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => ReportFatal("Fatal error", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            e.SetObserved();
            ReportFatal("Background task error", e.Exception);
        };

        try
        {
            using var context = new TrayApplicationContext(args, singleInstance);
            Application.Run(context);
        }
        catch (Exception ex)
        {
            ReportFatal("Clash for .NET could not start", ex);
        }
    }

    /// <summary>Shows a failure to the user. Re-entrant calls are dropped so a broken message pump cannot loop.</summary>
    private static void ReportFatal(string title, Exception? exception)
    {
        if (Interlocked.Exchange(ref _reportingFatal, 1) == 1) return;

        var detail = exception?.ToString() ?? "An unknown error occurred.";
        try
        {
            MessageBox.Show(
                detail,
                $"Clash for .NET - {title}",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        catch (Exception)
        {
            // Nothing left to report to; the process is going down anyway.
        }
        finally
        {
            Interlocked.Exchange(ref _reportingFatal, 0);
        }
    }
}
