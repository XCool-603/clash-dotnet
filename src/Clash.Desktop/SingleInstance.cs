namespace Clash.Desktop;

/// <summary>
/// Named-object single-instance guard.
/// <para>
/// The first process creates and owns a named <see cref="Mutex"/> and parks a
/// wait on a named <see cref="EventWaitHandle"/>. Every later process finds the
/// mutex already taken, sets the event to ask the owner to surface its
/// dashboard, and then exits. The <c>Global\</c> namespace is tried first so
/// instances started from different sessions still collide; if the account
/// lacks <c>SeCreateGlobalPrivilege</c> the <c>Local\</c> namespace is used
/// instead.
/// </para>
/// </summary>
internal sealed class SingleInstance : IDisposable
{
    private const string MutexBaseName = "ClashForDotNet.SingleInstance";
    private const string EventBaseName = "ClashForDotNet.ShowDashboard";

    private readonly Mutex? _mutex;
    private readonly EventWaitHandle? _signal;
    private readonly RegisteredWaitHandle? _registration;
    private bool _disposed;

    private SingleInstance(Mutex? mutex, EventWaitHandle? signal, bool isOwner, string scope)
    {
        _mutex = mutex;
        _signal = signal;
        IsOwner = isOwner;
        Scope = scope;

        if (isOwner && signal is not null)
        {
            _registration = ThreadPool.RegisterWaitForSingleObject(
                signal,
                static (state, _) => ((SingleInstance)state!).RaiseShowRequested(),
                this,
                Timeout.Infinite,
                executeOnlyOnce: false);
        }
    }

    /// <summary>True when this process created (and therefore owns) the guard objects.</summary>
    public bool IsOwner { get; }

    /// <summary>The kernel-object namespace that was used, for diagnostics.</summary>
    public string Scope { get; }

    /// <summary>Raised on a thread-pool thread when another instance asks this one to show its dashboard.</summary>
    public event Action? ShowRequested;

    /// <summary>Creates or opens the guard objects, preferring the global namespace.</summary>
    public static SingleInstance Acquire()
    {
        foreach (var scope in new[] { @"Global\", @"Local\" })
        {
            Mutex? mutex = null;
            EventWaitHandle? signal = null;
            try
            {
                mutex = new Mutex(initiallyOwned: true, scope + MutexBaseName, out var createdNew);
                signal = new EventWaitHandle(false, EventResetMode.AutoReset, scope + EventBaseName, out _);
                return new SingleInstance(mutex, signal, createdNew, scope);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or NotSupportedException)
            {
                mutex?.Dispose();
                signal?.Dispose();
            }
        }

        // Last resort: run without a guard rather than refusing to start.
        return new SingleInstance(null, null, isOwner: true, scope: string.Empty);
    }

    /// <summary>Asks the running instance to bring its dashboard to the front. Safe to call when no owner exists.</summary>
    public void SignalExistingInstance()
    {
        try
        {
            _signal?.Set();
        }
        catch (Exception ex) when (ex is ObjectDisposedException or UnauthorizedAccessException or IOException)
        {
            // The owner vanished between the mutex check and the signal; nothing to do.
        }
    }

    private void RaiseShowRequested()
    {
        try
        {
            ShowRequested?.Invoke();
        }
        catch (Exception)
        {
            // A tray callback must never tear down the wait registration.
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _registration?.Unregister(null);

        if (IsOwner && _mutex is not null)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
                // Never owned (fallback path) - releasing is unnecessary.
            }
        }

        _signal?.Dispose();
        _mutex?.Dispose();
    }
}
