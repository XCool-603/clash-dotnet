using System.Collections.Concurrent;
using Clash.Core.Common;

namespace Clash.Core.Adapter;

/// <summary>
/// Shared behaviour for every concrete outbound and group: delay history,
/// liveness, connection tracking for <c>CloseConnections</c>, and the API extras
/// bag. Protocol adapters override <see cref="DialTcpAsync"/> and, when they can
/// carry datagrams, <see cref="DialUdpAsync"/>.
/// </summary>
public abstract class ProxyAdapter : IProxy
{
    private static readonly IReadOnlyDictionary<string, object?> NoExtra =
        new Dictionary<string, object?>();

    private readonly Lock _historyLock = new();
    private readonly LinkedList<DelayHistory> _history = new();
    private readonly ConcurrentDictionary<long, IDisposable> _connections = new();
    private long _connectionSequence;
    private volatile bool _alive = true;

    protected ProxyAdapter(string name, ProxyType type)
    {
        Name = name ?? throw new ArgumentNullException(nameof(name));
        Type = type;
    }

    public string Name { get; }

    public ProxyType Type { get; }

    public virtual string TypeName => Type.ToApiString();

    public bool Alive
    {
        get => _alive;
        protected set => _alive = value;
    }

    public virtual bool SupportUdp => false;

    public virtual bool IsGroup => false;

    /// <summary>Oldest first, newest last, capped at <see cref="MaxHistory"/> like Clash.</summary>
    public IReadOnlyList<DelayHistory> History
    {
        get
        {
            lock (_historyLock) return _history.ToArray();
        }
    }

    public virtual IReadOnlyDictionary<string, object?> ApiExtra => NoExtra;

    /// <summary>Number of flows this adapter is currently carrying.</summary>
    public int ActiveConnections => _connections.Count;

    /// <summary>Appends a probe result and trims the history to the last ten entries.</summary>
    public void PushHistory(int delayMs)
    {
        lock (_historyLock)
        {
            _history.AddLast(new DelayHistory(DateTimeOffset.UtcNow, delayMs));
            while (_history.Count > 10) _history.RemoveFirst();
        }

        // A successful probe proves the node is usable; a failure marks it dead
        // until the next successful probe, matching Clash's `alive` semantics.
        Alive = delayMs > 0;
    }

    /// <summary>Marks the adapter dead after a dial failure.</summary>
    public void MarkFailed() => Alive = false;

    /// <summary>Marks the adapter alive after a successful dial.</summary>
    public void MarkAlive() => Alive = true;

    public abstract Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default);

    public virtual Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromException<IPacketConnection>(
            new NotSupportedException($"proxy [{Name}] of type [{TypeName}] does not support UDP"));

    public virtual void CloseConnections()
    {
        foreach (var connection in _connections.Values)
        {
            try { connection.Dispose(); } catch { /* already gone */ }
        }
        _connections.Clear();
    }

    /// <summary>Registers a live flow so <see cref="CloseConnections"/> can tear it down.</summary>
    protected IDisposable TrackConnection(IDisposable connection)
    {
        var id = Interlocked.Increment(ref _connectionSequence);
        var tracked = new TrackedHandle(this, id, connection);
        _connections[id] = tracked;
        return tracked;
    }

    /// <summary>Wraps a stream so its lifetime is tracked by this adapter.</summary>
    protected ProxyStream Track(ProxyStream stream) => new(stream, stream.LocalEndPoint, stream.RemoteEndPoint, TrackConnection(stream));

    private void Untrack(long id) => _connections.TryRemove(id, out _);

    private sealed class TrackedHandle(ProxyAdapter owner, long id, IDisposable inner) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            owner.Untrack(id);
            try { inner.Dispose(); } catch { /* ignore */ }
        }
    }
}
