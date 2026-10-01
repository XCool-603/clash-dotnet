using System.Net;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;

namespace Clash.Core.Tunnel;

/// <summary>
/// The central router. Every inbound hands its flows here; the tunnel matches
/// rules, picks an adapter, dials it, relays bytes, and keeps the accounting the
/// REST API reports.
/// </summary>
public interface ITunnel
{
    ClashConfig Config { get; }
    IDnsResolver Dns { get; }
    IGeoData Geo { get; }
    IProxyManager Proxies { get; }
    ConnectionManager Connections { get; }
    IRuleEngine Rules { get; }
    TrafficTracker Traffic { get; }
    IDelayTester DelayTester { get; }

    /// <summary>Current routing mode; changing it is what <c>PATCH /configs</c> does.</summary>
    Mode Mode { get; set; }

    /// <summary>Resolves the outbound for a flow without dialing.</summary>
    Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default);

    /// <summary>Matches, dials and returns the outbound stream. Used for chained dials.</summary>
    Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default);

    /// <summary>Matches and opens a UDP association.</summary>
    Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default);

    /// <summary>Full lifecycle for an accepted TCP stream: match, dial, relay, account, close.</summary>
    Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default);

    /// <summary>Full lifecycle for an accepted UDP association, including NAT bookkeeping.</summary>
    Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default);

    /// <summary>Emits a log line to every <c>/logs</c> subscriber.</summary>
    void Log(string level, string message);

    /// <summary>Raised for each log line; the API bridges this to WebSocket clients.</summary>
    event Action<string, string>? LogEmitted;
}

/// <summary>Registry of every adapter known to the running instance.</summary>
public interface IProxyManager
{
    IReadOnlyDictionary<string, IProxy> Proxies { get; }

    IReadOnlyList<IProxy> All { get; }

    /// <summary>Adapters contributed by <c>proxy-providers</c>, keyed by provider name.</summary>
    IReadOnlyDictionary<string, IReadOnlyList<IProxy>> ProviderProxies { get; }

    IProxy? Get(string name);

    IProxy MustGet(string name);

    bool Add(IProxy proxy);

    bool Remove(string name);

    void Clear();

    /// <summary>The <c>GLOBAL</c> selector group every proxy is a member of.</summary>
    IProxy Global { get; }

    /// <summary>The <c>DIRECT</c> adapter.</summary>
    IProxy Direct { get; }

    /// <summary>The <c>REJECT</c> adapter.</summary>
    IProxy Reject { get; }

    /// <summary>Raised whenever membership changes, so the API can push updates.</summary>
    event Action? Changed;
}

/// <summary>Rule storage and evaluation.</summary>
public interface IRuleEngine
{
    IReadOnlyList<IRule> Rules { get; }

    IReadOnlyDictionary<string, IRuleSet> RuleSets { get; }

    /// <summary>First-match-wins evaluation, resolving the destination when a rule requires it.</summary>
    Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default);

    void SetRules(IReadOnlyList<IRule> rules);

    /// <summary>Backs <c>PATCH /rules</c>: disables one rule for the lifetime of the process.</summary>
    bool Disable(string ruleType, string payload);

    /// <summary>Re-enables a previously disabled rule.</summary>
    bool Enable(string ruleType, string payload);

    /// <summary>True when the rule is currently disabled.</summary>
    bool IsDisabled(string ruleType, string payload);
}

/// <summary>Per-second and cumulative byte accounting.</summary>
public sealed class TrafficTracker
{
    private long _uploadTotal;
    private long _downloadTotal;
    private long _uploadDelta;
    private long _downloadDelta;

    public long UploadTotal => Interlocked.Read(ref _uploadTotal);
    public long DownloadTotal => Interlocked.Read(ref _downloadTotal);

    public void AddUpload(long bytes)
    {
        Interlocked.Add(ref _uploadTotal, bytes);
        Interlocked.Add(ref _uploadDelta, bytes);
    }

    public void AddDownload(long bytes)
    {
        Interlocked.Add(ref _downloadTotal, bytes);
        Interlocked.Add(ref _downloadDelta, bytes);
    }

    /// <summary>Reads and clears the bytes accumulated since the previous call.</summary>
    public (long Upload, long Download) TakeDelta()
        => (Interlocked.Exchange(ref _uploadDelta, 0), Interlocked.Exchange(ref _downloadDelta, 0));

    public void Reset()
    {
        Interlocked.Exchange(ref _uploadTotal, 0);
        Interlocked.Exchange(ref _downloadTotal, 0);
        TakeDelta();
    }
}

/// <summary>One live flow, as reported by <c>GET /connections</c>.</summary>
public sealed class TrackedConnection : IDisposable
{
    private readonly ByteCounter _upload = new();
    private readonly ByteCounter _download = new();
    private int _closed;

    public TrackedConnection(Metadata metadata)
    {
        Id = Guid.NewGuid().ToString();
        Metadata = metadata;
        StartTime = DateTimeOffset.UtcNow;
    }

    public string Id { get; }

    public Metadata Metadata { get; }

    public DateTimeOffset StartTime { get; }

    public long Upload => _upload.Value;

    public long Download => _download.Value;

    public bool Closed => Volatile.Read(ref _closed) != 0;

    /// <summary>Chains as reported by the API: innermost adapter first.</summary>
    public IReadOnlyList<string> Chain => Metadata.Chain;

    public string? Rule => Metadata.Rule;

    public string? RulePayload => Metadata.RulePayload;

    public void AddUpload(long bytes) => _upload.Add(bytes);

    public void AddDownload(long bytes) => _download.Add(bytes);

    /// <summary>Raised exactly once, when the flow is torn down.</summary>
    public event Action<TrackedConnection>? Closed1;

    internal void MarkClosed() => Interlocked.Exchange(ref _closed, 1);

    /// <summary>Set by the tunnel so <see cref="Dispose"/> can tear the transport down.</summary>
    internal Action? CloseAction { get; set; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        try { CloseAction?.Invoke(); } catch { /* already gone */ }
        try { Closed1?.Invoke(this); } catch { /* observer fault must not escape */ }
    }

    /// <summary>Milliseconds this flow has been alive.</summary>
    public long AgeMs => (long)(DateTimeOffset.UtcNow - StartTime).TotalMilliseconds;
}

/// <summary>Tracks live flows and cumulative totals.</summary>
public sealed class ConnectionManager
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, TrackedConnection> _connections = new();
    private readonly TrafficTracker _traffic;

    public ConnectionManager(TrafficTracker traffic) => _traffic = traffic;

    public event Action<TrackedConnection>? ConnectionAdded;

    public event Action<TrackedConnection>? ConnectionClosed;

    public int ActiveCount => _connections.Count;

    public TrafficTracker Traffic => _traffic;

    /// <summary>Snapshot ordered newest first, matching Clash's ordering.</summary>
    public IReadOnlyList<TrackedConnection> Snapshot()
        => _connections.Values.OrderByDescending(c => c.StartTime).ToList();

    public TrackedConnection Track(Metadata metadata)
    {
        var connection = new TrackedConnection(metadata);
        connection.Closed1 += OnClosed;
        _connections[connection.Id] = connection;
        ConnectionAdded?.Invoke(connection);
        return connection;
    }

    public bool Close(string id)
    {
        if (!_connections.TryGetValue(id, out var connection)) return false;
        connection.Dispose();
        return true;
    }

    public void CloseAll()
    {
        foreach (var connection in _connections.Values.ToList())
        {
            connection.Dispose();
        }
        _connections.Clear();
    }

    private void OnClosed(TrackedConnection connection)
    {
        _connections.TryRemove(connection.Id, out _);
        ConnectionClosed?.Invoke(connection);
    }
}
