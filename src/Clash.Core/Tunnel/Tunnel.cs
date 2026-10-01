using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Tunnel;

/// <summary>
/// The central router. Inbound listeners hand their flows here; the tunnel
/// enriches the metadata (fake-IP reversal, sniffing), matches a rule, picks an
/// adapter, relays the bytes and keeps the accounting the REST API reports.
/// </summary>
public sealed class Tunnel : ITunnel, IAsyncDisposable
{
    private const int RelayBufferSize = 32 * 1024;
    private const int SniffByteCount = 4096;
    private static readonly TimeSpan SniffTimeout = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// How long the surviving direction may keep running after the other one ends.
    /// Long enough for a response to drain, short enough that an abandoned flow
    /// does not pin a connection open.
    /// </summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(20);

    private readonly ILogger<Tunnel> _logger;
    private readonly ConnectionManager _connections;
    private readonly TrafficTracker _traffic = new();
    private volatile Mode _mode;
    private int _disposed;

    public Tunnel(
        ClashConfig config,
        IDnsResolver dns,
        IGeoData geo,
        IProxyManager proxies,
        IRuleEngine rules,
        ILogger<Tunnel> logger)
    {
        Config = config ?? throw new ArgumentNullException(nameof(config));
        Dns = dns ?? throw new ArgumentNullException(nameof(dns));
        Geo = geo ?? throw new ArgumentNullException(nameof(geo));
        Proxies = proxies ?? throw new ArgumentNullException(nameof(proxies));
        Rules = rules ?? throw new ArgumentNullException(nameof(rules));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _mode = config.Mode;
        _connections = new ConnectionManager(_traffic);
        DelayTester = new DelayTester();
    }

    public ClashConfig Config { get; private set; }

    public IDnsResolver Dns { get; }

    public IGeoData Geo { get; }

    public IProxyManager Proxies { get; private set; }

    public ConnectionManager Connections => _connections;

    public IRuleEngine Rules { get; private set; }

    public TrafficTracker Traffic => _traffic;

    public IDelayTester DelayTester { get; }

    public Mode Mode
    {
        get => _mode;
        set
        {
            if (_mode == value) return;
            _mode = value;
            Log("info", $"mode changed to {value.ToApiString()}");
        }
    }

    public event Action<string, string>? LogEmitted;

    /// <summary>Swaps in a freshly parsed configuration, keeping the runtime state.</summary>
    public void UpdateConfig(ClashConfig config)
    {
        Config = config;
        Mode = config.Mode;
    }

    /// <summary>
    /// Swaps the proxy registry and rule engine after a reload. In-flight flows
    /// keep running against the adapters they already hold; only new flows see the
    /// new registry. The previous registry is disposed in the background.
    /// </summary>
    public void ReplaceProxies(IProxyManager proxies, IRuleEngine rules)
    {
        ArgumentNullException.ThrowIfNull(proxies);
        ArgumentNullException.ThrowIfNull(rules);

        var previous = Proxies;
        Proxies = proxies;
        Rules = rules;

        if (!ReferenceEquals(previous, proxies) && previous is IAsyncDisposable disposable)
        {
            _ = Task.Run(async () =>
            {
                try { await disposable.DisposeAsync().ConfigureAwait(false); }
                catch (Exception ex) { _logger.LogDebug(ex, "disposing the previous proxy registry failed"); }
            });
        }
    }

    public void Log(string level, string message)
    {
        try { LogEmitted?.Invoke(level, message); } catch { /* observers must not break routing */ }

        if (level.Equals("error", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogError("{Message}", message);
        }
        else if (level.Equals("warning", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("{Message}", message);
        }
        else
        {
            _logger.LogInformation("{Message}", message);
        }
    }

    public async Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        NormalizeMetadata(metadata);

        // A special-proxy rule short-circuits everything else.
        if (!string.IsNullOrEmpty(metadata.SpecialProxy))
        {
            metadata.Rule = "Match";
            metadata.RulePayload = string.Empty;
            return null;
        }

        if (Mode is Mode.Direct or Mode.Global)
        {
            metadata.Rule = "Match";
            metadata.RulePayload = string.Empty;
            return null;
        }

        return await Rules.MatchAsync(metadata, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var match = await MatchAsync(metadata, cancellationToken).ConfigureAwait(false);
        var adapter = ResolveAdapter(metadata, match);

        metadata.Chain.Add(adapter.Name);
        var stream = await adapter.DialTcpAsync(metadata, null, cancellationToken).ConfigureAwait(false);

        if (stream.RemoteAddressString is { } remote) metadata.RemoteDestination = remote;
        return stream;
    }

    public async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var match = await MatchAsync(metadata, cancellationToken).ConfigureAwait(false);
        var adapter = ResolveAdapter(metadata, match);

        metadata.Chain.Add(adapter.Name);
        return await adapter.DialUdpAsync(metadata, cancellationToken).ConfigureAwait(false);
    }

    public async Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbound);
        ArgumentNullException.ThrowIfNull(metadata);

        var tracked = _connections.Track(metadata);
        var peekable = inbound as PeekableStream ?? new PeekableStream(inbound);
        ProxyStream? outbound = null;

        try
        {
            await TrySniffAsync(peekable, metadata, cancellationToken).ConfigureAwait(false);

            var match = await MatchAsync(metadata, cancellationToken).ConfigureAwait(false);
            var adapter = ResolveAdapter(metadata, match);
            metadata.Chain.Add(adapter.Name);

            outbound = await adapter.DialTcpAsync(metadata, null, cancellationToken).ConfigureAwait(false);
            if (outbound.RemoteAddressString is { } remote) metadata.RemoteDestination = remote;

            tracked.CloseAction = () =>
            {
                try { outbound.Dispose(); } catch { /* ignore */ }
                try { peekable.Dispose(); } catch { /* ignore */ }
            };

            await RelayAsync(tracked, peekable, outbound, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Client went away or the tunnel is shutting down.
        }
        catch (Exception ex)
        {
            Log("warning", $"[TCP] {metadata.DestinationString} via {string.Join(" -> ", metadata.Chain)} failed: {ex.Message}");
        }
        finally
        {
            tracked.Dispose();
            if (outbound is not null)
            {
                try { await outbound.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
            }
            try { await peekable.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
        }
    }

    public async Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inbound);
        ArgumentNullException.ThrowIfNull(metadata);

        // One outbound association per destination, so a single client-side
        // association can reach many destinations through different rules.
        var sessions = new ConcurrentDictionary<string, UdpSession>(StringComparer.Ordinal);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var buffer = ArrayPool<byte>.Shared.Rent(65_535);
                try
                {
                    var received = await inbound.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (received.BytesRead <= 0 || received.Remote is null) return;

                    var session = await GetOrCreateSessionAsync(sessions, inbound, received.Remote, metadata, cancellationToken)
                        .ConfigureAwait(false);
                    if (session is null) continue;

                    var payload = buffer.AsMemory(0, received.BytesRead);
                    await session.Outbound.SendAsync(payload, received.Remote, cancellationToken).ConfigureAwait(false);

                    session.Tracked.AddUpload(received.BytesRead);
                    _traffic.AddUpload(received.BytesRead);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        catch (Exception ex)
        {
            Log("warning", $"[UDP] {metadata.DestinationString} failed: {ex.Message}");
        }
        finally
        {
            foreach (var session in sessions.Values)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
            }
            sessions.Clear();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        _connections.CloseAll();
        if (Proxies is IAsyncDisposable asyncDisposable)
        {
            try { await asyncDisposable.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
        }
        GC.SuppressFinalize(this);
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// <summary>
    /// Maps a fake destination address back to the domain it stands for and marks
    /// the flow, so domain rules and the API report the real host.
    /// </summary>
    private void NormalizeMetadata(Metadata metadata)
    {
        if (metadata.Resolved) return;

        if (IPAddress.TryParse(metadata.DestinationAddress, out var address))
        {
            if (Dns.IsFakeIp(address))
            {
                var host = Dns.ReverseFakeIp(address);
                if (!string.IsNullOrEmpty(host))
                {
                    metadata.Host = host;
                    metadata.DnsMode = DnsMode.FakeIp;
                }
            }
            else if (string.IsNullOrEmpty(metadata.Host))
            {
                // A real address: remember it so IP rules can match without a lookup.
                metadata.Host = null;
            }
        }
        else if (string.IsNullOrEmpty(metadata.Host))
        {
            metadata.Host = metadata.DestinationAddress;
        }
    }

    private async Task TrySniffAsync(PeekableStream stream, Metadata metadata, CancellationToken cancellationToken)
    {
        var sniffer = Config.Sniffer;
        if (!sniffer.Enable) return;

        // Sniffing only adds information when the destination is not already a name.
        if (!metadata.DestinationIsIp) return;
        if (IsExemptFromSniffing(metadata)) return;

        try
        {
            var available = await stream.PeekAsync(SniffByteCount, SniffTimeout, cancellationToken).ConfigureAwait(false);
            if (available <= 0) return;

            var data = stream.Peeked.Span;
            var host = Sniffer.SniffTlsServerName(data)
                       ?? Sniffer.SniffHttpHost(data)
                       ?? Sniffer.SniffQuicServerName(data);

            if (string.IsNullOrEmpty(host)) return;

            metadata.SniffHost = host;
            if (sniffer.OverrideDestination || string.IsNullOrEmpty(metadata.Host))
            {
                metadata.Host = host;
            }
        }
        catch (OperationCanceledException)
        {
            // Cancellation during sniffing is not fatal; routing proceeds with the
            // original destination.
        }
    }

    private bool IsExemptFromSniffing(Metadata metadata)
    {
        var sniffer = Config.Sniffer;
        var host = metadata.DestinationAddress;

        foreach (var pattern in sniffer.SkipDomain)
        {
            if (DomainPatternMatches(pattern, host)) return true;
        }

        foreach (var pattern in sniffer.ForceDomain)
        {
            if (DomainPatternMatches(pattern, host)) return false;
        }

        // Only sniff the ports the configuration enables.
        var port = metadata.DestinationPort;
        return !PortMatches(sniffer.Sniff.Tls.Ports, port)
               && !PortMatches(sniffer.Sniff.Http.Ports, port)
               && !PortMatches(sniffer.Sniff.Quic.Ports, port);
    }

    private static bool PortMatches(List<object?> ports, ushort port)
    {
        if (ports.Count == 0) return true;

        foreach (var entry in ports)
        {
            switch (entry)
            {
                case long single when single == port:
                    return true;
                case int single when single == port:
                    return true;
                case string text when text.Contains('-', StringComparison.Ordinal):
                {
                    var parts = text.Split('-', 2);
                    if (parts.Length == 2 &&
                        int.TryParse(parts[0], out var low) &&
                        int.TryParse(parts[1], out var high) &&
                        port >= low && port <= high)
                    {
                        return true;
                    }
                    break;
                }
                case string text when int.TryParse(text, out var single) && single == port:
                    return true;
            }
        }

        return false;
    }

    private static bool DomainPatternMatches(string pattern, string host)
    {
        if (string.IsNullOrEmpty(pattern)) return false;

        var value = pattern.StartsWith("+.", StringComparison.Ordinal) ? pattern[2..]
            : pattern.StartsWith("*.", StringComparison.Ordinal) ? pattern[2..]
            : pattern;

        return host.Equals(value, StringComparison.OrdinalIgnoreCase)
               || host.EndsWith("." + value, StringComparison.OrdinalIgnoreCase);
    }

    private IProxy ResolveAdapter(Metadata metadata, RuleMatch? match)
    {
        if (!string.IsNullOrEmpty(metadata.SpecialProxy))
        {
            return Proxies.MustGet(metadata.SpecialProxy);
        }

        switch (Mode)
        {
            case Mode.Direct:
                return Proxies.Direct;

            case Mode.Global:
                return ResolveGlobal();

            default:
                if (match is null)
                {
                    metadata.Rule = "Match";
                    metadata.RulePayload = string.Empty;
                    return Proxies.Direct;
                }
                return Proxies.MustGet(match.AdapterName);
        }
    }

    private IProxy ResolveGlobal()
    {
        var global = Proxies.Global;
        if (global is IProxyGroup group && group.SelectedName is { } selected)
        {
            return Proxies.Get(selected) ?? global;
        }

        // No explicit selection: fall back to the first usable member, else DIRECT.
        if (global is IProxyGroup { Members.Count: > 0 } withMembers)
        {
            return withMembers.Members[0];
        }

        return Proxies.Direct;
    }

    /// <summary>
    /// Pumps bytes in both directions. When one direction ends the peer's send
    /// side is half-closed and the other direction is given a bounded grace period
    /// to drain, which is what request/response protocols need: closing the client
    /// write side must not discard the response.
    /// </summary>
    private async Task RelayAsync(TrackedConnection tracked, Stream inbound, Stream outbound, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var upload = PumpAsync(inbound, outbound, tracked.AddUpload, _traffic.AddUpload, cts.Token);
        var download = PumpAsync(outbound, inbound, tracked.AddDownload, _traffic.AddDownload, cts.Token);

        var first = await Task.WhenAny(upload, download).ConfigureAwait(false);
        var uploadFinishedFirst = ReferenceEquals(first, upload);
        var remaining = uploadFinishedFirst ? download : upload;

        // The pump that finished has stopped writing; tell its peer so the peer
        // can complete and close.
        HalfClose(uploadFinishedFirst ? outbound : inbound);

        try
        {
            await remaining.WaitAsync(DrainTimeout, cts.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Timeout, cancellation or a faulted pump: the flow is over.
        }

        await cts.CancelAsync().ConfigureAwait(false);

        try
        {
            await Task.WhenAll(upload, download).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Half-close races are normal; the flow is over either way.
        }
    }

    private static void HalfClose(Stream stream)
    {
        switch (stream)
        {
            case ProxyStream proxy:
                proxy.ShutdownSend();
                break;
            case IHalfCloseable halfCloseable:
                try { halfCloseable.ShutdownSend(); } catch { /* peer already gone */ }
                break;
        }
    }

    private static async Task PumpAsync(
        Stream source,
        Stream destination,
        Action<long> onTracked,
        Action<long> onTraffic,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(RelayBufferSize);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read <= 0) break;

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                await destination.FlushAsync(cancellationToken).ConfigureAwait(false);

                onTracked(read);
                onTraffic(read);
            }
        }
        catch (Exception)
        {
            // Either side going away ends this direction; the caller disposes both.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task<UdpSession?> GetOrCreateSessionAsync(
        ConcurrentDictionary<string, UdpSession> sessions,
        IPacketConnection inbound,
        EndPoint remote,
        Metadata template,
        CancellationToken cancellationToken)
    {
        var key = remote.ToString() ?? string.Empty;
        if (sessions.TryGetValue(key, out var existing)) return existing;

        // Serialise creation per key so two datagrams to the same destination do
        // not open two associations.
        var created = await UdpSession.CreateAsync(this, inbound, remote, template, cancellationToken).ConfigureAwait(false);
        if (created is null) return null;

        var session = sessions.GetOrAdd(key, created);
        if (!ReferenceEquals(session, created))
        {
            await created.DisposeAsync().ConfigureAwait(false);
        }

        return session;
    }

    /// <summary>One destination reached over UDP, plus the pump that returns replies.</summary>
    private sealed class UdpSession : IAsyncDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        private readonly EndPoint _remote;
        private Task? _pump;
        private int _disposed;

        private UdpSession(IPacketConnection outbound, TrackedConnection tracked, EndPoint remote)
        {
            Outbound = outbound;
            Tracked = tracked;
            _remote = remote;
        }

        public IPacketConnection Outbound { get; }

        public TrackedConnection Tracked { get; }

        /// <summary>
        /// Dials the outbound association for one destination and starts the reply
        /// pump that writes datagrams back to the client association.
        /// </summary>
        public static async Task<UdpSession?> CreateAsync(
            Tunnel tunnel,
            IPacketConnection inbound,
            EndPoint remote,
            Metadata template,
            CancellationToken cancellationToken)
        {
            var metadata = template.Clone();
            metadata.Network = Network.Udp;

            if (remote is IPEndPoint endpoint)
            {
                metadata.DestinationAddress = endpoint.Address.ToString();
                metadata.DestinationPort = (ushort)endpoint.Port;
                metadata.Host = null;
            }
            else
            {
                metadata.DestinationAddress = remote.ToString() ?? string.Empty;
            }

            TrackedConnection? tracked = null;
            try
            {
                tracked = tunnel._connections.Track(metadata);
                var outbound = await tunnel.DialUdpAsync(metadata, cancellationToken).ConfigureAwait(false);

                var session = new UdpSession(outbound, tracked, remote);
                tracked.CloseAction = () =>
                {
                    try { outbound.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { /* ignore */ }
                };
                session._pump = Task.Run(() => session.PumpAsync(inbound, tunnel), CancellationToken.None);
                return session;
            }
            catch (Exception ex)
            {
                tracked?.Dispose();
                tunnel.Log("warning", $"[UDP] dial {metadata.DestinationString} failed: {ex.Message}");
                return null;
            }
        }

        private async Task PumpAsync(IPacketConnection inbound, Tunnel tunnel)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(65_535);
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var received = await Outbound.ReceiveAsync(buffer, _cts.Token).ConfigureAwait(false);
                    if (received.BytesRead <= 0) break;

                    var destination = received.Remote ?? _remote;
                    await inbound.SendAsync(buffer.AsMemory(0, received.BytesRead), destination, _cts.Token)
                        .ConfigureAwait(false);

                    Tracked.AddDownload(received.BytesRead);
                    tunnel._traffic.AddDownload(received.BytesRead);
                }
            }
            catch (OperationCanceledException)
            {
                // Session torn down.
            }
            catch (Exception ex)
            {
                tunnel.Log("debug", $"[UDP] reply pump for {_remote} ended: {ex.Message}");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            try { await _cts.CancelAsync().ConfigureAwait(false); } catch { /* ignore */ }
            try { await Outbound.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }

            if (_pump is not null)
            {
                try { await _pump.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { /* ignore */ }
            }

            Tracked.Dispose();
            _cts.Dispose();
        }
    }
}
