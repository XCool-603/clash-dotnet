using Clash.Core.Common;

namespace Clash.Core.Adapter;

/// <summary>
/// Anything that can carry a flow: a concrete outbound protocol, a built-in
/// adapter (<c>DIRECT</c>/<c>REJECT</c>), or a proxy group.
/// </summary>
public interface IProxy
{
    /// <summary>Unique name as written in the configuration.</summary>
    string Name { get; }

    ProxyType Type { get; }

    /// <summary>The exact string the REST API reports in the <c>type</c> field.</summary>
    string TypeName { get; }

    /// <summary>False once a health check or a dial has definitively failed.</summary>
    bool Alive { get; }

    /// <summary>Whether UDP flows can be carried by this adapter.</summary>
    bool SupportUdp { get; }

    /// <summary>True for select/url-test/fallback/load-balance/relay adapters.</summary>
    bool IsGroup { get; }

    /// <summary>Most recent first, capped like Clash (10 entries).</summary>
    IReadOnlyList<DelayHistory> History { get; }

    /// <summary>Extra fields merged verbatim into this proxy's API object.</summary>
    IReadOnlyDictionary<string, object?> ApiExtra { get; }

    /// <summary>
    /// Opens a TCP flow. When <paramref name="upstream"/> is non-null the adapter
    /// must tunnel to that existing stream instead of connecting to
    /// <see cref="Metadata.DestinationAddress"/> directly — this is what makes
    /// <c>relay</c> chains and the <c>dialer-proxy</c> option work.
    /// </summary>
    Task<ProxyStream> DialTcpAsync(Metadata metadata, Stream? upstream = null, CancellationToken cancellationToken = default);

    /// <summary>Opens a UDP association. Throws <see cref="NotSupportedException"/> when <see cref="SupportUdp"/> is false.</summary>
    Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default);

    /// <summary>Drops every live flow currently carried by this adapter.</summary>
    void CloseConnections();
}

/// <summary>Extra surface exposed by group adapters.</summary>
public interface IProxyGroup : IProxy{
    /// <summary>Resolved members, in configuration order, already expanded from providers.</summary>
    IReadOnlyList<IProxy> Members { get; }

    /// <summary>For <c>select</c>: the currently chosen member. For others: the last winner.</summary>
    string? SelectedName { get; }

    /// <summary>Delay-test URL configured for this group.</summary>
    string TestUrl { get; }

    /// <summary>Selection is only meaningful for <c>select</c>; others return false.</summary>
    Task<bool> SelectAsync(string proxyName);

    /// <summary>Runs a health check over every member and returns name → delay (0 = failed).</summary>
    Task<IReadOnlyDictionary<string, int>> UrlTestAsync(CancellationToken cancellationToken = default);

    /// <summary>True when the group is hidden from the API listing (but still usable by rules).</summary>
    bool Hidden { get; }

    /// <summary>Icon URL declared by the group, if any.</summary>
    string? Icon { get; }
}

/// <summary>Result of probing one node.</summary>
public readonly record struct DelayProbeResult(string Name, int DelayMs, string? Error)
{
    public bool Success => DelayMs > 0;
}

/// <summary>
/// A lazily evaluated collection of proxies, used by <c>url-test</c> style health
/// checks and by the <c>/proxies/:name/delay</c> endpoint.
/// </summary>
public interface IDelayTester
{
    Task<DelayProbeResult> TestAsync(IProxy proxy, string url, int timeoutMs, CancellationToken cancellationToken = default);
}

/// <summary>Thrown when a configuration references an adapter name that does not exist.</summary>
public sealed class ProxyNotFoundException(string name)
    : ClashException($"proxy [{name}] not found");

/// <summary>Thrown when a group selection targets a name outside the group.</summary>
public sealed class ProxyNotInGroupException(string proxy, string group)
    : ClashException($"proxy [{proxy}] not found in group [{group}]");

/// <summary>
/// A concrete outbound that owns a server endpoint. Relay groups need this to
/// chain members: each hop is dialed to the <em>next</em> hop's server address.
/// </summary>
public interface IOutboundProxy : IProxy
{
    string? ServerHost { get; }

    int ServerPort { get; }

    /// <summary>Name of the adapter this one dials through, from <c>dialer-proxy</c>.</summary>
    string? DialerProxy { get; }
}

/// <summary>
/// Late-bound access to the tunnel. Adapters are constructed before the tunnel
/// exists, so they resolve it through this indirection instead of a constructor
/// argument.
/// </summary>
public interface ITunnelAccessor
{
    /// <summary>The live tunnel. Throws <see cref="InvalidOperationException"/> before it is attached.</summary>
    Tunnel.ITunnel Tunnel { get; }

    /// <summary>True once <see cref="Tunnel"/> can be read.</summary>
    bool IsReady { get; }
}

/// <summary>Default <see cref="ITunnelAccessor"/>; the host assigns the tunnel once built.</summary>
public sealed class TunnelAccessor : ITunnelAccessor
{
    private Tunnel.ITunnel? _tunnel;

    public Tunnel.ITunnel Tunnel =>
        Volatile.Read(ref _tunnel) ?? throw new InvalidOperationException("the tunnel is not attached yet");

    public bool IsReady => Volatile.Read(ref _tunnel) is not null;

    public void Attach(Tunnel.ITunnel tunnel) => Volatile.Write(ref _tunnel, tunnel);
}
