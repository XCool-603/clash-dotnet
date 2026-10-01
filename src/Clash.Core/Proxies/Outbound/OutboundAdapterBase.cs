using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Clash.Core.Dns;
using Clash.Core.Transport;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Shared plumbing for the outbound protocol adapters in this build: the
/// configured server endpoint, the hand-off to the transport stack, the UDP flag
/// and the small API extras bag.
/// <para>
/// Every adapter derives from this, so the "read <c>server</c>/<c>port</c>, honour
/// <c>dialer-proxy</c>, compose the <c>tcp</c>/<c>tls</c>/<c>ws</c>/<c>grpc</c>
/// stack" logic exists exactly once.
/// </para>
/// </summary>
public abstract class OutboundAdapter : ProxyAdapter, IOutboundProxy
{
    private readonly IReadOnlyDictionary<string, object?> _apiExtra;

    /// <summary>Reads the endpoint and the shared options out of the entry.</summary>
    protected OutboundAdapter(ProxyConfigEntry entry, AdapterBuildContext context, ProxyType type, bool udp)
        : base(entry.Name, type)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        Entry = entry;
        Context = context;
        Options = entry.Map;
        (ServerHost, ServerPort) = OutboundOptions.RequireEndpoint(entry);
        DialerProxy = OutboundOptions.ReadDialerProxy(entry.Map);
        UdpEnabled = udp;
        _apiExtra = OutboundOptions.BuildApiExtra(entry.Map, udp);
        Logger = context.LoggerFactory.CreateLogger(GetType());
    }

    /// <summary>The configuration entry this adapter was built from.</summary>
    protected ProxyConfigEntry Entry { get; }

    /// <summary>The build context, giving access to the tunnel and the transports.</summary>
    protected AdapterBuildContext Context { get; }

    /// <summary>The raw option map of the entry.</summary>
    protected YamlMap Options { get; }

    /// <summary>A logger named after the concrete adapter type.</summary>
    protected ILogger Logger { get; }

    /// <summary>Whether the configuration asked for UDP and the protocol can carry it.</summary>
    protected bool UdpEnabled { get; }

    /// <inheritdoc />
    public string? ServerHost { get; }

    /// <inheritdoc />
    public int ServerPort { get; }

    /// <inheritdoc />
    public string? DialerProxy { get; }

    /// <inheritdoc />
    public override bool SupportUdp => UdpEnabled;

    /// <inheritdoc />
    public override IReadOnlyDictionary<string, object?> ApiExtra => _apiExtra;

    /// <summary>
    /// The option map handed to the transport stack. Adapters that must force a
    /// layer (Trojan and HTTPS proxies always run over TLS, <c>v2ray-plugin</c>
    /// needs the websocket layer) override this.
    /// </summary>
    protected virtual YamlMap DialOptions => Options;

    /// <summary>
    /// Opens the byte pipe a protocol handshake runs over: either the stream a
    /// previous hop already established, or a fresh connection through the
    /// configured transport stack (which itself honours <c>dialer-proxy</c>).
    /// The returned stream is tracked, so <see cref="ProxyAdapter.CloseConnections"/>
    /// tears it down.
    /// </summary>
    protected async Task<ProxyStream> OpenAsync(
        Metadata metadata,
        Stream? upstream,
        CancellationToken cancellationToken)
        => await OpenAsync(metadata, upstream, ServerHost!, ServerPort, DialOptions, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc cref="OpenAsync(Metadata,Stream?,CancellationToken)"/>
    protected async Task<ProxyStream> OpenAsync(
        Metadata metadata,
        Stream? upstream,
        string host,
        int port,
        YamlMap options,
        CancellationToken cancellationToken)
    {
        if (upstream is not null)
        {
            var based = upstream as ProxyStream;
            return Track(new ProxyStream(upstream, based?.LocalEndPoint, based?.RemoteEndPoint));
        }

        var dialContext = new DialContext
        {
            Host = host,
            Port = port,
            Metadata = metadata,
            Tunnel = Context.Tunnel.IsReady ? Context.Tunnel.Tunnel : null,
            DialerProxy = DialerProxy,
            CancellationToken = cancellationToken,
        };

        var stream = await Context.Transports.ConnectAsync(dialContext, options, cancellationToken).ConfigureAwait(false);
        return Track(stream);
    }

    /// <summary>Wraps a protocol stream over the endpoints of the stream it was built on.</summary>
    protected static ProxyStream Wrap(Stream framed, ProxyStream basedOn)
        => new(framed, basedOn.LocalEndPoint, basedOn.RemoteEndPoint);

    /// <summary>Records a successful dial and returns the stream unchanged.</summary>
    protected ProxyStream Complete(ProxyStream stream)
    {
        MarkAlive();
        return stream;
    }

    /// <summary>Records a failed dial before rethrowing, so health checks see it.</summary>
    protected Exception Fail(Exception exception)
    {
        MarkFailed();
        return exception;
    }

    /// <summary>
    /// The resolver, IPv6 preference and interface binding to use for the
    /// protocol's own UDP socket, taken from the tunnel when it is attached.
    /// </summary>
    protected (IDnsResolver? Resolver, bool Ipv6, string? InterfaceName) SocketHints()
    {
        if (!Context.Tunnel.IsReady) return (null, true, null);

        var tunnel = Context.Tunnel.Tunnel;
        return (tunnel.Dns, tunnel.Config.Ipv6, tunnel.Config.InterfaceName);
    }
}

/// <summary>Option readers shared by every outbound factory.</summary>
internal static class OutboundOptions
{
    /// <summary>
    /// Reads the mandatory <c>server</c>/<c>port</c> pair, raising
    /// <see cref="ProxyCreationException"/> with a message that names the proxy and
    /// the offending value.
    /// </summary>
    internal static (string Host, int Port) RequireEndpoint(ProxyConfigEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        var map = entry.Map;

        var host = map.GetNonEmptyString("server");
        if (host is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] of type [{entry.Type}] requires a non-empty 'server'");
        }

        if (!map.Has("port"))
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] of type [{entry.Type}] requires a 'port'");
        }

        var port = map.GetInt("port");
        if (port is <= 0 or > 65535)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] of type [{entry.Type}] has an invalid 'port' ({map.GetString("port")}); expected 1-65535");
        }

        return (host, port);
    }

    /// <summary>Reads <c>dialer-proxy</c>, tolerating the underscored spelling.</summary>
    internal static string? ReadDialerProxy(YamlMap map)
    {
        ArgumentNullException.ThrowIfNull(map);
        return map.GetNonEmptyString("dialer-proxy") ?? map.GetNonEmptyString("dialer_proxy");
    }

    /// <summary>
    /// Builds the small extras bag Clash merges into the proxy's API object:
    /// always the <c>udp</c> capability, plus <c>tfo</c>/<c>mux</c> when the
    /// configuration declares them.
    /// </summary>
    internal static IReadOnlyDictionary<string, object?> BuildApiExtra(YamlMap map, bool udp)
    {
        ArgumentNullException.ThrowIfNull(map);

        var extra = new Dictionary<string, object?>(StringComparer.Ordinal) { ["udp"] = udp };
        if (map.Has("tfo")) extra["tfo"] = map.GetBool("tfo");
        if (map.Has("mux")) extra["mux"] = map.GetBool("mux");
        return extra;
    }

    /// <summary>
    /// The host to put on the wire. In fake-IP mode the metadata carries the real
    /// domain in <see cref="Metadata.Host"/>, so the placeholder address must never
    /// be sent to the proxy: the remote must resolve the name itself.
    /// </summary>
    internal static string Destination(Metadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        return metadata.DnsMode == DnsMode.FakeIp && !string.IsNullOrEmpty(metadata.Host)
            ? metadata.Host!
            : metadata.DestinationAddress;
    }

    /// <summary>Encodes the SOCKS5 address block for the flow's destination.</summary>
    internal static int WriteDestination(Span<byte> destination, Metadata metadata)
        => Socks5Address.Write(destination, Destination(metadata), metadata.DestinationPort);
}

/// <summary>Bridges an <see cref="IAsyncDisposable"/> into the synchronous tracking handle.</summary>
internal sealed class AsyncDisposeBridge : IDisposable
{
    private readonly IAsyncDisposable _inner;
    private int _disposed;

    internal AsyncDisposeBridge(IAsyncDisposable inner) => _inner = inner;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _ = _inner.DisposeAsync();
    }
}
