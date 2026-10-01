using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>
/// Builds the transport stack for an outbound from its configuration map and runs
/// it.
/// <para>
/// <b>Ordering.</b> <c>tcp</c> is always first and is the only layer that opens a
/// socket. <c>tls</c>, when enabled, comes next, and the <c>network</c> layer
/// (<c>ws</c>, <c>grpc</c>, <c>h2</c>, <c>http</c>) is applied last because it
/// wraps the encrypted stream. The list returned by <see cref="Compose"/> is
/// therefore the order <see cref="ConnectAsync"/> feeds to
/// <see cref="ITransportLayer.WrapAsync"/>.
/// </para>
/// <para>
/// <b>ALPN.</b> For <c>grpc</c> and <c>h2</c> the TLS layer is handed a copy of
/// the options with <c>alpn: [h2]</c>, because HTTP/2 over TLS is selected by
/// ALPN and a stack that offers <c>http/1.1</c> as well would be negotiated down
/// to it.
/// </para>
/// </summary>
public sealed class TransportComposer : ITransportComposer
{
    private static readonly Dictionary<string, Func<ITransportLayer>> Factories = new(StringComparer.OrdinalIgnoreCase)
    {
        ["tcp"] = static () => new TcpTransport(),
        ["tls"] = static () => new TlsTransport(),
        ["ws"] = static () => new WebSocketTransport(),
        ["grpc"] = static () => new GrpcTransport(),
        ["h2"] = static () => new H2Transport(),
        ["http"] = static () => new HttpObfsTransport(),
    };

    /// <summary>Registers or replaces a layer factory.</summary>
    public static void Register(string name, Func<ITransportLayer> factory)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(factory);
        Factories[name] = factory;
    }

    /// <summary>True when the composer knows how to build the named layer.</summary>
    public static bool IsSupported(string name) => Factories.ContainsKey(name);

    /// <summary>Every layer name the composer can build.</summary>
    public static IReadOnlyCollection<string> Names => Factories.Keys.ToList();

    /// <summary>Builds one layer by name.</summary>
    public static ITransportLayer Get(string name)
        => Factories.TryGetValue(name, out var factory)
            ? factory()
            : throw new TransportNotSupportedException($"network '{name}' (known: {string.Join(", ", Factories.Keys)})");

    /// <inheritdoc />
    public IReadOnlyList<ITransportLayer> Compose(YamlMap proxyOptions)
        => [.. Plan(proxyOptions).Select(static step => step.Layer)];

    /// <inheritdoc />
    public async Task<ProxyStream> ConnectAsync(
        DialContext context,
        YamlMap proxyOptions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var plan = Plan(proxyOptions);
        ProxyStream? stream = null;

        foreach (var (layer, options) in plan)
        {
            stream = await layer.WrapAsync(stream, context, options, cancellationToken).ConfigureAwait(false);
        }

        return stream ?? throw new ClashException("transport: the composed stack is empty");
    }

    /// <summary>
    /// Resolves the layer list and the per-layer options. Exposed so callers can
    /// inspect the plan without connecting.
    /// </summary>
    public static IReadOnlyList<(ITransportLayer Layer, YamlMap Options)> Plan(YamlMap proxyOptions)
    {
        ArgumentNullException.ThrowIfNull(proxyOptions);

        var network = (proxyOptions.GetNonEmptyString("network") ?? "tcp").Trim().ToLowerInvariant();
        var tlsEnabled = proxyOptions.GetBool("tls");
        var plan = new List<(ITransportLayer, YamlMap)>(3);

        plan.Add((Get("tcp"), proxyOptions));

        switch (network)
        {
            case "tcp":
                if (tlsEnabled) plan.Add((Get("tls"), proxyOptions));
                break;

            case "ws":
                if (tlsEnabled) plan.Add((Get("tls"), proxyOptions));
                plan.Add((Get("ws"), proxyOptions));
                break;

            case "grpc":
                // gRPC runs over HTTP/2, so TLS must offer h2 through ALPN.
                if (tlsEnabled) plan.Add((Get("tls"), WithH2Alpn(proxyOptions)));
                plan.Add((Get("grpc"), proxyOptions));
                break;

            case "h2":
                // The h2 transport is HTTP/2 over TLS by definition.
                plan.Add((Get("tls"), WithH2Alpn(proxyOptions)));
                plan.Add((Get("h2"), proxyOptions));
                break;

            case "http":
                if (tlsEnabled) plan.Add((Get("tls"), proxyOptions));
                plan.Add((Get("http"), proxyOptions));
                break;

            case "quic":
                throw new TransportNotSupportedException(
                    "network 'quic' (QUIC needs a userspace implementation of the QUIC handshake, congestion control "
                    + "and stream multiplexing; System.Net.Quic only exposes the client role over its own socket, not a "
                    + "layer over an existing stream, so it cannot be composed into this stack)");

            default:
                throw new TransportNotSupportedException($"network '{network}' (known: {string.Join(", ", Factories.Keys)})");
        }

        return plan;
    }

    private static YamlMap WithH2Alpn(YamlMap options)
        => options.With("alpn", new List<object?> { "h2" });
}
