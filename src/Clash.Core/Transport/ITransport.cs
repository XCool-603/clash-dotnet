using Clash.Core.Common;
using Clash.Core.Tunnel;

namespace Clash.Core.Transport;

/// <summary>Everything a transport layer needs to establish or wrap a connection.</summary>
public sealed class DialContext
{
    /// <summary>Target host, already resolved or still a domain depending on the protocol.</summary>
    public required string Host { get; init; }

    public required int Port { get; init; }

    /// <summary>The flow being carried; carries the process, inbound and rule information.</summary>
    public required Metadata Metadata { get; init; }

    /// <summary>
    /// The tunnel, when the layer needs to dial through a <c>dialer-proxy</c> or
    /// resolve a name through the configured DNS.
    /// </summary>
    public ITunnel? Tunnel { get; init; }

    /// <summary>
    /// An already-established stream to tunnel over. Set for chained dials and
    /// relay groups; when null the base TCP layer connects to
    /// <see cref="Host"/>:<see cref="Port"/> itself.
    /// </summary>
    public ProxyStream? Upstream { get; init; }

    /// <summary>Adapter selected by <c>dialer-proxy</c>, when the config sets one.</summary>
    public string? DialerProxy { get; init; }

    public CancellationToken CancellationToken { get; init; }
}

/// <summary>
/// One composable layer of an outbound connection. Layers are applied innermost
/// first: <c>tcp</c> → <c>tls</c> → <c>ws</c>, producing the stream a protocol
/// adapter then speaks over.
/// </summary>
public interface ITransportLayer
{
    /// <summary><c>tcp</c>, <c>tls</c>, <c>ws</c>, <c>grpc</c>, <c>h2</c>, <c>http</c>, <c>quic</c>.</summary>
    string Name { get; }

    /// <summary>
    /// Establishes this layer. When <paramref name="inner"/> is null the layer is
    /// responsible for opening the base connection; otherwise it wraps the given
    /// stream. Implementations must not dispose <paramref name="inner"/> on
    /// failure — the caller owns it until a <see cref="ProxyStream"/> is returned.
    /// </summary>
    Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default);
}

/// <summary>TLS knobs shared by every protocol that can run over TLS.</summary>
public sealed record TlsOptions
{
    public bool Enabled { get; init; }
    public string? ServerName { get; init; }
    public bool SkipCertVerify { get; init; }
    public List<string> Alpn { get; init; } = [];
    public string? Fingerprint { get; init; }
    public string? ClientFingerprint { get; init; }
    public string? RealityPublicKey { get; init; }
    public string? RealityShortId { get; init; }
    public string? RealitySpiderX { get; init; }
    public bool Insecure { get; init; }
    public bool DisableSni { get; init; }
}

/// <summary>WebSocket layer options (<c>ws-opts</c>).</summary>
public sealed record WebSocketOptions
{
    public string Path { get; init; } = "/";
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public int MaxEarlyData { get; init; }
    public string? EarlyDataHeaderName { get; init; }
    public string? Host { get; init; }
    public bool V2rayHttpUpgrade { get; init; }
}

/// <summary>gRPC layer options (<c>grpc-opts</c>).</summary>
public sealed record GrpcOptions
{
    public string ServiceName { get; init; } = string.Empty;
    public string? Host { get; init; }
    public string Mode { get; init; } = "gun";
}

/// <summary>HTTP/2 layer options (<c>h2-opts</c>).</summary>
public sealed record H2Options
{
    public string Path { get; init; } = "/";
    public List<string> Host { get; init; } = [];
}

/// <summary>HTTP obfuscation layer options (<c>http-opts</c>).</summary>
public sealed record HttpObfsOptions
{
    public string Method { get; init; } = "GET";
    public List<string> Path { get; init; } = ["/"];
    public Dictionary<string, List<string>> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Builds the transport stack for an outbound from its configuration map.
/// The composer reads <c>tls</c>, <c>network</c>, <c>ws-opts</c>, <c>grpc-opts</c>,
/// <c>h2-opts</c> and <c>http-opts</c> and returns the layers in application order.
/// </summary>
public interface ITransportComposer
{
    /// <summary>Layers innermost first; the first layer is expected to be <c>tcp</c>.</summary>
    IReadOnlyList<ITransportLayer> Compose(YamlMap proxyOptions);

    /// <summary>Runs the whole stack and returns the ready-to-use stream.</summary>
    Task<ProxyStream> ConnectAsync(DialContext context, YamlMap proxyOptions, CancellationToken cancellationToken = default);
}

/// <summary>Thrown when a transport feature cannot be honoured (for example REALITY).</summary>
public sealed class TransportNotSupportedException(string feature)
    : ClashException($"transport feature not supported: {feature}");
