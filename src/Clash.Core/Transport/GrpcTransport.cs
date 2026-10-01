using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>
/// v2ray's gRPC transport: one HTTP/2 stream whose <c>:path</c> is
/// <c>/&lt;serviceName&gt;/Tun</c>, whose <c>content-type</c> is
/// <c>application/grpc</c>, and whose body is a sequence of
/// <c>[compressed(1)][length(4, big-endian)][payload]</c> messages.
/// <para>
/// It is built on <see cref="HttpClient"/> with
/// <see cref="HttpVersion.Version20"/> and
/// <see cref="HttpVersionPolicy.RequestVersionExact"/>; see
/// <see cref="Http2Duplex"/> for how the duplex stream is arranged, since .NET
/// has no <c>DuplexContent</c> type.
/// </para>
/// <para>
/// The <c>gun</c> and <c>multi</c> modes differ only in how many concurrent
/// streams a client opens per connection; both put exactly one stream on the
/// wire per dial, so they are handled identically here.
/// </para>
/// </summary>
public sealed class GrpcTransport : ITransportLayer
{
    public string Name => "grpc";

    public async Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (inner is null) throw new ClashException("grpc: the layer needs an inner stream");

        var grpc = TransportOptions.ReadGrpcOptions(options);
        var path = BuildPath(grpc.ServiceName);
        var authority = string.IsNullOrEmpty(grpc.Host) ? null : grpc.Host;

        var stream = await Http2Duplex.ConnectAsync(
            inner.Inner,
            context.Host,
            context.Port,
            path,
            authority,
            "application/grpc",
            owner: null,
            cancellationToken).ConfigureAwait(false);

        return TransportStream.Wrap(stream, inner);
    }

    /// <summary>Builds the <c>:path</c> for a service name, matching v2ray's <c>/&lt;name&gt;/Tun</c>.</summary>
    public static string BuildPath(string? serviceName)
    {
        var trimmed = serviceName?.Trim().Trim('/') ?? string.Empty;
        return trimmed.Length == 0 ? "/Tun" : "/" + trimmed + "/Tun";
    }
}

/// <summary>
/// v2ray's HTTP/2 transport. The framing is identical to
/// <see cref="GrpcTransport"/>; only the <c>:path</c> and the
/// <c>:authority</c>/<c>Host</c> handling differ, since <c>h2-opts</c> supplies
/// the path directly and a list of host names to rotate through.
/// </summary>
public sealed class H2Transport : ITransportLayer
{
    public string Name => "h2";

    public async Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (inner is null) throw new ClashException("h2: the layer needs an inner stream");

        var h2 = TransportOptions.ReadH2Options(options);
        var path = string.IsNullOrEmpty(h2.Path) ? "/" : h2.Path;
        var authority = h2.Host.Count > 0 ? h2.Host[Random.Shared.Next(h2.Host.Count)] : null;

        var stream = await Http2Duplex.ConnectAsync(
            inner.Inner,
            context.Host,
            context.Port,
            path,
            authority,
            "application/grpc",
            owner: null,
            cancellationToken).ConfigureAwait(false);

        return TransportStream.Wrap(stream, inner);
    }
}
