using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The <c>http</c> adapter: an HTTP <c>CONNECT</c> tunnel, optionally to a proxy
/// that itself speaks TLS (<c>tls: true</c>, which the transport stack provides).
/// No UDP: HTTP proxies have no datagram relay.
/// </summary>
public sealed class HttpAdapter : OutboundAdapter
{
    private readonly string? _authorization;
    private readonly List<KeyValuePair<string, string>> _headers;
    private readonly YamlMap _transportOptions;

    internal HttpAdapter(
        ProxyConfigEntry entry,
        AdapterBuildContext context,
        string? authorization,
        List<KeyValuePair<string, string>> headers,
        bool tls)
        : base(entry, context, ProxyType.Http, udp: false)
    {
        _authorization = authorization;
        _headers = headers;
        _transportOptions = tls ? entry.Map.With("tls", true) : entry.Map;
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static HttpAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var map = entry.Map;
        var user = map.GetNonEmptyString("user");
        var password = map.GetString("password") ?? string.Empty;

        string? authorization = null;
        if (user is not null)
        {
            authorization = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{password}"));
        }

        var headers = new List<KeyValuePair<string, string>>();
        var custom = map.GetMap("headers");
        foreach (var (key, value) in custom.Raw)
        {
            if (string.IsNullOrWhiteSpace(key)) continue;
            headers.Add(new KeyValuePair<string, string>(key, Render(value)));
        }

        return new HttpAdapter(entry, context, authorization, headers, map.GetBool("tls"));
    }

    /// <inheritdoc />
    protected override YamlMap DialOptions => _transportOptions;

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var raw = await OpenAsync(metadata, upstream, cancellationToken).ConfigureAwait(false);
        try
        {
            var host = OutboundOptions.Destination(metadata);
            var request = BuildConnectRequest(host, metadata.DestinationPort);
            await raw.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            await raw.FlushAsync(cancellationToken).ConfigureAwait(false);

            var response = await OutboundIo
                .ReadUntilAsync(raw, "\r\n\r\n"u8.ToArray(), OutboundIo.MaxHeaderBytes, cancellationToken)
                .ConfigureAwait(false);

            if (!OutboundIo.TryParseStatusCode(response.Block, out var status))
            {
                throw new ClashException("http: the proxy returned a malformed CONNECT response");
            }

            if (status != 200)
            {
                var reason = OutboundIo.FindHeader(response.Block, "Proxy-Agent") ?? string.Empty;
                throw new ClashException(
                    $"http: the proxy refused CONNECT to {host}:{metadata.DestinationPort} with status {status} {reason}".TrimEnd());
            }

            // Any payload the proxy pipelined behind the response header must not be lost.
            var stream = response.Leftover.Length > 0 ? new PrefixStream(response.Leftover, raw) : (Stream)raw;
            return Complete(Wrap(stream, raw));
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <summary>Builds the exact <c>CONNECT</c> request, including the header terminator.</summary>
    internal byte[] BuildConnectRequest(string host, int port)
    {
        var authority = host.Contains(':') && !host.StartsWith('[')
            ? $"[{host}]:{port}"
            : $"{host}:{port}";

        var builder = new StringBuilder(256);
        builder.Append("CONNECT ").Append(authority).Append(" HTTP/1.1\r\n");
        builder.Append("Host: ").Append(authority).Append("\r\n");
        builder.Append("Proxy-Connection: Keep-Alive\r\n");
        if (_authorization is not null)
        {
            builder.Append("Proxy-Authorization: ").Append(_authorization).Append("\r\n");
        }

        foreach (var (key, value) in _headers)
        {
            builder.Append(key).Append(": ").Append(value).Append("\r\n");
        }

        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static string Render(object? value) => value switch
    {
        null => string.Empty,
        string s => s,
        List<object?> list => string.Join(", ", list.Select(x => Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture))),
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
    };
}

/// <summary>Builds <see cref="HttpAdapter"/> instances.</summary>
internal sealed class HttpAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "http";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => HttpAdapter.Create(entry, context);
}
