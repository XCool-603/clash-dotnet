using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// An HTTP proxy inbound (<c>port</c> in the configuration). Speaks plain
/// HTTP/1.1 over the raw socket: <c>CONNECT</c> tunnels and absolute-URI
/// requests, with optional <c>Proxy-Authorization: Basic</c>.
/// </summary>
public sealed class HttpListener : ListenerBase
{
    /// <summary>Creates the listener.</summary>
    /// <param name="config">Configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="port">Overrides <see cref="ClashConfig.Port"/>; 0 binds an ephemeral port.</param>
    /// <param name="name">Configured name, for <c>listeners</c> entries.</param>
    /// <param name="bindAddress">Overrides <see cref="ClashConfig.BindAddress"/>.</param>
    public HttpListener(ClashConfig config, ILogger logger, int? port = null, string? name = null, string? bindAddress = null)
        : base("http", name, port ?? (config ?? throw new ArgumentNullException(nameof(config))).Port, config, logger, bindAddress)
    {
    }

    /// <inheritdoc />
    protected override Task OnStartAsync(CancellationToken cancellationToken) => StartTcpListenerAsync(cancellationToken);

    /// <inheritdoc />
    protected override async Task HandleClientAsync(Socket socket, CancellationToken cancellationToken)
    {
        await using var stream = CreateInboundStream(socket);
        await HttpProxyProtocol.HandleAsync(this, stream, socket, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// The HTTP proxy protocol itself, shared by <see cref="HttpListener"/> and
/// <see cref="MixedListener"/>.
/// </summary>
internal static class HttpProxyProtocol
{
    /// <summary>Upper bound on the request line plus headers, in bytes.</summary>
    internal const int MaxHeaderBytes = 64 * 1024;

    private static readonly byte[] ConnectEstablished =
        Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");

    private static readonly byte[] BadRequest =
        Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");

    private static readonly byte[] ProxyAuthenticationRequired =
        Encoding.ASCII.GetBytes(
            "HTTP/1.1 407 Proxy Authentication Required\r\n" +
            "Proxy-Authenticate: Basic realm=\"Clash\"\r\n" +
            "Proxy-Connection: close\r\n" +
            "Content-Length: 0\r\n\r\n");

    private static readonly string[] HopByHopHeaders =
    [
        "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailer", "upgrade",
    ];

    /// <summary>Parses one proxied HTTP request and hands the flow to the tunnel.</summary>
    public static async Task HandleAsync(ListenerBase listener, InboundStream stream, Socket socket, CancellationToken cancellationToken)
    {
        var requestLine = await stream.ReadLineAsync(MaxHeaderBytes, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(requestLine))
        {
            return;
        }

        var firstSpace = requestLine.IndexOf(' ');
        var lastSpace = requestLine.LastIndexOf(' ');
        if (firstSpace <= 0 || lastSpace <= firstSpace)
        {
            await WriteAsync(stream, BadRequest, cancellationToken).ConfigureAwait(false);
            return;
        }

        var method = requestLine[..firstSpace];
        var target = requestLine[(firstSpace + 1)..lastSpace];
        var version = requestLine[(lastSpace + 1)..];

        var headers = await ReadHeadersAsync(stream, requestLine.Length, cancellationToken).ConfigureAwait(false);
        if (headers is null)
        {
            return;
        }

        var remote = socket.RemoteEndPoint;

        // ── Authentication ───────────────────────────────────────────────────
        string? user = null;
        var accounts = listener.Config.Authentication;
        if (accounts.Count > 0)
        {
            var authorization = FindHeader(headers, "Proxy-Authorization");
            user = Authenticate(authorization, accounts);
            if (user is null)
            {
                await WriteAsync(stream, ProxyAuthenticationRequired, cancellationToken).ConfigureAwait(false);
                throw new AuthenticationException(DecodeBasicCredentials(authorization) ?? "anonymous");
            }
        }

        var tunnel = listener.RequireTunnel();

        // ── CONNECT host:port ────────────────────────────────────────────────
        if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryParseHostPort(target, 0, out var connectHost, out var connectPort))
            {
                await WriteAsync(stream, BadRequest, cancellationToken).ConfigureAwait(false);
                return;
            }

            var connectMetadata = listener.CreateMetadata(remote, connectHost, connectPort, Network.Tcp);
            connectMetadata.InboundUser = user;
            await WriteAsync(stream, ConnectEstablished, cancellationToken).ConfigureAwait(false);

            // Whatever followed the header block (the first TLS records, or an
            // HTTP body) is still buffered and is replayed to the tunnel.
            await tunnel.HandleTcpAsync(stream, connectMetadata, cancellationToken).ConfigureAwait(false);
            return;
        }

        // ── Absolute-URI request: GET http://host/path HTTP/1.1 ──────────────
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Host.Length == 0)
            {
                await WriteAsync(stream, BadRequest, cancellationToken).ConfigureAwait(false);
                return;
            }

            var host = uri.Host.Trim('[', ']');
            var port = uri.IsDefaultPort ? (uri.Scheme == "https" ? 443 : 80) : uri.Port;
            var originForm = uri.PathAndQuery.Length == 0 ? "/" : uri.PathAndQuery;
            var head = BuildHead(method, originForm, version, headers, FindHeader(headers, "Host") is null ? uri.Authority : null);
            stream.Prepend(head);

            var metadata = listener.CreateMetadata(remote, host, (ushort)port, Network.Tcp);
            metadata.InboundUser = user;
            await tunnel.HandleTcpAsync(stream, metadata, cancellationToken).ConfigureAwait(false);
            return;
        }

        // ── Origin-form request carrying a Host header ───────────────────────
        if (target.StartsWith('/'))
        {
            var hostHeader = FindHeader(headers, "Host");
            if (hostHeader is null || !TryParseHostPort(hostHeader, 80, out var host, out var port))
            {
                await WriteAsync(stream, BadRequest, cancellationToken).ConfigureAwait(false);
                return;
            }

            stream.Prepend(BuildHead(method, target, version, headers, null));
            var metadata = listener.CreateMetadata(remote, host, port, Network.Tcp);
            metadata.InboundUser = user;
            await tunnel.HandleTcpAsync(stream, metadata, cancellationToken).ConfigureAwait(false);
            return;
        }

        await WriteAsync(stream, BadRequest, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<List<KeyValuePair<string, string>>?> ReadHeadersAsync(
        InboundStream stream,
        int consumed,
        CancellationToken cancellationToken)
    {
        var headers = new List<KeyValuePair<string, string>>();
        while (true)
        {
            var line = await stream.ReadLineAsync(MaxHeaderBytes, cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                return null;
            }

            consumed += line.Length + 2;
            if (consumed > MaxHeaderBytes)
            {
                throw new ClashException($"HTTP header block exceeds {MaxHeaderBytes} bytes");
            }

            if (line.Length == 0)
            {
                return headers;
            }

            if (line[0] is ' ' or '\t')
            {
                if (headers.Count > 0)
                {
                    var last = headers[^1];
                    headers[^1] = new KeyValuePair<string, string>(last.Key, last.Value + " " + line.Trim());
                }

                continue;
            }

            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            headers.Add(new KeyValuePair<string, string>(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
    }

    private static byte[] BuildHead(
        string method,
        string target,
        string version,
        List<KeyValuePair<string, string>> headers,
        string? injectedHost)
    {
        var connectionTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers)
        {
            if (!header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var token in header.Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                connectionTokens.Add(token);
            }
        }

        var builder = new StringBuilder(256);
        builder.Append(method).Append(' ').Append(target).Append(' ').Append(version).Append("\r\n");
        foreach (var header in headers)
        {
            if (IsHopByHop(header.Key) || connectionTokens.Contains(header.Key))
            {
                continue;
            }

            builder.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }

        if (injectedHost is not null)
        {
            builder.Append("Host: ").Append(injectedHost).Append("\r\n");
        }

        builder.Append("\r\n");
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static bool IsHopByHop(string name)
    {
        foreach (var candidate in HopByHopHeaders)
        {
            if (string.Equals(candidate, name, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string? FindHeader(List<KeyValuePair<string, string>> headers, string name)
    {
        foreach (var header in headers)
        {
            if (string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return header.Value;
            }
        }

        return null;
    }

    private static string? Authenticate(string? authorization, IReadOnlyList<string> accounts)
    {
        var credentials = DecodeBasicCredentials(authorization);
        if (credentials is null)
        {
            return null;
        }

        var colon = credentials.IndexOf(':');
        if (colon <= 0)
        {
            return null;
        }

        var user = credentials[..colon];
        foreach (var account in accounts)
        {
            if (FixedTimeEquals(account, credentials))
            {
                return user;
            }
        }

        return null;
    }

    private static string? DecodeBasicCredentials(string? authorization)
    {
        if (string.IsNullOrEmpty(authorization))
        {
            return null;
        }

        const string prefix = "Basic ";
        if (!authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(authorization[prefix.Length..].Trim()));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static bool FixedTimeEquals(string expected, string actual)
    {
        var left = Encoding.UTF8.GetBytes(expected);
        var right = Encoding.UTF8.GetBytes(actual);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static async Task WriteAsync(InboundStream stream, byte[] payload, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Parses <c>host:port</c>, <c>[v6]:port</c> or a bare host using <paramref name="defaultPort"/>.</summary>
    internal static bool TryParseHostPort(string value, int defaultPort, out string host, out ushort port)
    {
        host = string.Empty;
        port = 0;
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            return false;
        }

        if (trimmed[0] == '[')
        {
            var close = trimmed.IndexOf(']');
            if (close < 0)
            {
                return false;
            }

            host = trimmed[1..close];
            var rest = trimmed[(close + 1)..];
            if (rest.StartsWith(':'))
            {
                if (!ushort.TryParse(rest[1..], out port))
                {
                    return false;
                }
            }
            else
            {
                port = (ushort)defaultPort;
            }
        }
        else
        {
            var colon = trimmed.LastIndexOf(':');
            if (colon > 0 && trimmed.IndexOf(':') == colon)
            {
                host = trimmed[..colon];
                if (!ushort.TryParse(trimmed[(colon + 1)..], out port))
                {
                    return false;
                }
            }
            else
            {
                host = trimmed;
                port = (ushort)defaultPort;
            }
        }

        return host.Length > 0 && port != 0;
    }
}
