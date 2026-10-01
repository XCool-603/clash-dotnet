using System.Buffers.Binary;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Clash.Core.Common;

namespace Clash.Core.Dns;

/// <summary>One upstream DNS transport: plain UDP/TCP, DoT, DoH, DHCP-derived or hosts.</summary>
public interface IDnsUpstream : IDisposable
{
    /// <summary>Human readable endpoint, e.g. <c>tls://1.1.1.1:853</c>.</summary>
    string Name { get; }

    /// <summary>Sends <paramref name="query"/> and returns the decoded reply.</summary>
    /// <exception cref="DnsException">The transport failed, timed out or the reply was malformed.</exception>
    Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken);
}

/// <summary>Shared plumbing for the concrete upstreams: codec, timeout and naming.</summary>
public abstract class DnsUpstreamBase : IDnsUpstream, IDisposable
{
    /// <summary>Timeout applied when a caller does not supply one.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Initialises the base with a per-query timeout and an optional codec.</summary>
    protected DnsUpstreamBase(TimeSpan timeout, IDnsCodec? codec = null)
    {
        Timeout = timeout <= TimeSpan.Zero ? DefaultTimeout : timeout;
        Codec = codec ?? new DnsCodec();
    }

    /// <summary>Per-query timeout.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>Codec used for the wire format.</summary>
    protected IDnsCodec Codec { get; }

    /// <inheritdoc />
    public abstract string Name { get; }

    /// <inheritdoc />
    public abstract Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken);

    /// <inheritdoc />
    public virtual void Dispose()
    {
    }

    /// <summary>Creates a token source that fires on <paramref name="cancellationToken"/> or the timeout.</summary>
    protected CancellationTokenSource CreateTimeoutScope(CancellationToken cancellationToken)
    {
        var scope = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        scope.CancelAfter(Timeout);
        return scope;
    }

    /// <summary>Builds the error raised when a transport exceeds its timeout.</summary>
    protected DnsException TimedOut(string what)
        => new($"{Name}: {what} timed out after {Timeout.TotalSeconds:0.#}s");

    /// <summary>Rewrites a cancellation into a timeout error unless the caller cancelled.</summary>
    protected Exception TranslateCancellation(OperationCanceledException error, CancellationToken caller, string what)
        => caller.IsCancellationRequested ? error : TimedOut(what);
}

/// <summary>Length-prefixed framing shared by DNS over TCP and DNS over TLS.</summary>
internal static class DnsFraming
{
    public static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length > ushort.MaxValue)
        {
            throw new DnsException($"DNS message of {payload.Length} bytes cannot be framed: the length prefix is 16 bits");
        }

        var header = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(header, (ushort)payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false);

        var length = BinaryPrimitives.ReadUInt16BigEndian(header);
        if (length == 0)
        {
            throw new DnsException("DNS stream declared a zero-length message");
        }

        var buffer = new byte[length];
        await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }

    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new DnsException("DNS stream closed before the declared message length was read");
            }

            offset += read;
        }
    }
}

/// <summary>
/// Plain UDP upstream. A reply with <c>TC=1</c> is automatically retried over
/// TCP, which is what RFC 1035 requires of a resolver.
/// </summary>
public sealed class UdpDnsUpstream : DnsUpstreamBase
{
    private readonly IPAddress _address;
    private readonly int _port;
    private readonly bool _retryOverTcp;

    /// <summary>Creates a UDP upstream, optionally with the TCP retry on truncation.</summary>
    public UdpDnsUpstream(IPAddress address, int port = 53, TimeSpan? timeout = null, bool retryOverTcp = true, IDnsCodec? codec = null)
        : base(timeout ?? DefaultTimeout, codec)
    {
        _address = address ?? throw new ArgumentNullException(nameof(address));
        _port = port;
        _retryOverTcp = retryOverTcp;
    }

    /// <inheritdoc />
    public override string Name => $"udp://{Format(_address)}:{_port}";

    /// <inheritdoc />
    public override async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        var payload = Codec.Encode(query);
        var response = await ExchangeUdpAsync(payload, query.Id, cancellationToken).ConfigureAwait(false);

        if (response.Truncated && _retryOverTcp)
        {
            using var tcp = new TcpDnsUpstream(_address, _port, Timeout, Codec);
            return await tcp.ExchangeAsync(query, cancellationToken).ConfigureAwait(false);
        }

        return response;
    }

    private async Task<DnsMessage> ExchangeUdpAsync(byte[] payload, ushort expectedId, CancellationToken cancellationToken)
    {
        using var client = new UdpClient(_address.AddressFamily);
        client.Connect(_address, _port);

        try
        {
            await client.SendAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException error)
        {
            throw new DnsException($"{Name}: send failed: {error.Message}");
        }

        using var scope = CreateTimeoutScope(cancellationToken);
        while (true)
        {
            UdpReceiveResult result;
            try
            {
                result = await client.ReceiveAsync(scope.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException error)
            {
                throw TranslateCancellation(error, cancellationToken, "query");
            }
            catch (SocketException error)
            {
                // ICMP port-unreachable surfaces here on Windows.
                throw new DnsException($"{Name}: receive failed: {error.Message}");
            }

            var message = Codec.Decode(result.Buffer);
            // Ignore stray datagrams; a connected socket already filters by peer.
            if (message.Id == expectedId) return message;
        }
    }

    internal static string Format(IPAddress address)
        => address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
}

/// <summary>DNS over TCP, using the two-byte length prefix framing of RFC 1035 §4.2.2.</summary>
public sealed class TcpDnsUpstream : DnsUpstreamBase
{
    private readonly IPAddress _address;
    private readonly int _port;

    /// <summary>Creates a TCP upstream.</summary>
    public TcpDnsUpstream(IPAddress address, int port = 53, TimeSpan? timeout = null, IDnsCodec? codec = null)
        : base(timeout ?? DefaultTimeout, codec)
    {
        _address = address ?? throw new ArgumentNullException(nameof(address));
        _port = port;
    }

    /// <inheritdoc />
    public override string Name => $"tcp://{UdpDnsUpstream.Format(_address)}:{_port}";

    /// <inheritdoc />
    public override async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        using var scope = CreateTimeoutScope(cancellationToken);
        var token = scope.Token;

        using var client = new TcpClient(_address.AddressFamily) { NoDelay = true };
        try
        {
            await client.ConnectAsync(_address, _port, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error)
        {
            throw TranslateCancellation(error, cancellationToken, "connect");
        }
        catch (SocketException error)
        {
            throw new DnsException($"{Name}: connect failed: {error.Message}");
        }

        using var stream = client.GetStream();
        try
        {
            await DnsFraming.WriteAsync(stream, Codec.Encode(query), token).ConfigureAwait(false);
            var payload = await DnsFraming.ReadAsync(stream, token).ConfigureAwait(false);
            var response = Codec.Decode(payload);
            if (response.Id != query.Id)
            {
                throw new DnsException($"{Name}: reply id {response.Id} does not match query id {query.Id}");
            }

            return response;
        }
        catch (OperationCanceledException error)
        {
            throw TranslateCancellation(error, cancellationToken, "query");
        }
        catch (IOException error)
        {
            throw new DnsException($"{Name}: {error.Message}");
        }
    }
}

/// <summary>
/// DNS over TLS (<c>tls://</c>, port 853). The configured host is sent as SNI so
/// certificate validation works for both IP-literal and domain nameservers.
/// </summary>
public sealed class TlsDnsUpstream : DnsUpstreamBase
{
    private readonly IPAddress _address;
    private readonly string _hostname;
    private readonly int _port;

    /// <summary>Creates a DoT upstream.</summary>
    /// <param name="address">Address actually dialled.</param>
    /// <param name="hostname">Name used for SNI and certificate validation.</param>
    /// <param name="port">TLS port; 853 by default.</param>
    /// <param name="timeout">Per-query timeout.</param>
    /// <param name="codec">Optional codec override.</param>
    public TlsDnsUpstream(IPAddress address, string hostname, int port = 853, TimeSpan? timeout = null, IDnsCodec? codec = null)
        : base(timeout ?? DefaultTimeout, codec)
    {
        _address = address ?? throw new ArgumentNullException(nameof(address));
        _hostname = string.IsNullOrWhiteSpace(hostname) ? address.ToString() : hostname;
        _port = port;
    }

    /// <inheritdoc />
    public override string Name => $"tls://{UdpDnsUpstream.Format(_address)}:{_port}";

    /// <inheritdoc />
    public override async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        using var scope = CreateTimeoutScope(cancellationToken);
        var token = scope.Token;

        using var client = new TcpClient(_address.AddressFamily) { NoDelay = true };
        try
        {
            await client.ConnectAsync(_address, _port, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error)
        {
            throw TranslateCancellation(error, cancellationToken, "connect");
        }
        catch (SocketException error)
        {
            throw new DnsException($"{Name}: connect failed: {error.Message}");
        }

        await using var tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
        try
        {
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = _hostname,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };

            await tls.AuthenticateAsClientAsync(options, token).ConfigureAwait(false);
            await DnsFraming.WriteAsync(tls, Codec.Encode(query), token).ConfigureAwait(false);
            var payload = await DnsFraming.ReadAsync(tls, token).ConfigureAwait(false);
            var response = Codec.Decode(payload);
            if (response.Id != query.Id)
            {
                throw new DnsException($"{Name}: reply id {response.Id} does not match query id {query.Id}");
            }

            return response;
        }
        catch (OperationCanceledException error)
        {
            throw TranslateCancellation(error, cancellationToken, "query");
        }
        catch (AuthenticationException error)
        {
            throw new DnsException($"{Name}: TLS handshake failed: {error.Message}");
        }
        catch (IOException error)
        {
            throw new DnsException($"{Name}: {error.Message}");
        }
    }
}

/// <summary>
/// DNS over HTTPS (<c>https://</c> and <c>h3://</c>): a POST of
/// <c>application/dns-message</c> to the configured path.
/// </summary>
/// <remarks>
/// <para>
/// The socket is dialled to the already-resolved address through
/// <see cref="SocketsHttpHandler.ConnectCallback"/> while the request URI keeps
/// the configured host, so SNI and certificate validation use the nameserver's
/// name even when the bootstrap resolved it.
/// </para>
/// <para>
/// <c>h3://</c> asks for HTTP/3 with <see cref="HttpVersionPolicy.RequestVersionOrLower"/>.
/// .NET can only speak HTTP/3 when MsQuic is present and when it is allowed to
/// own the QUIC connection, which conflicts with the pinned-address
/// <c>ConnectCallback</c> above; in practice the request therefore negotiates
/// HTTP/2 (or HTTP/1.1) over TLS. This is a deliberate, documented degradation.
/// </para>
/// </remarks>
public sealed class HttpsDnsUpstream : DnsUpstreamBase
{
    private readonly HttpClient _client;
    private readonly Uri _uri;
    private readonly bool _preferHttp3;

    /// <summary>Creates a DoH upstream.</summary>
    /// <param name="address">Address actually dialled.</param>
    /// <param name="hostname">Host used in the request URI, SNI and certificate validation.</param>
    /// <param name="port">TLS port; 443 by default.</param>
    /// <param name="path">Request path, normally <c>/dns-query</c>.</param>
    /// <param name="timeout">Per-query timeout.</param>
    /// <param name="preferHttp3">Ask for HTTP/3, falling back to HTTP/2.</param>
    /// <param name="codec">Optional codec override.</param>
    public HttpsDnsUpstream(
        IPAddress address,
        string hostname,
        int port = 443,
        string path = "/dns-query",
        TimeSpan? timeout = null,
        bool preferHttp3 = false,
        IDnsCodec? codec = null)
        : base(timeout ?? DefaultTimeout, codec)
    {
        ArgumentNullException.ThrowIfNull(address);

        _preferHttp3 = preferHttp3;
        Hostname = string.IsNullOrWhiteSpace(hostname) ? address.ToString() : hostname;
        Port = port;

        var effectivePath = string.IsNullOrWhiteSpace(path) ? "/dns-query" : path;
        if (!effectivePath.StartsWith('/')) effectivePath = "/" + effectivePath;
        _uri = new UriBuilder("https", Hostname, port, effectivePath).Uri;

        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = Timeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.None,
            AllowAutoRedirect = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = Hostname,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            },
            ConnectCallback = async (_, token) =>
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, port), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };

        _client = new HttpClient(handler, disposeHandler: true)
        {
            // The linked token source enforces the per-query timeout instead.
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
    }

    /// <summary>Host used for SNI, certificate validation and the request URI.</summary>
    public string Hostname { get; }

    /// <summary>TCP port dialled.</summary>
    public int Port { get; }

    /// <summary>Absolute request URI.</summary>
    public Uri Uri => _uri;

    /// <inheritdoc />
    public override string Name
        => $"https://{(Hostname.Contains(':') ? $"[{Hostname}]" : Hostname)}:{Port}{_uri.AbsolutePath}";

    /// <inheritdoc />
    public override async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        using var scope = CreateTimeoutScope(cancellationToken);
        var token = scope.Token;

        using var request = new HttpRequestMessage(HttpMethod.Post, _uri)
        {
            Content = new ByteArrayContent(Codec.Encode(query)),
            Version = _preferHttp3 ? HttpVersion.Version30 : HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };

        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

        HttpResponseMessage response;
        try
        {
            response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException error)
        {
            throw TranslateCancellation(error, cancellationToken, "query");
        }
        catch (HttpRequestException error)
        {
            throw new DnsException($"{Name}: {error.Message}");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new DnsException($"{Name}: HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
            }

            byte[] payload;
            try
            {
                payload = await response.Content.ReadAsByteArrayAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException error)
            {
                throw TranslateCancellation(error, cancellationToken, "response read");
            }
            catch (HttpRequestException error)
            {
                throw new DnsException($"{Name}: {error.Message}");
            }

            if (payload.Length == 0)
            {
                throw new DnsException($"{Name}: empty response body");
            }

            var message = Codec.Decode(payload);
            if (message.Id != query.Id)
            {
                throw new DnsException($"{Name}: reply id {message.Id} does not match query id {query.Id}");
            }

            return message;
        }
    }

    /// <inheritdoc />
    public override void Dispose() => _client.Dispose();
}

/// <summary>
/// <c>dhcp://</c>: resolves through the DNS servers the operating system learned
/// from the active network adapter.
/// </summary>
/// <remarks>
/// Windows does not expose a managed DHCP lease API, so the servers are read
/// from <see cref="NetworkInterface.GetAllNetworkInterfaces"/> — the same list
/// the OS resolver uses — preferring adapters that are up, non-loopback and have
/// a default gateway. The list is cached for a minute so a lease change is
/// picked up without re-enumerating adapters on every query.
/// </remarks>
public sealed class DhcpDnsUpstream : DnsUpstreamBase
{
    private readonly object _gate = new();
    private readonly bool _ipv6;
    private readonly TimeSpan _refreshInterval;

    private IDnsUpstream? _inner;
    private DateTimeOffset _resolvedAt;

    /// <summary>Creates a DHCP-derived upstream.</summary>
    /// <param name="ipv6">Prefer IPv6 servers when the adapter offers both.</param>
    /// <param name="timeout">Per-query timeout forwarded to the chosen server.</param>
    /// <param name="refreshInterval">How long a discovered server list is reused.</param>
    /// <param name="codec">Optional codec override.</param>
    public DhcpDnsUpstream(bool ipv6 = false, TimeSpan? timeout = null, TimeSpan? refreshInterval = null, IDnsCodec? codec = null)
        : base(timeout ?? DefaultTimeout, codec)
    {
        _ipv6 = ipv6;
        _refreshInterval = refreshInterval ?? TimeSpan.FromMinutes(1);
    }

    /// <inheritdoc />
    public override string Name => "dhcp://";

    /// <inheritdoc />
    public override async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        var inner = GetOrCreateInner();
        if (inner is null)
        {
            throw new DnsException("dhcp://: no DNS server is configured on any active network adapter");
        }

        return await inner.ExchangeAsync(query, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Lists the DNS servers configured on the machine's active adapters,
    /// gateway-bearing adapters first.
    /// </summary>
    public static IReadOnlyList<IPAddress> GetSystemDnsServers(bool ipv6)
    {
        var preferred = new List<IPAddress>();
        var others = new List<IPAddress>();

        NetworkInterface[] adapters;
        try
        {
            adapters = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch (NetworkInformationException)
        {
            return [];
        }

        foreach (var adapter in adapters)
        {
            if (adapter.OperationalStatus != OperationalStatus.Up) continue;
            if (adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            IPInterfaceProperties properties;
            try
            {
                properties = adapter.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            var hasGateway = false;
            try
            {
                foreach (var gateway in properties.GatewayAddresses)
                {
                    var address = gateway?.Address;
                    if (address is null) continue;
                    if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) continue;
                    hasGateway = true;
                    break;
                }
            }
            catch (NetworkInformationException)
            {
                hasGateway = false;
            }

            var target = hasGateway ? preferred : others;
            try
            {
                foreach (var address in properties.DnsAddresses)
                {
                    if (address is null) continue;
                    if (IPAddress.IsLoopback(address)) continue;
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6LinkLocal && address.ScopeId == 0) continue;
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6Multicast) continue;
                    if (!target.Contains(address)) target.Add(address);
                }
            }
            catch (NetworkInformationException)
            {
                // A single misbehaving adapter must not hide the others.
            }
        }

        var all = new List<IPAddress>(preferred.Count + others.Count);
        all.AddRange(preferred);
        all.AddRange(others);

        var matching = all.Where(a => (a.AddressFamily == AddressFamily.InterNetworkV6) == ipv6).ToList();
        if (matching.Count > 0) return matching;
        return all;
    }

    private IDnsUpstream? GetOrCreateInner()
    {
        var current = _inner;
        if (current is not null && DateTimeOffset.UtcNow - _resolvedAt < _refreshInterval) return current;

        lock (_gate)
        {
            if (_inner is not null && DateTimeOffset.UtcNow - _resolvedAt < _refreshInterval) return _inner;

            var servers = GetSystemDnsServers(_ipv6);
            if (servers.Count == 0) return null;

            var address = servers[0];
            var created = new UdpDnsUpstream(address, 53, Timeout, retryOverTcp: true, Codec);
            _inner = created;
            _resolvedAt = DateTimeOffset.UtcNow;
            return created;
        }
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        lock (_gate)
        {
            _inner?.Dispose();
            _inner = null;
        }
    }
}

/// <summary>
/// <c>hosts://</c>: answers from the hosts table (the OS file by default) and
/// returns NXDOMAIN for everything else, so it can be used as a nameserver entry
/// without ever touching the network.
/// </summary>
public sealed class SystemHostsDnsUpstream : DnsUpstreamBase
{
    private readonly HostsTable _hosts;

    /// <summary>Creates a hosts-backed upstream.</summary>
    public SystemHostsDnsUpstream(bool useSystemHosts = true, IDnsCodec? codec = null)
        : base(TimeSpan.FromSeconds(1), codec)
    {
        _hosts = new HostsTable(hosts: null, useSystemHosts);
    }

    /// <inheritdoc />
    public override string Name => "hosts://";

    /// <inheritdoc />
    public override Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        var question = query.Questions.Count > 0 ? query.Questions[0] : null;
        if (question is null)
        {
            return Task.FromResult(DnsCodec.CreateResponse(query, DnsResponseCode.FormatError));
        }

        if (question.Type is DnsQueryType.A or DnsQueryType.Aaaa
            && _hosts.TryResolve(question.Name, out var addresses))
        {
            var wanted = question.Type == DnsQueryType.A ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            var answers = addresses
                .Where(a => a.AddressFamily == wanted)
                .Select(a => DnsCodec.CreateAddressRecord(question.Name, a))
                .ToList();

            return Task.FromResult(DnsCodec.WithAnswers(query, answers, 1));
        }

        return Task.FromResult(DnsCodec.CreateResponse(query, DnsResponseCode.NameError));
    }
}

/// <summary>
/// Wraps an upstream whose server host is a domain name: the name is resolved
/// through the bootstrap servers (or the system resolver) once, then cached, and
/// the real transport is built against the resulting address.
/// </summary>
/// <remarks>
/// A bootstrap server that is itself a domain name is never accepted — only IP
/// literals — which is what keeps this from recursing forever.
/// </remarks>
public sealed class BootstrapDnsUpstream : DnsUpstreamBase
{
    private readonly object _gate = new();
    private readonly string _host;
    private readonly Func<IPAddress, IDnsUpstream> _factory;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolver;
    private readonly bool _ipv6;
    private readonly TimeSpan _cacheFor;

    private IDnsUpstream? _inner;
    private DateTimeOffset _resolvedAt;

    /// <summary>Creates a bootstrap-resolving wrapper.</summary>
    /// <param name="host">Domain name of the nameserver.</param>
    /// <param name="factory">Builds the real upstream once an address is known.</param>
    /// <param name="resolver">Resolves the name; normally the resolver's default-nameserver path.</param>
    /// <param name="ipv6">Prefer AAAA results.</param>
    /// <param name="timeout">Per-query timeout.</param>
    /// <param name="cacheFor">How long a resolved address is reused.</param>
    /// <param name="codec">Optional codec override.</param>
    public BootstrapDnsUpstream(
        string host,
        Func<IPAddress, IDnsUpstream> factory,
        Func<string, CancellationToken, Task<IPAddress[]>> resolver,
        bool ipv6 = false,
        TimeSpan? timeout = null,
        TimeSpan? cacheFor = null,
        IDnsCodec? codec = null)
        : base(timeout ?? DefaultTimeout, codec)
    {
        _host = host;
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _ipv6 = ipv6;
        _cacheFor = cacheFor ?? TimeSpan.FromMinutes(5);
    }

    /// <inheritdoc />
    public override string Name => $"bootstrap://{_host}";

    /// <summary>The nameserver name that still has to be resolved.</summary>
    public string Host => _host;

    /// <summary>True once an address has been resolved and a transport built.</summary>
    public bool IsReady => _inner is not null;

    /// <inheritdoc />
    public override async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        var inner = await GetInnerAsync(cancellationToken).ConfigureAwait(false);
        return await inner.ExchangeAsync(query, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IDnsUpstream> GetInnerAsync(CancellationToken cancellationToken)
    {
        var current = _inner;
        if (current is not null && DateTimeOffset.UtcNow - _resolvedAt < _cacheFor) return current;

        IPAddress[] addresses;
        try
        {
            addresses = await _resolver(_host, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception error) when (error is DnsException or SocketException)
        {
            throw new DnsException($"bootstrap resolution of '{_host}' failed: {error.Message}");
        }

        var address = Pick(addresses);
        if (address is null)
        {
            throw new DnsException($"bootstrap resolution of '{_host}' returned no {(_ipv6 ? "IPv6" : "IPv4")} address");
        }

        lock (_gate)
        {
            if (_inner is not null && DateTimeOffset.UtcNow - _resolvedAt < _cacheFor) return _inner;
            _inner?.Dispose();
            _inner = _factory(address);
            _resolvedAt = DateTimeOffset.UtcNow;
            return _inner;
        }
    }

    private IPAddress? Pick(IPAddress[] addresses)
    {
        if (addresses.Length == 0) return null;

        var wanted = _ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        foreach (var address in addresses)
        {
            if (address.AddressFamily == wanted) return address;
        }

        return addresses[0];
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        lock (_gate)
        {
            _inner?.Dispose();
            _inner = null;
        }
    }
}

/// <summary>
/// Builds an <see cref="IDnsUpstream"/> from a <c>nameserver</c> entry.
/// </summary>
public static class DnsUpstreams
{
    /// <summary>Default request path for a DoH server that does not specify one.</summary>
    public const string DefaultDohPath = "/dns-query";

    /// <summary>
    /// Creates the upstream for one nameserver entry.
    /// </summary>
    /// <param name="nameserver">
    /// Entry such as <c>1.1.1.1</c>, <c>tcp://8.8.8.8</c>, <c>tls://dns.google</c>,
    /// <c>https://cloudflare-dns.com/dns-query</c>, <c>h3://dns.google/dns-query</c>,
    /// <c>dhcp://en0</c> or <c>hosts://</c>.
    /// </param>
    /// <param name="bootstrap">
    /// <c>default-nameserver</c> entries used to resolve a domain-valued
    /// nameserver host. Only entries that are IP literals are used.
    /// </param>
    /// <param name="ipv6">Prefer AAAA results while bootstrapping.</param>
    /// <param name="bootstrapResolver">
    /// Optional resolver consulted when the bootstrap list yields nothing; the
    /// owning <see cref="DnsResolver"/> passes its default-nameserver path here.
    /// </param>
    public static IDnsUpstream Create(
        string nameserver,
        IReadOnlyList<string>? bootstrap = null,
        bool ipv6 = false,
        Func<string, CancellationToken, Task<IPAddress[]>>? bootstrapResolver = null)
    {
        if (string.IsNullOrWhiteSpace(nameserver))
        {
            throw new DnsException("nameserver entry is empty");
        }

        var parsed = NameServerParser.Parse(nameserver);

        if (parsed.Transport == NameServerParser.Transport.Hosts)
        {
            return new SystemHostsDnsUpstream(useSystemHosts: true);
        }

        if (parsed.Transport == NameServerParser.Transport.Dhcp)
        {
            return new DhcpDnsUpstream(ipv6);
        }

        // NameServerParser only splits the path off https:// URLs, so an
        // h3://host/dns-query entry arrives with the path glued to the host.
        var host = parsed.Host;
        var path = parsed.Path;
        var slash = host.IndexOf('/');
        if (slash >= 0)
        {
            path ??= host[slash..];
            host = host[..slash];
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            throw new DnsException($"nameserver entry '{nameserver}' does not name a host");
        }

        var endpoint = parsed with { Host = host, Path = path };

        if (IPAddress.TryParse(host, out var literal))
        {
            return BuildTransport(endpoint, literal);
        }

        var resolver = BuildBootstrapResolver(bootstrap, ipv6, bootstrapResolver);
        return new BootstrapDnsUpstream(host, address => BuildTransport(endpoint, address), resolver, ipv6);
    }

    /// <summary>Creates the concrete transport for an already-resolved endpoint.</summary>
    private static IDnsUpstream BuildTransport(NameServerParser.ParsedNameServer parsed, IPAddress address)
    {
        var path = string.IsNullOrWhiteSpace(parsed.Path) ? DefaultDohPath : parsed.Path!;

        return parsed.Transport switch
        {
            NameServerParser.Transport.Tcp => new TcpDnsUpstream(address, parsed.Port),
            NameServerParser.Transport.Tls => new TlsDnsUpstream(address, parsed.Host, parsed.Port),
            NameServerParser.Transport.Https => new HttpsDnsUpstream(address, parsed.Host, parsed.Port, path),

            // h3:// is DoH over HTTP/3; quic:// is DoQ. .NET has no managed QUIC
            // DNS client, so quic:// is served over DoT and h3:// over HTTP/2
            // unless MsQuic is available.
            NameServerParser.Transport.Quic => IsDoq(parsed.Raw)
                ? new TlsDnsUpstream(address, parsed.Host, parsed.Port)
                : new HttpsDnsUpstream(address, parsed.Host, parsed.Port, path, preferHttp3: true),

            _ => new UdpDnsUpstream(address, parsed.Port),
        };
    }

    private static bool IsDoq(string raw)
        => raw.TrimStart().StartsWith("quic://", StringComparison.OrdinalIgnoreCase);

    private static Func<string, CancellationToken, Task<IPAddress[]>> BuildBootstrapResolver(
        IReadOnlyList<string>? bootstrap,
        bool ipv6,
        Func<string, CancellationToken, Task<IPAddress[]>>? fallback)
    {
        var servers = new List<IDnsUpstream>();

        foreach (var entry in bootstrap ?? [])
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;

            NameServerParser.ParsedNameServer parsed;
            try
            {
                parsed = NameServerParser.Parse(entry);
            }
            catch (Exception)
            {
                continue;
            }

            if (parsed.Transport is NameServerParser.Transport.Hosts or NameServerParser.Transport.Dhcp) continue;

            // Only IP literals: a bootstrap server that needs bootstrapping would
            // recurse forever.
            if (!IPAddress.TryParse(parsed.Host, out var address)) continue;

            servers.Add(BuildTransport(parsed, address));
        }

        return async (host, cancellationToken) =>
        {
            foreach (var server in servers)
            {
                try
                {
                    var addresses = await QueryAsync(server, host, ipv6, cancellationToken).ConfigureAwait(false);
                    if (addresses.Length > 0) return addresses;
                }
                catch (DnsException)
                {
                    // Try the next bootstrap server.
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    // Treat a timeout like any other failure.
                }
                catch (SocketException)
                {
                }
            }

            if (fallback is not null) return await fallback(host, cancellationToken).ConfigureAwait(false);

            return await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        };
    }

    /// <summary>Issues A/AAAA queries for <paramref name="host"/> against one upstream.</summary>
    public static async Task<IPAddress[]> QueryAsync(
        IDnsUpstream upstream,
        string host,
        bool ipv6,
        CancellationToken cancellationToken)
    {
        var results = new List<IPAddress>();

        var v4 = await QueryTypeAsync(upstream, host, DnsQueryType.A, cancellationToken).ConfigureAwait(false);
        results.AddRange(v4.Where(a => a.AddressFamily == AddressFamily.InterNetwork));

        if (ipv6)
        {
            var v6 = await QueryTypeAsync(upstream, host, DnsQueryType.Aaaa, cancellationToken).ConfigureAwait(false);
            results.AddRange(v6.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6));
        }

        return [.. results];
    }

    private static async Task<IPAddress[]> QueryTypeAsync(
        IDnsUpstream upstream,
        string host,
        DnsQueryType type,
        CancellationToken cancellationToken)
    {
        var query = DnsMessage.CreateQuery(host, type, id: (ushort)Random.Shared.Next(1, ushort.MaxValue));
        var response = await upstream.ExchangeAsync(query, cancellationToken).ConfigureAwait(false);

        if (response.ResponseCode != DnsResponseCode.NoError) return [];

        var addresses = new List<IPAddress>();
        foreach (var answer in response.Answers)
        {
            if (answer.Type != type || answer.Address is null) continue;
            addresses.Add(answer.Address);
        }

        return [.. addresses];
    }
}
