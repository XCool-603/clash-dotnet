using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Dns;

/// <summary>
/// The <c>dns</c> inbound: serves UDP and TCP on <c>dns.listen</c> and answers
/// through <see cref="ITunnel.Dns"/>, i.e. straight through the resolver rather
/// than the rule engine, so upstream queries can never be routed back into this
/// listener.
/// </summary>
/// <remarks>
/// <see cref="HandlePacketAsync"/> is also the entry point the TUN stack uses to
/// hand over hijacked raw queries, so a TUN-based DNS hijack needs no separate
/// server.
/// </remarks>
public sealed class DnsListener : IInboundListener
{
    /// <summary>Classic maximum UDP DNS payload, used to set <c>TC</c> instead of fragmenting.</summary>
    public const int MaxUdpPayload = 512;

    private readonly DnsConfig _config;
    private readonly ILogger<DnsListener>? _logger;
    private readonly IDnsCodec _codec;
    private readonly CancellationTokenSource _lifetime = new();

    private UdpClient? _udp;
    private TcpListener? _tcp;
    private Task? _udpLoop;
    private Task? _tcpLoop;
    private ITunnel? _tunnel;
    private int _active;

    /// <summary>Creates a DNS listener for the configured <c>dns.listen</c> endpoint.</summary>
    /// <param name="config">The DNS configuration.</param>
    /// <param name="logger">Optional logger.</param>
    /// <param name="codec">Optional codec override.</param>
    public DnsListener(DnsConfig config, ILogger<DnsListener>? logger = null, IDnsCodec? codec = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger;
        _codec = codec ?? new DnsCodec();

        var (address, port) = ParseListen(config.Listen);
        BindAddress = address;
        Port = port;
    }

    /// <inheritdoc />
    public string Type => "dns";

    /// <inheritdoc />
    public string? Name => "dns";

    /// <inheritdoc />
    public string? Address { get; private set; }

    /// <inheritdoc />
    public int Port { get; private set; }

    /// <inheritdoc />
    public int ActiveConnections => Volatile.Read(ref _active);

    /// <summary>Address the listener binds to.</summary>
    public IPAddress BindAddress { get; }

    /// <summary>Codec in use, exposed so the TUN path can share it.</summary>
    public IDnsCodec Codec => _codec;

    /// <summary>
    /// Parses a Clash <c>listen</c> value: <c>0.0.0.0:1053</c>, <c>*:1053</c>,
    /// <c>:1053</c>, <c>[::]:1053</c>, a bare port, or a bare address.
    /// </summary>
    public static (IPAddress Address, int Port) ParseListen(string? listen)
    {
        var value = string.IsNullOrWhiteSpace(listen) ? "0.0.0.0:1053" : listen.Trim();

        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close > 0)
            {
                var literal = value[1..close];
                var rest = value[(close + 1)..];
                var literalPort = 1053;
                if (rest.StartsWith(':') && int.TryParse(rest[1..], out var parsed)) literalPort = parsed;
                return (ParseHost(literal), literalPort);
            }
        }

        var firstColon = value.IndexOf(':');
        var lastColon = value.LastIndexOf(':');

        if (firstColon < 0)
        {
            // Either a bare port or a bare address.
            return int.TryParse(value, out var barePort) ? (IPAddress.Any, barePort) : (ParseHost(value), 1053);
        }

        if (firstColon == lastColon)
        {
            var host = value[..lastColon];
            var port = 1053;
            if (int.TryParse(value[(lastColon + 1)..], out var parsed)) port = parsed;
            return (ParseHost(host), port);
        }

        // Several colons and no brackets: a bare IPv6 literal.
        return (ParseHost(value), 1053);
    }

    /// <inheritdoc />
    public Task StartAsync(ITunnel tunnel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(tunnel);
        _tunnel = tunnel;

        if (!_config.Enable)
        {
            _logger?.LogInformation("dns listener disabled by configuration");
            return Task.CompletedTask;
        }

        if (_udp is not null || _tcp is not null) return Task.CompletedTask;

        try
        {
            _udp = new UdpClient(new IPEndPoint(BindAddress, Port));
        }
        catch (SocketException error)
        {
            throw new ListenerBindException(Type, $"{BindAddress}:{Port}/udp", error);
        }

        try
        {
            _tcp = new TcpListener(new IPEndPoint(BindAddress, Port));
            _tcp.Start();
        }
        catch (SocketException error)
        {
            _udp.Dispose();
            _udp = null;
            throw new ListenerBindException(Type, $"{BindAddress}:{Port}/tcp", error);
        }

        // Port 0 means "pick one"; report what we actually got.
        if (_udp.Client.LocalEndPoint is IPEndPoint bound) Port = bound.Port;

        Address = BindAddress.ToString();
        _udpLoop = Task.Run(() => UdpLoopAsync(_lifetime.Token), CancellationToken.None);
        _tcpLoop = Task.Run(() => TcpLoopAsync(_lifetime.Token), CancellationToken.None);

        _logger?.LogInformation("dns listener listening on {Address}:{Port} (udp+tcp)", BindAddress, Port);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync()
    {
        try
        {
            await _lifetime.CancelAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
        }

        try
        {
            _udp?.Dispose();
        }
        catch (ObjectDisposedException)
        {
        }

        try
        {
            _tcp?.Stop();
        }
        catch (ObjectDisposedException)
        {
        }

        foreach (var loop in new[] { _udpLoop, _tcpLoop })
        {
            if (loop is null) continue;
            try
            {
                await loop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Shutdown is best-effort.
            }
        }

        _udp = null;
        _tcp = null;
        _udpLoop = null;
        _tcpLoop = null;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _lifetime.Dispose();
    }

    /// <summary>
    /// Answers one raw DNS query. The TUN stack calls this for hijacked
    /// datagrams; <paramref name="reply"/> receives the encoded response.
    /// </summary>
    /// <param name="payload">Raw DNS message.</param>
    /// <param name="source">Where the query came from; passed back to <paramref name="reply"/>.</param>
    /// <param name="reply">Sends the encoded response back to the caller.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <param name="maxPayload">
    /// When positive, responses longer than this are truncated and flagged with
    /// <c>TC=1</c> so the client retries over TCP. Zero disables truncation,
    /// which is what the TUN path wants.
    /// </param>
    public async Task HandlePacketAsync(
        ReadOnlyMemory<byte> payload,
        EndPoint source,
        Func<ReadOnlyMemory<byte>, EndPoint, Task> reply,
        CancellationToken ct,
        int maxPayload = 0)
    {
        ArgumentNullException.ThrowIfNull(reply);

        var resolver = _tunnel?.Dns;
        if (resolver is null)
        {
            _logger?.LogDebug("dns listener received a query before StartAsync; dropping it");
            return;
        }

        DnsMessage query;
        try
        {
            query = _codec.Decode(payload.Span);
        }
        catch (DnsException error)
        {
            _logger?.LogDebug("dns: dropping malformed query from {Source}: {Message}", source, error.Message);
            return;
        }

        if (query.IsResponse) return;

        DnsMessage response;
        try
        {
            response = await resolver.ExchangeAsync(query, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            _logger?.LogWarning(error, "dns: resolving {Name} failed", query.Questions.Count > 0 ? query.Questions[0].Name : "?");
            response = DnsCodec.CreateResponse(query, DnsResponseCode.ServerFailure);
        }

        // The resolver is expected to do this, but the id is the one thing a
        // client will always notice.
        response.Id = query.Id;

        byte[] wire;
        try
        {
            wire = _codec.Encode(response);
        }
        catch (DnsException error)
        {
            _logger?.LogWarning("dns: could not encode the response for {Name}: {Message}", query.Questions.Count > 0 ? query.Questions[0].Name : "?", error.Message);
            return;
        }

        if (maxPayload > 0 && wire.Length > maxPayload)
        {
            response.Truncated = true;
            response.Answers.Clear();
            response.Authorities.Clear();
            response.Additionals.Clear();

            try
            {
                wire = _codec.Encode(response);
            }
            catch (DnsException)
            {
                return;
            }
        }

        try
        {
            await reply(wire, source).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            _logger?.LogDebug(error, "dns: replying to {Source} failed", source);
        }
    }

    // ── Serving loops ───────────────────────────────────────────────────────

    private async Task UdpLoopAsync(CancellationToken ct)
    {
        var socket = _udp;
        if (socket is null) return;

        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await socket.ReceiveAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException error)
            {
                if (ct.IsCancellationRequested) break;
                _logger?.LogDebug(error, "dns: udp receive failed");
                continue;
            }

            _ = ServeDatagramAsync(socket, result, ct);
        }
    }

    private async Task ServeDatagramAsync(UdpClient socket, UdpReceiveResult result, CancellationToken ct)
    {
        Interlocked.Increment(ref _active);
        try
        {
            var remote = result.RemoteEndPoint;
            await HandlePacketAsync(
                result.Buffer,
                remote,
                async (data, _) =>
                {
                    try
                    {
                        await socket.SendAsync(data, remote, ct).ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException)
                    {
                    }
                    catch (SocketException error)
                    {
                        _logger?.LogDebug(error, "dns: udp send failed");
                    }
                },
                ct,
                MaxUdpPayload).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            _logger?.LogDebug(error, "dns: udp query failed");
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private async Task TcpLoopAsync(CancellationToken ct)
    {
        var listener = _tcp;
        if (listener is null) return;

        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException error)
            {
                if (ct.IsCancellationRequested) break;
                _logger?.LogDebug(error, "dns: tcp accept failed");
                continue;
            }

            _ = ServeTcpClientAsync(client, ct);
        }
    }

    private async Task ServeTcpClientAsync(TcpClient client, CancellationToken ct)
    {
        Interlocked.Increment(ref _active);
        try
        {
            client.NoDelay = true;

            EndPoint remote;
            try
            {
                remote = client.Client.RemoteEndPoint ?? new IPEndPoint(IPAddress.None, 0);
            }
            catch (SocketException)
            {
                remote = new IPEndPoint(IPAddress.None, 0);
            }

            using (client)
            await using (var stream = client.GetStream())
            {
                while (!ct.IsCancellationRequested)
                {
                    byte[] payload;
                    try
                    {
                        payload = await DnsFraming.ReadAsync(stream, ct).ConfigureAwait(false);
                    }
                    catch (DnsException)
                    {
                        break;
                    }
                    catch (IOException)
                    {
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }

                    await HandlePacketAsync(
                        payload,
                        remote,
                        async (data, _) =>
                        {
                            try
                            {
                                await DnsFraming.WriteAsync(stream, data.ToArray(), ct).ConfigureAwait(false);
                            }
                            catch (IOException)
                            {
                            }
                            catch (ObjectDisposedException)
                            {
                            }
                            catch (OperationCanceledException)
                            {
                            }
                        },
                        ct).ConfigureAwait(false);
                }
            }
        }
        catch (Exception error)
        {
            _logger?.LogDebug(error, "dns: tcp client failed");
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    private static IPAddress ParseHost(string host) => host.Trim() switch
    {
        "" or "*" or "0.0.0.0" => IPAddress.Any,
        "::" or "[::]" => IPAddress.IPv6Any,
        "localhost" => IPAddress.Loopback,
        var value => IPAddress.TryParse(value, out var address) ? address : IPAddress.Any,
    };
}
