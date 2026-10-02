using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;

namespace Clash.Core.Proxies.Outbound;

/// <summary>The SOCKS5 wire helpers shared by the TCP and UDP paths.</summary>
internal static class Socks5Client
{
    private const byte Version = 0x05;
    private const byte MethodNoAuth = 0x00;
    private const byte MethodUserPassword = 0x02;
    private const byte MethodNoneAcceptable = 0xFF;

    /// <summary>Performs the greeting and, when credentials are configured, the sub-negotiation.</summary>
    internal static async ValueTask HandshakeAsync(
        Stream stream,
        string? user,
        string? password,
        CancellationToken cancellationToken)
    {
        byte[] greeting;
        if (!string.IsNullOrEmpty(user))
        {
            greeting = [Version, 0x02, MethodNoAuth, MethodUserPassword];
        }
        else
        {
            greeting = [Version, 0x01, MethodNoAuth];
        }

        await stream.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);

        var choice = new byte[2];
        await OutboundIo.ReadExactlyAsync(stream, choice, cancellationToken).ConfigureAwait(false);
        if (choice[0] != Version)
        {
            throw new ClashException($"socks5: the proxy answered with version {choice[0]} instead of 5");
        }

        switch (choice[1])
        {
            case MethodNoAuth:
                return;

            case MethodUserPassword:
            {
                if (string.IsNullOrEmpty(user))
                {
                    throw new ClashException("socks5: the proxy demands username/password authentication but none is configured");
                }

                var userBytes = Encoding.UTF8.GetBytes(user);
                var passwordBytes = Encoding.UTF8.GetBytes(password ?? string.Empty);
                if (userBytes.Length > 255 || passwordBytes.Length > 255)
                {
                    throw new ClashException("socks5: the username or password is longer than 255 bytes");
                }

                var request = new byte[3 + userBytes.Length + passwordBytes.Length];
                request[0] = 0x01;
                request[1] = (byte)userBytes.Length;
                userBytes.CopyTo(request, 2);
                request[2 + userBytes.Length] = (byte)passwordBytes.Length;
                passwordBytes.CopyTo(request, 3 + userBytes.Length);

                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

                var result = new byte[2];
                await OutboundIo.ReadExactlyAsync(stream, result, cancellationToken).ConfigureAwait(false);
                if (result[1] != 0x00)
                {
                    throw new ClashException("socks5: the proxy rejected the username/password authentication");
                }

                return;
            }

            case MethodNoneAcceptable:
                throw new ClashException("socks5: the proxy rejected every offered authentication method");

            default:
                throw new ClashException($"socks5: the proxy selected unsupported authentication method {choice[1]}");
        }
    }

    /// <summary>
    /// Sends a request (CONNECT or UDP ASSOCIATE) and reads the reply, returning
    /// the bound endpoint the reply advertises.
    /// </summary>
    internal static async ValueTask<IPEndPoint?> RequestAsync(
        Stream stream,
        byte command,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        var request = new byte[4 + Socks5Address.Size(host)];
        request[0] = Version;
        request[1] = command;
        request[2] = 0x00;
        Socks5Address.Write(request.AsSpan(3), host, port);

        await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);

        var reply = new byte[4];
        await OutboundIo.ReadExactlyAsync(stream, reply, cancellationToken).ConfigureAwait(false);
        if (reply[0] != Version)
        {
            throw new ClashException($"socks5: the reply carried version {reply[0]} instead of 5");
        }

        var bound = await ReadEndpointAsync(stream, reply[3], cancellationToken).ConfigureAwait(false);

        if (reply[1] != 0x00)
        {
            throw new ClashException($"socks5: the proxy refused the request with code 0x{reply[1]:x2} ({DescribeReply(reply[1])})");
        }

        return bound;
    }

    /// <summary>Reads <c>ATYP ADDR PORT</c> and returns it as an endpoint when it is an address literal.</summary>
    internal static async ValueTask<IPEndPoint?> ReadEndpointAsync(Stream stream, byte addressType, CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case Socks5Address.TypeIpv4:
            case Socks5Address.TypeIpv6:
            {
                var length = addressType == Socks5Address.TypeIpv6 ? 16 : 4;
                var buffer = new byte[length + 2];
                await OutboundIo.ReadExactlyAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
                return new IPEndPoint(new IPAddress(buffer.AsSpan(0, length)), (buffer[length] << 8) | buffer[length + 1]);
            }

            case Socks5Address.TypeDomain:
            {
                var lengthByte = new byte[1];
                await OutboundIo.ReadExactlyAsync(stream, lengthByte, cancellationToken).ConfigureAwait(false);
                var buffer = new byte[lengthByte[0] + 2];
                await OutboundIo.ReadExactlyAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
                return null;
            }

            default:
                throw new ClashException($"socks5: unknown address type 0x{addressType:x2} in the reply");
        }
    }

    private static string DescribeReply(byte code) => code switch
    {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown",
    };
}

/// <summary>
/// A SOCKS5 UDP association: the TCP control connection stays open while
/// datagrams are relayed through the endpoint the <c>UDP ASSOCIATE</c> reply
/// advertised, framed as <c>RSV(2) FRAG(1) ATYP ADDR PORT DATA</c>.
/// </summary>
internal sealed class Socks5PacketConnection : IPacketConnection
{
    private const int MaxDatagram = 65535;

    private readonly ProxyStream _control;
    private readonly Socket _socket;
    private readonly EndPoint _template;
    private readonly EndPoint _server;
    private EndPoint? _lastDestination;
    private bool _disposed;

    internal Socks5PacketConnection(ProxyStream control, Socket socket, EndPoint server)
    {
        _control = control ?? throw new ArgumentNullException(nameof(control));
        _socket = socket ?? throw new ArgumentNullException(nameof(socket));
        _server = server;
        _template = SocketDialer.AnyEndpoint(socket.AddressFamily);
    }

    /// <inheritdoc />
    public bool SupportsMultipleDestinations => true;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _socket.LocalEndPoint;

    /// <inheritdoc />
    public async ValueTask<int> SendAsync(
        ReadOnlyMemory<byte> payload,
        EndPoint destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination is not IPEndPoint endpoint)
        {
            throw new NotSupportedException($"socks5: unsupported UDP destination {destination}");
        }

        var address = new byte[Socks5Address.Size(endpoint.Address)];
        var addressLength = Socks5Address.Write(address, endpoint.Address, endpoint.Port);

        var packet = new byte[3 + addressLength + payload.Length];
        Socks5Address.Write(packet.AsSpan(3), endpoint.Address, endpoint.Port);
        payload.Span.CopyTo(packet.AsSpan(3 + addressLength));

        await _socket.SendAsync(packet, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        _lastDestination = destination;
        return payload.Length;
    }

    /// <inheritdoc />
    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var rented = ArrayPool<byte>.Shared.Rent(MaxDatagram);
        try
        {
            while (true)
            {
                var received = await _socket
                    .ReceiveFromAsync(rented, SocketFlags.None, _template, cancellationToken)
                    .ConfigureAwait(false);

                var packet = rented.AsSpan(0, received.ReceivedBytes);
                if (packet.Length < 4) continue;
                if (packet[0] != 0 || packet[1] != 0) continue;

                // FRAG != 0 means the datagram is a fragment; fragments are dropped.
                if (packet[2] != 0) continue;

                if (!Socks5Address.TryParse(packet[3..], out var addressLength, out var host, out var port)) continue;

                var payload = packet[(3 + addressLength)..];
                var copied = OutboundIo.CopyInto(payload, buffer);
                return new PacketResult(copied, ResolveRemote(host, port, received.RemoteEndPoint));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private EndPoint ResolveRemote(string host, int port, EndPoint fallback)
    {
        if (!string.IsNullOrEmpty(host) && IPAddress.TryParse(host, out var address))
        {
            return new IPEndPoint(address, port);
        }

        return _lastDestination ?? fallback ?? _server;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        try { _socket.Dispose(); } catch { /* already gone */ }
        await _control.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// The <c>socks5</c> adapter: greeting, optional username/password
/// sub-negotiation, <c>CONNECT</c> with a domain address whenever the destination
/// is a name (so the proxy resolves it), and <c>UDP ASSOCIATE</c> for datagrams.
/// </summary>
public sealed class Socks5Adapter : OutboundAdapter
{
    private readonly string? _user;
    private readonly string? _password;
    private readonly YamlMap _transportOptions;

    internal Socks5Adapter(ProxyConfigEntry entry, AdapterBuildContext context, string? user, string? password, bool udp)
        : base(entry, context, ProxyType.Socks5, udp)
    {
        _user = user;
        _password = password;
        _transportOptions = entry.Map.GetBool("tls") ? entry.Map.With("tls", true) : entry.Map;
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static Socks5Adapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var user = entry.Map.GetNonEmptyString("user");
        var password = entry.Map.GetString("password");
        if (user is null && !string.IsNullOrEmpty(password))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (socks5) sets a 'password' without a 'user'; both are required for username/password authentication");
        }

        return new Socks5Adapter(entry, context, user, password, entry.Map.GetBool("udp"));
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
            await Socks5Client.HandshakeAsync(raw, _user, _password, cancellationToken).ConfigureAwait(false);
            await Socks5Client
                .RequestAsync(raw, 0x01, OutboundOptions.Destination(metadata), metadata.DestinationPort, cancellationToken)
                .ConfigureAwait(false);

            return Complete(Wrap(raw, raw));
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <inheritdoc />
    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!UdpEnabled)
        {
            throw new NotSupportedException($"proxy [{Name}] of type [{TypeName}] has UDP disabled in its configuration");
        }

        var control = await OpenAsync(metadata, null, cancellationToken).ConfigureAwait(false);
        try
        {
            await Socks5Client.HandshakeAsync(control, _user, _password, cancellationToken).ConfigureAwait(false);

            // UDP ASSOCIATE names the address the client will send from; all zeros
            // lets the proxy pick, which is what every client does.
            var bound = await Socks5Client
                .RequestAsync(control, 0x03, "0.0.0.0", 0, cancellationToken)
                .ConfigureAwait(false);

            var (resolver, ipv6, interfaceName) = SocketHints();
            var relayHost = bound is null || bound.Address.Equals(IPAddress.Any) || bound.Address.Equals(IPAddress.IPv6Any)
                ? ServerHost!
                : bound.Address.ToString();
            var relayPort = bound is null || bound.Port == 0 ? ServerPort : bound.Port;

            var socket = await SocketDialer
                .ConnectUdpAsync(relayHost, relayPort, resolver, ipv6, interfaceName, cancellationToken)
                .ConfigureAwait(false);

            var connection = new Socks5PacketConnection(control, socket, new IPEndPoint(IPAddress.Any, 0));
            TrackConnection(new AsyncDisposeBridge(connection));
            return connection;
        }
        catch (Exception ex)
        {
            await control.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }
}

/// <summary>Builds <see cref="Socks5Adapter"/> instances.</summary>
internal sealed class Socks5AdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "socks5";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => ["socks"];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => Socks5Adapter.Create(entry, context);
}
