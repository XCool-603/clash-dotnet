using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;

namespace Clash.Core.Listeners;

/// <summary>
/// An <see cref="EndPoint"/> standing for a destination named by a domain rather
/// than by an address. SOCKS5 UDP, redir and TProxy flows can all request one.
/// </summary>
internal sealed class DomainEndPoint : EndPoint
{
    /// <summary>Creates a domain endpoint.</summary>
    public DomainEndPoint(string host, int port)
    {
        Host = host ?? throw new ArgumentNullException(nameof(host));
        Port = port;
    }

    /// <summary>The requested name.</summary>
    public string Host { get; }

    /// <summary>The requested port.</summary>
    public int Port { get; }

    /// <inheritdoc />
    public override AddressFamily AddressFamily => AddressFamily.Unspecified;

    /// <inheritdoc />
    public override string ToString() => $"{Host}:{Port}";

    /// <inheritdoc />
    public override bool Equals(object? obj)
        => obj is DomainEndPoint other
           && other.Port == Port
           && string.Equals(other.Host, Host, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(Host), Port);

    /// <inheritdoc />
    public override EndPoint Create(SocketAddress socketAddress) => throw new NotSupportedException();

    /// <inheritdoc />
    public override SocketAddress Serialize() => throw new NotSupportedException();
}

/// <summary>
/// The simplest UDP association: one datagram socket already connected to a
/// single remote endpoint. <see cref="SendAsync"/> ignores the destination
/// because the socket can only ever talk to the peer it was connected to.
/// </summary>
public sealed class ConnectedUdpPacketConnection : IPacketConnection
{
    private readonly Socket _socket;
    private int _disposed;

    /// <summary>Takes ownership of a socket that is already connected.</summary>
    /// <param name="socket">A connected datagram socket.</param>
    public ConnectedUdpPacketConnection(Socket socket)
    {
        _socket = socket ?? throw new ArgumentNullException(nameof(socket));
        if (socket.SocketType != SocketType.Dgram)
        {
            throw new ArgumentException("a datagram socket is required", nameof(socket));
        }
    }

    /// <summary>Opens a connected association to <paramref name="remote"/>.</summary>
    /// <param name="remote">The remote endpoint to connect to.</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    public static async ValueTask<ConnectedUdpPacketConnection> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(remote);
        var socket = new Socket(remote.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            await socket.ConnectAsync(remote, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return new ConnectedUdpPacketConnection(socket);
    }

    /// <inheritdoc />
    public bool SupportsMultipleDestinations => false;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => SafeLocal();

    /// <summary>The peer this association is connected to.</summary>
    public EndPoint? RemoteEndPoint
    {
        get
        {
            try
            {
                return _socket.RemoteEndPoint;
            }
            catch (SocketException)
            {
                return null;
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
        }
    }

    /// <inheritdoc />
    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
        => _socket.SendAsync(payload, SocketFlags.None, cancellationToken);

    /// <inheritdoc />
    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var received = await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        return new PacketResult(received, RemoteEndPoint);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try
            {
                _socket.Dispose();
            }
            catch (SocketException)
            {
                // Already gone.
            }
        }

        return ValueTask.CompletedTask;
    }

    private EndPoint? SafeLocal()
    {
        try
        {
            return _socket.LocalEndPoint;
        }
        catch (SocketException)
        {
            return null;
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
    }
}

/// <summary>
/// A NAT-style association: one bound datagram socket multiplexes several client
/// source endpoints, and replies are routed back to the client that most
/// recently addressed the remote they came from.
/// <para>
/// Direction conventions, which every inbound UDP path in this project follows:
/// <list type="bullet">
/// <item><see cref="ReceiveAsync"/> yields a datagram sent by a client, with
/// <see cref="PacketResult.Remote"/> set to the destination that client asked
/// for (parsed from SOCKS5 framing, TProxy ancillary data, and so on).</item>
/// <item><see cref="SendAsync"/> is the reply path: <c>destination</c> is the
/// remote endpoint a reply arrived from, and the payload is framed and sent to
/// the client associated with it.</item>
/// <item><see cref="SendToRemoteAsync"/> is the forward path, used when the
/// association itself must push a datagram towards a remote.</item>
/// </list>
/// </para>
/// </summary>
public class NatPacketConnection : INatPacketConnection
{
    private readonly Dictionary<string, EndPoint> _clientByRemote = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();
    private readonly Socket _socket;
    private EndPoint? _lastClient;
    private int _disposed;

    /// <summary>Takes ownership of a bound datagram socket.</summary>
    /// <param name="socket">An unconnected datagram socket.</param>
    public NatPacketConnection(Socket socket)
    {
        _socket = socket ?? throw new ArgumentNullException(nameof(socket));
        if (socket.SocketType != SocketType.Dgram)
        {
            throw new ArgumentException("a datagram socket is required", nameof(socket));
        }
    }

    /// <inheritdoc />
    public bool SupportsMultipleDestinations => true;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint
    {
        get
        {
            try
            {
                return _socket.LocalEndPoint;
            }
            catch (SocketException)
            {
                return null;
            }
            catch (ObjectDisposedException)
            {
                return null;
            }
        }
    }

    /// <summary>The socket carrying the association, for subclasses that need raw access.</summary>
    protected Socket Socket => _socket;

    /// <summary>Number of client source endpoints currently tracked.</summary>
    public int TrackedSources
    {
        get
        {
            lock (_gate)
            {
                return _clientByRemote.Count;
            }
        }
    }

    /// <inheritdoc />
    public void RegisterSource(EndPoint source)
    {
        ArgumentNullException.ThrowIfNull(source);
        lock (_gate)
        {
            _lastClient = source;
        }
    }

    /// <summary>Records that <paramref name="remote"/> replies must reach <paramref name="client"/>.</summary>
    public void Associate(EndPoint remote, EndPoint client)
    {
        ArgumentNullException.ThrowIfNull(remote);
        ArgumentNullException.ThrowIfNull(client);
        lock (_gate)
        {
            _clientByRemote[remote.ToString() ?? string.Empty] = client;
            _lastClient = client;
        }
    }

    /// <summary>The client that talked to <paramref name="remote"/>, falling back to the most recent source.</summary>
    protected EndPoint? ClientFor(EndPoint remote)
    {
        ArgumentNullException.ThrowIfNull(remote);
        lock (_gate)
        {
            if (_clientByRemote.TryGetValue(remote.ToString() ?? string.Empty, out var client))
            {
                return client;
            }

            return _lastClient;
        }
    }

    /// <summary>Sends a datagram to the remote endpoint of the association.</summary>
    public ValueTask<int> SendToRemoteAsync(ReadOnlyMemory<byte> payload, EndPoint remote, CancellationToken cancellationToken = default)
        => _socket.SendToAsync(payload, SocketFlags.None, remote, cancellationToken);

    /// <summary>Receives a raw datagram, reporting the endpoint it came from.</summary>
    public async ValueTask<PacketResult> ReceiveRawAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var received = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, AnyEndPoint(), cancellationToken).ConfigureAwait(false);
        RegisterSource(received.RemoteEndPoint);
        return new PacketResult(received.ReceivedBytes, received.RemoteEndPoint);
    }

    /// <inheritdoc />
    public virtual async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => await ReceiveRawAsync(buffer, cancellationToken).ConfigureAwait(false);

    /// <inheritdoc />
    public virtual ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
    {
        var client = ClientFor(destination);
        if (client is null)
        {
            return ValueTask.FromResult(0);
        }

        return _socket.SendToAsync(payload, SocketFlags.None, client, cancellationToken);
    }

    /// <inheritdoc />
    public virtual ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try
            {
                _socket.Dispose();
            }
            catch (SocketException)
            {
                // Already gone.
            }

            lock (_gate)
            {
                _clientByRemote.Clear();
                _lastClient = null;
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>A wildcard endpoint matching the association's address family.</summary>
    protected EndPoint AnyEndPoint()
        => _socket.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);
}
