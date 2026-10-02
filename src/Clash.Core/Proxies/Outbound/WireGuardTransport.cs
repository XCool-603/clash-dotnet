using System.Net;
using System.Net.Sockets;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The one datagram pipe a WireGuard session runs over: a connected UDP socket in
/// production, an in-process queue in tests.
/// <para>
/// Why an interface rather than a <see cref="Socket"/>: WireGuard is UDP-only and
/// has no framing of its own, so the whole protocol is "hand these bytes to the
/// peer" and "here are the bytes the peer sent". Keeping that boundary explicit is
/// what makes the handshake, the transport messages and the netstack testable
/// without a socket, a port or a timing dependency anywhere in the suite.
/// </para>
/// <para>
/// Implementations must be safe to call concurrently from one sender and one
/// receiver, which is the only concurrency a <see cref="WireGuardSession"/>
/// produces.
/// </para>
/// </summary>
public interface IWireGuardDatagramTransport : IAsyncDisposable
{
    /// <summary>The local endpoint, when the transport has one.</summary>
    EndPoint? LocalEndPoint { get; }

    /// <summary>The peer's endpoint, when the transport is connected to one.</summary>
    EndPoint? RemoteEndPoint { get; }

    /// <summary>Sends one complete WireGuard message (handshake or transport).</summary>
    /// <param name="datagram">The message.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    ValueTask<int> SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken);

    /// <summary>
    /// Receives one datagram. Returning 0 means "nothing usable arrived"; the
    /// session's pump simply loops. Implementations should surface a transient
    /// network error as 0 rather than as an exception, because a WireGuard session
    /// has no recovery path other than continuing to listen.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Ends the wait.</param>
    ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken);
}

/// <summary>
/// A <see cref="IWireGuardDatagramTransport"/> over a connected UDP socket.
/// <para>
/// One socket per session: WireGuard has exactly one local/remote port pair, and a
/// connected socket is what keeps the peer's replies from being delivered to
/// anything else on the machine.
/// </para>
/// </summary>
public sealed class WireGuardUdpTransport : IWireGuardDatagramTransport
{
    private readonly Socket _socket;
    private int _disposed;

    /// <summary>Takes ownership of an already connected datagram socket.</summary>
    /// <param name="socket">A connected <see cref="SocketType.Dgram"/> socket.</param>
    public WireGuardUdpTransport(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        _socket = socket;

        // WireGuard's handshake bursts (up to 18 retries) and a busy inner TCP
        // flow can both queue faster than the default 8 KiB receive buffer drains.
        try { _socket.ReceiveBufferSize = Math.Max(_socket.ReceiveBufferSize, 1 << 20); }
        catch (SocketException) { /* the platform refused the hint; the default is still correct */ }
    }

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => Safe(() => _socket.LocalEndPoint);

    /// <inheritdoc />
    public EndPoint? RemoteEndPoint => Safe(() => _socket.RemoteEndPoint);

    /// <inheritdoc />
    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
        => _socket.SendAsync(datagram, SocketFlags.None, cancellationToken);

    /// <inheritdoc />
    public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        try
        {
            return await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException)
        {
            // A connectionless protocol surfaces ICMP port-unreachable and
            // "message too long" here. Neither ends the session: the peer may
            // simply have moved, and the next handshake retry will find it.
            return 0;
        }
        catch (ObjectDisposedException)
        {
            return 0;
        }
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try { _socket.Dispose(); } catch (ObjectDisposedException) { /* already gone */ }
        }

        return ValueTask.CompletedTask;
    }

    private static EndPoint? Safe(Func<EndPoint?> read)
    {
        try { return read(); }
        catch (Exception) { return null; }
    }
}
