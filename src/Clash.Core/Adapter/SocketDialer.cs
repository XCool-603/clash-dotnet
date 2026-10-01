using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Dns;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Adapter;

/// <summary>
/// Shared socket plumbing for the outbound adapters: name resolution that
/// respects the tunnel's resolver, optional interface binding, and
/// address-family fallback.
/// </summary>
public static class SocketDialer
{
    /// <summary>
    /// Resolves <paramref name="host"/> to candidate addresses, preferring the
    /// tunnel's resolver (which honours hosts overrides and maps fake addresses
    /// back to real ones) and falling back to the platform resolver.
    /// </summary>
    public static async Task<IPAddress[]> ResolveAsync(
        string host,
        IDnsResolver? resolver,
        bool allowIpv6,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(host, out var literal)) return [literal];

        if (resolver is not null)
        {
            try
            {
                var addresses = await resolver.ResolveAsync(host, allowIpv6, cancellationToken).ConfigureAwait(false);
                if (addresses.Length > 0) return addresses;
            }
            catch (Exception)
            {
                // Fall through to the platform resolver; a DNS outage must not
                // make DIRECT unusable.
            }
        }

        try
        {
            var system = await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
            return allowIpv6 ? system : system.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
        }
        catch (SocketException)
        {
            return [];
        }
    }

    /// <summary>Binds a socket to the address of the configured interface, when one is set.</summary>
    public static void BindInterface(Socket socket, string? interfaceName)
    {
        if (string.IsNullOrWhiteSpace(interfaceName)) return;

        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!string.Equals(nic.Name, interfaceName, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(nic.Id, interfaceName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var address = nic.GetIPProperties().UnicastAddresses
                .Select(u => u.Address)
                .FirstOrDefault(a => a.AddressFamily == socket.AddressFamily);

            if (address is not null)
            {
                try { socket.Bind(new IPEndPoint(address, 0)); } catch (SocketException) { /* best effort */ }
            }
            return;
        }
    }

    /// <summary>Opens a TCP connection, trying each candidate address in turn.</summary>
    public static async Task<Socket> ConnectTcpAsync(
        string host,
        int port,
        IDnsResolver? resolver,
        bool allowIpv6,
        string? interfaceName,
        ILogger? logger,
        CancellationToken cancellationToken)
    {
        var addresses = await ResolveAsync(host, resolver, allowIpv6, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        Exception? last = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                BindInterface(socket, interfaceName);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token).ConfigureAwait(false);
                return socket;
            }
            catch (Exception ex)
            {
                last = ex;
                socket.Dispose();
                logger?.LogDebug("connect {Address}:{Port} failed: {Message}", address, port, ex.Message);
            }
        }

        throw last ?? new SocketException((int)SocketError.HostUnreachable);
    }

    /// <summary>Opens a UDP socket, optionally connected to a fixed destination.</summary>
    public static async Task<Socket> ConnectUdpAsync(
        string host,
        int port,
        IDnsResolver? resolver,
        bool allowIpv6,
        string? interfaceName,
        CancellationToken cancellationToken)
    {
        var addresses = await ResolveAsync(host, resolver, allowIpv6, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0) throw new SocketException((int)SocketError.HostNotFound);

        var socket = new Socket(addresses[0].AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        BindInterface(socket, interfaceName);
        socket.Connect(new IPEndPoint(addresses[0], port));
        return socket;
    }

    /// <summary>An all-zero endpoint matching an address family, used as the receive template.</summary>
    public static IPEndPoint AnyEndpoint(AddressFamily family)
        => family == AddressFamily.InterNetworkV6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
}

/// <summary>A UDP association over a connected socket, used by <c>DIRECT</c> and DNS.</summary>
public sealed class DirectPacketConnection : IPacketConnection
{
    private readonly Socket _socket;
    private readonly IPEndPoint _template;

    public DirectPacketConnection(Socket socket)
    {
        _socket = socket;
        _template = SocketDialer.AnyEndpoint(socket.AddressFamily);
    }

    public bool SupportsMultipleDestinations => false;

    public EndPoint? LocalEndPoint => _socket.LocalEndPoint;

    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
    {
        // A connected socket ignores the destination argument, which is exactly
        // the DIRECT semantics: one association per destination.
        return _socket.SendAsync(payload, SocketFlags.None, cancellationToken);
    }

    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, _template, cancellationToken).ConfigureAwait(false);
        return new PacketResult(result.ReceivedBytes, result.RemoteEndPoint);
    }

    public ValueTask DisposeAsync()
    {
        try { _socket.Dispose(); } catch { /* ignore */ }
        return ValueTask.CompletedTask;
    }
}

/// <summary>
/// A stream over a <see cref="Socket"/> that supports half-close. Preferred over
/// <see cref="NetworkStream"/> because a relay must be able to signal EOF to the
/// peer while still reading its response.
/// </summary>
public sealed class SocketStream : Stream, IHalfCloseable
{
    private readonly Socket _socket;
    private readonly NetworkStream _inner;
    private int _sendShutdown;

    public SocketStream(Socket socket)
    {
        _socket = socket ?? throw new ArgumentNullException(nameof(socket));
        _inner = new NetworkStream(socket, ownsSocket: false);
    }

    public Socket Socket => _socket;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => Volatile.Read(ref _sendShutdown) == 0;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>Sends a TCP FIN, leaving the receive direction open.</summary>
    public void ShutdownSend()
    {
        if (Interlocked.Exchange(ref _sendShutdown, 1) != 0) return;
        try { _socket.Shutdown(SocketShutdown.Send); } catch (SocketException) { /* already closed */ }
        catch (ObjectDisposedException) { /* already closed */ }
    }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override int Read(Span<byte> buffer) => _inner.Read(buffer);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.ReadAsync(buffer, cancellationToken);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.ReadAsync(buffer, offset, count, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _inner.Dispose(); } catch { /* ignore */ }
            try { _socket.Dispose(); } catch { /* ignore */ }
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
        try { _socket.Dispose(); } catch { /* ignore */ }
        GC.SuppressFinalize(this);
    }
}

/// <summary>A stream that is immediately at end-of-stream and discards writes.</summary>
public sealed class NullStream : Stream
{
    public static readonly NullStream Instance = new();

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => 0;

    public override long Position
    {
        get => 0;
        set => throw new NotSupportedException();
    }

    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => 0;
    public override int Read(Span<byte> buffer) => 0;
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(0);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => Task.FromResult(0);
    public override long Seek(long offset, SeekOrigin origin) => 0;
    public override void SetLength(long value) { }
    public override void Write(byte[] buffer, int offset, int count) { }
    public override void Write(ReadOnlySpan<byte> buffer) { }
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => Task.CompletedTask;
}
