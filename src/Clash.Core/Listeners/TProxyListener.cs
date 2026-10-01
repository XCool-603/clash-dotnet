using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// The TPROXY inbound for Linux (<c>tproxy-port</c>). The listening socket is
/// marked <c>IP_TRANSPARENT</c>, TCP flows learn their original destination from
/// the accepted socket's local address, and UDP flows recover it from
/// <c>IP_RECVORIGDSTADDR</c> ancillary data read with <c>recvmsg</c>.
/// </summary>
public sealed class TProxyListener : ListenerBase
{
    /// <summary>Level of the IPv4 socket options used by TPROXY.</summary>
    internal const int SolIp = 0;

    /// <summary>Level of the IPv6 socket options used by TPROXY.</summary>
    internal const int SolIpv6 = 41;

    /// <summary><c>IP_TRANSPARENT</c>, required to bind non-local addresses.</summary>
    internal const int IpTransparent = 19;

    /// <summary><c>IP_RECVORIGDSTADDR</c>: ask for the original destination as ancillary data.</summary>
    internal const int IpRecvOrigDstAddr = 20;

    /// <summary><c>IPV6_RECVORIGDSTADDR</c>.</summary>
    internal const int Ipv6RecvOrigDstAddr = 74;

    /// <summary><c>IP_ORIGDSTADDR</c>, the ancillary data type carrying the destination.</summary>
    internal const int IpOrigDstAddr = 20;

    /// <summary><c>IPV6_ORIGDSTADDR</c>.</summary>
    internal const int Ipv6OrigDstAddr = 74;

    private Socket? _udpSocket;
    private TProxyUdpPacketConnection? _udpConnection;

    /// <summary>Creates the listener.</summary>
    /// <param name="config">Configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="port">Overrides <see cref="ClashConfig.TProxyPort"/>; 0 binds an ephemeral port.</param>
    /// <param name="name">Configured name, for <c>listeners</c> entries.</param>
    /// <param name="bindAddress">Overrides <see cref="ClashConfig.BindAddress"/>.</param>
    public TProxyListener(ClashConfig config, ILogger logger, int? port = null, string? name = null, string? bindAddress = null)
        : base("tproxy", name, port ?? (config ?? throw new ArgumentNullException(nameof(config))).TProxyPort, config, logger, bindAddress)
    {
    }

    /// <inheritdoc />
    protected override async Task OnStartAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "the tproxy inbound needs Linux TPROXY support (IP_TRANSPARENT and IP_RECVORIGDSTADDR); " +
                "use a tun inbound or the mixed port on Windows and macOS");
        }

        await StartTcpListenerAsync(cancellationToken).ConfigureAwait(false);
        StartUdpAssociation(cancellationToken);
    }

    /// <inheritdoc />
    protected override Socket CreateListenSocket(IPAddress address, int port)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.SetRawSocketOption(LevelFor(address), IpTransparent, [1]);
            socket.Bind(new IPEndPoint(address, port));
            socket.Listen(512);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return socket;
    }

    /// <inheritdoc />
    protected override async Task HandleClientAsync(Socket socket, CancellationToken cancellationToken)
    {
        // With TPROXY the kernel keeps the original destination as the accepted
        // socket's local address, so no getsockopt round trip is needed.
        var local = socket.LocalEndPoint as IPEndPoint
            ?? throw new ClashException("tproxy: the accepted socket has no local endpoint to use as destination");

        var metadata = CreateMetadata(socket.RemoteEndPoint, local.Address.ToString(), (ushort)local.Port, Network.Tcp);
        await using var stream = CreateInboundStream(socket);
        await RequireTunnel().HandleTcpAsync(stream, metadata, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async ValueTask OnStoppedAsync()
    {
        var connection = Interlocked.Exchange(ref _udpConnection, null);
        var socket = Interlocked.Exchange(ref _udpSocket, null);
        if (connection is not null)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }

        socket?.Dispose();
    }

    private void StartUdpAssociation(CancellationToken cancellationToken)
    {
        var address = ResolveBindAddress();
        var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            var level = LevelFor(address);
            socket.SetRawSocketOption(level, IpTransparent, [1]);
            socket.SetRawSocketOption(level, address.AddressFamily == AddressFamily.InterNetworkV6 ? Ipv6RecvOrigDstAddr : IpRecvOrigDstAddr, [1]);
            socket.Bind(new IPEndPoint(address, Port));
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException or InvalidOperationException)
        {
            socket.Dispose();
            throw new ListenerBindException(Type, FormatEndpoint(address, Port), ex);
        }

        var connection = new TProxyUdpPacketConnection(socket);
        _udpSocket = socket;
        _udpConnection = connection;

        var metadata = CreateMetadata(null, address.ToString(), (ushort)Math.Clamp(Port, 0, ushort.MaxValue), Network.Udp);
        var tunnel = RequireTunnel();
        _ = Task.Run(
            async () =>
            {
                try
                {
                    await tunnel.HandleUdpAsync(connection, metadata, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown.
                }
                catch (Exception ex)
                {
                    ReportError(ex);
                }
            },
            CancellationToken.None);
    }

    private static int LevelFor(IPAddress address)
        => address.AddressFamily == AddressFamily.InterNetworkV6 ? SolIpv6 : SolIp;
}

/// <summary>
/// A TPROXY UDP association. Datagrams are read with <c>recvmsg</c> so the
/// original destination arrives as <c>IP_ORIGDSTADDR</c> ancillary data; replies
/// leave from a socket bound to that same destination, which is what makes the
/// client see them coming from the server it addressed.
/// </summary>
internal sealed class TProxyUdpPacketConnection : NatPacketConnection
{
    private const int AddressFamilyInet = 2;
    private const int AddressFamilyInet6Linux = 10;
    private const int ControlBufferSize = 512;
    private const int MaxDatagramSize = 65535;

    private readonly Channel<(byte[] Payload, EndPoint Source, EndPoint Destination)> _channel =
        Channel.CreateUnbounded<(byte[], EndPoint, EndPoint)>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
        });

    private readonly byte[] _control = new byte[ControlBufferSize];
    private readonly byte[] _scratch = new byte[MaxDatagramSize];
    private readonly Dictionary<string, Socket> _replySockets = new(StringComparer.Ordinal);
    private readonly Lock _replyGate = new();
    private readonly CancellationTokenSource _pumpLifetime = new();
    private readonly Task _pump;
    private int _disposed;

    /// <summary>Takes ownership of the TPROXY datagram socket.</summary>
    public TProxyUdpPacketConnection(Socket socket)
        : base(socket)
    {
        _pump = Task.Factory.StartNew(Pump, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    /// <inheritdoc />
    public override async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            while (_channel.Reader.TryRead(out var datagram))
            {
                var length = Math.Min(datagram.Payload.Length, buffer.Length);
                datagram.Payload.AsSpan(0, length).CopyTo(buffer.Span);
                RegisterSource(datagram.Source);
                Associate(datagram.Destination, datagram.Source);
                return new PacketResult(length, datagram.Destination);
            }
        }

        return new PacketResult(0, null);
    }

    /// <inheritdoc />
    public override ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
    {
        var client = ClientFor(destination);
        if (client is null)
        {
            return ValueTask.FromResult(0);
        }

        var replySocket = ReplySocketFor(destination);
        if (replySocket is null)
        {
            return ValueTask.FromResult(0);
        }

        return replySocket.SendToAsync(payload, SocketFlags.None, client, cancellationToken);
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            _pumpLifetime.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already cancelled.
        }

        await base.DisposeAsync().ConfigureAwait(false);
        _channel.Writer.TryComplete();

        lock (_replyGate)
        {
            foreach (var socket in _replySockets.Values)
            {
                socket.Dispose();
            }

            _replySockets.Clear();
        }

        try
        {
            await _pump.ConfigureAwait(false);
        }
        catch
        {
            // The pump ends when the socket goes away.
        }

        _pumpLifetime.Dispose();
    }

    private Socket? ReplySocketFor(EndPoint destination)
    {
        if (destination is not IPEndPoint local)
        {
            return null;
        }

        var key = local.ToString();
        lock (_replyGate)
        {
            if (_replySockets.TryGetValue(key, out var existing))
            {
                return existing;
            }

            if (Volatile.Read(ref _disposed) != 0)
            {
                return null;
            }

            var socket = new Socket(local.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.SetRawSocketOption(
                    local.AddressFamily == AddressFamily.InterNetworkV6 ? TProxyListener.SolIpv6 : TProxyListener.SolIp,
                    TProxyListener.IpTransparent,
                    [1]);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.Bind(local);
            }
            catch (SocketException)
            {
                socket.Dispose();
                return null;
            }

            _replySockets[key] = socket;
            return socket;
        }
    }

    private void Pump()
    {
        int descriptor;
        try
        {
            descriptor = checked((int)Socket.Handle.ToInt64());
        }
        catch (Exception)
        {
            _channel.Writer.TryComplete();
            return;
        }

        while (!_pumpLifetime.IsCancellationRequested)
        {
            var received = ReceiveMessage(descriptor, _scratch, _control, out var source, out var destination);
            if (received < 0)
            {
                break;
            }

            if (received == 0 || source is null || destination is null)
            {
                continue;
            }

            var payload = _scratch.AsSpan(0, received).ToArray();
            if (!_channel.Writer.TryWrite((payload, source, destination)))
            {
                break;
            }
        }

        _channel.Writer.TryComplete();
    }

    private static unsafe int ReceiveMessage(int descriptor, byte[] payload, byte[] control, out EndPoint? source, out EndPoint? destination)
    {
        source = null;
        destination = null;
        fixed (byte* payloadPointer = payload)
        fixed (byte* controlPointer = control)
        {
            var name = stackalloc byte[128];
            var iovec = new IoVector
            {
                Base = (nint)payloadPointer,
                Length = (nuint)payload.Length,
            };

            var header = new MessageHeader
            {
                Name = (nint)name,
                NameLength = 128,
                Iov = (nint)(&iovec),
                IovLength = 1,
                Control = (nint)controlPointer,
                ControlLength = (nuint)control.Length,
                Flags = 0,
            };

            var received = recvmsg(descriptor, ref header, 0);
            if (received < 0)
            {
                return -1;
            }

            source = ParseSocketAddress(name, (int)header.NameLength);
            destination = ParseControlMessages(controlPointer, (int)header.ControlLength);
            return (int)received;
        }
    }

    private static unsafe EndPoint? ParseControlMessages(byte* control, int length)
    {
        var offset = 0;
        while (offset + 16 <= length)
        {
            var messageLength = *(nuint*)(control + offset);
            var level = *(int*)(control + offset + 8);
            var type = *(int*)(control + offset + 12);
            if (messageLength < 16 || offset + (int)messageLength > length)
            {
                break;
            }

            var isOriginalDestination =
                (level == TProxyListener.SolIp && type == TProxyListener.IpOrigDstAddr)
                || (level == TProxyListener.SolIpv6 && type == TProxyListener.Ipv6OrigDstAddr);
            if (isOriginalDestination)
            {
                var parsed = ParseSocketAddress(control + offset + 16, (int)messageLength - 16);
                if (parsed is not null)
                {
                    return parsed;
                }
            }

            offset += (int)((messageLength + 7) & ~(nuint)7);
        }

        return null;
    }

    private static unsafe EndPoint? ParseSocketAddress(byte* data, int length)
    {
        if (length < 8)
        {
            return null;
        }

        var family = *(ushort*)data;
        var port = (ushort)((data[2] << 8) | data[3]);
        if (family == AddressFamilyInet)
        {
            return new IPEndPoint(new IPAddress(new ReadOnlySpan<byte>(data + 4, 4)), port);
        }

        if (family == AddressFamilyInet6Linux && length >= 24)
        {
            return new IPEndPoint(new IPAddress(new ReadOnlySpan<byte>(data + 8, 16)), port);
        }

        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoVector
    {
        public nint Base;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MessageHeader
    {
        public nint Name;
        public uint NameLength;
        public nint Iov;
        public nuint IovLength;
        public nint Control;
        public nuint ControlLength;
        public int Flags;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern nint recvmsg(int socket, ref MessageHeader message, int flags);
}
