using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;
using Clash.Core.Tunnel;
using Xunit;

namespace Clash.Tests.Listeners;

/// <summary>
/// A tunnel stand-in that records the metadata and bytes an inbound listener
/// produced, and can echo the stream back to the client.
/// </summary>
internal sealed class FakeTunnel : ITunnel
{
    private readonly TaskCompletionSource<Metadata> _tcpCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<Metadata> _udpCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly List<string> _logs = [];
    private readonly Lock _logGate = new();

    public FakeTunnel(ClashConfig? config = null)
    {
        Config = config ?? new ClashConfig();
        Traffic = new TrafficTracker();
        Connections = new ConnectionManager(Traffic);
    }

    public ClashConfig Config { get; }

    public IDnsResolver Dns => throw new NotSupportedException();

    public IGeoData Geo => throw new NotSupportedException();

    public IProxyManager Proxies => throw new NotSupportedException();

    public ConnectionManager Connections { get; }

    public IRuleEngine Rules => throw new NotSupportedException();

    public TrafficTracker Traffic { get; }

    public IDelayTester DelayTester => throw new NotSupportedException();

    public Mode Mode { get; set; } = Mode.Rule;

    /// <summary>Bytes the tunnel read from the inbound stream.</summary>
    public byte[] Received { get; private set; } = [];

    /// <summary>The bytes the tunnel read, decoded as UTF-8.</summary>
    public string ReceivedText => Encoding.UTF8.GetString(Received);

    /// <summary>Metadata of the last TCP flow.</summary>
    public Metadata? TcpMetadata { get; private set; }

    /// <summary>Metadata of the last UDP association.</summary>
    public Metadata? UdpMetadata { get; private set; }

    /// <summary>When true, everything read is written straight back to the client.</summary>
    public bool Echo { get; set; } = true;

    /// <summary>Stops reading once this many bytes have been collected.</summary>
    public int StopAfterBytes { get; set; } = int.MaxValue;

    /// <summary>Replaces the default one-datagram echo for UDP associations.</summary>
    public Func<IPacketConnection, Metadata, CancellationToken, Task>? UdpHandler { get; set; }

    /// <summary>Completes once <see cref="HandleTcpAsync"/> has read everything it was going to read.</summary>
    public Task<Metadata> TcpHandled => _tcpCompletion.Task;

    /// <summary>Completes as soon as <see cref="HandleUdpAsync"/> is entered.</summary>
    public Task<Metadata> UdpHandled => _udpCompletion.Task;

    /// <summary>Every line passed to <see cref="Log"/>.</summary>
    public IReadOnlyList<string> Logs
    {
        get
        {
            lock (_logGate)
            {
                return [.. _logs];
            }
        }
    }

    public Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult<RuleMatch?>(null);

    public Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public async Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default)
    {
        TcpMetadata = metadata;
        var buffer = new byte[8192];
        using var collected = new MemoryStream();
        while (true)
        {
            int read;
            try
            {
                read = await inbound.ReadAsync(buffer, cancellationToken);
            }
            catch
            {
                break;
            }

            if (read <= 0)
            {
                break;
            }

            collected.Write(buffer, 0, read);
            if (Echo)
            {
                try
                {
                    await inbound.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    await inbound.FlushAsync(cancellationToken);
                }
                catch
                {
                    break;
                }
            }

            if (collected.Length >= StopAfterBytes)
            {
                break;
            }
        }

        Received = collected.ToArray();
        _tcpCompletion.TrySetResult(metadata);
    }

    public async Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default)
    {
        UdpMetadata = metadata;
        _udpCompletion.TrySetResult(metadata);
        if (UdpHandler is not null)
        {
            await UdpHandler(inbound, metadata, cancellationToken);
            return;
        }

        var buffer = new byte[65535];
        var result = await inbound.ReceiveAsync(buffer, cancellationToken);
        if (result.Remote is not null && result.BytesRead > 0)
        {
            await inbound.SendAsync(buffer.AsMemory(0, result.BytesRead), result.Remote, cancellationToken);
        }
    }

    public void Log(string level, string message)
    {
        lock (_logGate)
        {
            _logs.Add($"{level}: {message}");
        }

        LogEmitted?.Invoke(level, message);
    }

    public event Action<string, string>? LogEmitted;
}

/// <summary>Socket helpers shared by the listener tests.</summary>
internal static class TestSockets
{
    /// <summary>How long a test waits for the peer before failing.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public static async Task<Socket> ConnectAsync(int port, CancellationToken cancellationToken = default)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), cancellationToken).AsTask().WaitAsync(Timeout, cancellationToken);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return socket;
    }

    public static Socket CreateUdpClient()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return socket;
    }

    public static async Task SendAsync(this Socket socket, byte[] payload, CancellationToken cancellationToken = default)
    {
        await socket.SendAsync(payload, SocketFlags.None, cancellationToken).AsTask().WaitAsync(Timeout, cancellationToken);
    }

    public static async Task<byte[]> ReadExactlyAsync(this Socket socket, int count, CancellationToken cancellationToken = default)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await socket.ReceiveAsync(buffer.AsMemory(offset), SocketFlags.None, cancellationToken).AsTask().WaitAsync(Timeout, cancellationToken);
            if (read <= 0)
            {
                throw new IOException($"connection closed after {offset} of {count} bytes");
            }

            offset += read;
        }

        return buffer;
    }

    /// <summary>Reads until <paramref name="marker"/> has been seen, returning everything read so far.</summary>
    public static async Task<string> ReadUntilAsync(this Socket socket, string marker, CancellationToken cancellationToken = default)
    {
        var builder = new StringBuilder();
        var buffer = new byte[512];
        while (builder.ToString().IndexOf(marker, StringComparison.Ordinal) < 0)
        {
            var read = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).AsTask().WaitAsync(Timeout, cancellationToken);
            if (read <= 0)
            {
                break;
            }

            builder.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }

        return builder.ToString();
    }

    /// <summary>Reads a full SOCKS5 reply, returning the reply code and the bound endpoint.</summary>
    public static async Task<(byte Reply, IPEndPoint? Bound)> ReadSocks5ReplyAsync(this Socket socket, CancellationToken cancellationToken = default)
    {
        var header = await socket.ReadExactlyAsync(4, cancellationToken);
        var reply = header[1];
        switch (header[3])
        {
            case 0x01:
            {
                var rest = await socket.ReadExactlyAsync(6, cancellationToken);
                return (reply, new IPEndPoint(new IPAddress(rest.AsSpan(0, 4)), (rest[4] << 8) | rest[5]));
            }

            case 0x04:
            {
                var rest = await socket.ReadExactlyAsync(18, cancellationToken);
                return (reply, new IPEndPoint(new IPAddress(rest.AsSpan(0, 16)), (rest[16] << 8) | rest[17]));
            }

            case 0x03:
            {
                var length = (await socket.ReadExactlyAsync(1, cancellationToken))[0];
                var rest = await socket.ReadExactlyAsync(length + 2, cancellationToken);
                var host = Encoding.ASCII.GetString(rest, 0, length);
                return (reply, IPAddress.TryParse(host, out var parsed)
                    ? new IPEndPoint(parsed, (rest[length] << 8) | rest[length + 1])
                    : null);
            }

            default:
                return (reply, null);
        }
    }

    /// <summary>Performs the SOCKS5 greeting and returns the selected method.</summary>
    public static async Task<byte> GreetSocks5Async(this Socket socket, params byte[] methods)
    {
        var greeting = new byte[2 + methods.Length];
        greeting[0] = 0x05;
        greeting[1] = (byte)methods.Length;
        methods.CopyTo(greeting, 2);
        await socket.SendAsync(greeting);
        var reply = await socket.ReadExactlyAsync(2);
        Assert.Equal(0x05, reply[0]);
        return reply[1];
    }

    /// <summary>Builds a SOCKS5 CONNECT-style request for an IPv4 target.</summary>
    public static byte[] Socks5Request(byte command, byte[] address, ushort port)
    {
        var request = new byte[4 + address.Length + 2];
        request[0] = 0x05;
        request[1] = command;
        request[2] = 0x00;
        request[3] = address.Length == 4 ? (byte)0x01 : address.Length == 16 ? (byte)0x04 : (byte)0x03;
        address.CopyTo(request, 4);
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)(port & 0xFF);
        return request;
    }

    /// <summary>Builds a SOCKS5 domain request: ATYP 0x03 plus a length-prefixed name.</summary>
    public static byte[] Socks5DomainRequest(byte command, string host, ushort port)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var request = new byte[4 + 1 + name.Length + 2];
        request[0] = 0x05;
        request[1] = command;
        request[2] = 0x00;
        request[3] = 0x03;
        request[4] = (byte)name.Length;
        name.CopyTo(request, 5);
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)(port & 0xFF);
        return request;
    }

    /// <summary>Builds a SOCKS5 UDP request datagram.</summary>
    public static byte[] Socks5UdpDatagram(string payload, IPAddress destination, ushort port, byte fragment = 0)
    {
        var body = Encoding.UTF8.GetBytes(payload);
        var datagram = new byte[4 + 4 + 2 + body.Length];
        datagram[0] = 0x00;
        datagram[1] = 0x00;
        datagram[2] = fragment;
        datagram[3] = 0x01;
        destination.GetAddressBytes().CopyTo(datagram, 4);
        datagram[8] = (byte)(port >> 8);
        datagram[9] = (byte)(port & 0xFF);
        body.CopyTo(datagram, 10);
        return datagram;
    }

    /// <summary>Parses a SOCKS5 UDP reply datagram.</summary>
    public static (IPAddress Destination, ushort Port, string Payload, byte Fragment) ParseSocks5UdpDatagram(byte[] datagram)
    {
        Assert.True(datagram.Length >= 10, "SOCKS5 UDP datagram is too short");
        Assert.Equal(0x00, datagram[0]);
        Assert.Equal(0x00, datagram[1]);
        Assert.Equal(0x01, datagram[3]);
        var destination = new IPAddress(datagram.AsSpan(4, 4));
        var port = (ushort)((datagram[8] << 8) | datagram[9]);
        return (destination, port, Encoding.UTF8.GetString(datagram, 10, datagram.Length - 10), datagram[2]);
    }

    /// <summary>Finds a port that is free right now, for the manager's bind tests.</summary>
    public static int FreePort()
    {
        var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)probe.LocalEndPoint!).Port;
        probe.Dispose();
        return port;
    }
}
