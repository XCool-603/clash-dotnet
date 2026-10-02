using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// A SOCKS inbound (<c>socks-port</c> in the configuration). Speaks SOCKS5 with
/// optional username/password authentication and SOCKS4/4a for compatibility,
/// including <c>UDP ASSOCIATE</c>.
/// </summary>
public sealed class SocksListener : ListenerBase
{
    /// <summary>Creates the listener.</summary>
    /// <param name="config">Configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="port">Overrides <see cref="ClashConfig.SocksPort"/>; 0 binds an ephemeral port.</param>
    /// <param name="name">Configured name, for <c>listeners</c> entries.</param>
    /// <param name="bindAddress">Overrides <see cref="ClashConfig.BindAddress"/>.</param>
    public SocksListener(ClashConfig config, ILogger logger, int? port = null, string? name = null, string? bindAddress = null)
        : base("socks", name, port ?? (config ?? throw new ArgumentNullException(nameof(config))).SocksPort, config, logger, bindAddress)
    {
    }

    /// <inheritdoc />
    protected override Task OnStartAsync(CancellationToken cancellationToken) => StartTcpListenerAsync(cancellationToken);

    /// <inheritdoc />
    protected override async Task HandleClientAsync(Socket socket, CancellationToken cancellationToken)
    {
        await using var stream = CreateInboundStream(socket);
        await SocksProxyProtocol.HandleAsync(this, stream, socket, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// The SOCKS protocol itself, shared by <see cref="SocksListener"/> and
/// <see cref="MixedListener"/>.
/// </summary>
internal static class SocksProxyProtocol
{
    private const byte Version5 = 0x05;
    private const byte Version4 = 0x04;

    private const byte MethodNoAuth = 0x00;
    private const byte MethodUserPass = 0x02;
    private const byte MethodNoneAcceptable = 0xFF;

    private const byte CommandConnect = 0x01;
    private const byte CommandBind = 0x02;
    private const byte CommandUdpAssociate = 0x03;

    private const byte ReplySucceeded = 0x00;
    private const byte ReplyGeneralFailure = 0x01;
    private const byte ReplyCommandNotSupported = 0x07;

    private const byte AddressIpv4 = 0x01;
    private const byte AddressDomain = 0x03;
    private const byte AddressIpv6 = 0x04;

    private const int MaxDomainLength = 255;

    /// <summary>Dispatches one SOCKS client by protocol version.</summary>
    public static async Task HandleAsync(ListenerBase listener, InboundStream stream, Socket socket, CancellationToken cancellationToken)
    {
        var version = await stream.PeekByteAsync(cancellationToken).ConfigureAwait(false);
        switch (version)
        {
            case Version5:
                await HandleSocks5Async(listener, stream, socket, cancellationToken).ConfigureAwait(false);
                break;
            case Version4:
                await HandleSocks4Async(listener, stream, socket, cancellationToken).ConfigureAwait(false);
                break;
            case -1:
                return;
            default:
                throw new ClashException($"unsupported SOCKS version 0x{version:X2}");
        }
    }

    private static async Task HandleSocks5Async(ListenerBase listener, InboundStream stream, Socket socket, CancellationToken cancellationToken)
    {
        var greeting = await stream.ReadExactAsync(2, cancellationToken).ConfigureAwait(false);
        if (greeting[0] != Version5)
        {
            throw new ClashException($"unsupported SOCKS version 0x{greeting[0]:X2}");
        }

        var methodCount = greeting[1];
        if (methodCount == 0)
        {
            throw new ClashException("SOCKS5 client offered no authentication methods");
        }

        var methods = await stream.ReadExactAsync(methodCount, cancellationToken).ConfigureAwait(false);
        var requireAuthentication = listener.Config.Authentication.Count > 0;
        var selected = MethodNoneAcceptable;
        if (requireAuthentication)
        {
            if (Array.IndexOf(methods, MethodUserPass) >= 0)
            {
                selected = MethodUserPass;
            }
        }
        else if (Array.IndexOf(methods, MethodNoAuth) >= 0)
        {
            selected = MethodNoAuth;
        }

        // Same rule as a rejected password: report before refusing.
        var methodRefusal = selected == MethodNoneAcceptable
            ? listener.RejectAuthentication(new AuthenticationException("no acceptable SOCKS5 authentication method"))
            : null;

        await stream.WriteAsync(new byte[] { Version5, selected }, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (methodRefusal is not null)
        {
            throw methodRefusal;
        }

        string? user = null;
        if (selected == MethodUserPass)
        {
            user = await AuthenticateAsync(listener, stream, cancellationToken).ConfigureAwait(false);
        }

        var request = await stream.ReadExactAsync(4, cancellationToken).ConfigureAwait(false);
        if (request[0] != Version5)
        {
            throw new ClashException($"unsupported SOCKS version 0x{request[0]:X2}");
        }

        var command = request[1];
        var addressType = request[3];
        var destination = await ReadDestinationAsync(stream, addressType, cancellationToken).ConfigureAwait(false);
        if (destination is null)
        {
            await WriteReplyAsync(stream, ReplyGeneralFailure, null, cancellationToken).ConfigureAwait(false);
            throw new ClashException($"unsupported SOCKS5 address type 0x{addressType:X2}");
        }

        switch (command)
        {
            case CommandConnect:
                await HandleConnectAsync(listener, stream, socket, destination.Value, user, cancellationToken).ConfigureAwait(false);
                break;
            case CommandUdpAssociate:
                await HandleUdpAssociateAsync(listener, stream, socket, destination.Value, user, cancellationToken).ConfigureAwait(false);
                break;
            default:
                await WriteReplyAsync(stream, ReplyCommandNotSupported, null, cancellationToken).ConfigureAwait(false);
                break;
        }
    }

    private static async Task HandleConnectAsync(
        ListenerBase listener,
        InboundStream stream,
        Socket socket,
        (string Host, ushort Port) destination,
        string? user,
        CancellationToken cancellationToken)
    {
        var metadata = listener.CreateMetadata(socket.RemoteEndPoint, destination.Host, destination.Port, Network.Tcp);
        metadata.InboundUser = user;
        await WriteReplyAsync(stream, ReplySucceeded, socket.LocalEndPoint, cancellationToken).ConfigureAwait(false);
        await listener.RequireTunnel().HandleTcpAsync(stream, metadata, cancellationToken).ConfigureAwait(false);
    }

    private static async Task HandleUdpAssociateAsync(
        ListenerBase listener,
        InboundStream stream,
        Socket socket,
        (string Host, ushort Port) declared,
        string? user,
        CancellationToken cancellationToken)
    {
        var local = socket.LocalEndPoint as IPEndPoint;
        var bindAddress = local?.Address ?? IPAddress.Loopback;
        var udpSocket = new Socket(bindAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            udpSocket.Bind(new IPEndPoint(bindAddress, 0));
        }
        catch (SocketException ex)
        {
            udpSocket.Dispose();
            await WriteReplyAsync(stream, ReplyGeneralFailure, null, cancellationToken).ConfigureAwait(false);
            throw new ListenerBindException(listener.Type, "udp associate", ex);
        }

        var association = new Socks5UdpPacketConnection(udpSocket);
        await WriteReplyAsync(stream, ReplySucceeded, udpSocket.LocalEndPoint, cancellationToken).ConfigureAwait(false);

        var host = declared.Host;
        var port = declared.Port;
        if (port == 0 || host.Length == 0 || host is "0.0.0.0" or "::")
        {
            host = local?.Address.ToString() ?? string.Empty;
            port = (ushort)(local?.Port ?? 0);
        }

        var metadata = listener.CreateMetadata(socket.RemoteEndPoint, host, port, Network.Udp);
        metadata.InboundUser = user;

        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var monitor = MonitorControlConnectionAsync(stream, lifetime);
        try
        {
            await listener.RequireTunnel().HandleUdpAsync(association, metadata, lifetime.Token).ConfigureAwait(false);
        }
        finally
        {
            try
            {
                lifetime.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The monitor already tore the association down.
            }

            await association.DisposeAsync().ConfigureAwait(false);
            _ = monitor;
        }
    }

    /// <summary>
    /// The SOCKS5 control connection stays open for the lifetime of the UDP
    /// association; when the client closes it, the association ends.
    /// </summary>
    private static async Task MonitorControlConnectionAsync(InboundStream stream, CancellationTokenSource lifetime)
    {
        var buffer = new byte[512];
        try
        {
            while (!lifetime.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer, lifetime.Token).ConfigureAwait(false);
                if (read <= 0)
                {
                    break;
                }
            }
        }
        catch
        {
            // Closed, cancelled or disposed: all of them end the association.
        }
        finally
        {
            try
            {
                lifetime.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The association is already gone.
            }
        }
    }

    private static async Task<string> AuthenticateAsync(ListenerBase listener, InboundStream stream, CancellationToken cancellationToken)
    {
        var header = await stream.ReadExactAsync(2, cancellationToken).ConfigureAwait(false);
        if (header[0] != 0x01)
        {
            throw new ClashException($"unsupported SOCKS5 authentication version 0x{header[0]:X2}");
        }

        var userNameLength = header[1];
        var user = userNameLength > 0
            ? Encoding.UTF8.GetString(await stream.ReadExactAsync(userNameLength, cancellationToken).ConfigureAwait(false))
            : string.Empty;
        var passwordLength = (await stream.ReadExactAsync(1, cancellationToken).ConfigureAwait(false))[0];
        var password = passwordLength > 0
            ? Encoding.UTF8.GetString(await stream.ReadExactAsync(passwordLength, cancellationToken).ConfigureAwait(false))
            : string.Empty;

        var credentials = $"{user}:{password}";
        var accepted = false;
        foreach (var account in listener.Config.Authentication)
        {
            if (FixedTimeEquals(account, credentials))
            {
                accepted = true;
                break;
            }
        }

        // Report the refusal before it goes on the wire, so the log line is
        // already there for anyone watching the refusal happen.
        var refusal = accepted ? null : listener.RejectAuthentication(user);

        await stream.WriteAsync(new byte[] { 0x01, accepted ? (byte)0x00 : (byte)0x01 }, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (refusal is not null)
        {
            throw refusal;
        }

        return user;
    }

    private static async Task HandleSocks4Async(ListenerBase listener, InboundStream stream, Socket socket, CancellationToken cancellationToken)
    {
        var header = await stream.ReadExactAsync(8, cancellationToken).ConfigureAwait(false);
        var command = header[1];
        var port = (ushort)((header[2] << 8) | header[3]);
        _ = await ReadNullTerminatedAsync(stream, cancellationToken).ConfigureAwait(false);

        string host;
        if (header[4] == 0 && header[5] == 0 && header[6] == 0 && header[7] != 0)
        {
            // SOCKS4a: the address is a placeholder and the name follows the user id.
            host = await ReadNullTerminatedAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            host = new IPAddress(header[4..8]).ToString();
        }

        if (command != CommandConnect || host.Length == 0 || port == 0)
        {
            await WriteSocks4ReplyAsync(stream, 0x5B, cancellationToken).ConfigureAwait(false);
            return;
        }

        var metadata = listener.CreateMetadata(socket.RemoteEndPoint, host, port, Network.Tcp);
        await WriteSocks4ReplyAsync(stream, 0x5A, cancellationToken).ConfigureAwait(false);
        await listener.RequireTunnel().HandleTcpAsync(stream, metadata, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ReadNullTerminatedAsync(InboundStream stream, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();
        while (builder.Length < MaxDomainLength)
        {
            var next = await stream.ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (next <= 0)
            {
                break;
            }

            builder.Append((char)next);
        }

        return builder.ToString();
    }

    private static async Task<(string Host, ushort Port)?> ReadDestinationAsync(
        InboundStream stream,
        byte addressType,
        CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case AddressIpv4:
            {
                var address = await stream.ReadExactAsync(4, cancellationToken).ConfigureAwait(false);
                var port = await ReadPortAsync(stream, cancellationToken).ConfigureAwait(false);
                return (new IPAddress(address).ToString(), port);
            }

            case AddressIpv6:
            {
                var address = await stream.ReadExactAsync(16, cancellationToken).ConfigureAwait(false);
                var port = await ReadPortAsync(stream, cancellationToken).ConfigureAwait(false);
                return (new IPAddress(address).ToString(), port);
            }

            case AddressDomain:
            {
                var length = (await stream.ReadExactAsync(1, cancellationToken).ConfigureAwait(false))[0];
                if (length == 0)
                {
                    return null;
                }

                var name = Encoding.UTF8.GetString(await stream.ReadExactAsync(length, cancellationToken).ConfigureAwait(false));
                var port = await ReadPortAsync(stream, cancellationToken).ConfigureAwait(false);
                return (name, port);
            }

            default:
                return null;
        }
    }

    private static async Task<ushort> ReadPortAsync(InboundStream stream, CancellationToken cancellationToken)
    {
        var raw = await stream.ReadExactAsync(2, cancellationToken).ConfigureAwait(false);
        return (ushort)((raw[0] << 8) | raw[1]);
    }

    private static Task WriteReplyAsync(InboundStream stream, byte reply, EndPoint? bound, CancellationToken cancellationToken)
        => WriteAsync(stream, BuildReply(reply, bound), cancellationToken);

    private static byte[] BuildReply(byte reply, EndPoint? bound)
    {
        var encoded = EncodeEndpoint(bound);
        var buffer = new byte[3 + encoded.Length];
        buffer[0] = Version5;
        buffer[1] = reply;
        buffer[2] = 0x00;
        encoded.CopyTo(buffer, 3);
        return buffer;
    }

    private static byte[] EncodeEndpoint(EndPoint? endpoint)
    {
        switch (endpoint)
        {
            case IPEndPoint { AddressFamily: AddressFamily.InterNetwork } ipv4:
            {
                var buffer = new byte[7];
                buffer[0] = AddressIpv4;
                ipv4.Address.GetAddressBytes().CopyTo(buffer, 1);
                buffer[5] = (byte)(ipv4.Port >> 8);
                buffer[6] = (byte)(ipv4.Port & 0xFF);
                return buffer;
            }

            case IPEndPoint { AddressFamily: AddressFamily.InterNetworkV6 } ipv6:
            {
                var buffer = new byte[19];
                buffer[0] = AddressIpv6;
                ipv6.Address.GetAddressBytes().CopyTo(buffer, 1);
                buffer[17] = (byte)(ipv6.Port >> 8);
                buffer[18] = (byte)(ipv6.Port & 0xFF);
                return buffer;
            }

            default:
                return [AddressIpv4, 0, 0, 0, 0, 0, 0];
        }
    }

    private static async Task WriteSocks4ReplyAsync(InboundStream stream, byte status, CancellationToken cancellationToken)
    {
        await WriteAsync(stream, [0x00, status, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteAsync(InboundStream stream, byte[] payload, CancellationToken cancellationToken)
    {
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static bool FixedTimeEquals(string expected, string actual)
        => System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(actual));
}

/// <summary>
/// A SOCKS5 <c>UDP ASSOCIATE</c> association: strips the
/// <c>RSV(2) FRAG(1) ATYP(1) ADDR PORT</c> request framing, tracks which client
/// source endpoint asked for which remote, and re-frames replies.
/// </summary>
internal sealed class Socks5UdpPacketConnection : NatPacketConnection
{
    private const int MaxDatagramSize = 65535 + 262;

    private readonly byte[] _scratch = new byte[MaxDatagramSize];

    /// <summary>Takes ownership of the bound association socket.</summary>
    public Socks5UdpPacketConnection(Socket socket)
        : base(socket)
    {
    }

    /// <summary>Datagrams dropped because they carried a non-zero FRAG field.</summary>
    public int FragmentedDatagramsDropped { get; private set; }

    /// <inheritdoc />
    public override async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            var received = await Socket.ReceiveFromAsync(_scratch, SocketFlags.None, AnyEndPoint(), cancellationToken).ConfigureAwait(false);
            var client = received.RemoteEndPoint;
            RegisterSource(client);

            var datagram = _scratch.AsSpan(0, received.ReceivedBytes);
            if (datagram.Length < 4 || datagram[0] != 0 || datagram[1] != 0)
            {
                continue;
            }

            if (datagram[2] != 0)
            {
                // FRAG is not supported: the datagram cannot be reassembled, so drop it.
                FragmentedDatagramsDropped++;
                continue;
            }

            var addressType = datagram[3];
            var offset = 4;
            if (!TryParseAddress(datagram, ref offset, addressType, out var destination))
            {
                continue;
            }

            var payloadLength = Math.Min(datagram.Length - offset, buffer.Length);
            datagram.Slice(offset, payloadLength).CopyTo(buffer.Span);
            Associate(destination, client);
            return new PacketResult(payloadLength, destination);
        }
    }

    /// <inheritdoc />
    public override ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
    {
        var client = ClientFor(destination);
        if (client is null)
        {
            return ValueTask.FromResult(0);
        }

        var addressLength = AddressLength(destination);
        if (addressLength == 0)
        {
            return ValueTask.FromResult(0);
        }

        // RSV(2) + FRAG(1) + ATYP/ADDR/PORT + payload.
        var frame = new byte[3 + addressLength + payload.Length];
        frame[0] = 0x00;
        frame[1] = 0x00;
        frame[2] = 0x00;
        EncodeAddress(destination, frame.AsSpan(3));
        payload.Span.CopyTo(frame.AsSpan(3 + addressLength));
        return Socket.SendToAsync(frame, SocketFlags.None, client, cancellationToken);
    }

    private static int AddressLength(EndPoint endpoint) => endpoint switch
    {
        IPEndPoint { AddressFamily: AddressFamily.InterNetwork } => 7,
        IPEndPoint { AddressFamily: AddressFamily.InterNetworkV6 } => 19,
        DomainEndPoint domain => 4 + Math.Min(domain.Host.Length, 255),
        _ => 0,
    };

    private static bool TryParseAddress(ReadOnlySpan<byte> datagram, ref int offset, byte addressType, out EndPoint destination)
    {
        destination = null!;
        switch (addressType)
        {
            case 0x01:
            {
                if (datagram.Length < offset + 6)
                {
                    return false;
                }

                var address = new IPAddress(datagram.Slice(offset, 4));
                offset += 4;
                var port = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
                offset += 2;
                destination = new IPEndPoint(address, port);
                return true;
            }

            case 0x04:
            {
                if (datagram.Length < offset + 18)
                {
                    return false;
                }

                var address = new IPAddress(datagram.Slice(offset, 16));
                offset += 16;
                var port = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
                offset += 2;
                destination = new IPEndPoint(address, port);
                return true;
            }

            case 0x03:
            {
                if (datagram.Length < offset + 1)
                {
                    return false;
                }

                var length = datagram[offset];
                offset++;
                if (length == 0 || datagram.Length < offset + length + 2)
                {
                    return false;
                }

                var host = Encoding.ASCII.GetString(datagram.Slice(offset, length));
                offset += length;
                var port = (ushort)((datagram[offset] << 8) | datagram[offset + 1]);
                offset += 2;
                destination = IPAddress.TryParse(host, out var literal)
                    ? new IPEndPoint(literal, port)
                    : new DomainEndPoint(host, port);
                return true;
            }

            default:
                return false;
        }
    }

    private static void EncodeAddress(EndPoint endpoint, Span<byte> destination)
    {
        switch (endpoint)
        {
            case IPEndPoint { AddressFamily: AddressFamily.InterNetwork } ipv4:
                destination[0] = 0x01;
                ipv4.Address.GetAddressBytes().CopyTo(destination[1..]);
                destination[5] = (byte)(ipv4.Port >> 8);
                destination[6] = (byte)(ipv4.Port & 0xFF);
                break;

            case IPEndPoint { AddressFamily: AddressFamily.InterNetworkV6 } ipv6:
                destination[0] = 0x04;
                ipv6.Address.GetAddressBytes().CopyTo(destination[1..]);
                destination[17] = (byte)(ipv6.Port >> 8);
                destination[18] = (byte)(ipv6.Port & 0xFF);
                break;

            case DomainEndPoint domain:
            {
                var name = Encoding.ASCII.GetBytes(domain.Host);
                var length = Math.Min(name.Length, 255);
                destination[0] = 0x03;
                destination[1] = (byte)length;
                name.AsSpan(0, length).CopyTo(destination[2..]);
                destination[2 + length] = (byte)(domain.Port >> 8);
                destination[3 + length] = (byte)(domain.Port & 0xFF);
                break;
            }
        }
    }
}
