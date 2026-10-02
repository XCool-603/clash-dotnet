using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Crypto;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// A Shadowsocks UDP association over one connected socket to the server.
/// <para>
/// One datagram per packet in every family:
/// </para>
/// <code>
/// AEAD   : salt || AEAD(subkey, nonce = 0, address || payload)
/// stream : iv   || keystream(address || payload)
/// 2022   : session id(8) || packet id(8) || AEAD(session subkey, body || address || payload)
/// </code>
/// <para>
/// The AEAD nonce is the all-zero 12-byte nonce SIP004 mandates for UDP; the 2022
/// session framing comes from <see cref="Shadowsocks2022UdpSession"/>.
/// </para>
/// </summary>
internal sealed class ShadowsocksPacketConnection : IPacketConnection
{
    private const int MaxDatagram = 65535;

    private readonly Socket _socket;
    private readonly ShadowsocksMethod _method;
    private readonly EndPoint _template;
    private readonly Shadowsocks2022UdpSession? _encodeSession;
    private readonly Dictionary<ulong, Shadowsocks2022UdpSession> _decodeSessions = [];
    private EndPoint? _lastDestination;

    internal ShadowsocksPacketConnection(Socket socket, ShadowsocksMethod method)
    {
        _socket = socket ?? throw new ArgumentNullException(nameof(socket));
        _method = method ?? throw new ArgumentNullException(nameof(method));
        _template = SocketDialer.AnyEndpoint(socket.AddressFamily);

        if (!method.Is2022) return;

        Span<byte> sessionId = stackalloc byte[Shadowsocks2022.SessionIdSize];
        RandomNumberGenerator.Fill(sessionId);
        _encodeSession = new Shadowsocks2022UdpSession(method.Aead!, method.Key, BinaryPrimitives.ReadUInt64LittleEndian(sessionId));
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

        var address = EncodeAddress(destination);
        var packet = _method.Kind switch
        {
            ShadowsocksKind.Aead => EncodeAead(address, payload.Span),
            ShadowsocksKind.Aead2022 => _encodeSession!.Encode(Shadowsocks2022PacketType.ClientPacket, address, payload.Span),
            _ => EncodeStream(address, payload.Span),
        };

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
            var received = await _socket
                .ReceiveFromAsync(rented, SocketFlags.None, _template, cancellationToken)
                .ConfigureAwait(false);

            var packet = rented.AsSpan(0, received.ReceivedBytes);
            if (!TryDecode(packet, out var host, out var port, out var payload))
            {
                return new PacketResult(0, received.RemoteEndPoint);
            }

            var copied = OutboundIo.CopyInto(payload, buffer);
            return new PacketResult(copied, ResolveRemote(host, port, received.RemoteEndPoint));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    /// <summary>Decodes one datagram into the destination it came from and its payload.</summary>
    private bool TryDecode(ReadOnlySpan<byte> packet, out string host, out int port, out byte[] payload)
    {
        host = string.Empty;
        port = 0;
        payload = [];

        switch (_method.Kind)
        {
            case ShadowsocksKind.Aead:
            {
                var cipher = _method.Aead!;
                if (packet.Length < cipher.SaltSize + cipher.TagSize) return false;

                var salt = packet[..cipher.SaltSize];
                var subkey = cipher.DeriveSubkey(_method.Key, salt);
                var sealedBody = packet[cipher.SaltSize..];
                var plaintext = new byte[sealedBody.Length - cipher.TagSize];

                Span<byte> nonce = stackalloc byte[ShadowsocksAeadFraming.NonceSize];
                if (!cipher.Decrypt(subkey, nonce, sealedBody, plaintext)) return false;
                return SplitAddress(plaintext, out host, out port, out payload);
            }

            case ShadowsocksKind.Aead2022:
            {
                if (!Shadowsocks2022.TryReadUdpHeader(packet, out var sessionId, out _)) return false;
                if (!_decodeSessions.TryGetValue(sessionId, out var session))
                {
                    session = new Shadowsocks2022UdpSession(_method.Aead!, _method.Key, sessionId);
                    _decodeSessions[sessionId] = session;
                }

                if (!session.TryDecode(packet, out var type, out _, out var address, out var body)) return false;
                if (type is not (Shadowsocks2022PacketType.ServerPacket or Shadowsocks2022PacketType.ServerStream))
                {
                    return false;
                }

                // The server's reply may or may not carry the echoed address.
                if (address.Length == 0)
                {
                    payload = body;
                    return true;
                }

                if (!Socks5Address.TryParse(address, out _, out host, out port)) return false;
                payload = body;
                return true;
            }

            default:
            {
                if (packet.Length < _method.IvSize) return false;

                var iv = packet[.._method.IvSize];
                var cipher = StreamCipherFactory.CreateDecryptor(_method.Name, _method.Key, iv);
                var plaintext = packet[_method.IvSize..].ToArray();
                cipher.Process(plaintext, plaintext);
                return SplitAddress(plaintext, out host, out port, out payload);
            }
        }
    }

    private static bool SplitAddress(ReadOnlySpan<byte> source, out string host, out int port, out byte[] payload)
    {
        host = string.Empty;
        port = 0;
        payload = [];

        if (!Socks5Address.TryParse(source, out var length, out host, out port)) return false;
        payload = source[length..].ToArray();
        return true;
    }

    private byte[] EncodeAead(ReadOnlySpan<byte> address, ReadOnlySpan<byte> payload)
    {
        var cipher = _method.Aead!;
        var salt = RandomNumberGenerator.GetBytes(cipher.SaltSize);
        var subkey = cipher.DeriveSubkey(_method.Key, salt);

        var plaintext = new byte[address.Length + payload.Length];
        address.CopyTo(plaintext);
        payload.CopyTo(plaintext.AsSpan(address.Length));

        var packet = new byte[salt.Length + plaintext.Length + cipher.TagSize];
        salt.CopyTo(packet, 0);

        Span<byte> nonce = stackalloc byte[ShadowsocksAeadFraming.NonceSize];
        cipher.Encrypt(subkey, nonce, plaintext, packet.AsSpan(salt.Length));
        return packet;
    }

    private byte[] EncodeStream(ReadOnlySpan<byte> address, ReadOnlySpan<byte> payload)
    {
        var iv = RandomNumberGenerator.GetBytes(_method.IvSize);
        var cipher = StreamCipherFactory.CreateEncryptor(_method.Name, _method.Key, iv);

        var plaintext = new byte[address.Length + payload.Length];
        address.CopyTo(plaintext);
        payload.CopyTo(plaintext.AsSpan(address.Length));
        cipher.Process(plaintext, plaintext);

        var packet = new byte[iv.Length + plaintext.Length];
        iv.CopyTo(packet, 0);
        plaintext.CopyTo(packet, iv.Length);
        return packet;
    }

    private static byte[] EncodeAddress(EndPoint destination)
    {
        if (destination is not IPEndPoint endpoint)
        {
            throw new NotSupportedException($"shadowsocks: unsupported UDP destination {destination}");
        }

        var buffer = new byte[Socks5Address.Size(endpoint.Address)];
        var written = Socks5Address.Write(buffer, endpoint.Address, endpoint.Port);
        return written == buffer.Length ? buffer : buffer[..written];
    }

    /// <summary>
    /// The endpoint a response came from. Shadowsocks echoes the address the client
    /// sent, but a server may answer with a name; in that case the most recent
    /// destination is the only sensible mapping.
    /// </summary>
    private EndPoint ResolveRemote(string host, int port, EndPoint fallback)
    {
        if (!string.IsNullOrEmpty(host) && IPAddress.TryParse(host, out var address))
        {
            return new IPEndPoint(address, port);
        }

        return _lastDestination ?? fallback;
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        try { _socket.Dispose(); } catch { /* already gone */ }
        return ValueTask.CompletedTask;
    }
}
