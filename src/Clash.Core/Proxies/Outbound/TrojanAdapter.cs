using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// A Trojan UDP association: every datagram is
/// <c>address || length(2, BE) || CRLF || payload</c> written to the same TLS
/// stream, with the matching packets read back in order.
/// </summary>
internal sealed class TrojanPacketConnection : IPacketConnection
{
    private readonly ProxyStream _stream;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly byte[] _inbound = new byte[65536];
    private int _inboundOffset;
    private int _inboundLength;
    private EndPoint? _lastDestination;
    private bool _disposed;

    internal TrojanPacketConnection(ProxyStream stream) => _stream = stream ?? throw new ArgumentNullException(nameof(stream));

    /// <inheritdoc />
    public bool SupportsMultipleDestinations => true;

    /// <inheritdoc />
    public EndPoint? LocalEndPoint => _stream.LocalEndPoint;

    /// <inheritdoc />
    public async ValueTask<int> SendAsync(
        ReadOnlyMemory<byte> payload,
        EndPoint destination,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination is not IPEndPoint endpoint)
        {
            throw new NotSupportedException($"trojan: unsupported UDP destination {destination}");
        }

        var buffer = new byte[Socks5Address.Size(endpoint.Address) + 4 + payload.Length];
        var written = TrojanCrypto.WriteUdpPacket(buffer, endpoint.Address.ToString(), endpoint.Port, payload.Span);

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(buffer.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            _lastDestination = destination;
            return payload.Length;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (TryTakePacket(out var host, out var port, out var payload))
            {
                var copied = OutboundIo.CopyInto(payload, buffer);
                return new PacketResult(copied, ResolveRemote(host, port));
            }

            if (!await FillAsync(cancellationToken).ConfigureAwait(false))
            {
                throw new ClashException("trojan: the UDP association was closed by the server");
            }
        }
    }

    /// <summary>Extracts one complete packet from the inbound buffer, if there is one.</summary>
    private bool TryTakePacket(out string host, out int port, out byte[] payload)
    {
        host = string.Empty;
        port = 0;
        payload = [];

        var buffered = _inbound.AsSpan(_inboundOffset, _inboundLength);
        if (buffered.IsEmpty) return false;

        if (!TrojanCrypto.TryReadUdpPacket(buffered, out var consumed, out host, out port, out payload)) return false;

        _inboundOffset += consumed;
        _inboundLength -= consumed;
        if (_inboundLength == 0) _inboundOffset = 0;
        return true;
    }

    private async ValueTask<bool> FillAsync(CancellationToken cancellationToken)
    {
        if (_inboundOffset > 0 && _inboundLength > 0)
        {
            Array.Copy(_inbound, _inboundOffset, _inbound, 0, _inboundLength);
            _inboundOffset = 0;
        }

        if (_inboundLength == _inbound.Length) throw new ClashException("trojan: UDP packet larger than the receive buffer");

        var read = await _stream
            .ReadAsync(_inbound.AsMemory(_inboundLength), cancellationToken)
            .ConfigureAwait(false);
        if (read <= 0) return false;

        _inboundLength += read;
        return true;
    }

    private EndPoint ResolveRemote(string host, int port)
    {
        if (!string.IsNullOrEmpty(host) && IPAddress.TryParse(host, out var address))
        {
            return new IPEndPoint(address, port);
        }

        return _lastDestination ?? new IPEndPoint(IPAddress.Any, 0);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _sendLock.Dispose();
        await _stream.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary>
/// The <c>trojan</c> adapter. Trojan always runs over TLS — the transport stack
/// provides the TLS layer and this adapter writes the password-hash request header
/// on top of it.
/// </summary>
public sealed class TrojanAdapter : OutboundAdapter
{
    private readonly string _passwordHashHex;
    private readonly YamlMap _transportOptions;

    internal TrojanAdapter(ProxyConfigEntry entry, AdapterBuildContext context, string passwordHashHex, bool udp)
        : base(entry, context, ProxyType.Trojan, udp)
    {
        _passwordHashHex = passwordHashHex;
        _transportOptions = entry.Map.With("tls", true);
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static TrojanAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var password = entry.Map.GetString("password");
        if (string.IsNullOrEmpty(password))
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (trojan) requires a non-empty 'password'");
        }

        return new TrojanAdapter(entry, context, TrojanCrypto.ComputePasswordHashHex(password), entry.Map.GetBool("udp"));
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
            var host = OutboundOptions.Destination(metadata);
            var header = new byte[TrojanCrypto.PasswordHashLength + 2 + 1 + Socks5Address.Size(host) + 2];
            var written = TrojanCrypto.WriteRequestHeader(
                header,
                _passwordHashHex,
                TrojanCrypto.CommandConnect,
                host,
                metadata.DestinationPort);

            await raw.WriteAsync(header.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            await raw.FlushAsync(cancellationToken).ConfigureAwait(false);

            // Trojan has no framing of its own and — unlike the Shadowsocks
            // family — the server sends no response header: Xray, v2ray and
            // mihomo all copy the target's bytes straight back. Reading a
            // "response header" here consumes the first bytes of the real
            // response and breaks every connection (verified against Xray).
            return Complete(raw);
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

        var raw = await OpenAsync(metadata, null, cancellationToken).ConfigureAwait(false);
        try
        {
            // A UDP association names no destination: the address block is all zeros.
            var header = new byte[TrojanCrypto.PasswordHashLength + 2 + 1 + 1 + 4 + 2 + 2];
            var written = TrojanCrypto.WriteRequestHeader(
                header,
                _passwordHashHex,
                TrojanCrypto.CommandUdpAssociate,
                "0.0.0.0",
                0);

            await raw.WriteAsync(header.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
            await raw.FlushAsync(cancellationToken).ConfigureAwait(false);

            var connection = new TrojanPacketConnection(raw);
            TrackConnection(new AsyncDisposeBridge(connection));
            return connection;
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }
}

/// <summary>Builds <see cref="TrojanAdapter"/> instances.</summary>
internal sealed class TrojanAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "trojan";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => TrojanAdapter.Create(entry, context);
}
