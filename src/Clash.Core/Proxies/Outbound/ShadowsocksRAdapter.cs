using System.Buffers.Binary;
using System.Security.Cryptography;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The <c>http_simple</c> ShadowsocksR obfuscation. The header itself is produced
/// by the frozen <see cref="ShadowsocksObfs"/> helpers, which implement exactly
/// the request shape simple-obfs and ShadowsocksR share.
/// </summary>
internal sealed class SsrHttpSimpleObfs : ISsrObfsPlugin
{
    /// <summary>The shared instance; the plugin is stateless.</summary>
    internal static readonly SsrHttpSimpleObfs Instance = new();

    private SsrHttpSimpleObfs()
    {
    }

    /// <inheritdoc />
    public string Name => ShadowsocksR.ObfsHttpSimple;

    /// <summary>
    /// The request header is wire-shaped like the reference one, but the
    /// user-agent pool and the exact random-length policy are the frozen helper's
    /// rather than a byte-for-byte copy of the reference plugin.
    /// </summary>
    public SsrSupportLevel Support => SsrSupportLevel.Partial;

    /// <inheritdoc />
    public int BuildClientHeader(Span<byte> destination, string host, int port, ReadOnlySpan<byte> firstPayload)
        => ShadowsocksObfs.BuildHttpSimpleRequest(destination, host, port, firstPayload);

    /// <inheritdoc />
    public int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> firstPayload)
        => ShadowsocksObfs.BuildHttpSimpleResponse(destination, firstPayload);

    /// <inheritdoc />
    public bool TryMeasureClientHeader(ReadOnlySpan<byte> source, out int consumed)
        => ShadowsocksObfs.TryParseHttpSimpleRequest(source, out consumed, out _, out _);

    /// <inheritdoc />
    public bool TryMeasureServerHeader(ReadOnlySpan<byte> source, out int consumed)
    {
        var index = source.IndexOf("\r\n\r\n"u8);
        consumed = index < 0 ? 0 : index + 4;
        return index >= 0;
    }

    /// <inheritdoc />
    public void TransformClientToServer(Span<byte> buffer)
    {
    }

    /// <inheritdoc />
    public void TransformServerToClient(Span<byte> buffer)
    {
    }
}

/// <summary>The <c>tls1.2_ticket_auth</c> ShadowsocksR obfuscation.</summary>
internal sealed class SsrTls12TicketAuthObfs : ISsrObfsPlugin
{
    /// <summary>The shared instance; the plugin is stateless.</summary>
    internal static readonly SsrTls12TicketAuthObfs Instance = new();

    private SsrTls12TicketAuthObfs()
    {
    }

    /// <inheritdoc />
    public string Name => ShadowsocksR.ObfsTls12TicketAuth;

    /// <summary>
    /// A structurally valid ClientHello is emitted, but the reference plugin's
    /// HMAC in the session id is not reproduced (see <see cref="ShadowsocksObfs"/>).
    /// </summary>
    public SsrSupportLevel Support => SsrSupportLevel.Partial;

    /// <inheritdoc />
    public int BuildClientHeader(Span<byte> destination, string host, int port, ReadOnlySpan<byte> firstPayload)
        => ShadowsocksObfs.BuildTls12TicketAuthClientHello(destination, host, firstPayload);

    /// <inheritdoc />
    public int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> firstPayload)
        => ShadowsocksObfs.BuildTls12TicketAuthServerHello(destination, firstPayload);

    /// <inheritdoc />
    public bool TryMeasureClientHeader(ReadOnlySpan<byte> source, out int consumed)
        => ShadowsocksObfs.TryMeasureTlsRecord(source, out consumed);

    /// <inheritdoc />
    public bool TryMeasureServerHeader(ReadOnlySpan<byte> source, out int consumed)
    {
        consumed = 0;

        // ServerHello record, then the ChangeCipherSpec record the fake handshake
        // appends. Anything after both is payload.
        if (!ShadowsocksObfs.TryMeasureTlsRecord(source, out var first)) return false;

        var afterFirst = first;
        if (source.Length < afterFirst + 6) return false;
        if (source[afterFirst] != 0x14) return false;

        var length = BinaryPrimitives.ReadUInt16BigEndian(source[(afterFirst + 3)..]);
        consumed = afterFirst + 5 + length;
        return source.Length >= consumed;
    }

    /// <inheritdoc />
    public void TransformClientToServer(Span<byte> buffer)
    {
    }

    /// <inheritdoc />
    public void TransformServerToClient(Span<byte> buffer)
    {
    }
}

/// <summary>
/// The ShadowsocksR TCP stream: <c>[iv]</c> followed by the stream cipher applied
/// to <c>obfs_header(protocol_header || rc4(address || payload))</c>.
/// <para>
/// <b>Layer order.</b> The obfuscation is the outermost layer, so the very first
/// bytes on the wire are the fake HTTP request line (or the fake ClientHello) —
/// which is the whole point of the disguise. The protocol header sits inside it,
/// and the SOCKS5 address sits inside that. The server peels them off in the
/// reverse order.
/// </para>
/// <para>
/// <b>Data transform.</b> The <c>auth_aes128_*</c> protocols RC4 the
/// client-to-server payload with the user key, discarding the client header's
/// random prefix from the keystream; that transform is applied here through
/// <see cref="SsrAuthAes128.CreateDataCipher"/>. The server-to-client direction is
/// not transformed, matching the reference.
/// </para>
/// </summary>
internal sealed class SsrTcpStream : Stream
{
    private readonly Stream _inner;
    private readonly ShadowsocksMethod _method;
    private readonly ISsrProtocolPlugin _protocol;
    private readonly ISsrObfsPlugin _obfs;
    private readonly byte[] _address;
    private readonly string _host;
    private readonly int _port;

    private IStreamCipher? _encryptor;
    private IStreamCipher? _decryptor;
    private bool _firstWrite = true;
    private bool _headersStripped;

    private byte[] _pending = [];
    private int _pendingOffset;
    private int _pendingLength;

    internal SsrTcpStream(
        Stream inner,
        ShadowsocksMethod method,
        ISsrProtocolPlugin protocol,
        ISsrObfsPlugin obfs,
        byte[] address,
        string host,
        int port)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _method = method ?? throw new ArgumentNullException(nameof(method));
        _protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
        _obfs = obfs ?? throw new ArgumentNullException(nameof(obfs));
        _address = address ?? throw new ArgumentNullException(nameof(address));
        _host = host;
        _port = port;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush() => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        if (buffer.IsEmpty) return;
        EnsureEncryptor();

        if (_firstWrite)
        {
            _firstWrite = false;
            var wire = BuildFirstPayload(buffer);
            EncryptAndWrite(wire);
            return;
        }

        EncryptAndWrite(buffer);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;
        await EnsureEncryptorAsync(cancellationToken).ConfigureAwait(false);

        if (_firstWrite)
        {
            _firstWrite = false;
            var wire = BuildFirstPayload(buffer.Span);
            await EncryptAndWriteAsync(wire, cancellationToken).ConfigureAwait(false);
            return;
        }

        await EncryptAndWriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Builds the first plaintext block: obfuscation, protocol header, address and payload.</summary>
    private byte[] BuildFirstPayload(ReadOnlySpan<byte> payload)
    {
        // 1. The protocol header, generated by the frozen ShadowsocksR layer.
        var protocolStaging = new byte[256];
        var protocolLength = _protocol.BuildClientHeader(protocolStaging, _method.Key);
        var randomLength = protocolLength > 0 ? protocolStaging[0] : 0;

        // 2. address || payload, RC4-transformed for the auth protocols.
        var data = new byte[_address.Length + payload.Length];
        _address.CopyTo(data, 0);
        payload.CopyTo(data.AsSpan(_address.Length));
        if (_protocol is SsrAuthAes128Protocol)
        {
            var rc4 = SsrAuthAes128.CreateDataCipher(_method.Key, randomLength);
            rc4.Process(data, data);
        }

        // 3. protocol header || transformed data.
        var inner = new byte[protocolLength + data.Length];
        protocolStaging.AsSpan(0, protocolLength).CopyTo(inner);
        data.CopyTo(inner, protocolLength);

        // 4. The obfuscation is the outermost layer, so it sees the whole block.
        var staging = new byte[4096 + inner.Length];
        var obfsLength = _obfs.BuildClientHeader(staging, _host, _port, inner);
        if (obfsLength == 0)
        {
            inner.CopyTo(staging, 0);
            obfsLength = inner.Length;
        }

        return obfsLength == staging.Length ? staging : staging[..obfsLength];
    }

    private void EnsureEncryptor()
    {
        if (_encryptor is not null) return;
        var iv = RandomNumberGenerator.GetBytes(_method.IvSize);
        if (iv.Length > 0) _inner.Write(iv, 0, iv.Length);
        _encryptor = StreamCipherFactory.CreateEncryptor(_method.Name, _method.Key, iv);
    }

    private async ValueTask EnsureEncryptorAsync(CancellationToken cancellationToken)
    {
        if (_encryptor is not null) return;
        var iv = RandomNumberGenerator.GetBytes(_method.IvSize);
        if (iv.Length > 0) await _inner.WriteAsync(iv, cancellationToken).ConfigureAwait(false);
        _encryptor = StreamCipherFactory.CreateEncryptor(_method.Name, _method.Key, iv);
    }

    private void EncryptAndWrite(ReadOnlySpan<byte> plaintext)
    {
        using var pooled = new PooledBuffer(plaintext.Length);
        plaintext.CopyTo(pooled.Span);
        _encryptor!.Process(pooled.Span[..plaintext.Length], pooled.Span[..plaintext.Length]);
        _inner.Write(pooled.Array, 0, plaintext.Length);
    }

    private async ValueTask EncryptAndWriteAsync(ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken)
    {
        using var pooled = new PooledBuffer(plaintext.Length);
        plaintext.Span.CopyTo(pooled.Span);
        _encryptor!.Process(pooled.Span[..plaintext.Length], pooled.Span[..plaintext.Length]);
        await _inner.WriteAsync(pooled.Memory(plaintext.Length), cancellationToken).ConfigureAwait(false);
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;
        EnsureDecryptor();
        if (!EnsureHeadersStripped()) return 0;
        if (_pendingLength == 0 && !Fill(1)) return 0;

        var take = Math.Min(buffer.Length, _pendingLength);
        _pending.AsSpan(_pendingOffset, take).CopyTo(buffer);
        _pendingOffset += take;
        _pendingLength -= take;
        return take;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;
        await EnsureDecryptorAsync(cancellationToken).ConfigureAwait(false);
        if (!await EnsureHeadersStrippedAsync(cancellationToken).ConfigureAwait(false)) return 0;
        if (_pendingLength == 0 && !await FillAsync(1, cancellationToken).ConfigureAwait(false)) return 0;

        var take = Math.Min(buffer.Length, _pendingLength);
        _pending.AsSpan(_pendingOffset, take).CopyTo(buffer.Span);
        _pendingOffset += take;
        _pendingLength -= take;
        return take;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    private void EnsureDecryptor()
    {
        if (_decryptor is not null) return;
        var iv = new byte[_method.IvSize];
        if (iv.Length > 0) OutboundIo.ReadExactly(_inner, iv);
        _decryptor = StreamCipherFactory.CreateDecryptor(_method.Name, _method.Key, iv);
    }

    private async ValueTask EnsureDecryptorAsync(CancellationToken cancellationToken)
    {
        if (_decryptor is not null) return;
        var iv = new byte[_method.IvSize];
        if (iv.Length > 0) await OutboundIo.ReadExactlyAsync(_inner, iv, cancellationToken).ConfigureAwait(false);
        _decryptor = StreamCipherFactory.CreateDecryptor(_method.Name, _method.Key, iv);
    }

    /// <summary>Strips the server's obfuscation header and then its protocol header.</summary>
    private bool EnsureHeadersStripped()
    {
        if (_headersStripped) return true;

        var offset = 0;
        var obfsLength = 0;
        while (!_obfs.TryMeasureServerHeader(_pending.AsSpan(_pendingOffset, _pendingLength), out obfsLength))
        {
            if (_pendingLength >= OutboundIo.MaxHeaderBytes) throw new ClashException("ssr: the obfuscation header never completed");
            if (!Fill(_pendingLength + 1)) return false;
        }

        offset += obfsLength;

        var protocolLength = 0;
        while (!_protocol.TryReadServerHeader(_pending.AsSpan(_pendingOffset + offset, _pendingLength - offset), _method.Key, out protocolLength))
        {
            if (_pendingLength - offset >= 256) throw new ClashException("ssr: the protocol header never completed");
            if (!Fill(_pendingLength + 1)) return false;
        }

        offset += protocolLength;
        _pendingOffset += offset;
        _pendingLength -= offset;
        _headersStripped = true;
        return true;
    }

    /// <inheritdoc cref="EnsureHeadersStripped"/>
    private async ValueTask<bool> EnsureHeadersStrippedAsync(CancellationToken cancellationToken)
    {
        if (_headersStripped) return true;

        var offset = 0;
        var obfsLength = 0;
        while (!_obfs.TryMeasureServerHeader(_pending.AsSpan(_pendingOffset, _pendingLength), out obfsLength))
        {
            if (_pendingLength >= OutboundIo.MaxHeaderBytes) throw new ClashException("ssr: the obfuscation header never completed");
            if (!await FillAsync(_pendingLength + 1, cancellationToken).ConfigureAwait(false)) return false;
        }

        offset += obfsLength;

        var protocolLength = 0;
        while (!_protocol.TryReadServerHeader(_pending.AsSpan(_pendingOffset + offset, _pendingLength - offset), _method.Key, out protocolLength))
        {
            if (_pendingLength - offset >= 256) throw new ClashException("ssr: the protocol header never completed");
            if (!await FillAsync(_pendingLength + 1, cancellationToken).ConfigureAwait(false)) return false;
        }

        offset += protocolLength;
        _pendingOffset += offset;
        _pendingLength -= offset;
        _headersStripped = true;
        return true;
    }

    private bool Fill(int minimum)
    {
        while (_pendingLength < minimum)
        {
            Compact();
            if (_pending.Length - _pendingLength < 4096) Array.Resize(ref _pending, Math.Max(_pending.Length * 2, _pendingLength + 4096));

            var read = _inner.Read(_pending.AsSpan(_pendingLength));
            if (read <= 0) return false;

            _decryptor!.Process(_pending.AsSpan(_pendingLength, read), _pending.AsSpan(_pendingLength, read));
            _pendingLength += read;
        }

        return true;
    }

    private async ValueTask<bool> FillAsync(int minimum, CancellationToken cancellationToken)
    {
        while (_pendingLength < minimum)
        {
            Compact();
            if (_pending.Length - _pendingLength < 4096) Array.Resize(ref _pending, Math.Max(_pending.Length * 2, _pendingLength + 4096));

            var read = await _inner.ReadAsync(_pending.AsMemory(_pendingLength), cancellationToken).ConfigureAwait(false);
            if (read <= 0) return false;

            _decryptor!.Process(_pending.AsSpan(_pendingLength, read), _pending.AsSpan(_pendingLength, read));
            _pendingLength += read;
        }

        return true;
    }

    private void Compact()
    {
        if (_pendingOffset == 0) return;
        if (_pendingLength > 0) Array.Copy(_pending, _pendingOffset, _pending, 0, _pendingLength);
        _pendingOffset = 0;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _inner.Dispose(); } catch { /* already gone */ }
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* already gone */ }
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// The <c>ssr</c> adapter: ShadowsocksR over the legacy stream ciphers, with the
/// <c>origin</c>/<c>plain</c>, <c>http_simple</c> and <c>tls1.2_ticket_auth</c>
/// layers and the <c>auth_aes128_md5</c>/<c>auth_aes128_sha1</c> protocol headers.
/// </summary>
public sealed class ShadowsocksRAdapter : OutboundAdapter
{
    private readonly ShadowsocksMethod _method;
    private readonly ISsrProtocolPlugin _protocol;
    private readonly ISsrObfsPlugin _obfs;
    private readonly string? _obfsParam;

    internal ShadowsocksRAdapter(
        ProxyConfigEntry entry,
        AdapterBuildContext context,
        ShadowsocksMethod method,
        ISsrProtocolPlugin protocol,
        ISsrObfsPlugin obfs,
        string? obfsParam,
        bool udp)
        : base(entry, context, ProxyType.ShadowsocksR, udp)
    {
        _method = method;
        _protocol = protocol;
        _obfs = obfs;
        _obfsParam = obfsParam;
    }

    /// <summary>The resolved cipher/framing family.</summary>
    internal ShadowsocksMethod Method => _method;

    /// <summary>The resolved protocol plugin.</summary>
    internal ISsrProtocolPlugin Protocol => _protocol;

    /// <summary>The resolved obfuscation plugin.</summary>
    internal ISsrObfsPlugin Obfs => _obfs;

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static ShadowsocksRAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var map = entry.Map;
        var cipher = map.GetNonEmptyString("cipher");
        if (cipher is null)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (ssr) requires a 'cipher' (for example 'aes-256-cfb' or 'chacha20-ietf')");
        }

        var password = map.GetString("password");
        if (string.IsNullOrEmpty(password))
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (ssr) requires a non-empty 'password'");
        }

        if (!StreamCiphers.TryGet(cipher, out var stream))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (ssr): unsupported cipher '{cipher}'. ShadowsocksR in this build supports the legacy "
                + $"stream ciphers: {string.Join(", ", StreamCiphers.Names.Order(StringComparer.Ordinal))}. "
                + "The AEAD and 2022 methods belong to the 'ss' adapter.");
        }

        var method = new ShadowsocksMethod(
            stream.Name,
            ShadowsocksKind.Stream,
            null,
            ShadowsocksKey.DeriveMasterKey(password, stream.KeySize),
            stream.IvSize);

        var protocolName = map.GetNonEmptyString("protocol") ?? ShadowsocksR.ProtocolOrigin;
        var obfsName = map.GetNonEmptyString("obfs") ?? ShadowsocksR.ObfsPlain;
        var protocol = CreateProtocol(protocolName, entry.Name);
        var obfs = CreateObfs(obfsName, entry.Name);

        var udp = map.GetBool("udp");
        if (udp && (protocol is not SsrPassThroughProtocol || obfs is not SsrPassThroughObfs))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (ssr): UDP is only implemented for 'protocol: origin' with 'obfs: plain'. "
                + $"This node asks for udp with protocol '{protocolName}' and obfs '{obfsName}'; "
                + "set 'udp: false' or use the plain plugins.");
        }

        return new ShadowsocksRAdapter(entry, context, method, protocol, obfs, map.GetNonEmptyString("obfs-param") ?? map.GetNonEmptyString("obfs_param"), udp);
    }

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
            var address = new byte[Socks5Address.Size(host)];
            OutboundOptions.WriteDestination(address, metadata);

            var framed = new SsrTcpStream(
                raw,
                _method,
                _protocol,
                _obfs,
                address,
                string.IsNullOrEmpty(_obfsParam) ? host : _obfsParam!,
                metadata.DestinationPort);

            return Complete(Wrap(framed, raw));
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <summary>
    /// The datagram path. With <c>protocol: origin</c> and <c>obfs: plain</c> — the
    /// only combination <see cref="Create"/> admits with UDP — an SSR datagram is
    /// exactly a Shadowsocks stream-cipher datagram, so the Shadowsocks packet
    /// connection is reused rather than duplicated.
    /// </summary>
    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!UdpEnabled)
        {
            throw new NotSupportedException($"proxy [{Name}] of type [{TypeName}] has UDP disabled in its configuration");
        }

        var (resolver, ipv6, interfaceName) = SocketHints();
        var socket = await SocketDialer
            .ConnectUdpAsync(ServerHost!, ServerPort, resolver, ipv6, interfaceName, cancellationToken)
            .ConfigureAwait(false);

        var connection = new ShadowsocksPacketConnection(socket, _method);
        TrackConnection(new AsyncDisposeBridge(connection));
        return connection;
    }

    /// <summary>Resolves a protocol plugin, turning the frozen layer's refusal into a creation error.</summary>
    private static ISsrProtocolPlugin CreateProtocol(string name, string proxyName)
    {
        try
        {
            return ShadowsocksR.CreateProtocol(name);
        }
        catch (NotSupportedException ex)
        {
            throw new ProxyCreationException($"proxy [{proxyName}] (ssr): {ex.Message}");
        }
    }

    /// <summary>
    /// Resolves an obfuscation plugin. <c>http_simple</c> and
    /// <c>tls1.2_ticket_auth</c> are provided here on top of the frozen
    /// <see cref="ShadowsocksObfs"/> helpers; <c>http_post</c> and the
    /// <c>fastauth</c> variant are not implemented and are refused rather than
    /// silently skipped.
    /// </summary>
    private static ISsrObfsPlugin CreateObfs(string name, string proxyName) => name.ToLowerInvariant() switch
    {
        ShadowsocksR.ObfsPlain or ShadowsocksR.ProtocolOrigin => SsrPassThroughObfs.Instance,
        ShadowsocksR.ObfsHttpSimple => SsrHttpSimpleObfs.Instance,
        ShadowsocksR.ObfsTls12TicketAuth => SsrTls12TicketAuthObfs.Instance,
        ShadowsocksR.ObfsHttpPost => throw new ProxyCreationException(
            $"proxy [{proxyName}] (ssr): obfs '{name}' is not implemented by this build "
            + "(only 'plain', 'http_simple' and 'tls1.2_ticket_auth' are; refusing rather than sending unobfuscated traffic)"),
        "tls1.2_ticket_fastauth" => throw new ProxyCreationException(
            $"proxy [{proxyName}] (ssr): obfs '{name}' is not implemented by this build "
            + "(the obfs4-style fastauth handshake is not reproduced)"),
        _ => throw new ProxyCreationException(
            $"proxy [{proxyName}] (ssr): unknown obfs '{name}' "
            + "(known: plain, http_simple, tls1.2_ticket_auth)"),
    };
}

/// <summary>Builds <see cref="ShadowsocksRAdapter"/> instances.</summary>
internal sealed class ShadowsocksRAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "ssr";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => ["shadowsocksr"];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => ShadowsocksRAdapter.Create(entry, context);
}
