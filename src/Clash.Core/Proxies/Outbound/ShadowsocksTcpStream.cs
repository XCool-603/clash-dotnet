using System.Buffers.Binary;
using System.Security.Cryptography;
using Clash.Core.Common;
using Clash.Core.Crypto;

namespace Clash.Core.Proxies.Outbound;

/// <summary>The two simple-obfs disguises.</summary>
internal enum SimpleObfsMode
{
    /// <summary>An HTTP <c>GET</c> request whose path smuggles the first ciphertext bytes.</summary>
    Http,

    /// <summary>A structurally valid TLS 1.2 ClientHello with the session-ticket extension.</summary>
    Tls,
}

/// <summary>
/// The simple-obfs layer of the <c>obfs</c> Shadowsocks plugin. It sits between
/// the socket and the cipher: the first bytes the cipher produces are smuggled
/// into an HTTP request line (or preceded by a fake ClientHello) and the server's
/// matching header is stripped from the first read.
/// <para>
/// <b>What is covered.</b> <c>mode: http</c> and <c>mode: tls</c> request headers,
/// and the response header stripping both modes need. The reference
/// implementation's <c>http_simple</c> response advertises
/// <c>Transfer-Encoding: chunked</c> without actually chunking the body, so the
/// body after the header block is treated as the raw stream — which is what the
/// reference client does too.
/// </para>
/// </summary>
internal sealed class SimpleObfsStream : Stream
{
    private readonly Stream _inner;
    private readonly SimpleObfsMode _mode;
    private readonly string _host;
    private readonly int _port;
    private Stream? _readSource;
    private bool _requestSent;
    private bool _responseStripped;

    internal SimpleObfsStream(Stream inner, SimpleObfsMode mode, string host, int port)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _mode = mode;
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

        if (_requestSent)
        {
            _inner.Write(buffer);
            return;
        }

        _requestSent = true;
        var staging = new byte[512 + ShadowsocksObfs.MaxPathPayload + buffer.Length];
        var written = _mode == SimpleObfsMode.Http
            ? ShadowsocksObfs.BuildHttpSimpleRequest(staging, _host, _port, buffer)
            : ShadowsocksObfs.BuildTls12TicketAuthClientHello(staging, _host, buffer);
        _inner.Write(staging.AsSpan(0, written));
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;

        if (_requestSent)
        {
            await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            return;
        }

        _requestSent = true;
        var staging = new byte[512 + ShadowsocksObfs.MaxPathPayload + buffer.Length];
        var written = _mode == SimpleObfsMode.Http
            ? ShadowsocksObfs.BuildHttpSimpleRequest(staging, _host, _port, buffer.Span)
            : ShadowsocksObfs.BuildTls12TicketAuthClientHello(staging, _host, buffer.Span);
        await _inner.WriteAsync(staging.AsMemory(0, written), cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        EnsureResponseStrippedAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return (_readSource ?? _inner).Read(buffer);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await EnsureResponseStrippedAsync(cancellationToken).ConfigureAwait(false);
        return await (_readSource ?? _inner).ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>Consumes the server's obfuscation header exactly once.</summary>
    private async ValueTask EnsureResponseStrippedAsync(CancellationToken cancellationToken)
    {
        if (_responseStripped) return;
        _responseStripped = true;

        if (_mode == SimpleObfsMode.Http)
        {
            var header = await OutboundIo
                .ReadUntilAsync(_inner, "\r\n\r\n"u8.ToArray(), OutboundIo.MaxHeaderBytes, cancellationToken)
                .ConfigureAwait(false);
            if (header.Leftover.Length > 0) _readSource = new PrefixStream(header.Leftover, _inner);
            return;
        }

        // The fake TLS response is a ServerHello record followed by a
        // ChangeCipherSpec record; the payload starts right after both.
        while (true)
        {
            var record = new byte[5];
            await OutboundIo.ReadExactlyAsync(_inner, record, cancellationToken).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(3));
            var body = new byte[length];
            await OutboundIo.ReadExactlyAsync(_inner, body, cancellationToken).ConfigureAwait(false);
            if (record[0] != 0x16) break;
        }
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
/// The Shadowsocks TCP stream for all three framing families.
/// <list type="bullet">
///   <item><description><b>AEAD (SIP004)</b>: <c>[salt][len+tag][payload+tag]…</c>, with the
///   SOCKS5 address prepended to the first payload byte.</description></item>
///   <item><description><b>2022 (SIP022)</b>: the same chunk framing over a BLAKE3 session
///   subkey, with the 2022 body header and the address inside the first chunk; the
///   server's header is stripped from the first read.</description></item>
///   <item><description><b>Stream</b>: <c>[iv]</c> followed by a raw keystream over
///   <c>address || payload</c>.</description></item>
/// </list>
/// </summary>
internal sealed class ShadowsocksTcpStream : Stream
{
    private readonly Stream _inner;
    private readonly ShadowsocksMethod _method;
    private readonly byte[] _header;

    private ShadowsocksAeadWriter? _writer;
    private ShadowsocksAeadReader? _reader;
    private IStreamCipher? _encryptor;
    private IStreamCipher? _decryptor;
    private bool _headerSent;
    private bool _responseHeaderStripped;

    private byte[] _pending = [];
    private int _pendingOffset;
    private int _pendingLength;

    internal ShadowsocksTcpStream(Stream inner, ShadowsocksMethod method, byte[] firstHeader)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _method = method ?? throw new ArgumentNullException(nameof(method));
        _header = firstHeader ?? [];
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

        switch (_method.Kind)
        {
            case ShadowsocksKind.Aead:
            case ShadowsocksKind.Aead2022:
            {
                _writer ??= new ShadowsocksAeadWriter(_inner, _method.Aead!, _method.Key);
                if (!_headerSent)
                {
                    _headerSent = true;
                    if (_header.Length > 0) _writer.Write(_header);
                }

                _writer.Write(buffer);
                break;
            }

            default:
            {
                if (_encryptor is null)
                {
                    var iv = RandomNumberGenerator.GetBytes(_method.IvSize);
                    _inner.Write(iv, 0, iv.Length);
                    _encryptor = StreamCipherFactory.CreateEncryptor(_method.Name, _method.Key, iv);
                }

                if (!_headerSent)
                {
                    _headerSent = true;
                    var combined = new byte[_header.Length + buffer.Length];
                    _header.CopyTo(combined, 0);
                    buffer.CopyTo(combined.AsSpan(_header.Length));
                    _encryptor.Process(combined, combined);
                    _inner.Write(combined, 0, combined.Length);
                    break;
                }

                using var pooled = new PooledBuffer(buffer.Length);
                buffer.CopyTo(pooled.Span);
                _encryptor.Process(pooled.Span[..buffer.Length], pooled.Span[..buffer.Length]);
                _inner.Write(pooled.Array, 0, buffer.Length);
                break;
            }
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;

        switch (_method.Kind)
        {
            case ShadowsocksKind.Aead:
            case ShadowsocksKind.Aead2022:
            {
                _writer ??= new ShadowsocksAeadWriter(_inner, _method.Aead!, _method.Key);
                if (!_headerSent)
                {
                    _headerSent = true;
                    if (_header.Length > 0) await _writer.WriteAsync(_header, cancellationToken).ConfigureAwait(false);
                }

                await _writer.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                break;
            }

            default:
            {
                if (_encryptor is null)
                {
                    var iv = RandomNumberGenerator.GetBytes(_method.IvSize);
                    await _inner.WriteAsync(iv, cancellationToken).ConfigureAwait(false);
                    _encryptor = StreamCipherFactory.CreateEncryptor(_method.Name, _method.Key, iv);
                }

                if (!_headerSent)
                {
                    _headerSent = true;
                    var combined = new byte[_header.Length + buffer.Length];
                    _header.CopyTo(combined, 0);
                    buffer.Span.CopyTo(combined.AsSpan(_header.Length));
                    _encryptor.Process(combined, combined);
                    await _inner.WriteAsync(combined, cancellationToken).ConfigureAwait(false);
                    break;
                }

                using var pooled = new PooledBuffer(buffer.Length);
                buffer.Span.CopyTo(pooled.Span);
                _encryptor.Process(pooled.Span[..buffer.Length], pooled.Span[..buffer.Length]);
                await _inner.WriteAsync(pooled.Memory(buffer.Length), cancellationToken).ConfigureAwait(false);
                break;
            }
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;

        switch (_method.Kind)
        {
            case ShadowsocksKind.Aead:
            {
                _reader ??= new ShadowsocksAeadReader(_inner, _method.Aead!, _method.Key);
                return _reader.Read(buffer);
            }

            case ShadowsocksKind.Aead2022:
            {
                _reader ??= new ShadowsocksAeadReader(_inner, _method.Aead!, _method.Key);
                Strip2022ResponseHeaderAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
                return _reader.Read(buffer);
            }

            default:
            {
                EnsureStreamDecryptor();
                if (_pendingLength == 0 && !Fill(1)) return 0;
                var take = Math.Min(buffer.Length, _pendingLength);
                _pending.AsSpan(_pendingOffset, take).CopyTo(buffer);
                _pendingOffset += take;
                _pendingLength -= take;
                return take;
            }
        }
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        switch (_method.Kind)
        {
            case ShadowsocksKind.Aead:
            {
                _reader ??= new ShadowsocksAeadReader(_inner, _method.Aead!, _method.Key);
                return await _reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }

            case ShadowsocksKind.Aead2022:
            {
                _reader ??= new ShadowsocksAeadReader(_inner, _method.Aead!, _method.Key);
                await Strip2022ResponseHeaderAsync(cancellationToken).ConfigureAwait(false);
                return await _reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }

            default:
            {
                EnsureStreamDecryptor();
                if (_pendingLength == 0 && !await FillAsync(1, cancellationToken).ConfigureAwait(false)) return 0;
                var take = Math.Min(buffer.Length, _pendingLength);
                _pending.AsSpan(_pendingOffset, take).CopyTo(buffer.Span);
                _pendingOffset += take;
                _pendingLength -= take;
                return take;
            }
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <summary>
    /// Consumes the 2022 server header (type, timestamp, padding length, padding)
    /// from the decrypted stream. The server's header carries no address.
    /// </summary>
    private async ValueTask Strip2022ResponseHeaderAsync(CancellationToken cancellationToken)
    {
        if (_responseHeaderStripped) return;
        _responseHeaderStripped = true;

        var reader = _reader ?? throw new InvalidOperationException("the 2022 reader must exist before the header is stripped");
        var fixedPart = new byte[Shadowsocks2022.UdpBodyHeaderSize];
        await ReadFromReaderAsync(reader, fixedPart, cancellationToken).ConfigureAwait(false);

        if (!Shadowsocks2022.TryReadUdpBodyHeader(fixedPart, out _, out _, out var paddingLength))
        {
            throw new ClashException("shadowsocks: the 2022 server header could not be parsed");
        }

        if (paddingLength == 0) return;

        var padding = new byte[paddingLength];
        await ReadFromReaderAsync(reader, padding, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask ReadFromReaderAsync(ShadowsocksAeadReader reader, Memory<byte> destination, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < destination.Length)
        {
            var n = await reader.ReadAsync(destination[read..], cancellationToken).ConfigureAwait(false);
            if (n <= 0) throw new ClashException("shadowsocks: the peer closed the connection mid-header");
            read += n;
        }
    }

    private void EnsureStreamDecryptor()
    {
        if (_decryptor is not null) return;

        var iv = new byte[_method.IvSize];
        if (iv.Length > 0) OutboundIo.ReadExactly(_inner, iv);
        _decryptor = StreamCipherFactory.CreateDecryptor(_method.Name, _method.Key, iv);
    }

    /// <summary>Reads and decrypts more bytes until at least <paramref name="minimum"/> are buffered.</summary>
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

    /// <inheritdoc cref="Fill(int)"/>
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
            _writer?.Dispose();
            try { _inner.Dispose(); } catch { /* already gone */ }
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        _writer?.Dispose();
        try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* already gone */ }
        GC.SuppressFinalize(this);
    }
}
