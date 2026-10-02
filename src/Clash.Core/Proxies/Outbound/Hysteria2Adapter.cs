using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The <c>"host:port"</c> string hysteria2 puts in a TCP request header.
/// <para>
/// Unlike the v2ray family this is <em>not</em> a SOCKS5 address block: the server
/// hands the string straight to its dialer, so an IPv6 literal has to be bracketed or
/// the port becomes indistinguishable from the address. The spec does not spell that
/// out; the bracketed form is the only one a host/port parser can read back.
/// </para>
/// </summary>
internal static class Hysteria2Address
{
    /// <summary>Formats <paramref name="host"/> and <paramref name="port"/> as the wire string.</summary>
    internal static string Format(string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);

        var bracketed = host.Contains(':', StringComparison.Ordinal) && !host.StartsWith('[')
            ? $"[{host}]"
            : host;

        return string.Concat(bracketed, ":", port.ToString(CultureInfo.InvariantCulture));
    }
}

/// <summary>
/// The first bytes of a client-initiated bidirectional stream: the hysteria2
/// <c>TCPRequest</c> header.
/// <para>
/// The layout is <c>varint(0x401) || varint(addressLength) || address ||
/// varint(paddingLength) || padding</c>, all numbers big-endian QUIC varints. The
/// frame type <c>0x401</c> is the only type a client ever sends on a bidi stream, and
/// it encodes as the two bytes <c>44 01</c> — which is the concrete check the protocol
/// document gives for a varint implementation.
/// </para>
/// <para>
/// The padding is the reference client's traffic-shaping filler: random
/// <c>[a-zA-Z0-9]</c> of length <c>[64,512)</c>. It carries nothing; the server reads
/// the length and skips it. It is emitted because the server reads the padding as part
/// of the request, so the request is only complete once it has been written.
/// </para>
/// </summary>
internal static class Hysteria2RequestHeader
{
    /// <summary>The <c>TCPRequest</c> frame type of PROTOCOL.md §3.</summary>
    internal const ulong TcpRequestFrame = 0x401;

    /// <summary>Smallest padding the reference client sends on a TCP request stream.</summary>
    internal const int MinPadding = 64;

    /// <summary>One past the largest padding the reference client sends.</summary>
    internal const int MaxPaddingExclusive = 512;

    /// <summary>Bytes <see cref="Write"/> needs for this destination and padding length.</summary>
    internal static int Size(string host, int port, int paddingLength)
    {
        var address = Hysteria2Address.Format(host, port);
        return Hysteria2Varint.Size(TcpRequestFrame)
            + Hysteria2Varint.Size((ulong)address.Length)
            + address.Length
            + Hysteria2Varint.Size((ulong)paddingLength)
            + paddingLength;
    }

    /// <summary>Writes the request header and returns how many bytes it occupied.</summary>
    internal static int Write(Span<byte> destination, string host, int port, ReadOnlySpan<byte> padding)
    {
        var address = Hysteria2Address.Format(host, port);
        var required = Size(host, port, padding.Length);
        if (destination.Length < required)
        {
            throw new ArgumentException($"destination must be at least {required} bytes, got {destination.Length}", nameof(destination));
        }

        var offset = 0;
        offset += Hysteria2Varint.Write(destination[offset..], TcpRequestFrame);
        offset += Hysteria2Varint.Write(destination[offset..], (ulong)address.Length);
        offset += Encoding.ASCII.GetBytes(address, destination[offset..]);
        offset += Hysteria2Varint.Write(destination[offset..], (ulong)padding.Length);
        padding.CopyTo(destination[offset..]);
        return offset + padding.Length;
    }

    /// <summary>Builds a request header with fresh random padding.</summary>
    internal static byte[] Build(string host, int port, Random? random = null)
    {
        var paddingLength = (random ?? Random.Shared).Next(MinPadding, MaxPaddingExclusive);
        var buffer = new byte[Size(host, port, paddingLength)];
        var padding = new byte[paddingLength];
        Hysteria2Padding.Fill(padding, random);
        var written = Write(buffer, host, port, padding);
        return buffer[..written];
    }
}

/// <summary>
/// The random ASCII filler hysteria2 asks for in its padding fields: the
/// <c>Hysteria-Padding</c> header and the tail of a TCP request header.
/// </summary>
internal static class Hysteria2Padding
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// <summary>Smallest <c>Hysteria-Padding</c> value the reference client sends.</summary>
    internal const int MinHeaderLength = 256;

    /// <summary>One past the largest <c>Hysteria-Padding</c> value the reference client sends.</summary>
    internal const int MaxHeaderLengthExclusive = 2048;

    /// <summary>A random ASCII string of the length the reference uses for the auth header.</summary>
    internal static string NextHeaderValue(Random? random = null)
    {
        var source = random ?? Random.Shared;
        var length = source.Next(MinHeaderLength, MaxHeaderLengthExclusive);
        var chars = new char[length];
        for (var i = 0; i < length; i++) chars[i] = Alphabet[source.Next(Alphabet.Length)];
        return new string(chars);
    }

    /// <summary>Fills <paramref name="destination"/> with random alphabet bytes.</summary>
    internal static void Fill(Span<byte> destination, Random? random = null)
    {
        var source = random ?? Random.Shared;
        for (var i = 0; i < destination.Length; i++) destination[i] = (byte)Alphabet[source.Next(Alphabet.Length)];
    }
}

/// <summary>
/// The server's answer to a <c>TCPRequest</c>: <c>status(1) | varint(messageLength) |
/// message | varint(paddingLength) | padding</c>.
/// <para>
/// Status <c>0x00</c> hands the stream over as a raw byte pipe; status <c>0x01</c>
/// means the server refused the destination and the message is the reason. The read is
/// kept behind <see cref="Hysteria2TcpStream.EnsureResponseAsync"/> rather than done in
/// the dial, because the reference's <c>fast-open</c> option deliberately skips waiting
/// for it — a server that only answers after it has seen payload would otherwise
/// deadlock the dial.
/// </para>
/// </summary>
internal static class Hysteria2Response
{
    /// <summary>Status byte meaning the server opened the destination.</summary>
    internal const byte StatusOk = 0x00;

    /// <summary>Status byte meaning the server refused it.</summary>
    internal const byte StatusError = 0x01;

    /// <summary>Reads the response and throws unless it is <see cref="StatusOk"/>.</summary>
    internal static async ValueTask ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var status = new byte[1];
        await OutboundIo.ReadExactlyAsync(stream, status, cancellationToken).ConfigureAwait(false);

        var messageLength = await Hysteria2Varint.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
        if (messageLength > 2048)
        {
            throw new ClashException($"hysteria2: the server announced a {messageLength}-byte error message, over the protocol's 2048-byte cap");
        }

        var message = new byte[(int)messageLength];
        if (message.Length > 0)
        {
            await OutboundIo.ReadExactlyAsync(stream, message, cancellationToken).ConfigureAwait(false);
        }

        var paddingLength = await Hysteria2Varint.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
        if (paddingLength > 4096)
        {
            throw new ClashException($"hysteria2: the server announced {paddingLength} bytes of padding, over the protocol's 4096-byte cap");
        }

        if (paddingLength > 0)
        {
            await OutboundIo.ReadExactlyAsync(stream, new byte[(int)paddingLength], cancellationToken).ConfigureAwait(false);
        }

        if (status[0] == StatusOk) return;

        var text = message.Length == 0 ? "(no message)" : Encoding.UTF8.GetString(message);
        throw new ClashException(status[0] == StatusError
            ? $"hysteria2: the server refused the destination: {text}"
            : $"hysteria2: the server answered an unknown TCP request status 0x{status[0]:X2}: {text}");
    }
}

/// <summary>
/// One hysteria2 TCP flow: a QUIC bidirectional stream after the server's response
/// header has been consumed.
/// <para>
/// <b>Half-close.</b> QUIC streams have a real send-side FIN, and hysteria2 relies on
/// it — the server forwards the FIN to the destination — so
/// <see cref="ShutdownSend"/> calls <c>QuicStream.CompleteWrites</c> rather than
/// closing the stream. That is what <see cref="IHalfCloseable"/> exists for, and it is
/// why the tunnel's relay does not have to wait out a drain timeout on every flow.
/// </para>
/// <para>
/// <b>Sync reads block on the async path</b> so the response state machine exists
/// exactly once; the relay is asynchronous and never takes the synchronous overload.
/// </para>
/// </summary>
internal sealed class Hysteria2TcpStream : Stream, IHalfCloseable
{
    private readonly Stream _inner;
    private readonly Action? _completeWrites;
    private bool _responseRead;
    private bool _disposed;

    /// <summary>
    /// Wraps an already-framed QUIC stream. <paramref name="completeWrites"/> is the
    /// stream's own <c>CompleteWrites</c>; it is passed as a delegate so this type
    /// stays testable over an in-memory stream that has no send-side FIN.
    /// </summary>
    internal Hysteria2TcpStream(Stream inner, Action? completeWrites = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _completeWrites = completeWrites;
    }

    /// <summary>Reads the server's TCP response once, leaving the stream on the first payload byte.</summary>
    internal async ValueTask EnsureResponseAsync(CancellationToken cancellationToken)
    {
        if (_responseRead) return;
        _responseRead = true;
        await Hysteria2Response.ReadAsync(_inner, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override bool CanRead => true;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override bool CanWrite => true;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>Sends the stream's FIN without tearing down the receive direction.</summary>
    public void ShutdownSend() => _completeWrites?.Invoke();

    /// <inheritdoc />
    public override void Flush() => _inner.Flush();

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    /// <inheritdoc cref="ReadAsync(Memory{byte},CancellationToken)"/>
    public override int Read(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return 0;
        EnsureResponseAsync(CancellationToken.None).AsTask().ConfigureAwait(false).GetAwaiter().GetResult();
        return _inner.Read(buffer);
    }

    /// <inheritdoc />
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;
        await EnsureResponseAsync(cancellationToken).ConfigureAwait(false);
        return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);

    /// <inheritdoc />
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            try { _inner.Dispose(); } catch { /* peer already gone */ }
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* peer already gone */ }
        }

        GC.SuppressFinalize(this);
    }
}

/// <summary>Everything <see cref="Hysteria2Connection"/> needs to open the QUIC connection.</summary>
internal sealed class Hysteria2ConnectOptions
{
    /// <summary>The configured <c>server</c>.</summary>
    internal required string Host { get; init; }

    /// <summary>The port to dial — the configured one, or one drawn from <c>ports</c>.</summary>
    internal required int Port { get; init; }

    /// <summary>The SNI to present; defaults to <see cref="Host"/>.</summary>
    internal required string Sni { get; init; }

    /// <summary>The ALPN list; <c>h3</c> unless the configuration overrides it.</summary>
    internal required string[] Alpn { get; init; }

    /// <summary>The bearer string for <c>Hysteria-Auth</c>.</summary>
    internal required string Password { get; init; }

    /// <summary>The client's receive rate in bytes per second; <c>0</c> means unknown.</summary>
    internal ulong CcRx { get; init; }

    /// <summary>When true the certificate is accepted whatever the chain says.</summary>
    internal bool SkipCertificateVerify { get; init; }

    /// <summary>Extra trust anchors from <c>ca</c>/<c>ca-str</c>.</summary>
    internal X509Certificate2Collection? CustomRoots { get; init; }

    /// <summary>A pinned SHA-256 of the server certificate's DER, from <c>fingerprint</c>.</summary>
    internal byte[]? PinnedSha256 { get; init; }

    /// <summary>The tunnel's resolver, when the tunnel is attached.</summary>
    internal IDnsResolver? Resolver { get; init; }

    /// <summary>Whether IPv6 candidates may be used.</summary>
    internal bool AllowIpv6 { get; init; } = true;

    /// <summary>The interface to bind the QUIC socket to, from the tunnel configuration.</summary>
    internal string? InterfaceName { get; init; }

    /// <summary>Logger for the handshake.</summary>
    internal required ILogger Logger { get; init; }

    /// <summary>Builds the TLS options, including the certificate policy.</summary>
    internal SslClientAuthenticationOptions BuildAuthenticationOptions()
    {
        var options = new SslClientAuthenticationOptions
        {
            TargetHost = Sni,
            ApplicationProtocols = [.. Alpn.Select(a => new SslApplicationProtocol(a))],
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };

        options.RemoteCertificateValidationCallback = (_, certificate, _, errors) => Validate(certificate, errors);
        return options;
    }

    /// <summary>
    /// The certificate policy. <c>skip-cert-verify</c> short-circuits everything, which
    /// is what makes a self-signed loopback server usable; otherwise a configured
    /// <c>fingerprint</c> pin and/or a custom trust store from <c>ca</c>/<c>ca-str</c>
    /// are applied, falling back to the platform chain result.
    /// </summary>
    private bool Validate(X509Certificate? certificate, SslPolicyErrors errors)
    {
        if (SkipCertificateVerify) return true;
        if (certificate is null) return false;

        var leaf = certificate as X509Certificate2
            ?? X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));

        if (PinnedSha256 is not null)
        {
            Span<byte> digest = stackalloc byte[32];
            SHA256.HashData(leaf.RawData, digest);
            if (!CryptographicOperations.FixedTimeEquals(digest, PinnedSha256)) return false;
        }

        if (CustomRoots is null) return errors == SslPolicyErrors.None;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.CustomTrustStore.AddRange(CustomRoots);
        return chain.Build(leaf);
    }
}

/// <summary>
/// One authenticated hysteria2 QUIC connection, shared by every TCP flow the adapter
/// carries.
/// <para>
/// <b>Why one connection.</b> hysteria2 multiplexes: the auth exchange happens once
/// and every TCP flow is then a fresh client-initiated bidirectional stream on the same
/// QUIC connection. Reconnecting per flow would work but would re-run the whole HTTP/3
/// handshake, so the connection is opened lazily and kept until it fails or
/// <c>CloseConnections</c> drops it.
/// </para>
/// <para>
/// <b>What is deliberately not drained.</b> The server opens its own control and QPACK
/// streams back at us. They carry only SETTINGS and encoder instructions this client
/// has no use for (the zero-capacity settings guarantee no dynamic inserts), so they are
/// left unread. The transport parameter <c>MaxInboundUnidirectionalStreams</c> is capped
/// at a small number so a peer cannot queue unbounded streams at us.
/// </para>
/// </summary>
internal sealed class Hysteria2Connection : IAsyncDisposable
{
    private readonly QuicConnection _connection;
    private readonly Hysteria2ConnectOptions _options;
    private readonly SemaphoreSlim _authLock = new(1, 1);
    private readonly List<QuicStream> _handshakeStreams = [];

    private int _authenticated;
    private int _failed;
    private int _disposed;

    private Hysteria2Connection(QuicConnection connection, Hysteria2ConnectOptions options)
    {
        _connection = connection;
        _options = options;
    }

    /// <summary>The peer endpoint, for the tunnel's connection accounting.</summary>
    internal IPEndPoint? RemoteEndPoint => _connection.RemoteEndPoint;

    /// <summary>The local endpoint, likewise.</summary>
    internal IPEndPoint? LocalEndPoint => _connection.LocalEndPoint;

    /// <summary>False once the connection has failed or been closed, so a dial reconnects.</summary>
    internal bool IsUsable => Volatile.Read(ref _failed) == 0 && Volatile.Read(ref _disposed) == 0;

    /// <summary>Opens the QUIC connection, trying each resolved address in turn.</summary>
    internal static async Task<Hysteria2Connection> ConnectAsync(Hysteria2ConnectOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var addresses = await SocketDialer
            .ResolveAsync(options.Host, options.Resolver, options.AllowIpv6, cancellationToken)
            .ConfigureAwait(false);
        if (addresses.Length == 0)
        {
            throw new ClashException($"hysteria2: could not resolve the server [{options.Host}]");
        }

        Exception? last = null;
        foreach (var address in addresses)
        {
            try
            {
                var local = FindInterfaceAddress(options.InterfaceName, address.AddressFamily);
                var quic = new QuicClientConnectionOptions
                {
                    RemoteEndPoint = new IPEndPoint(address, options.Port),
                    LocalEndPoint = local is null ? null : new IPEndPoint(local, 0),
                    ClientAuthenticationOptions = options.BuildAuthenticationOptions(),
                    HandshakeTimeout = TimeSpan.FromSeconds(10),
                    IdleTimeout = TimeSpan.FromSeconds(30),
                    KeepAliveInterval = TimeSpan.FromSeconds(10),

                    // The server never opens a bidirectional stream to us; the eight
                    // credits exist only so a peer that tried would not kill the
                    // connection outright. Its own control and QPACK streams are
                    // unidirectional, and sixteen is comfortably above the three it uses.
                    MaxInboundBidirectionalStreams = 8,
                    MaxInboundUnidirectionalStreams = 16,
                    DefaultCloseErrorCode = 0,
                    DefaultStreamErrorCode = 0,
                };

                var connection = await QuicConnection.ConnectAsync(quic, cancellationToken).ConfigureAwait(false);
                options.Logger.LogDebug(
                    "hysteria2: QUIC connection to {Host}:{Port} established over {Alpn}",
                    options.Host,
                    options.Port,
                    connection.NegotiatedApplicationProtocol);
                return new Hysteria2Connection(connection, options);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                last = ex;
                options.Logger.LogDebug("hysteria2: QUIC connect to {Address}:{Port} failed: {Message}", address, options.Port, ex.Message);
            }
        }

        throw new ClashException(
            $"hysteria2: could not open a QUIC connection to {options.Host}:{options.Port}: {last?.Message}",
            last ?? new SocketException((int)SocketError.HostUnreachable));
    }

    /// <summary>
    /// Runs the auth handshake once, then opens a TCP request stream to
    /// <paramref name="host"/>:<paramref name="port"/>.
    /// </summary>
    internal async Task<Stream> OpenTcpStreamAsync(string host, int port, bool fastOpen, CancellationToken cancellationToken)
    {
        await EnsureAuthenticatedAsync(cancellationToken).ConfigureAwait(false);

        QuicStream stream;
        try
        {
            stream = await _connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(false);
        }
        catch (QuicException)
        {
            Volatile.Write(ref _failed, 1);
            throw;
        }

        try
        {
            var header = Hysteria2RequestHeader.Build(host, port);
            await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);

            var framed = new Hysteria2TcpStream(stream, stream.CompleteWrites);
            if (!fastOpen)
            {
                await framed.EnsureResponseAsync(cancellationToken).ConfigureAwait(false);
            }

            return framed;
        }
        catch (Exception ex)
        {
            if (ex is QuicException) Volatile.Write(ref _failed, 1);
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Opens the three unidirectional HTTP/3 streams and the auth request stream, and
    /// validates the server's <c>:status: 233</c>. Only one caller wins; the rest wait
    /// on the same semaphore and then see <c>_authenticated</c> set.
    /// </summary>
    private async ValueTask EnsureAuthenticatedAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _authenticated) != 0) return;

        await _authLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _authenticated) != 0) return;
            await AuthenticateAsync(cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _authenticated, 1);
        }
        finally
        {
            _authLock.Release();
        }
    }

    private async Task AuthenticateAsync(CancellationToken cancellationToken)
    {
        // RFC 9114 §6.2.1 and RFC 9204 §4.2: the control and QPACK streams must be
        // opened at the start of the connection and must never be closed by the sender,
        // so these are opened, written, and then held for the connection's lifetime.
        _handshakeStreams.Add(await OpenUnidirectionalAsync(Hysteria2Http3.ControlStream(), cancellationToken).ConfigureAwait(false));
        _handshakeStreams.Add(await OpenUnidirectionalAsync(Hysteria2Http3.QpackEncoderStream(), cancellationToken).ConfigureAwait(false));
        _handshakeStreams.Add(await OpenUnidirectionalAsync(Hysteria2Http3.QpackDecoderStream(), cancellationToken).ConfigureAwait(false));

        var stream = await _connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken).ConfigureAwait(false);

        // The auth stream is held, not reset. The server hijacks the HTTP/3 connection
        // on this stream, and a QuicStream whose last reference is dropped would be
        // aborted by its finaliser, so it is kept alive with the control streams until
        // the whole connection is torn down.
        _handshakeStreams.Add(stream);

        var padding = Hysteria2Padding.NextHeaderValue();
        var fieldSection = Hysteria2Auth.BuildRequest(_options.Password, _options.CcRx, padding);
        await stream.WriteAsync(Hysteria2Http3.HeadersFrame(fieldSection), cancellationToken).ConfigureAwait(false);

        // A POST with no body: the request is complete as soon as its HEADERS are out.
        stream.CompleteWrites();

        var fields = await Hysteria2Http3.ReadHeadersAsync(stream, cancellationToken).ConfigureAwait(false);
        var result = Hysteria2Auth.ParseResponse(fields);

        _options.Logger.LogDebug(
            "hysteria2: authenticated; server udp={Udp} cc-rx={CcRx}{Auto}",
            result.Udp,
            result.CcRx,
            result.CcRxAuto ? " (auto)" : string.Empty);
    }

    private async Task<QuicStream> OpenUnidirectionalAsync(byte[] payload, CancellationToken cancellationToken)
    {
        var stream = await _connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        return stream;
    }

    /// <summary>Resolves the address of the configured interface, or null when none is set.</summary>
    private static IPAddress? FindInterfaceAddress(string? interfaceName, AddressFamily family)
    {
        if (string.IsNullOrWhiteSpace(interfaceName)) return null;

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!string.Equals(nic.Name, interfaceName, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(nic.Id, interfaceName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return nic.GetIPProperties().UnicastAddresses
                .Select(u => u.Address)
                .FirstOrDefault(a => a.AddressFamily == family);
        }

        return null;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        // This runs only when the whole session ends, so releasing the handshake
        // streams here cannot disturb a live auth exchange.
        foreach (var stream in _handshakeStreams)
        {
            try { await stream.DisposeAsync().ConfigureAwait(false); } catch { /* connection already gone */ }
        }

        _handshakeStreams.Clear();

        try { await _connection.DisposeAsync().ConfigureAwait(false); } catch { /* already gone */ }
        _authLock.Dispose();
    }
}

/// <summary>
/// The <c>hysteria2</c> outbound adapter: an HTTP/3 <c>POST /auth</c> over QUIC and
/// then one bidirectional QUIC stream per TCP flow.
/// <para>
/// <b>What this adapter does not do, and refuses rather than fakes.</b>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <b>UDP.</b> hysteria2 carries datagrams as QUIC DATAGRAM frames (RFC 9221).
/// <c>System.Net.Quic</c> in .NET 10 exposes no datagram API — no <c>QuicDatagram</c>
/// type and no send or receive member on <c>QuicConnection</c> — so there is no
/// interception point and no way to put a <c>UDPMessage</c> on the wire.
/// <c>udp: true</c> is accepted so the entry still loads, but
/// <see cref="SupportUdp"/> stays false and <see cref="DialUdpAsync"/> refuses.
/// </description></item>
/// <item><description>
/// <b>Salamander and Gecko obfuscation.</b> Both rewrite every raw UDP datagram
/// <em>below</em> QUIC (XOR against a BLAKE2b keystream keyed by a per-packet salt,
/// with Gecko additionally fragmenting long-header packets). <c>System.Net.Quic</c>
/// owns the socket and exposes no handle to it, so there is no layer at which to
/// transform the packets. A configuration carrying <c>obfs</c> is refused at
/// construction: connecting un-obfuscated to an obfuscated server does not fail
/// cleanly, it hangs.
/// </description></item>
/// <item><description>
/// <b><c>ChromeParrot</c>.</b> The reference client defaults to it and forces a
/// zero-length source connection ID so its Initial packets resemble Chrome's. MsQuic
/// chooses the connection ID and the Initial packet shape itself, so this client's
/// handshake is measurably different on the wire. That is a detectability difference,
/// not a correctness one.
/// </description></item>
/// <item><description>
/// <b>Brutal congestion control.</b> <c>up</c>/<c>down</c> are still reported in
/// <c>Hysteria-CC-RX</c> because the protocol requires the header, but the actual
/// pacing is MsQuic's own loss-based controller: .NET exposes no way to replace it.
/// </description></item>
/// <item><description>
/// <b>Port hopping.</b> <c>ports</c> selects the port this connection is pinned to;
/// hopping mid-connection needs QUIC connection migration, which
/// <c>System.Net.Quic</c> does not expose. <c>hop-interval</c> is therefore reported
/// as unimplemented rather than silently ignored.
/// </description></item>
/// <item><description>
/// <b><c>dialer-proxy</c> and relay chaining.</b> A QUIC connection cannot be built on
/// top of a supplied stream, so both are refused at construction — silently dialling
/// directly would leak traffic outside the configured chain.
/// </description></item>
/// <item><description>
/// <b><c>disable-mtu-discovery</c>.</b> Accepted and logged as ignored: MsQuic runs its
/// own path-MTU discovery and .NET exposes no switch for it.
/// </description></item>
/// </list>
/// </summary>
public sealed class Hysteria2Adapter : OutboundAdapter
{
    private readonly string _password;
    private readonly string _sni;
    private readonly bool _skipCertificateVerify;
    private readonly string[] _alpn;
    private readonly ulong _ccRx;
    private readonly bool _fastOpen;
    private readonly (int Begin, int End)? _portRange;
    private readonly X509Certificate2Collection? _customRoots;
    private readonly byte[]? _pinnedSha256;
    private readonly SemaphoreSlim _connectLock = new(1, 1);

    private Hysteria2Connection? _connection;

    internal Hysteria2Adapter(
        ProxyConfigEntry entry,
        AdapterBuildContext context,
        string password,
        string sni,
        bool skipCertificateVerify,
        string[] alpn,
        ulong ccRx,
        bool fastOpen,
        (int Begin, int End)? portRange,
        X509Certificate2Collection? customRoots,
        byte[]? pinnedSha256)
        : base(entry, context, ProxyType.Hysteria2, udp: false)
    {
        _password = password;
        _sni = sni;
        _skipCertificateVerify = skipCertificateVerify;
        _alpn = alpn;
        _ccRx = ccRx;
        _fastOpen = fastOpen;
        _portRange = portRange;
        _customRoots = customRoots;
        _pinnedSha256 = pinnedSha256;

        if (entry.Map.GetBool("udp"))
        {
            Logger.LogWarning(
                "proxy [{Name}] (hysteria2) declares udp: true, but this build cannot carry datagrams over hysteria2 "
                + "(System.Net.Quic has no QUIC datagram API); UDP flows will not be routed to it",
                entry.Name);
        }

        if (entry.Map.GetBool("disable-mtu-discovery") || entry.Map.GetBool("disable_mtu_discovery"))
        {
            Logger.LogInformation(
                "proxy [{Name}] (hysteria2) sets disable-mtu-discovery, which this build ignores: MsQuic runs its own path-MTU "
                + "discovery and System.Net.Quic exposes no switch for it",
                entry.Name);
        }
    }

    /// <summary>
    /// Validates the entry and builds the adapter. Everything that would change the wire
    /// format but cannot be honoured is refused here rather than at dial time, so a
    /// misconfiguration is visible while the configuration loads.
    /// </summary>
    internal static Hysteria2Adapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var password = entry.Map.GetNonEmptyString("password");
        if (password is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (hysteria2) requires a non-empty 'password'");
        }

        var obfs = entry.Map.GetNonEmptyString("obfs");
        if (obfs is not null)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) requests 'obfs: {obfs}'. Salamander and Gecko both rewrite every raw UDP datagram "
                + "below QUIC (a BLAKE2b keystream XOR keyed by a per-packet salt, plus Gecko's fragmentation of long-header packets), "
                + "and System.Net.Quic owns the UDP socket and exposes no handle to it, so this build has no layer at which to apply "
                + "the obfuscation. Connecting without it to an obfuscated server does not fail cleanly - it hangs - so the entry is "
                + "refused instead. Remove 'obfs', or terminate the obfuscation outside .NET.");
        }

        var dialerProxy = OutboundOptions.ReadDialerProxy(entry.Map);
        if (dialerProxy is not null)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) sets 'dialer-proxy: {dialerProxy}'. A hysteria2 session is a QUIC connection, "
                + "which System.Net.Quic opens on its own UDP socket and cannot be built on top of a supplied stream, so this build "
                + "cannot route it through another proxy. Remove 'dialer-proxy' - ignoring it would send the traffic outside the "
                + "configured chain.");
        }

        var portRange = ParsePortRange(entry);
        if (entry.Map.GetNonEmptyString("hop-interval") is { } hopInterval)
        {
            context.LoggerFactory.CreateLogger<Hysteria2Adapter>().LogWarning(
                "proxy [{Name}] (hysteria2) sets hop-interval: {Interval}, but mid-connection port hopping needs QUIC connection "
                + "migration, which System.Net.Quic does not expose; this connection stays pinned to one port",
                entry.Name,
                hopInterval);
        }

        var roots = LoadCustomRoots(entry);
        var pin = ParsePin(entry);

        // Validate the endpoint here as well as in the base constructor, so the SNI
        // default can name the configured server rather than an empty string.
        var (server, _) = OutboundOptions.RequireEndpoint(entry);

        return new Hysteria2Adapter(
            entry,
            context,
            password,
            entry.Map.GetNonEmptyString("sni") ?? entry.Map.GetNonEmptyString("peer") ?? server,
            entry.Map.GetBool("skip-cert-verify") || entry.Map.GetBool("skip_cert_verify") || entry.Map.GetBool("insecure"),
            ParseAlpn(entry),
            ParseBandwidth(entry.Map.GetNonEmptyString("down") ?? entry.Map.GetNonEmptyString("downmbps"), entry, "down"),
            entry.Map.GetBool("fast-open") || entry.Map.GetBool("fast_open") || entry.Map.GetBool("tfo"),
            portRange,
            roots,
            pin);
    }

    /// <summary>UDP is not advertised, because there is no datagram API to advertise it with.</summary>
    public override bool SupportUdp => false;

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        if (upstream is not null)
        {
            throw Fail(new NotSupportedException(
                $"proxy [{Name}] (hysteria2) cannot be chained behind another proxy: a hysteria2 session is a QUIC connection on its "
                + "own UDP socket, and System.Net.Quic cannot build one on top of a supplied stream."));
        }

        if (!QuicConnection.IsSupported)
        {
            throw Fail(new NotSupportedException(
                $"proxy [{Name}] (hysteria2) needs QUIC, and System.Net.Quic reports the platform has no QUIC implementation "
                + "(MsQuic). Install the platform QUIC library, or drop the proxy."));
        }

        try
        {
            var connection = await GetConnectionAsync(cancellationToken).ConfigureAwait(false);
            var host = OutboundOptions.Destination(metadata);
            var stream = await connection
                .OpenTcpStreamAsync(host, metadata.DestinationPort, _fastOpen, cancellationToken)
                .ConfigureAwait(false);

            var wrapped = new ProxyStream(stream, connection.LocalEndPoint, connection.RemoteEndPoint);
            return Complete(Track(wrapped));
        }
        catch (Exception ex)
        {
            throw Fail(ex);
        }
    }

    /// <summary>
    /// Refuses every UDP flow. See the type remarks: hysteria2's datagrams are QUIC
    /// DATAGRAM frames, and <c>System.Net.Quic</c> has no API for them at all, so a UDP
    /// association here could only ever be a lie.
    /// </summary>
    public override Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        return Task.FromException<IPacketConnection>(new NotSupportedException(
            $"proxy [{Name}] (hysteria2): UDP is not implemented in this build. hysteria2 carries datagrams as QUIC DATAGRAM "
            + "frames (RFC 9221), and System.Net.Quic in .NET 10 exposes no datagram API - no QuicDatagram type and no send or "
            + "receive member on QuicConnection - so a UDPMessage cannot be put on the wire. Route UDP through a different proxy, "
            + "or use a TCP-only rule."));
    }

    /// <summary>
    /// Drops the shared QUIC connection along with every flow. The connection is not a
    /// "connection" for accounting purposes, so it is not registered with
    /// <see cref="ProxyAdapter.TrackConnection"/>.
    /// </summary>
    public override void CloseConnections()
    {
        var connection = Interlocked.Exchange(ref _connection, null);
        if (connection is not null) Forget(connection.DisposeAsync());

        base.CloseConnections();
    }

    /// <summary>The live connection, or a freshly opened one when there is none or it has failed.</summary>
    private async Task<Hysteria2Connection> GetConnectionAsync(CancellationToken cancellationToken)
    {
        var existing = Volatile.Read(ref _connection);
        if (existing is not null && existing.IsUsable) return existing;

        await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            existing = Volatile.Read(ref _connection);
            if (existing is not null && existing.IsUsable) return existing;

            if (existing is not null)
            {
                Interlocked.CompareExchange(ref _connection, null, existing);
                Forget(existing.DisposeAsync());
            }

            var (resolver, ipv6, interfaceName) = SocketHints();
            var options = new Hysteria2ConnectOptions
            {
                Host = ServerHost!,
                Port = SelectPort(),
                Sni = _sni,
                Alpn = _alpn,
                Password = _password,
                CcRx = _ccRx,
                SkipCertificateVerify = _skipCertificateVerify,
                CustomRoots = _customRoots,
                PinnedSha256 = _pinnedSha256,
                Resolver = resolver,
                AllowIpv6 = ipv6,
                InterfaceName = interfaceName,
                Logger = Logger,
            };

            var created = await Hysteria2Connection.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _connection, created);
            return created;
        }
        finally
        {
            _connectLock.Release();
        }
    }

    /// <summary>The port to dial: the configured one, or a random member of <c>ports</c>.</summary>
    private int SelectPort()
    {
        if (_portRange is not { } range) return ServerPort;
        return range.Begin == range.End ? range.Begin : Random.Shared.Next(range.Begin, range.End + 1);
    }

    /// <summary>
    /// Parses <c>ports</c> (<c>begin-end</c> or a single port). A comma-separated list —
    /// the other form mihomo accepts — is refused rather than half-read.
    /// </summary>
    private static (int Begin, int End)? ParsePortRange(ProxyConfigEntry entry)
    {
        var text = entry.Map.GetNonEmptyString("ports") ?? entry.Map.GetNonEmptyString("mport");
        if (text is null) return null;

        var dash = text.IndexOf('-', StringComparison.Ordinal);
        var beginText = dash < 0 ? text : text[..dash];
        var endText = dash < 0 ? text : text[(dash + 1)..];

        if (!int.TryParse(beginText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var begin)
            || !int.TryParse(endText.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var end))
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) has a malformed 'ports' [{text}]; this build accepts 'begin-end' or a single port");
        }

        if (begin is < 1 or > 65535 || end is < 1 or > 65535 || end < begin)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) has an invalid 'ports' [{text}]; expected 1-65535 with begin <= end");
        }

        return (begin, end);
    }

    /// <summary>
    /// The ALPN list. hysteria2 runs HTTP/3, so <c>h3</c> is the default; an explicit
    /// <c>alpn</c> wins, because a user pointing this adapter at something that is not
    /// hysteria2 should get the protocol they asked for rather than a silent override.
    /// </summary>
    private static string[] ParseAlpn(ProxyConfigEntry entry)
    {
        var list = entry.Map.GetStringList("alpn")
            .Select(a => a.Trim().ToLowerInvariant())
            .Where(a => a.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return list.Length == 0 ? ["h3"] : list;
    }

    /// <summary>
    /// Converts Clash's <c>up</c>/<c>down</c> bandwidth strings to the bytes-per-second
    /// <c>Hysteria-CC-RX</c> wants. A bare number is read as Mbps, which is the unit the
    /// Clash documentation uses for hysteria's <c>up</c>/<c>down</c>; anything that is
    /// not a number with a recognised unit is refused rather than guessed at, because a
    /// wrong value would make the server pace the connection to the wrong rate.
    /// </summary>
    internal static ulong ParseBandwidth(string? value, ProxyConfigEntry entry, string key)
    {
        if (string.IsNullOrWhiteSpace(value)) return 0;

        var text = value.Trim().ToLowerInvariant();
        var digits = 0;
        while (digits < text.Length && (char.IsAsciiDigit(text[digits]) || text[digits] == '.')) digits++;

        if (digits == 0
            || !double.TryParse(text[..digits], NumberStyles.Float, CultureInfo.InvariantCulture, out var number)
            || number < 0)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) has a malformed '{key}' [{value}]; expected a number with an optional "
                + "bps/kbps/mbps/gbps unit, e.g. '100 Mbps'");
        }

        var multiplier = text[digits..].Trim() switch
        {
            "" or "m" or "mb" or "mbps" or "mbit" => 1_000_000d / 8d,
            "g" or "gb" or "gbps" or "gbit" => 1_000_000_000d / 8d,
            "k" or "kb" or "kbps" or "kbit" => 1_000d / 8d,
            "b" or "bps" or "bit" => 1d / 8d,
            var unit => throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) has an unknown '{key}' unit [{unit}]; this build understands bps, kbps, mbps and gbps"),
        };

        return (ulong)Math.Round(number * multiplier);
    }

    /// <summary>
    /// Loads the extra trust anchors from <c>ca</c> (a file) and <c>ca-str</c> (inline
    /// PEM). A file may hold either PEM or a single DER certificate.
    /// </summary>
    private static X509Certificate2Collection? LoadCustomRoots(ProxyConfigEntry entry)
    {
        var path = entry.Map.GetNonEmptyString("ca");
        var pem = entry.Map.GetNonEmptyString("ca-str") ?? entry.Map.GetNonEmptyString("ca_str");
        if (path is null && pem is null) return null;

        var roots = new X509Certificate2Collection();
        if (path is not null)
        {
            byte[] bytes;
            try
            {
                bytes = File.ReadAllBytes(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                throw new ProxyCreationException($"proxy [{entry.Name}] (hysteria2) cannot read 'ca' [{path}]: {ex.Message}");
            }

            try
            {
                roots.ImportFromPem(Encoding.UTF8.GetString(bytes));
            }
            catch (CryptographicException)
            {
                roots.Add(X509CertificateLoader.LoadCertificate(bytes));
            }
        }

        if (pem is not null)
        {
            try
            {
                roots.ImportFromPem(pem);
            }
            catch (CryptographicException ex)
            {
                throw new ProxyCreationException($"proxy [{entry.Name}] (hysteria2) has an unreadable 'ca-str': {ex.Message}");
            }
        }

        if (roots.Count == 0)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (hysteria2) configured a CA that contained no certificate");
        }

        return roots;
    }

    /// <summary>
    /// Parses <c>fingerprint</c> (the reference's <c>pinSHA256</c>) into the 32 raw
    /// bytes of a SHA-256. Both the base64 spelling the reference emits and plain hex
    /// are accepted.
    /// </summary>
    private static byte[]? ParsePin(ProxyConfigEntry entry)
    {
        var text = entry.Map.GetNonEmptyString("fingerprint")
            ?? entry.Map.GetNonEmptyString("pinSHA256")
            ?? entry.Map.GetNonEmptyString("pin-sha256");
        if (text is null) return null;

        var trimmed = text.Trim();
        byte[]? pin = null;
        try
        {
            pin = Convert.FromBase64String(trimmed);
        }
        catch (FormatException)
        {
            // Not base64; try hex below.
        }

        if (pin is null || pin.Length != 32)
        {
            var hex = trimmed.Replace(":", string.Empty, StringComparison.Ordinal).Replace(" ", string.Empty, StringComparison.Ordinal);
            if (hex.Length == 64)
            {
                try
                {
                    pin = Convert.FromHexString(hex);
                }
                catch (FormatException)
                {
                    // Not hex either; the validation below reports it.
                }
            }
        }

        if (pin is null || pin.Length != 32)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (hysteria2) has a 'fingerprint' that is not a SHA-256 digest; expected 32 bytes as base64 "
                + "(the reference's pinSHA256 form) or 64 hex digits");
        }

        return pin;
    }

    /// <summary>
    /// Fire-and-forgets an async teardown without discarding the <see cref="ValueTask"/>,
    /// which would risk losing a pooled task source.
    /// </summary>
    private static void Forget(ValueTask task)
    {
        if (task.IsCompletedSuccessfully) return;

        _ = task.AsTask().ContinueWith(
            static t => _ = t.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }
}

/// <summary>Builds <see cref="Hysteria2Adapter"/> instances.</summary>
internal sealed class Hysteria2AdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "hysteria2";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => ["hy2"];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => Hysteria2Adapter.Create(entry, context);
}
