using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The AnyTLS session command byte. The numbering is the one the protocol document
/// fixes (version 1 commands 0-6, version 2 commands 7-10); the constants are named
/// after the document's <c>cmd*</c> identifiers so the framing code reads the same
/// way the specification does.
/// </summary>
internal static class AnyTlsCommand
{
    /// <summary>Padding; the receiver reads the data and discards it silently.</summary>
    internal const byte Waste = 0;

    /// <summary>Open a stream (client to server).</summary>
    internal const byte Syn = 1;

    /// <summary>Stream data.</summary>
    internal const byte Psh = 2;

    /// <summary>Close a stream, i.e. the EOF mark.</summary>
    internal const byte Fin = 3;

    /// <summary>Settings; client to server only, and mandatory as a session's first frame.</summary>
    internal const byte Settings = 4;

    /// <summary>Server to client warning text; both sides then close the session.</summary>
    internal const byte Alert = 5;

    /// <summary>Server to client: a replacement padding scheme.</summary>
    internal const byte UpdatePaddingScheme = 6;

    /// <summary>Version 2: the server reports the stream's outbound handshake result.</summary>
    internal const byte SynAck = 7;

    /// <summary>Version 2: keepalive request.</summary>
    internal const byte HeartRequest = 8;

    /// <summary>Version 2: keepalive reply.</summary>
    internal const byte HeartResponse = 9;

    /// <summary>Version 2: server to client settings.</summary>
    internal const byte ServerSettings = 10;
}

/// <summary>
/// One entry of a padding strategy: either a target size range or the <c>c</c>
/// check mark ("if the user data ran out at this point, stop padding here").
/// </summary>
internal readonly record struct AnyTlsPaddingStep(int Min, int Max, bool Check)
{
    /// <summary>The <c>c</c> check mark.</summary>
    internal static readonly AnyTlsPaddingStep CheckMark = new(0, 0, true);
}

/// <summary>
/// The AnyTLS padding scheme, in the grammar the protocol document defines:
/// <code>
/// stop=N
/// k=MIN-MAX[,...]
/// </code>
/// where <c>stop</c> bounds the packets that are padded at all, <c>k</c> is the
/// packet (TLS write) index and every token of a strategy is either a size range
/// or the <c>c</c> check mark.
/// <para>
/// Only two packets are ever produced by this build — packet 0 (the auth block) and
/// packet 1 (<c>cmdSettings</c> plus the first stream's <c>cmdSYN</c> +
/// <c>cmdPSH</c>) — because one flow opens one session here. Multi-segment
/// strategies and the <c>c</c> marks therefore cannot be honoured; see
/// <see cref="AnyTlsAdapter"/> for the exact limitation.
/// </para>
/// </summary>
internal sealed class AnyTlsPaddingScheme
{
    /// <summary>
    /// The default scheme, verbatim from the protocol document. This exact byte
    /// sequence is also what <see cref="Md5Hex"/> hashes, because the server
    /// compares the advertised digest against its own scheme to decide whether to
    /// push a replacement: hashing anything else would make every session look out
    /// of date.
    /// </summary>
    internal const string DefaultText =
        "stop=8\n"
        + "0=30-30\n"
        + "1=100-400\n"
        + "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        + "3=9-9,500-1000\n"
        + "4=500-1000\n"
        + "5=500-1000\n"
        + "6=500-1000\n"
        + "7=500-1000";

    /// <summary>Largest size a strategy may name; a single padding packet fits one frame.</summary>
    private const int MaxSize = ushort.MaxValue;

    private readonly Dictionary<int, List<AnyTlsPaddingStep>> _packets = [];

    private AnyTlsPaddingScheme(byte[] raw)
    {
        Raw = raw;
        // md5 is a change-detection token here, not a security primitive: the
        // protocol uses it only to decide whether client and server already agree
        // on a padding scheme.
        Md5Hex = Convert.ToHexStringLower(MD5.HashData(raw));
    }

    /// <summary>The bytes this scheme was parsed from; the digest is taken over exactly these.</summary>
    internal byte[] Raw { get; }

    /// <summary>Lower-case hex md5 of <see cref="Raw"/>, as advertised in <c>cmdSettings</c>.</summary>
    internal string Md5Hex { get; }

    /// <summary>Packets <c>0 .. Stop-1</c> are padded; later packets are sent as they are.</summary>
    internal int Stop { get; private set; }

    /// <summary>The built-in scheme every new connection starts with.</summary>
    internal static AnyTlsPaddingScheme Default { get; } = Parse(Encoding.UTF8.GetBytes(DefaultText))!;

    /// <summary>
    /// Parses a scheme, rejecting anything that does not follow the grammar rather
    /// than silently falling back: a scheme that cannot be understood would produce
    /// traffic the operator did not ask for.
    /// </summary>
    internal static bool TryParse(ReadOnlySpan<byte> raw, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out AnyTlsPaddingScheme? scheme)
        => (scheme = Parse(raw)) is not null;

    private static AnyTlsPaddingScheme? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.IsEmpty) return null;

        var parsed = new AnyTlsPaddingScheme(raw.ToArray());
        var stop = -1;

        foreach (var rawLine in Encoding.UTF8.GetString(raw).Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0) continue;

            var separator = line.IndexOf('=');
            if (separator <= 0 || separator == line.Length - 1) return null;

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..];

            if (key.Equals("stop", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(value, out stop) || stop < 0) return null;
                continue;
            }

            if (!int.TryParse(key, out var packet) || packet < 0) return null;
            if (!TryParseSteps(value, out var steps)) return null;
            parsed._packets[packet] = steps;
        }

        // `stop` is what bounds the scheme; without it the document's grammar is
        // incomplete and nothing should be padded.
        if (stop < 0) return null;

        parsed.Stop = stop;
        return parsed;
    }

    private static bool TryParseSteps(string value, out List<AnyTlsPaddingStep> steps)
    {
        steps = [];

        foreach (var rawToken in value.Split(','))
        {
            var token = rawToken.Trim();
            if (token.Length == 0) continue;

            if (token.Equals("c", StringComparison.OrdinalIgnoreCase))
            {
                steps.Add(AnyTlsPaddingStep.CheckMark);
                continue;
            }

            var dash = token.IndexOf('-');
            if (dash <= 0 || dash == token.Length - 1) return false;
            if (!int.TryParse(token[..dash], out var min) || !int.TryParse(token[(dash + 1)..], out var max)) return false;
            if (min < 0 || max < min || max > MaxSize) return false;

            steps.Add(new AnyTlsPaddingStep(min, max, false));
        }

        return steps.Count > 0;
    }

    /// <summary>
    /// The size of <c>padding0</c>: packet 0 is the only padded packet outside the
    /// session loop, and the document requires it to be sent together with the
    /// credential, so its length must be known before any frame is written.
    /// </summary>
    internal int Padding0Length()
        => Stop > 0 && _packets.TryGetValue(0, out var steps) && steps.Count > 0 && !steps[0].Check
            ? Draw(steps[0].Min, steps[0].Max)
            : 0;

    /// <summary>
    /// The target size range for <paramref name="packet"/>, or <see langword="null"/>
    /// when the scheme does not define one (packets at or past <c>stop</c>, and
    /// packets the scheme leaves out, are sent unpadded).
    /// <para>
    /// Only the first token of a strategy is consulted. A multi-segment strategy
    /// describes how to split one logical write across several TLS records, which
    /// <c>SslStream</c> does not let a managed client control; using the first
    /// segment as the target size keeps the byte volume in the intended band
    /// without pretending to reproduce the segmentation.
    /// </para>
    /// </summary>
    internal (int Min, int Max)? TargetFor(int packet)
    {
        if (packet < 0 || packet >= Stop) return null;
        if (!_packets.TryGetValue(packet, out var steps) || steps.Count == 0) return null;

        var first = steps[0];
        return first.Check ? null : (first.Min, first.Max);
    }

    /// <summary>
    /// Draws a size from <c>[min, max)</c>, the way the reference does
    /// (<c>rand.Int(max - min) + min</c>); a degenerate <c>min == max</c> range is
    /// that one size, which is what the default scheme's <c>0=30-30</c> relies on.
    /// </summary>
    internal static int Draw(int min, int max) => max > min ? Random.Shared.Next(min, max) : min;
}

/// <summary>
/// The AnyTLS frame codec. Every frame on the session is
/// <c>[command u8][streamId u32 BE][data length u16 BE][data]</c>, so the header is
/// always seven bytes and the length is what keeps the two sides in step.
/// </summary>
internal static class AnyTlsFrames
{
    /// <summary>Bytes of framing in front of every frame's data.</summary>
    internal const int HeaderSize = 1 + 4 + 2;

    /// <summary>The largest data block a single frame's <c>u16</c> length can describe.</summary>
    internal const int MaxDataLength = ushort.MaxValue;

    /// <summary>Protocol version this build reports in <c>cmdSettings</c>.</summary>
    internal const int ProtocolVersion = 2;

    /// <summary>Writes a frame header into <paramref name="destination"/>.</summary>
    internal static void WriteHeader(Span<byte> destination, byte command, uint streamId, int length)
    {
        if (destination.Length < HeaderSize) throw new ArgumentException($"a frame header needs {HeaderSize} bytes", nameof(destination));
        if (length is < 0 or > MaxDataLength) throw new ArgumentOutOfRangeException(nameof(length));

        destination[0] = command;
        BinaryPrimitives.WriteUInt32BigEndian(destination[1..], streamId);
        BinaryPrimitives.WriteUInt16BigEndian(destination[5..], (ushort)length);
    }

    /// <summary>
    /// The <c>cmdSettings</c> payload: UTF-8 <c>key=value</c> pairs joined by
    /// <c>\n</c>. <c>client</c> names this implementation truthfully rather than
    /// impersonating the reference client, which the protocol document asks of
    /// third-party implementations.
    /// </summary>
    internal static byte[] BuildSettings(string clientName, string paddingMd5)
        => Encoding.UTF8.GetBytes($"v={ProtocolVersion}\nclient={clientName}\npadding-md5={paddingMd5}");
}

/// <summary>
/// One AnyTLS stream: the payload side of a session. Writes become <c>cmdPSH</c>
/// frames on the stream's id; reads pull frames off the session, surface only that
/// stream's payload, translate <c>cmdFIN</c> into EOF, and turn a server
/// <c>cmdAlert</c> or a failed <c>cmdSYNACK</c> into a protocol error so a broken
/// stream fails instead of hanging.
/// </summary>
internal sealed class AnyTlsStream : Stream
{
    /// <summary>
    /// The stream id used for the single flow this adapter carries per session. The
    /// protocol only requires ids to be monotonically increasing within a session,
    /// so the first id is always a legal choice.
    /// </summary>
    internal const uint SingleStreamId = 1;

    private readonly Stream _inner;
    private readonly uint _streamId;
    private readonly ILogger _logger;
    private readonly Action<byte[]>? _onPaddingScheme;

    /// <summary>
    /// Serialises whole frames. The read path answers keepalives on this same
    /// session, so two writers can be live at once and a frame must never be
    /// interleaved with another.
    /// </summary>
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private readonly byte[] _outHeader = new byte[AnyTlsFrames.HeaderSize];
    private readonly byte[] _inHeader = new byte[AnyTlsFrames.HeaderSize];

    /// <summary>Payload of a frame that was larger than the caller's buffer.</summary>
    private byte[]? _leftover;
    private int _leftoverOffset;

    private bool _eof;
    private bool _finSent;
    private bool _disposed;

    internal AnyTlsStream(Stream inner, uint streamId, ILogger logger, Action<byte[]>? onPaddingScheme = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _streamId = streamId;
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _onPaddingScheme = onPaddingScheme;
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

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return 0;

        if (_leftover is not null)
        {
            var take = Math.Min(buffer.Length, _leftover.Length - _leftoverOffset);
            _leftover.AsSpan(_leftoverOffset, take).CopyTo(buffer.Span);
            _leftoverOffset += take;
            if (_leftoverOffset >= _leftover.Length) _leftover = null;
            return take;
        }

        if (_eof) return 0;

        while (true)
        {
            await OutboundIo.ReadExactlyAsync(_inner, _inHeader, cancellationToken).ConfigureAwait(false);

            var command = _inHeader[0];
            var streamId = BinaryPrimitives.ReadUInt32BigEndian(_inHeader.AsSpan(1));
            var length = BinaryPrimitives.ReadUInt16BigEndian(_inHeader.AsSpan(5));

            if (command == AnyTlsCommand.Psh && streamId == _streamId)
            {
                if (length == 0) continue;

                if (length <= buffer.Length)
                {
                    await OutboundIo.ReadExactlyAsync(_inner, buffer[..length], cancellationToken).ConfigureAwait(false);
                    return length;
                }

                // The frame is bigger than the caller asked for; hand over what
                // fits and keep the rest for the next read.
                await OutboundIo.ReadExactlyAsync(_inner, buffer, cancellationToken).ConfigureAwait(false);
                _leftover = new byte[length - buffer.Length];
                _leftoverOffset = 0;
                await OutboundIo.ReadExactlyAsync(_inner, _leftover, cancellationToken).ConfigureAwait(false);
                return buffer.Length;
            }

            // Every other command's data is still part of the byte stream, so it is
            // always read before the command is interpreted: skipping it is what
            // keeps the session in step.
            var data = await ReadDataAsync(length, cancellationToken).ConfigureAwait(false);

            switch (command)
            {
                case AnyTlsCommand.Fin when streamId == _streamId:
                    _eof = true;
                    return 0;

                case AnyTlsCommand.Alert:
                    var alert = Describe(data);
                    _logger.LogWarning("anytls: the server sent an alert and closed the session: {Alert}", alert);
                    throw new ClashException($"anytls: the server sent an alert: {alert}");

                case AnyTlsCommand.SynAck when streamId == _streamId:
                    // An empty payload reports success; anything else is the
                    // server's own error text for the outbound connection.
                    if (data.Length > 0)
                    {
                        throw new ClashException($"anytls: the server could not open the stream: {Describe(data)}");
                    }

                    break;

                case AnyTlsCommand.HeartRequest:
                    // The protocol requires a reply. This build never initiates a
                    // heartbeat of its own, so the tunnel is only probed by peers
                    // that choose to.
                    await WriteFrameAsync(AnyTlsCommand.HeartResponse, 0, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
                    break;

                case AnyTlsCommand.ServerSettings:
                    _logger.LogDebug("anytls: the server reported its settings: {Settings}", Describe(data));
                    break;

                case AnyTlsCommand.UpdatePaddingScheme:
                    // The document scopes a pushed scheme to the sessions opened
                    // after it arrives, so it is stored for the next dial rather
                    // than applied to this one.
                    if (data.Length > 0) _onPaddingScheme?.Invoke(data);
                    break;

                default:
                    // cmdWaste, and any command this build does not know: the
                    // header already said how much data to drop, so the session
                    // stays synchronised either way.
                    break;
            }
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty) return;

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameAsync(AnyTlsCommand.Psh, _streamId, buffer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>
    /// Closes the stream with a <c>cmdFIN</c> so the server can retire it, then
    /// drops the session. The document says a peer that receives <c>cmdFIN</c> must
    /// not reply with one, so this is the only FIN this side ever sends.
    /// </summary>
    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;

            if (!_eof && !_finSent)
            {
                _finSent = true;
                try
                {
                    await _writeLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
                    try
                    {
                        await WriteFrameAsync(AnyTlsCommand.Fin, _streamId, ReadOnlyMemory<byte>.Empty, CancellationToken.None).ConfigureAwait(false);
                    }
                    finally
                    {
                        _writeLock.Release();
                    }
                }
                catch
                {
                    // The session is going away regardless; a FIN that cannot be
                    // delivered is not worth failing a dispose over.
                }
            }

            _writeLock.Dispose();
            try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* already gone */ }
        }

        GC.SuppressFinalize(this);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            // The synchronous path is the abort path (CloseConnections and process
            // teardown); it drops the session without a FIN, because the caller is
            // tearing everything down anyway.
            _disposed = true;
            _writeLock.Dispose();
            try { _inner.Dispose(); } catch { /* already gone */ }
        }

        base.Dispose(disposing);
    }

    /// <summary>
    /// Writes one logical block as one or more frames, splitting on the <c>u16</c>
    /// data length. The caller must hold <see cref="_writeLock"/>.
    /// </summary>
    private async ValueTask WriteFrameAsync(byte command, uint streamId, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        var offset = 0;
        do
        {
            var size = Math.Min(payload.Length - offset, AnyTlsFrames.MaxDataLength);
            AnyTlsFrames.WriteHeader(_outHeader, command, streamId, size);

            await _inner.WriteAsync(_outHeader, cancellationToken).ConfigureAwait(false);
            if (size > 0)
            {
                await _inner.WriteAsync(payload.Slice(offset, size), cancellationToken).ConfigureAwait(false);
            }

            offset += size;
        }
        while (offset < payload.Length);
    }

    /// <summary>Reads a frame's data block; empty when the length is zero.</summary>
    private async ValueTask<byte[]> ReadDataAsync(int length, CancellationToken cancellationToken)
    {
        if (length == 0) return [];

        var data = new byte[length];
        await OutboundIo.ReadExactlyAsync(_inner, data, cancellationToken).ConfigureAwait(false);
        return data;
    }

    private static string Describe(ReadOnlySpan<byte> data)
        => data.IsEmpty ? "<no message>" : Encoding.UTF8.GetString(data);
}

/// <summary>
/// The <c>anytls</c> adapter: TLS over TCP, then a static credential block, then a
/// session of length-prefixed frames.
/// <para>
/// <b>What this build does.</b> One flow opens one TLS connection carrying one
/// stream, with the mandatory <c>cmdSettings</c> as the session's first frame, then
/// <c>cmdSYN</c> and a <c>cmdPSH</c> whose data is the SOCKS5-style destination
/// address, then <c>cmdPSH</c> frames in both directions until <c>cmdFIN</c>. It
/// reads <c>cmdWaste</c>, <c>cmdFIN</c>, <c>cmdAlert</c>, <c>cmdSYNACK</c>,
/// <c>cmdHeartRequest</c>, <c>cmdServerSettings</c> and
/// <c>cmdUpdatePaddingScheme</c>, answers keepalive requests, and remembers a
/// pushed padding scheme for the next session.
/// </para>
/// <para>
/// <b>Session reuse is not implemented.</b> The reference implementation keeps an
/// idle-session pool and multiplexes streams over it, which the protocol document
/// requires of a client. This build opens one session per flow and closes it with
/// the flow, so every connection carries a single stream and the pool never exists.
/// That is legal on the wire (a session may carry one stream) but it costs a TLS
/// handshake per flow and does not reproduce the reference's traffic shape.
/// </para>
/// <para>
/// <b>Padding is approximated.</b> Packet 0 — the auth block — is exact: the
/// default scheme's <c>0=30-30</c> gives the documented 34 bytes of overhead on top
/// of the 32-byte digest. Packet 1 is padded by byte volume only: the scheme's
/// target is drawn from <c>[min, max)</c> and the difference is filled with
/// <c>cmdWaste</c> frames, but the scheme really describes TLS <em>record payload</em>
/// sizes and <see cref="System.Net.Security.SslStream"/> gives a managed client no
/// control over record boundaries or the maximum fragment length, so the resulting
/// record-size distribution is not the reference's. Packets 2 and later, and the
/// multi-segment <c>c</c> strategies, are not padded at all.
/// </para>
/// <para>
/// <b>ALPN.</b> The reference sends no ALPN list. This adapter sets no
/// <c>alpn</c> option either, but the shared TLS layer in this build substitutes its
/// own default list (<c>h2</c>, <c>http/1.1</c>) when the configuration names none,
/// so the ClientHello still advertises protocols the reference's does not.
/// </para>
/// <para>
/// <b>Not implemented.</b> UDP (which would mean speaking sing-box
/// <c>udp-over-tcp</c> v2 to <c>sp.v2.udp-over-tcp.arpa</c>), so <c>udp: true</c> is
/// accepted, reported as unsupported and logged. <c>client-fingerprint</c> is
/// accepted and passed to the TLS layer, which can only reorder cipher suites:
/// on Windows <c>SslStream</c> uses Schannel and cannot present a uTLS ClientHello,
/// so the mimicry the protocol exists to defeat is not reproduced.
/// </para>
/// </summary>
public sealed class AnyTlsAdapter : OutboundAdapter
{
    /// <summary>
    /// Software name and version reported in <c>cmdSettings</c>. The protocol
    /// document asks third-party implementations to name themselves truthfully
    /// instead of impersonating the reference client.
    /// </summary>
    internal const string ClientName = "Clash.NET/1.0.0";

    /// <summary>Raw <c>sha256(password)</c>; the protocol uses no salt and no KDF.</summary>
    private readonly byte[] _passwordHash;

    /// <summary>The entry's options with TLS forced on, so the transport stack wraps the TCP layer.</summary>
    private readonly YamlMap _transportOptions;

    /// <summary>
    /// The padding scheme for the next session. The default scheme is used until a
    /// server pushes a replacement, which then applies to subsequent sessions.
    /// </summary>
    private AnyTlsPaddingScheme _scheme;

    internal AnyTlsAdapter(ProxyConfigEntry entry, AdapterBuildContext context, byte[] passwordHash, AnyTlsPaddingScheme scheme)
        : base(entry, context, ProxyType.AnyTls, udp: false)
    {
        _passwordHash = passwordHash;
        _scheme = scheme;
        _transportOptions = entry.Map.With("tls", true);

        if (entry.Map.GetBool("udp"))
        {
            Logger.LogWarning(
                "proxy [{Name}] (anytls) sets udp: true, but this build does not implement anytls UDP (sing-box udp-over-tcp v2) and will refuse the association",
                entry.Name);
        }
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static AnyTlsAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var password = entry.Map.GetString("password");
        if (string.IsNullOrEmpty(password))
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (anytls) requires a non-empty 'password'");
        }

        // The share-link parser does not emit `padding-scheme`, but the protocol
        // treats it as a first-class parameter, so a YAML entry may set it.
        var scheme = AnyTlsPaddingScheme.Default;
        if (entry.Map.GetNonEmptyString("padding-scheme") is { } text)
        {
            if (!AnyTlsPaddingScheme.TryParse(Encoding.UTF8.GetBytes(text), out var parsed))
            {
                throw new ProxyCreationException($"proxy [{entry.Name}] (anytls) has a malformed 'padding-scheme'");
            }

            scheme = parsed;
        }

        return new AnyTlsAdapter(entry, context, SHA256.HashData(Encoding.UTF8.GetBytes(password)), scheme);
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
            var scheme = Volatile.Read(ref _scheme);

            // Packet 0 and packet 1 are the two TLS writes the padding scheme can
            // describe for this build, and they are written separately so the
            // packet-1 target applies to the session frames alone.
            await WriteAuthAsync(raw, scheme, cancellationToken).ConfigureAwait(false);
            await WriteSessionOpenAsync(raw, scheme, metadata, cancellationToken).ConfigureAwait(false);
            await raw.FlushAsync(cancellationToken).ConfigureAwait(false);

            var framed = new AnyTlsStream(raw, AnyTlsStream.SingleStreamId, Logger, ApplyPaddingScheme);
            return Complete(Wrap(framed, raw));
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <summary>
    /// Packet 0: the static credential block. The server reads the digest, the
    /// big-endian padding length and the padding itself before it will look at a
    /// single frame, and it sends no reply on success — a rejected password simply
    /// ends the connection, or falls back to serving ordinary HTTP.
    /// </summary>
    private async ValueTask WriteAuthAsync(Stream stream, AnyTlsPaddingScheme scheme, CancellationToken cancellationToken)
    {
        var padding = scheme.Padding0Length();
        var block = new byte[_passwordHash.Length + 2 + padding];

        _passwordHash.CopyTo(block, 0);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(_passwordHash.Length), (ushort)padding);
        // The padding bytes stay zero: the server discards them, so their content
        // carries no information, and the reference writes zeros as well.

        await stream.WriteAsync(block, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Packet 1: <c>cmdSettings</c>, then the new stream's <c>cmdSYN</c>, then a
    /// <c>cmdPSH</c> whose data is the SOCKS5-style destination address followed by
    /// its port. <c>cmdSettings</c> must come first or the server rejects the
    /// session with an alert, and the document expects these three frames in the
    /// same TLS write, so they are assembled into one buffer.
    /// </summary>
    private async ValueTask WriteSessionOpenAsync(
        Stream stream,
        AnyTlsPaddingScheme scheme,
        Metadata metadata,
        CancellationToken cancellationToken)
    {
        var settings = AnyTlsFrames.BuildSettings(ClientName, scheme.Md5Hex);
        var host = OutboundOptions.Destination(metadata);
        var addressLength = Socks5Address.Size(host);
        var address = new byte[addressLength];
        Socks5Address.Write(address, host, metadata.DestinationPort);

        var content = AnyTlsFrames.HeaderSize + settings.Length     // cmdSettings
            + AnyTlsFrames.HeaderSize                               // cmdSYN
            + AnyTlsFrames.HeaderSize + addressLength;              // cmdPSH carrying the address

        var waste = PlanPadding(scheme, content);

        var total = content;
        foreach (var length in waste) total += AnyTlsFrames.HeaderSize + length;

        var packet = new byte[total];
        var offset = 0;

        offset += WriteFrame(packet.AsSpan(offset), AnyTlsCommand.Settings, 0, settings);
        offset += WriteFrame(packet.AsSpan(offset), AnyTlsCommand.Syn, AnyTlsStream.SingleStreamId, []);
        offset += WriteFrame(packet.AsSpan(offset), AnyTlsCommand.Psh, AnyTlsStream.SingleStreamId, address);

        // cmdWaste frames close the packet out to the scheme's target size. Their
        // data stays zero, as the document suggests.
        foreach (var length in waste)
        {
            AnyTlsFrames.WriteHeader(packet.AsSpan(offset), AnyTlsCommand.Waste, 0, length);
            offset += AnyTlsFrames.HeaderSize + length;
        }

        await stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Decides how much <c>cmdWaste</c> data packet 1 needs. Returns the data
    /// lengths of the padding frames, in order; empty when the scheme defines no
    /// target for packet 1, or when the content already reaches it.
    /// </summary>
    private static List<int> PlanPadding(AnyTlsPaddingScheme scheme, int content)
    {
        var waste = new List<int>();
        if (scheme.TargetFor(1) is not { } range || content >= range.Max) return waste;

        var target = AnyTlsPaddingScheme.Draw(range.Min, range.Max);
        var remaining = target - content;

        // Each padding frame costs its own header, so the budget is spent in whole
        // frames; a leftover smaller than a header cannot be placed and is dropped
        // rather than overshooting the target.
        while (remaining >= AnyTlsFrames.HeaderSize)
        {
            var data = Math.Min(remaining - AnyTlsFrames.HeaderSize, AnyTlsFrames.MaxDataLength);
            waste.Add(data);
            remaining -= AnyTlsFrames.HeaderSize + data;
        }

        return waste;
    }

    /// <summary>Writes one frame into <paramref name="destination"/> and returns its length.</summary>
    private static int WriteFrame(Span<byte> destination, byte command, uint streamId, ReadOnlySpan<byte> data)
    {
        AnyTlsFrames.WriteHeader(destination, command, streamId, data.Length);
        data.CopyTo(destination[AnyTlsFrames.HeaderSize..]);
        return AnyTlsFrames.HeaderSize + data.Length;
    }

    /// <summary>
    /// Stores a padding scheme the server pushed. It is deliberately not applied to
    /// the session it arrived on: the document scopes a replacement to the sessions
    /// opened afterwards.
    /// </summary>
    private void ApplyPaddingScheme(byte[] raw)
    {
        if (!AnyTlsPaddingScheme.TryParse(raw, out var scheme))
        {
            Logger.LogWarning("anytls: the server pushed a padding scheme this build cannot parse; keeping the current one");
            return;
        }

        Volatile.Write(ref _scheme, scheme);
        Logger.LogInformation(
            "anytls: the server pushed a new padding scheme ({Length} bytes, md5 {Md5}); it applies to the next session",
            raw.Length,
            scheme.Md5Hex);
    }
}

/// <summary>Builds <see cref="AnyTlsAdapter"/> instances.</summary>
internal sealed class AnyTlsAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "anytls";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => AnyTlsAdapter.Create(entry, context);
}
