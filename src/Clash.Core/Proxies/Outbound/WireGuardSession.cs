using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Channels;
using Clash.Core.Common;
using Clash.Core.Crypto;
using Clash.Core.Netstack;

namespace Clash.Core.Proxies.Outbound;

/// <summary>How a pending handshake attempt ended.</summary>
internal enum WireGuardHandshakeOutcome
{
    /// <summary>A valid message 2 arrived and the session keys were derived.</summary>
    Response,

    /// <summary>A cookie reply arrived; the initiation must be resent with a valid mac2.</summary>
    Cookie,
}

/// <summary>
/// Everything a <see cref="WireGuardSession"/> needs that comes from the
/// configuration, plus the timer constants the protocol fixes.
/// <para>
/// The defaults are the verbatim WireGuard v1 values from
/// <c>device/constants.go</c>. They are settable only so the test suite can drive
/// a retry or a rekey in milliseconds instead of minutes; a production adapter
/// never changes them.
/// </para>
/// </summary>
public sealed class WireGuardSessionOptions
{
    /// <summary>Our static Curve25519 private key, 32 bytes.</summary>
    public required byte[] LocalPrivateKey { get; init; }

    /// <summary>The peer's static Curve25519 public key, 32 bytes.</summary>
    public required byte[] PeerPublicKey { get; init; }

    /// <summary>
    /// The optional pre-shared key, 32 bytes. <c>null</c> means "no PSK", which the
    /// protocol represents as 32 zero bytes mixed at exactly the same point.
    /// </summary>
    public byte[]? PresharedKey { get; init; }

    /// <summary>
    /// The three WARP "reserved" bytes, or null for standard WireGuard (which
    /// requires the field to be zero). Cloudflare's WARP service reads them out of
    /// the handshake initiation; a standard peer ignores the field entirely.
    /// </summary>
    public byte[]? Reserved { get; init; }

    /// <summary>
    /// A fixed sender index, or 0 to draw a fresh random one for every handshake.
    /// Only tests set this: two live handshakes must never share an index.
    /// </summary>
    public uint SenderIndex { get; init; }

    /// <summary>How long a completed session is used before the initiator rekeys.</summary>
    public TimeSpan RekeyAfterTime { get; init; } = TimeSpan.FromSeconds(120);

    /// <summary>How long the initiator keeps retrying a handshake before giving up.</summary>
    public TimeSpan RekeyAttemptTime { get; init; } = TimeSpan.FromSeconds(90);

    /// <summary>How long an unanswered initiation waits before it is retried.</summary>
    public TimeSpan RekeyTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>The exclusive upper bound of the per-attempt jitter, in milliseconds.</summary>
    public int RekeyTimeoutJitterMaxMs { get; init; } = 334;

    /// <summary>How long a session may still receive before its key is refused outright.</summary>
    public TimeSpan RejectAfterTime { get; init; } = TimeSpan.FromSeconds(180);

    /// <summary>How long after receiving with nothing sent a keepalive is due.</summary>
    public TimeSpan KeepaliveTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>How long a received cookie is reused before a fresh one is demanded.</summary>
    public TimeSpan CookieRefreshTime { get; init; } = TimeSpan.FromSeconds(120);

    /// <summary>The number of initiation attempts before the handshake is abandoned.</summary>
    public int MaxTimerHandshakes { get; init; } = 18;

    /// <summary>The send counter at which the initiator rekeys.</summary>
    public ulong RekeyAfterMessages { get; init; } = 1UL << 60;

    /// <summary>The send counter at which the key must not be used again.</summary>
    public ulong RejectAfterMessages { get; init; } = ulong.MaxValue - (1UL << 13);

    /// <summary>The number of prior counters the replay window remembers.</summary>
    public int ReplayWindowSize { get; init; } = 2048;

    /// <summary>Throws when a value cannot be honoured.</summary>
    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(LocalPrivateKey);
        ArgumentNullException.ThrowIfNull(PeerPublicKey);

        if (LocalPrivateKey.Length != WireGuardCrypto.KeySize)
        {
            throw new ProxyCreationException($"wireguard: 'private-key' must decode to {WireGuardCrypto.KeySize} bytes");
        }

        if (PeerPublicKey.Length != WireGuardCrypto.KeySize)
        {
            throw new ProxyCreationException($"wireguard: 'public-key' must decode to {WireGuardCrypto.KeySize} bytes");
        }

        if (PresharedKey is not null && PresharedKey.Length != WireGuardCrypto.KeySize)
        {
            throw new ProxyCreationException($"wireguard: 'pre-shared-key' must decode to {WireGuardCrypto.KeySize} bytes");
        }

        if (Reserved is not null && Reserved.Length != 3)
        {
            throw new ProxyCreationException("wireguard: 'reserved' must be exactly 3 bytes (the WARP convention)");
        }

        if (RekeyTimeout <= TimeSpan.Zero || RekeyAttemptTime <= TimeSpan.Zero || RejectAfterTime <= TimeSpan.Zero)
        {
            throw new ProxyCreationException("wireguard: the rekey and reject intervals must be positive");
        }

        if (MaxTimerHandshakes < 1)
        {
            throw new ProxyCreationException("wireguard: MaxTimerHandshakes must be at least 1");
        }

        if (ReplayWindowSize < 64 || ReplayWindowSize % 64 != 0)
        {
            throw new ProxyCreationException("wireguard: the replay window must be a positive multiple of 64");
        }

        if (RekeyAfterMessages >= RejectAfterMessages)
        {
            throw new ProxyCreationException("wireguard: RekeyAfterMessages must be below RejectAfterMessages");
        }
    }
}

/// <summary>
/// One WireGuard v1 session, as the <em>initiator only</em>.
/// <para>
/// The handshake is <c>Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s</c>, transcribed
/// literally from the protocol page: message 1 is 148 bytes, message 2 is 92
/// bytes, a cookie reply is 64 bytes, and every transport message is a 16-byte
/// header (<c>type</c>, 3 reserved bytes, <c>receiver_index</c> u32 LE,
/// <c>counter</c> u64 LE) followed by the sealed, zero-padded inner IP packet and
/// its 16-byte Poly1305 tag.
/// </para>
/// <para>
/// Why the responder half is absent: this repository only ever acts as the client
/// of a configured peer. Implementing the responder would add a state machine that
/// nothing can exercise and that a bug could silently corrupt the initiator with,
/// so a datagram whose type is <c>1</c> is dropped rather than answered.
/// </para>
/// <para>
/// Timers are evaluated on activity, not by a timer thread: an idle session has
/// nothing to keep alive, and the next send rekeys first if the key has aged out.
/// The one exception is the keepalive a received-but-not-sent-for window owes the
/// peer, which the receive pump emits as soon as it notices. A background timer
/// would make the session non-deterministic under test for no protocol benefit.
/// </para>
/// <para>
/// Out of scope, and refused rather than approximated: the responder role,
/// multiple peers (one session binds one static key pair to one peer), roaming
/// and endpoint updates (the transport's peer is fixed for the session's life),
/// IPv6, IP fragmentation, and the AmneziaWG fork, whose wire format differs and
/// which must be rejected by the adapter rather than spoken as plain WireGuard.
/// </para>
/// </summary>
public sealed class WireGuardSession : IAsyncDisposable
{
    /// <summary>Handshake initiation, client to server.</summary>
    public const byte MessageHandshakeInitiation = 1;

    /// <summary>Handshake response, server to client.</summary>
    public const byte MessageHandshakeResponse = 2;

    /// <summary>Cookie reply, server to client, sent only under load.</summary>
    public const byte MessageCookieReply = 3;

    /// <summary>Transport data (or a keepalive), either direction.</summary>
    public const byte MessageTransportData = 4;

    /// <summary>The exact size of a handshake initiation.</summary>
    public const int HandshakeInitiationSize = 148;

    /// <summary>The exact size of a handshake response.</summary>
    public const int HandshakeResponseSize = 92;

    /// <summary>The exact size of a cookie reply.</summary>
    public const int CookieReplySize = 64;

    /// <summary>The fixed size of a transport message header.</summary>
    public const int TransportHeaderSize = 16;

    /// <summary>The size of a keepalive: the header plus an empty plaintext's tag.</summary>
    public const int KeepaliveSize = TransportHeaderSize + WireGuardCrypto.MacSize;

    /// <summary>PaddingMultiple: inner packets are padded up to a multiple of this.</summary>
    private const int PaddingMultiple = 16;

    /// <summary>The offset of <c>mac1</c> in a handshake initiation.</summary>
    private const int InitiationMac1Offset = 116;

    /// <summary>The offset of <c>mac2</c> in a handshake initiation.</summary>
    private const int InitiationMac2Offset = 132;

    /// <summary>The offset of <c>mac1</c> in a handshake response.</summary>
    private const int ResponseMac1Offset = 60;

    private readonly WireGuardSessionOptions _options;
    private readonly IWireGuardDatagramTransport _transport;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _handshakeGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly ReplayWindow _replay;
    private readonly Task _pump;

    private readonly byte[] _localPublicKey;
    private readonly byte[] _presharedKey;

    // Handshake state, valid between building an initiation and consuming the
    // matching response.
    private byte[] _chainKey = new byte[WireGuardCrypto.HashSize];
    private byte[] _hash = new byte[WireGuardCrypto.HashSize];
    private byte[] _ephemeralPrivate = [];
    private byte[] _lastInitiationMac1 = [];
    private uint _senderIndex;
    private TaskCompletionSource<WireGuardHandshakeOutcome>? _pendingHandshake;

    // Cookie state.
    private byte[]? _cookie;
    private DateTimeOffset _cookieAt;

    // Established session state.
    private byte[] _sendingKey = [];
    private byte[] _receivingKey = [];
    private uint _peerIndex;

    /// <summary>
    /// The sender index of the session currently in use, which is what an inbound
    /// transport message must name as its receiver index. It is kept separately
    /// from <see cref="_senderIndex"/> so that a handshake in flight — which
    /// overwrites the latter — does not blind the session that is still carrying
    /// traffic.
    /// </summary>
    private uint _sessionSenderIndex;

    private ulong _sendCounter;
    private bool _established;
    private DateTimeOffset _establishedAt;
    private DateTimeOffset _lastSentAt;
    private DateTimeOffset _lastReceivedAt;

    private long _lastTimestampTicks;
    private int _handshakeCount;
    private int _disposed;

    /// <summary>Creates a session and starts its receive pump.</summary>
    /// <param name="options">Keys and timers.</param>
    /// <param name="transport">The datagram pipe to the peer. It is disposed with the session.</param>
    /// <param name="timeProvider">The clock the timers read; defaults to the system clock.</param>
    public WireGuardSession(
        WireGuardSessionOptions options,
        IWireGuardDatagramTransport transport,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(transport);

        options.Validate();
        _options = options;
        _transport = transport;
        _time = timeProvider ?? TimeProvider.System;
        _replay = new ReplayWindow(options.ReplayWindowSize);

        _localPublicKey = WireGuardCrypto.PublicKeyFrom(options.LocalPrivateKey);
        _presharedKey = options.PresharedKey ?? new byte[WireGuardCrypto.KeySize];

        var now = _time.GetUtcNow();
        _lastSentAt = now;
        _lastReceivedAt = now;
        _establishedAt = now;

        _pump = Task.Run(PumpAsync);
    }

    /// <summary>True once a handshake response has been accepted.</summary>
    public bool IsEstablished
    {
        get
        {
            lock (_gate) return _established;
        }
    }

    /// <summary>The peer's index for the current session, learned from the response.</summary>
    public uint PeerIndex
    {
        get
        {
            lock (_gate) return _peerIndex;
        }
    }

    /// <summary>The next counter this session will send under.</summary>
    public ulong SendCounter
    {
        get
        {
            lock (_gate) return _sendCounter;
        }
    }

    /// <summary>How many initiations this session has sent.</summary>
    public int HandshakeCount => Volatile.Read(ref _handshakeCount);

    /// <summary>The local endpoint of the underlying transport, when it has one.</summary>
    public EndPoint? LocalEndPoint => _transport.LocalEndPoint;

    /// <summary>The peer's endpoint, when the transport is connected to one.</summary>
    public EndPoint? RemoteEndPoint => _transport.RemoteEndPoint;

    /// <summary>
    /// Sends one inner IP packet, completing a handshake first when the session has
    /// no usable key. The plaintext is zero-padded to a multiple of 16 bytes and
    /// sealed with the sending key and the current counter.
    /// </summary>
    /// <param name="ipPacket">The complete inner IPv4 datagram.</param>
    /// <param name="cancellationToken">Cancels the handshake and the send.</param>
    public async ValueTask SendAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (ipPacket.IsEmpty)
        {
            throw new ArgumentException("a WireGuard transport message needs a non-empty inner packet", nameof(ipPacket));
        }

        await EnsureUsableAsync(cancellationToken).ConfigureAwait(false);
        await SendTransportAsync(ipPacket, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends an empty transport message. It doubles as the key confirmation the
    /// responder waits for before it will use the new session, which is why an
    /// initiator with nothing queued sends one rather than leaving the handshake
    /// unconfirmed.
    /// </summary>
    /// <param name="cancellationToken">Cancels the handshake and the send.</param>
    public async ValueTask SendKeepaliveAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await EnsureUsableAsync(cancellationToken).ConfigureAwait(false);
        await SendTransportAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Waits for the next inner IP packet. Handshake messages, cookie replies and
    /// keepalives are consumed here and never surface; the returned bytes are the
    /// decrypted plaintext <em>including</em> its zero padding, because stripping it
    /// is the IP layer's job (the inner header's total-length field says how much
    /// of it is real).
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Ends the wait.</param>
    /// <returns>The number of bytes written, or 0 when the session ended.</returns>
    public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        byte[] packet;
        try
        {
            packet = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            // The session ended: report end-of-stream rather than throwing, so the
            // caller's receive loop can stop the way it would on a closed socket.
            return 0;
        }

        // An inner datagram can never exceed 65535 bytes, so a smaller buffer means
        // the caller asked for a truncated read and gets exactly that.
        var copied = Math.Min(packet.Length, buffer.Length);
        packet.AsMemory(0, copied).CopyTo(buffer);
        return copied;
    }

    /// <summary>Stops the pump and disposes the transport.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        await _lifetime.CancelAsync().ConfigureAwait(false);
        _inbound.Writer.TryComplete();

        lock (_gate)
        {
            _pendingHandshake?.TrySetCanceled();
            _pendingHandshake = null;
        }

        try
        {
            await _pump.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation, or a transport that ignores it; the transport is disposed next.
        }

        await _transport.DisposeAsync().ConfigureAwait(false);
        _handshakeGate.Dispose();
        _lifetime.Dispose();
    }

    // ── handshake ────────────────────────────────────────────────────────────

    private bool IsUsable()
    {
        lock (_gate)
        {
            if (!_established) return false;

            var now = _time.GetUtcNow();

            // RejectAfterTime: past this point the peer refuses the key outright,
            // and RekeyAfterTime: only the original initiator rekeys on time.
            if (now - _establishedAt >= _options.RejectAfterTime) return false;
            if (now - _establishedAt >= _options.RekeyAfterTime) return false;

            if (_sendCounter >= _options.RekeyAfterMessages) return false;

            // We sent but nothing came back for KeepaliveTimeout + RekeyTimeout:
            // the path may have been re-bound, so re-handshake before trusting it.
            if (now - _lastReceivedAt >= _options.KeepaliveTimeout + _options.RekeyTimeout) return false;

            return true;
        }
    }

    private async ValueTask EnsureUsableAsync(CancellationToken cancellationToken)
    {
        if (IsUsable()) return;
        await HandshakeAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the initiation/response exchange, retrying an unanswered initiation
    /// after <c>RekeyTimeout</c> plus jitter and obeying a cookie reply immediately.
    /// </summary>
    private async ValueTask HandshakeAsync(CancellationToken cancellationToken)
    {
        await _handshakeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsUsable()) return;

            var startedAt = _time.GetUtcNow();

            for (var attempt = 0; attempt < _options.MaxTimerHandshakes; attempt++)
            {
                if (_time.GetUtcNow() - startedAt >= _options.RekeyAttemptTime) break;

                var initiation = BuildInitiation(out var signal);
                var jitter = TimeSpan.FromMilliseconds(Random.Shared.Next(_options.RekeyTimeoutJitterMaxMs));
                var timeout = _options.RekeyTimeout + jitter;

                await _transport.SendAsync(initiation, cancellationToken).ConfigureAwait(false);
                lock (_gate)
                {
                    _lastSentAt = _time.GetUtcNow();
                }

                var completed = await Task
                    .WhenAny(signal.Task, Task.Delay(timeout, _time, cancellationToken))
                    .ConfigureAwait(false);

                lock (_gate)
                {
                    if (ReferenceEquals(_pendingHandshake, signal)) _pendingHandshake = null;
                }

                if (!ReferenceEquals(completed, signal.Task)) continue;

                var outcome = await signal.Task.ConfigureAwait(false);
                if (outcome == WireGuardHandshakeOutcome.Response)
                {
                    // No separate keepalive here: the send that follows immediately
                    // is itself the key confirmation the responder is waiting for,
                    // and an extra empty message would just burn a counter.
                    return;
                }

                // A cookie reply is not a failure: resend immediately, now carrying
                // a valid mac2 over the cookie the peer just handed us.
            }

            throw new ClashException(
                $"wireguard: the peer [{_transport.RemoteEndPoint}] did not complete the handshake "
                + $"within {_options.RekeyAttemptTime.TotalSeconds:0.###}s ({_options.MaxTimerHandshakes} attempts)");
        }
        finally
        {
            _handshakeGate.Release();
        }
    }

    /// <summary>
    /// Builds message 1 exactly as the protocol page lays it out. The message is
    /// 148 bytes: type, 3 reserved bytes, sender index, ephemeral public key, the
    /// sealed static key (32+16), the sealed timestamp (12+16), and two 16-byte
    /// MACs.
    /// </summary>
    private byte[] BuildInitiation(out TaskCompletionSource<WireGuardHandshakeOutcome> signal)
    {
        var peerPublic = _options.PeerPublicKey;
        var message = new byte[HandshakeInitiationSize];
        message[0] = MessageHandshakeInitiation;

        // Standard WireGuard requires these three bytes to be zero; the WARP
        // service reads them out of the initiation, so they are copied only when
        // the configuration asked for it.
        if (_options.Reserved is { Length: 3 } reserved) reserved.CopyTo(message, 1);

        var ephemeralPrivate = RandomNumberGenerator.GetBytes(WireGuardCrypto.KeySize);
        var ephemeralPublic = WireGuardCrypto.PublicKeyFrom(ephemeralPrivate);

        uint senderIndex;
        byte[] cookie;
        lock (_gate)
        {
            senderIndex = _options.SenderIndex != 0 ? _options.SenderIndex : NextSenderIndex();
            cookie = _cookie is not null && _time.GetUtcNow() - _cookieAt < _options.CookieRefreshTime ? _cookie : [];
        }

        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(4), senderIndex);
        ephemeralPublic.CopyTo(message.AsSpan(8));

        Span<byte> chainKey = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> hash = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> temp = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> key = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> dh = stackalloc byte[WireGuardCrypto.KeySize];

        // chaining_key = HASH(CONSTRUCTION)
        WireGuardCrypto.Hash(WireGuardCrypto.Construction, chainKey);

        // hash = HASH(HASH(chaining_key ‖ IDENTIFIER) ‖ responder.static_public)
        WireGuardCrypto.Hash(chainKey, WireGuardCrypto.Identifier, hash);
        WireGuardCrypto.Hash(hash, peerPublic, hash);

        // hash = HASH(hash ‖ msg.unencrypted_ephemeral)
        WireGuardCrypto.Hash(hash, ephemeralPublic, hash);

        MixKey(chainKey, ephemeralPublic, temp);
        WireGuardCrypto.Dh(ephemeralPrivate, peerPublic, dh);
        MixKey(chainKey, dh, temp);
        DeriveKey(temp, chainKey, key);
        WireGuardCrypto.AeadSeal(key, 0, _localPublicKey, message.AsSpan(40, 48), hash);
        WireGuardCrypto.Hash(hash, message.AsSpan(40, 48), hash);

        MixKeyStatic(chainKey, dh, temp, key);
        Span<byte> timestamp = stackalloc byte[WireGuardCrypto.TimestampSize];
        WireGuardCrypto.Tai64N(NextTimestamp(), timestamp);
        WireGuardCrypto.AeadSeal(key, 0, timestamp, message.AsSpan(88, 28), hash);
        WireGuardCrypto.Hash(hash, message.AsSpan(88, 28), hash);

        Span<byte> mac1Key = stackalloc byte[WireGuardCrypto.HashSize];
        WireGuardCrypto.Hash(WireGuardCrypto.LabelMac1, peerPublic, mac1Key);
        WireGuardCrypto.Mac(mac1Key, message.AsSpan(0, InitiationMac1Offset), message.AsSpan(InitiationMac1Offset, 16));

        if (cookie.Length == WireGuardCrypto.MacSize)
        {
            WireGuardCrypto.Mac(cookie, message.AsSpan(0, InitiationMac2Offset), message.AsSpan(InitiationMac2Offset, 16));
        }

        var pending = new TaskCompletionSource<WireGuardHandshakeOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate)
        {
            chainKey.CopyTo(_chainKey);
            hash.CopyTo(_hash);
            _ephemeralPrivate = ephemeralPrivate;
            _senderIndex = senderIndex;
            _lastInitiationMac1 = message.AsSpan(InitiationMac1Offset, 16).ToArray();
            _pendingHandshake = pending;
            _handshakeCount++;
        }

        CryptographicOperations.ZeroMemory(chainKey);
        CryptographicOperations.ZeroMemory(hash);
        CryptographicOperations.ZeroMemory(temp);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(dh);

        signal = pending;
        return message;
    }

    /// <summary>
    /// A fresh 32-bit sender index. The BCL has no 32-bit random helper, so four
    /// bytes are drawn and read little-endian, which is the order the field uses on
    /// the wire.
    /// </summary>
    private static uint NextSenderIndex()
        => BinaryPrimitives.ReadUInt32LittleEndian(RandomNumberGenerator.GetBytes(4));

    /// <summary>
    /// The second static-key DH of the initiation, factored out so the two
    /// identical <c>MixKey</c>/<c>DeriveKey</c> pairs read the same.
    /// </summary>
    private void MixKeyStatic(Span<byte> chainKey, Span<byte> dh, Span<byte> temp, Span<byte> key)
    {
        WireGuardCrypto.Dh(_options.LocalPrivateKey, _options.PeerPublicKey, dh);
        MixKey(chainKey, dh, temp);
        DeriveKey(temp, chainKey, key);
    }

    /// <summary>
    /// <c>temp = HMAC(chaining_key, data); chaining_key = HMAC(temp, 0x1)</c> — the
    /// Noise <c>MixKey</c>, written out with the literal one-byte label rather than
    /// through a generic HKDF, because the label and the concatenation order
    /// <em>are</em> the specification.
    /// </summary>
    private static void MixKey(Span<byte> chainingKey, ReadOnlySpan<byte> data, Span<byte> temp)
    {
        WireGuardCrypto.Hmac(chainingKey, data, temp);
        Span<byte> one = stackalloc byte[1];
        one[0] = 0x01;
        WireGuardCrypto.Hmac(temp, one, chainingKey);
    }

    /// <summary><c>key = HMAC(temp, chaining_key ‖ 0x2)</c>.</summary>
    private static void DeriveKey(ReadOnlySpan<byte> temp, ReadOnlySpan<byte> chainingKey, Span<byte> key)
    {
        Span<byte> label = stackalloc byte[WireGuardCrypto.HashSize + 1];
        chainingKey.CopyTo(label);
        label[WireGuardCrypto.HashSize] = 0x02;
        WireGuardCrypto.Hmac(temp, label, key);
    }

    /// <summary>
    /// A strictly increasing TAI64N reading. The responder discards an initiation
    /// whose timestamp is not greater than the last one it saw, so two handshakes
    /// inside the clock's resolution must still differ.
    /// </summary>
    private DateTimeOffset NextTimestamp()
    {
        lock (_gate)
        {
            var ticks = _time.GetUtcNow().UtcTicks;
            if (ticks <= _lastTimestampTicks) ticks = _lastTimestampTicks + 1;
            _lastTimestampTicks = ticks;
            return new DateTimeOffset(ticks, TimeSpan.Zero);
        }
    }

    // ── transport ────────────────────────────────────────────────────────────

    private async ValueTask SendTransportAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken)
    {
        byte[] sendingKey;
        uint peerIndex;
        ulong counter;

        lock (_gate)
        {
            if (!_established)
            {
                throw new ClashException("wireguard: the session is not established");
            }

            if (_sendCounter >= _options.RejectAfterMessages)
            {
                throw new ClashException("wireguard: the sending counter reached RejectAfterMessages; the key must not be reused");
            }

            sendingKey = _sendingKey;
            peerIndex = _peerIndex;
            counter = _sendCounter++;

            // Counted as sent even if the send below fails: a counter that is
            // burned is harmless, one that is reused destroys the whole cipher.
            _lastSentAt = _time.GetUtcNow();
        }

        // PaddingMultiple = 16: the inner packet is zero-padded up to the next
        // multiple of sixteen so the ciphertext length reveals only a coarse size.
        var padded = (ipPacket.Length + (PaddingMultiple - 1)) & ~(PaddingMultiple - 1);
        var message = new byte[TransportHeaderSize + padded + WireGuardCrypto.MacSize];

        message[0] = MessageTransportData;
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(4), peerIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(message.AsSpan(8), counter);
        ipPacket.Span.CopyTo(message.AsSpan(TransportHeaderSize));

        // The padding bytes are already zero, so the sealed region can be sealed
        // in place over the message it belongs to.
        WireGuardCrypto.AeadSeal(
            sendingKey,
            counter,
            message.AsSpan(TransportHeaderSize, padded),
            message.AsSpan(TransportHeaderSize));

        await _transport.SendAsync(message, cancellationToken).ConfigureAwait(false);
    }

    // ── receive pump ─────────────────────────────────────────────────────────

    private async Task PumpAsync()
    {
        var token = _lifetime.Token;
        var buffer = ArrayPool<byte>.Shared.Rent(ushort.MaxValue);

        try
        {
            while (!token.IsCancellationRequested)
            {
                var read = await _transport.ReceiveAsync(buffer, token).ConfigureAwait(false);
                if (read <= 0) continue;

                try
                {
                    HandleDatagram(buffer.AsSpan(0, read));
                }
                catch (Exception)
                {
                    // A malformed or hostile datagram must never end the pump; it
                    // is simply dropped, exactly as an unauthenticated packet is.
                }
            }
        }
        catch (Exception)
        {
            // Cancellation, or the transport is gone: either way this pump ends.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            _inbound.Writer.TryComplete();
        }
    }

    private void HandleDatagram(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < 4) return;

        switch (datagram[0])
        {
            case MessageHandshakeResponse:
                HandleResponse(datagram);
                break;
            case MessageCookieReply:
                HandleCookieReply(datagram);
                break;
            case MessageTransportData:
                HandleTransportData(datagram);
                break;
            default:
                // Type 1 (an initiation) and anything unknown: this session is an
                // initiator, so it has no responder state to run.
                break;
        }
    }

    /// <summary>
    /// Validates and consumes message 2, then derives the per-direction transport
    /// keys. Every check the protocol page lists is made in the order it lists
    /// them: exact length, receiver index, mac1, then the empty AEAD that is the
    /// key confirmation.
    /// </summary>
    private void HandleResponse(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length != HandshakeResponseSize) return;

        TaskCompletionSource<WireGuardHandshakeOutcome>? pending;
        byte[] ephemeralPrivate;
        byte[] peerPublic = _options.PeerPublicKey;

        Span<byte> chainKey = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> hash = stackalloc byte[WireGuardCrypto.HashSize];

        lock (_gate)
        {
            pending = _pendingHandshake;
            if (pending is null) return;
            if (BinaryPrimitives.ReadUInt32LittleEndian(datagram[8..]) != _senderIndex) return;

            ephemeralPrivate = _ephemeralPrivate;
            _chainKey.CopyTo(chainKey);
            _hash.CopyTo(hash);
        }

        // mac1 is keyed by HASH("mac1----" ‖ the recipient's static public key),
        // and the recipient of a response is us.
        Span<byte> mac1Key = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> mac1 = stackalloc byte[16];
        WireGuardCrypto.Hash(WireGuardCrypto.LabelMac1, _localPublicKey, mac1Key);
        WireGuardCrypto.Mac(mac1Key, datagram[..ResponseMac1Offset], mac1);
        if (!WireGuardCrypto.FixedTimeEquals(mac1, datagram.Slice(ResponseMac1Offset, 16))) return;

        Span<byte> peerEphemeral = stackalloc byte[WireGuardCrypto.KeySize];
        datagram.Slice(12, WireGuardCrypto.KeySize).CopyTo(peerEphemeral);

        Span<byte> temp = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> temp2 = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> key = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> dh = stackalloc byte[WireGuardCrypto.KeySize];

        // hash = HASH(hash ‖ msg.unencrypted_ephemeral)
        WireGuardCrypto.Hash(hash, peerEphemeral, hash);

        MixKey(chainKey, peerEphemeral, temp);
        WireGuardCrypto.Dh(ephemeralPrivate, peerEphemeral, dh);
        MixKey(chainKey, dh, temp);
        WireGuardCrypto.Dh(_options.LocalPrivateKey, peerEphemeral, dh);
        MixKey(chainKey, dh, temp);

        // psk2: the pre-shared key is mixed after the second DH of the response.
        MixKey(chainKey, _presharedKey, temp);

        // temp2 = HMAC(temp, chaining_key ‖ 0x2); key = HMAC(temp, temp2 ‖ 0x3)
        DeriveKey(temp, chainKey, temp2);
        Span<byte> label3 = stackalloc byte[WireGuardCrypto.HashSize + 1];
        temp2.CopyTo(label3);
        label3[WireGuardCrypto.HashSize] = 0x03;
        WireGuardCrypto.Hmac(temp, label3, key);

        // hash = HASH(hash ‖ temp2), then the empty AEAD that confirms the keys.
        WireGuardCrypto.Hash(hash, temp2, hash);
        Span<byte> nothing = default;
        if (!WireGuardCrypto.AeadOpen(key, 0, datagram.Slice(44, 16), nothing, hash)) return;

        // Data keys: initiator sending = temp2, receiving = temp3.
        Span<byte> temp1 = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> sending = stackalloc byte[WireGuardCrypto.HashSize];
        Span<byte> receiving = stackalloc byte[WireGuardCrypto.HashSize];
        ReadOnlySpan<byte> empty = default;
        WireGuardCrypto.Hmac(chainKey, empty, temp1);
        Span<byte> one = stackalloc byte[1];
        one[0] = 0x01;
        WireGuardCrypto.Hmac(temp1, one, sending);
        Span<byte> label2 = stackalloc byte[WireGuardCrypto.HashSize + 1];
        sending.CopyTo(label2);
        label2[WireGuardCrypto.HashSize] = 0x02;
        WireGuardCrypto.Hmac(temp1, label2, receiving);

        var now = _time.GetUtcNow();
        lock (_gate)
        {
            _sendingKey = sending.ToArray();
            _receivingKey = receiving.ToArray();
            _peerIndex = BinaryPrimitives.ReadUInt32LittleEndian(datagram[4..]);
            _sessionSenderIndex = _senderIndex;
            _sendCounter = 0;
            _established = true;
            _establishedAt = now;
            _lastReceivedAt = now;
            _replay.Reset();
            _pendingHandshake = null;
        }

        CryptographicOperations.ZeroMemory(chainKey);
        CryptographicOperations.ZeroMemory(hash);
        CryptographicOperations.ZeroMemory(temp);
        CryptographicOperations.ZeroMemory(temp2);
        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(dh);
        CryptographicOperations.ZeroMemory(sending);
        CryptographicOperations.ZeroMemory(receiving);
        CryptographicOperations.ZeroMemory(temp1);

        pending.TrySetResult(WireGuardHandshakeOutcome.Response);
    }

    /// <summary>
    /// Consumes message 3. A cookie reply is not an error: the peer is under load
    /// and wants the next initiation to carry a <c>mac2</c> derived from a secret
    /// only it can compute, which is what proves the source address is real.
    /// </summary>
    private void HandleCookieReply(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length != CookieReplySize) return;

        TaskCompletionSource<WireGuardHandshakeOutcome>? pending;
        byte[]? mac1;

        lock (_gate)
        {
            pending = _pendingHandshake;
            mac1 = _lastInitiationMac1.Length == 16 ? _lastInitiationMac1 : null;
        }

        if (pending is null || mac1 is null) return;

        // The cookie is sealed under HASH("cookie--" ‖ the sender's static public
        // key) — here the sender of the cookie reply is our peer.
        Span<byte> key = stackalloc byte[WireGuardCrypto.HashSize];
        WireGuardCrypto.Hash(WireGuardCrypto.LabelCookie, _options.PeerPublicKey, key);

        Span<byte> cookie = stackalloc byte[16];
        if (!XChaCha20Poly1305.TryDecrypt(
                key,
                datagram.Slice(8, 24),
                datagram.Slice(32, 16),
                datagram.Slice(48, 16),
                cookie,
                mac1))
        {
            return;
        }

        lock (_gate)
        {
            _cookie = cookie.ToArray();
            _cookieAt = _time.GetUtcNow();
        }

        pending.TrySetResult(WireGuardHandshakeOutcome.Cookie);
    }

    /// <summary>
    /// Consumes a transport message: verifies the receiver index and the tag,
    /// applies the replay window <em>after</em> the tag check (the protocol's own
    /// ordering, so a forged counter cannot advance the window), then routes the
    /// plaintext.
    /// </summary>
    private void HandleTransportData(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < KeepaliveSize) return;

        byte[] receivingKey;
        ulong counter;

        lock (_gate)
        {
            if (!_established) return;
            // The receiver index names *us*: it is the index we chose for this
            // session in the initiation that created it.
            if (BinaryPrimitives.ReadUInt32LittleEndian(datagram[4..]) != _sessionSenderIndex) return;
            receivingKey = _receivingKey;
            counter = BinaryPrimitives.ReadUInt64LittleEndian(datagram[8..]);
        }

        var sealedBody = datagram[TransportHeaderSize..];
        var plaintext = new byte[sealedBody.Length - WireGuardCrypto.MacSize];
        ReadOnlySpan<byte> empty = default;
        if (!WireGuardCrypto.AeadOpen(receivingKey, counter, sealedBody, plaintext, empty)) return;

        var now = _time.GetUtcNow();
        lock (_gate)
        {
            if (!_replay.TryAccept(counter)) return;
            _lastReceivedAt = now;
        }

        if (plaintext.Length == 0)
        {
            // A keepalive carries nothing; it exists only to keep the path open
            // and to confirm the keys to the responder.
            MaybeSendKeepalive();
            return;
        }

        _inbound.Writer.TryWrite(plaintext);
        MaybeSendKeepalive();
    }

    /// <summary>
    /// The "received something but have not sent for KeepaliveTimeout" rule: an
    /// empty transport message keeps the peer's NAT binding and its own timers
    /// happy. It is fired and forgotten, because a keepalive that cannot be sent
    /// must never stall the receive path.
    /// </summary>
    private void MaybeSendKeepalive()
    {
        bool due;
        lock (_gate)
        {
            due = _established
                && _lastReceivedAt > _lastSentAt
                && _time.GetUtcNow() - _lastSentAt >= _options.KeepaliveTimeout;
        }

        if (due) Forget(SendKeepaliveAsync(_lifetime.Token));
    }

    private static void Forget(ValueTask task)
    {
        if (task.IsCompletedSuccessfully) return;
        _ = Await(task);

        static async Task Await(ValueTask pending)
        {
            try
            {
                await pending.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // A keepalive that cannot be sent is not a session failure.
            }
        }
    }

    /// <summary>
    /// The RFC 6479-style sliding window WireGuard uses: a counter is accepted once
    /// and only once, counters may not be wound backwards, and anything older than
    /// the window is refused outright.
    /// </summary>
    private sealed class ReplayWindow
    {
        private readonly ulong[] _bits;
        private ulong _highest;
        private bool _any;

        internal ReplayWindow(int size) => _bits = new ulong[size / 64];

        internal void Reset()
        {
            Array.Clear(_bits);
            _highest = 0;
            _any = false;
        }

        /// <summary>True when <paramref name="counter"/> is fresh and inside the window.</summary>
        internal bool TryAccept(ulong counter)
        {
            var size = _bits.Length * 64;

            if (!_any)
            {
                _any = true;
                _highest = counter;
                _bits[0] = 1;
                return true;
            }

            if (counter > _highest)
            {
                Shift(counter - _highest);
                _highest = counter;
                _bits[0] |= 1;
                return true;
            }

            var delta = _highest - counter;
            if (delta >= (ulong)size) return false;

            var index = (int)delta;
            var mask = 1UL << (index & 63);
            if ((_bits[index >> 6] & mask) != 0) return false;

            _bits[index >> 6] |= mask;
            return true;
        }

        private void Shift(ulong shift)
        {
            var size = _bits.Length * 64;
            if (shift >= (ulong)size)
            {
                Array.Clear(_bits);
                return;
            }

            var words = (int)(shift >> 6);
            var bits = (int)(shift & 63);

            if (words > 0)
            {
                for (var i = _bits.Length - 1; i >= words; i--) _bits[i] = _bits[i - words];
                for (var i = words - 1; i >= 0; i--) _bits[i] = 0;
            }

            if (bits > 0)
            {
                for (var i = _bits.Length - 1; i >= 1; i--)
                {
                    _bits[i] = (_bits[i] << bits) | (_bits[i - 1] >> (64 - bits));
                }

                _bits[0] <<= bits;
            }
        }
    }
}
