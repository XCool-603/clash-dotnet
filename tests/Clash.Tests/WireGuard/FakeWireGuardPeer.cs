using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Clash.Core.Proxies.Outbound;
using Clash.Tests.Netstack;

namespace Clash.Tests.WireGuard;

/// <summary>
/// A hand-written WireGuard peer: it implements the <em>responder</em> half of
/// <c>Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s</c> straight from the protocol page,
/// independent of the initiator under test, and then plays the internet on top of
/// the decrypted inner packets.
/// <para>
/// Everything runs in process over two channels; no socket, port or timing
/// dependency exists anywhere. Processing happens on one pump task, so by the time
/// a test observes <see cref="Initiations"/> the peer's own state is already
/// settled and no assertion can race it.
/// </para>
/// <para>
/// The peer also records every transport message it decrypts, which is what lets a
/// test assert the counter sequence, the tag verification and the keepalive
/// without reaching into the initiator's internals.
/// </para>
/// </summary>
internal sealed class FakeWireGuardPeer : IAsyncDisposable
{
    private const byte MessageInitiation = 1;
    private const byte MessageResponse = 2;
    private const byte MessageCookieReply = 3;
    private const byte MessageTransport = 4;
    private const int PaddingMultiple = 16;

    private readonly byte[] _staticPrivateKey;
    private readonly byte[] _presharedKey;
    private readonly byte[] _cookieSecret = RandomNumberGenerator.GetBytes(32);
    private readonly Channel<byte[]> _toPeer = Channel.CreateUnbounded<byte[]>();
    private readonly Channel<byte[]> _toClient = Channel.CreateUnbounded<byte[]>();
    private readonly SemaphoreSlim _progress = new(0);
    private readonly Lock _gate = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _pump;

    private readonly List<byte[]> _initiations = [];
    private readonly List<byte[]> _transportMessages = [];
    private readonly List<ulong> _counters = [];
    private readonly List<byte[]> _plaintexts = [];
    private readonly List<byte[]> _innerPackets = [];

    private uint _peerIndex = 0x55667788;
    private uint _clientIndex;
    private byte[] _receivingKey = [];
    private byte[] _sendingKey = [];
    private ulong _sendCounter;
    private bool _established;
    private byte[]? _cookie;
    private byte[]? _lastSent;
    private int _cookieRepliesRemaining;
    private Exception? _failure;

    // The TCP "internet" the peer answers for.
    private uint _clientAddress;
    private uint _serverAddress;
    private ushort _clientPort;
    private ushort _serverPort;
    private uint _clientNext;
    private uint _serverNext;
    private bool _tcpOpen;

    internal FakeWireGuardPeer(byte[]? presharedKey = null)
    {
        _staticPrivateKey = RandomNumberGenerator.GetBytes(TestCrypto.KeySize);
        PublicKey = TestCrypto.PublicFrom(_staticPrivateKey);
        _presharedKey = presharedKey ?? new byte[TestCrypto.KeySize];
        _pump = Task.Run(PumpAsync);
    }

    /// <summary>The peer's static public key, which the initiator must be configured with.</summary>
    internal byte[] PublicKey { get; }

    /// <summary>The outer UDP endpoint the association is addressed to.</summary>
    internal IPEndPoint OuterEndPoint { get; } = new(IPAddress.Parse("127.0.0.1"), 51820);

    /// <summary>Echo TCP payload back, as a server would.</summary>
    internal bool EchoTcp { get; set; } = true;

    /// <summary>
    /// Accept initiations but never answer them, which is what a peer that has gone
    /// away — or that has silently dropped an unauthorised client — looks like.
    /// </summary>
    internal bool IgnoreInitiations { get; set; }

    /// <summary>The peer's own initial sequence number for the fake TCP flow.</summary>
    internal uint ServerInitialSequence { get; set; } = 5000;

    /// <summary>How many further initiations are answered with a cookie reply instead.</summary>
    internal int CookieRepliesRemaining
    {
        get
        {
            lock (_gate) return _cookieRepliesRemaining;
        }
        set
        {
            lock (_gate) _cookieRepliesRemaining = value;
        }
    }

    /// <summary>The cookie handed out in the last cookie reply, or null.</summary>
    internal byte[]? Cookie
    {
        get
        {
            lock (_gate) return _cookie;
        }
    }

    /// <summary>Every initiation the peer received, in order.</summary>
    internal IReadOnlyList<byte[]> Initiations
    {
        get
        {
            lock (_gate) return [.. _initiations];
        }
    }

    /// <summary>Every transport message the peer received, in order.</summary>
    internal IReadOnlyList<byte[]> TransportMessages
    {
        get
        {
            lock (_gate) return [.. _transportMessages];
        }
    }

    /// <summary>The counter of every transport message the peer decrypted.</summary>
    internal IReadOnlyList<ulong> Counters
    {
        get
        {
            lock (_gate) return [.. _counters];
        }
    }

    /// <summary>The decrypted, still-padded plaintext of every transport message.</summary>
    internal IReadOnlyList<byte[]> Plaintexts
    {
        get
        {
            lock (_gate) return [.. _plaintexts];
        }
    }

    /// <summary>The inner IPv4 packets the peer decrypted, padding stripped.</summary>
    internal IReadOnlyList<byte[]> InnerPackets
    {
        get
        {
            lock (_gate) return [.. _innerPackets];
        }
    }

    /// <summary>True once a response has been sent and the peer has a session.</summary>
    internal bool IsEstablished
    {
        get
        {
            lock (_gate) return _established;
        }
    }

    /// <summary>The client transport a <see cref="WireGuardSession"/> should be built over.</summary>
    internal IWireGuardDatagramTransport CreateClientTransport() => new ClientSide(this);

    /// <summary>
    /// Waits until <paramref name="predicate"/> holds, waking on every datagram the
    /// peer processes. Event-driven and bounded, so a missing packet fails the test
    /// instead of hanging it.
    /// </summary>
    internal async Task WaitForAsync(Func<bool> predicate, int timeoutMilliseconds = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        while (true)
        {
            if (_failure is not null)
            {
                throw new InvalidOperationException("the fake WireGuard peer failed", _failure);
            }

            if (predicate()) return;

            var remaining = (int)(deadline - Environment.TickCount64);
            if (remaining <= 0)
            {
                throw new TimeoutException("the fake WireGuard peer never saw the expected message");
            }

            await _progress.WaitAsync(remaining).ConfigureAwait(false);
        }
    }

    /// <summary>Sends one inner IPv4 packet to the client as a transport message.</summary>
    internal void SendInnerPacket(byte[] ipPacket, bool corruptTag = false)
    {
        lock (_gate)
        {
            if (!_established) throw new InvalidOperationException("the peer has no session yet");
            EncryptAndQueue(ipPacket, corruptTag);
        }
    }

    /// <summary>Sends an empty transport message, as a real peer's keepalive would be.</summary>
    internal void SendKeepalive()
    {
        lock (_gate)
        {
            if (!_established) throw new InvalidOperationException("the peer has no session yet");
            EncryptAndQueue([], corruptTag: false);
        }
    }

    /// <summary>
    /// Re-sends the last transport message verbatim, which is exactly what a
    /// replayed datagram looks like: the same counter under the same key.
    /// </summary>
    internal void ReplayLastSent()
    {
        lock (_gate)
        {
            if (_lastSent is null) throw new InvalidOperationException("the peer has not sent anything yet");
            _toClient.Writer.TryWrite(_lastSent);
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _lifetime.CancelAsync().ConfigureAwait(false);
        _toPeer.Writer.TryComplete();
        _toClient.Writer.TryComplete();

        try
        {
            await _pump.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation; the pump owns nothing that needs unwinding.
        }

        _progress.Dispose();
    }

    // ── responder ────────────────────────────────────────────────────────────

    private async Task PumpAsync()
    {
        try
        {
            await foreach (var datagram in _toPeer.Reader.ReadAllAsync(_lifetime.Token).ConfigureAwait(false))
            {
                try
                {
                    switch (datagram[0])
                    {
                        case MessageInitiation:
                            HandleInitiation(datagram);
                            break;
                        case MessageTransport:
                            HandleTransport(datagram);
                            break;
                        default:
                            throw new InvalidOperationException($"the client sent an unexpected message type {datagram[0]}");
                    }
                }
                catch (Exception exception)
                {
                    _failure ??= exception;
                }
                finally
                {
                    _progress.Release();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Disposed.
        }
    }

    /// <summary>
    /// The responder half of the initiation, transcribed from the protocol page.
    /// The chaining key and hash it recomputes are the same values the initiator
    /// derived, which is what makes the response's AEAD a key confirmation.
    /// </summary>
    private void HandleInitiation(byte[] message)
    {
        if (message.Length != WireGuardSession.HandshakeInitiationSize)
        {
            throw new InvalidOperationException($"an initiation is 148 bytes, got {message.Length}");
        }

        lock (_gate)
        {
            _initiations.Add(message);
        }

        if (IgnoreInitiations) return;

        // mac1 must be MAC(HASH("mac1----" ‖ our static public key), message[0..116)).
        Span<byte> mac1Key = stackalloc byte[TestCrypto.HashSize];
        TestCrypto.Hash("mac1----"u8, PublicKey, mac1Key);
        Span<byte> expectedMac1 = stackalloc byte[TestCrypto.MacSize];
        TestCrypto.Mac(mac1Key, message.AsSpan(0, 116), expectedMac1);
        if (!expectedMac1.SequenceEqual(message.AsSpan(116, 16)))
        {
            throw new InvalidOperationException("the initiation's mac1 is not MAC(HASH(\"mac1----\" ‖ peer public key), msg[0..116))");
        }

        var cookieReplies = Interlocked.Decrement(ref _cookieRepliesRemaining);
        if (cookieReplies >= 0)
        {
            SendCookieReply(message);
            return;
        }

        var cookie = Cookie;
        if (cookie is not null)
        {
            Span<byte> expectedMac2 = stackalloc byte[TestCrypto.MacSize];
            TestCrypto.Mac(cookie, message.AsSpan(0, 132), expectedMac2);
            if (!expectedMac2.SequenceEqual(message.AsSpan(132, 16)))
            {
                throw new InvalidOperationException("the initiation's mac2 does not match the cookie the peer handed out");
            }
        }

        Span<byte> chainKey = stackalloc byte[TestCrypto.HashSize];
        Span<byte> hash = stackalloc byte[TestCrypto.HashSize];
        Span<byte> temp = stackalloc byte[TestCrypto.HashSize];
        Span<byte> temp2 = stackalloc byte[TestCrypto.HashSize];
        Span<byte> key = stackalloc byte[TestCrypto.HashSize];
        Span<byte> dh = stackalloc byte[TestCrypto.KeySize];

        TestCrypto.Hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"u8, chainKey);
        TestCrypto.Hash(chainKey, "WireGuard v1 zx2c4 Jason@zx2c4.com"u8, hash);
        TestCrypto.Hash(hash, PublicKey, hash);

        Span<byte> clientEphemeral = stackalloc byte[TestCrypto.KeySize];
        message.AsSpan(8, TestCrypto.KeySize).CopyTo(clientEphemeral);
        TestCrypto.Hash(hash, clientEphemeral, hash);

        MixKey(chainKey, clientEphemeral, temp);
        TestCrypto.Dh(_staticPrivateKey, clientEphemeral, dh);
        MixKey(chainKey, dh, temp);
        DeriveKey(temp, chainKey, key);

        var clientStatic = new byte[TestCrypto.KeySize];
        if (!TestCrypto.AeadOpen(key, 0, message.AsSpan(40, 48), clientStatic, hash))
        {
            throw new InvalidOperationException("the initiation's encrypted static key did not authenticate");
        }

        TestCrypto.Hash(hash, message.AsSpan(40, 48), hash);

        TestCrypto.Dh(_staticPrivateKey, clientStatic, dh);
        MixKey(chainKey, dh, temp);
        DeriveKey(temp, chainKey, key);

        Span<byte> timestamp = stackalloc byte[12];
        if (!TestCrypto.AeadOpen(key, 0, message.AsSpan(88, 28), timestamp, hash))
        {
            throw new InvalidOperationException("the initiation's encrypted timestamp did not authenticate");
        }

        TestCrypto.Hash(hash, message.AsSpan(88, 28), hash);

        // The response.
        var ephemeralPrivate = RandomNumberGenerator.GetBytes(TestCrypto.KeySize);
        var ephemeralPublic = TestCrypto.PublicFrom(ephemeralPrivate);
        var response = new byte[WireGuardSession.HandshakeResponseSize];
        response[0] = MessageResponse;
        BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(4), _peerIndex);
        BinaryPrimitives.WriteUInt32LittleEndian(
            response.AsSpan(8),
            BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(4)));
        ephemeralPublic.CopyTo(response, 12);

        TestCrypto.Hash(hash, ephemeralPublic, hash);
        MixKey(chainKey, ephemeralPublic, temp);
        TestCrypto.Dh(ephemeralPrivate, clientEphemeral, dh);
        MixKey(chainKey, dh, temp);
        TestCrypto.Dh(ephemeralPrivate, clientStatic, dh);
        MixKey(chainKey, dh, temp);

        // psk2 mixes the pre-shared key after the second DH of the response.
        MixKey(chainKey, _presharedKey, temp);

        DeriveKey(temp, chainKey, temp2);
        Span<byte> label3 = stackalloc byte[TestCrypto.HashSize + 1];
        temp2.CopyTo(label3);
        label3[TestCrypto.HashSize] = 0x03;
        TestCrypto.Hmac(temp, label3, ReadOnlySpan<byte>.Empty, key);

        TestCrypto.Hash(hash, temp2, hash);
        TestCrypto.AeadSeal(key, 0, ReadOnlySpan<byte>.Empty, response.AsSpan(44, 16), hash);
        TestCrypto.Hash(hash, response.AsSpan(44, 16), hash);

        Span<byte> responseMacKey = stackalloc byte[TestCrypto.HashSize];
        TestCrypto.Hash("mac1----"u8, clientStatic, responseMacKey);
        TestCrypto.Mac(responseMacKey, response.AsSpan(0, 60), response.AsSpan(60, 16));

        // Data keys: the responder receives with temp2 and sends with temp3.
        Span<byte> temp1 = stackalloc byte[TestCrypto.HashSize];
        Span<byte> receiving = stackalloc byte[TestCrypto.HashSize];
        Span<byte> sending = stackalloc byte[TestCrypto.HashSize];
        TestCrypto.Hmac(chainKey, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, temp1);
        Span<byte> one = stackalloc byte[1];
        one[0] = 0x01;
        TestCrypto.Hmac(temp1, one, ReadOnlySpan<byte>.Empty, receiving);
        Span<byte> label2 = stackalloc byte[TestCrypto.HashSize + 1];
        receiving.CopyTo(label2);
        label2[TestCrypto.HashSize] = 0x02;
        TestCrypto.Hmac(temp1, label2, ReadOnlySpan<byte>.Empty, sending);

        lock (_gate)
        {
            _receivingKey = receiving.ToArray();
            _sendingKey = sending.ToArray();
            _clientIndex = BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(4));
            _sendCounter = 0;
            _established = true;
        }

        _toClient.Writer.TryWrite(response);
    }

    /// <summary>
    /// Message 3: the peer is "under load" and demands a mac2 on the next
    /// initiation. The cookie is sealed under
    /// <c>HASH("cookie--" ‖ our static public key)</c> with the mac1 of the message
    /// that provoked it as associated data.
    /// </summary>
    private void SendCookieReply(byte[] initiation)
    {
        Span<byte> key = stackalloc byte[TestCrypto.HashSize];
        TestCrypto.Hash("cookie--"u8, PublicKey, key);

        // cookie = MAC(changing_secret, initiator address). The address is opaque to
        // the client, so any stable value works here.
        Span<byte> cookie = stackalloc byte[TestCrypto.MacSize];
        TestCrypto.Mac(_cookieSecret, "127.0.0.1"u8, cookie);

        var nonce = RandomNumberGenerator.GetBytes(24);
        var reply = new byte[WireGuardSession.CookieReplySize];
        reply[0] = MessageCookieReply;
        BinaryPrimitives.WriteUInt32LittleEndian(
            reply.AsSpan(4),
            BinaryPrimitives.ReadUInt32LittleEndian(initiation.AsSpan(4)));
        nonce.CopyTo(reply, 8);

        Clash.Core.Crypto.XChaCha20Poly1305.Encrypt(
            key,
            nonce,
            cookie,
            reply.AsSpan(32, 16),
            reply.AsSpan(48, 16),
            initiation.AsSpan(116, 16));

        lock (_gate)
        {
            _cookie = cookie.ToArray();
        }

        _toClient.Writer.TryWrite(reply);
    }

    /// <summary>
    /// Verifies the receiver index and the tag of a transport message, records it,
    /// and — when it carries an inner packet — hands it to the fake internet.
    /// </summary>
    private void HandleTransport(byte[] message)
    {
        if (message.Length < WireGuardSession.KeepaliveSize)
        {
            throw new InvalidOperationException($"a transport message is at least 32 bytes, got {message.Length}");
        }

        byte[] receivingKey;
        lock (_gate)
        {
            if (!_established) throw new InvalidOperationException("the client sent a transport message before the handshake");
            receivingKey = _receivingKey;
        }

        if (BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(4)) != _peerIndex)
        {
            throw new InvalidOperationException("the transport message names the wrong receiver index");
        }

        var counter = BinaryPrimitives.ReadUInt64LittleEndian(message.AsSpan(8));
        var body = message.AsSpan(16);
        var plaintext = new byte[body.Length - TestCrypto.MacSize];

        if (!TestCrypto.AeadOpen(receivingKey, counter, body, plaintext, ReadOnlySpan<byte>.Empty))
        {
            throw new InvalidOperationException($"the transport message with counter {counter} failed its tag check");
        }

        byte[] inner = [];
        if (plaintext.Length > 0)
        {
            var totalLength = BinaryPrimitives.ReadUInt16BigEndian(plaintext.AsSpan(2));
            if (totalLength < 20 || totalLength > plaintext.Length)
            {
                throw new InvalidOperationException("the inner packet's total length is not inside the padded plaintext");
            }

            inner = plaintext[..totalLength];
        }

        lock (_gate)
        {
            _transportMessages.Add(message);
            _counters.Add(counter);
            _plaintexts.Add(plaintext);
            if (inner.Length > 0) _innerPackets.Add(inner);
        }

        if (inner.Length > 0) HandleInnerPacket(inner);
    }

    /// <summary>The fake internet: answer a SYN with a SYN-ACK and echo TCP payload.</summary>
    private void HandleInnerPacket(byte[] inner)
    {
        if (!TestPackets.TryParse(inner, out var segment)) return;
        if (!segment.ChecksumValid) return;

        lock (_gate)
        {
            if (segment.Syn && !segment.Ack)
            {
                _clientAddress = segment.SourceAddress;
                _serverAddress = segment.DestinationAddress;
                _clientPort = segment.SourcePort;
                _serverPort = segment.DestinationPort;
                _clientNext = segment.Sequence + 1;
                _serverNext = ServerInitialSequence + 1;
                _tcpOpen = true;

                EncryptAndQueue(
                    TestPackets.Build(
                        _serverAddress,
                        _clientAddress,
                        _serverPort,
                        _clientPort,
                        ServerInitialSequence,
                        _clientNext,
                        (byte)(TestPackets.FlagSyn | TestPackets.FlagAck),
                        default,
                        65535,
                        1360),
                    corruptTag: false);
                return;
            }

            if (!_tcpOpen) return;

            if (segment.Payload.Length > 0 && segment.Sequence == _clientNext)
            {
                _clientNext += (uint)segment.Payload.Length;

                if (EchoTcp)
                {
                    EncryptAndQueue(
                        TestPackets.Build(
                            _serverAddress,
                            _clientAddress,
                            _serverPort,
                            _clientPort,
                            _serverNext,
                            _clientNext,
                            (byte)(TestPackets.FlagAck | TestPackets.FlagPsh),
                            segment.Payload),
                        corruptTag: false);
                    _serverNext += (uint)segment.Payload.Length;
                }
                else
                {
                    EncryptAndQueue(
                        TestPackets.Build(
                            _serverAddress,
                            _clientAddress,
                            _serverPort,
                            _clientPort,
                            _serverNext,
                            _clientNext,
                            TestPackets.FlagAck,
                            default),
                        corruptTag: false);
                }

                return;
            }

            if (segment.Fin)
            {
                _clientNext += 1;
                EncryptAndQueue(
                    TestPackets.Build(
                        _serverAddress,
                        _clientAddress,
                        _serverPort,
                        _clientPort,
                        _serverNext,
                        _clientNext,
                        TestPackets.FlagAck,
                        default),
                    corruptTag: false);
            }
        }
    }

    /// <summary>Seals one inner packet (or a keepalive) and queues it for the client.</summary>
    private void EncryptAndQueue(byte[] ipPacket, bool corruptTag)
    {
        var counter = _sendCounter++;
        var padded = (ipPacket.Length + (PaddingMultiple - 1)) & ~(PaddingMultiple - 1);
        var message = new byte[WireGuardSession.TransportHeaderSize + padded + TestCrypto.MacSize];

        message[0] = MessageTransport;
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(4), _clientIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(message.AsSpan(8), counter);
        ipPacket.CopyTo(message, WireGuardSession.TransportHeaderSize);

        TestCrypto.AeadSeal(
            _sendingKey,
            counter,
            message.AsSpan(WireGuardSession.TransportHeaderSize, padded),
            message.AsSpan(WireGuardSession.TransportHeaderSize),
            ReadOnlySpan<byte>.Empty);

        if (corruptTag) message[^1] ^= 0xFF;

        _lastSent = message;
        _toClient.Writer.TryWrite(message);
    }

    private static void MixKey(Span<byte> chainingKey, ReadOnlySpan<byte> data, Span<byte> temp)
    {
        TestCrypto.Hmac(chainingKey, data, ReadOnlySpan<byte>.Empty, temp);
        Span<byte> one = stackalloc byte[1];
        one[0] = 0x01;
        TestCrypto.Hmac(temp, one, ReadOnlySpan<byte>.Empty, chainingKey);
    }

    private static void DeriveKey(ReadOnlySpan<byte> temp, ReadOnlySpan<byte> chainingKey, Span<byte> key)
    {
        Span<byte> label = stackalloc byte[TestCrypto.HashSize + 1];
        chainingKey.CopyTo(label);
        label[TestCrypto.HashSize] = 0x02;
        TestCrypto.Hmac(temp, label, ReadOnlySpan<byte>.Empty, key);
    }

    /// <summary>The client's side of the in-process datagram pipe.</summary>
    private sealed class ClientSide : IWireGuardDatagramTransport
    {
        private readonly FakeWireGuardPeer _peer;

        internal ClientSide(FakeWireGuardPeer peer) => _peer = peer;

        /// <inheritdoc />
        public EndPoint? LocalEndPoint { get; } = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 51820);

        /// <inheritdoc />
        public EndPoint? RemoteEndPoint => _peer.OuterEndPoint;

        /// <inheritdoc />
        public ValueTask<int> SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
        {
            if (!_peer._toPeer.Writer.TryWrite(datagram.ToArray()))
            {
                throw new InvalidOperationException("the fake peer is gone");
            }

            return ValueTask.FromResult(datagram.Length);
        }

        /// <inheritdoc />
        public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            var datagram = await _peer._toClient.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            datagram.CopyTo(buffer);
            return datagram.Length;
        }

        /// <inheritdoc />
        public ValueTask DisposeAsync()
        {
            _peer._toClient.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}
