using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Crypto;
using Clash.Core.Proxies.Outbound;
using Clash.Tests.Netstack;
using Xunit;

namespace Clash.Tests.WireGuard;

/// <summary>
/// Drives the initiator against <see cref="FakeWireGuardPeer"/>, a responder
/// written separately from the protocol page. Every assertion here is about bytes
/// on the wire or about state the peer can independently confirm, never about the
/// initiator's own bookkeeping.
/// </summary>
public class WireGuardHandshakeTests
{
    /// <summary>A fixed client static key, so a failing test is reproducible.</summary>
    private static readonly byte[] ClientPrivateKey =
        Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

    /// <summary>A fixed pre-shared key, so the psk2 mixing is exercised in every test.</summary>
    private static readonly byte[] PresharedKey =
        Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    [Fact]
    public async Task InitiationIsOneHundredAndFortyEightBytesWithTheDocumentedLayout()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        var initiation = Assert.Single(peer.Initiations);

        Assert.Equal(WireGuardSession.HandshakeInitiationSize, initiation.Length);
        Assert.Equal(WireGuardSession.MessageHandshakeInitiation, initiation[0]);
        Assert.Equal(new byte[] { 0, 0, 0 }, initiation[1..4]);
        Assert.Equal(0x11223344u, BinaryPrimitives.ReadUInt32LittleEndian(initiation.AsSpan(4)));

        // The ephemeral key must be present and must not be all zeroes.
        Assert.False(WireGuardCrypto.IsAllZero(initiation.AsSpan(8, 32)));

        // mac1 = MAC(HASH("mac1----" �?responder.static_public), msg[0..116)).
        var mac1Key = new byte[WireGuardCrypto.HashSize];
        TestCrypto.Hash("mac1----"u8, peer.PublicKey, mac1Key);
        var expectedMac1 = new byte[WireGuardCrypto.MacSize];
        TestCrypto.Mac(mac1Key, initiation.AsSpan(0, 116), expectedMac1);
        Assert.Equal(expectedMac1, initiation[116..132]);

        // mac2 stays zero until a cookie has been received.
        Assert.Equal(new byte[WireGuardCrypto.MacSize], initiation[132..148]);

        Assert.True(session.IsEstablished);
    }

    [Fact]
    public async Task TheResponseIsParsedAndTheDerivedKeysDecryptWhatThePeerSends()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(session.IsEstablished);
        Assert.Equal(0x55667788u, session.PeerIndex);

        // The peer encrypts with the key it derived as the responder. Decrypting it
        // here is only possible if both sides agree on the whole schedule.
        var inner = InnerPacket("peer-pkt");
        peer.SendInnerPacket(inner);

        var buffer = new byte[2048];
        var read = await session.ReceiveAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(inner.Length, read);
        Assert.Equal(inner, buffer[..read]);
    }

    [Fact]
    public async Task TransportDataRoundTripsWithAnIncrementingCounterAndAVerifiedTag()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        // The handshake's key-confirmation keepalive is counter 0.
        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        var first = InnerPacket("first!!!");
        var second = InnerPacket("second!!");
        await session.SendAsync(first);
        await session.SendAsync(second);

        await peer.WaitForAsync(() => peer.Counters.Count == 3);

        Assert.Equal(new ulong[] { 0, 1, 2 }, peer.Counters);
        Assert.Empty(peer.Plaintexts[0]);
        Assert.Equal(first, peer.InnerPackets[0]);
        Assert.Equal(second, peer.InnerPackets[1]);
        Assert.Equal(3UL, session.SendCounter);

        // Header: type 4, three reserved bytes, the peer's index, the u64 counter.
        var message = peer.TransportMessages[1];
        Assert.Equal(WireGuardSession.MessageTransportData, message[0]);
        Assert.Equal(new byte[] { 0, 0, 0 }, message[1..4]);
        Assert.Equal(0x55667788u, BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(4)));
        Assert.Equal(1UL, BinaryPrimitives.ReadUInt64LittleEndian(message.AsSpan(8)));
        Assert.Equal(WireGuardSession.TransportHeaderSize + first.Length + WireGuardCrypto.MacSize, message.Length);
    }

    [Fact]
    public async Task ATransportMessageWithATamperedTagIsDropped()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        var tampered = InnerPacket("bad!!!!!");
        var good = InnerPacket("good!!!!");
        peer.SendInnerPacket(tampered, corruptTag: true);
        peer.SendInnerPacket(good);

        var buffer = new byte[2048];
        var read = await session.ReceiveAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        // Reading the *second* message proves the first was discarded rather than
        // merely slow: the tampered one carried counter 0 and was never accepted.
        Assert.Equal(good.Length, read);
        Assert.Equal(good, buffer[..read]);
    }

    [Fact]
    public async Task AKeepaliveIsAnEmptyTransportMessageOfExactlyThirtyTwoBytes()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await peer.WaitForAsync(() => peer.TransportMessages.Count == 1);

        var keepalive = peer.TransportMessages[0];
        Assert.Equal(WireGuardSession.KeepaliveSize, keepalive.Length);
        Assert.Equal(32, keepalive.Length);
        Assert.Equal(WireGuardSession.MessageTransportData, keepalive[0]);
        Assert.Equal(0UL, peer.Counters[0]);
        Assert.Empty(peer.Plaintexts[0]);
        Assert.Equal(1UL, session.SendCounter);

        // A keepalive from the peer must not surface as a packet either.
        var good = InnerPacket("good!!!!");
        peer.SendKeepalive();
        peer.SendInnerPacket(good);

        var buffer = new byte[2048];
        var read = await session.ReceiveAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(good.Length, read);
        Assert.Equal(good, buffer[..read]);
    }

    [Fact]
    public async Task ACookieReplyIsDecryptedAndTheInitiationIsRetriedWithAMac2()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey) { CookieRepliesRemaining = 1 };
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await peer.WaitForAsync(() => peer.Initiations.Count == 2);

        Assert.True(session.IsEstablished);

        var first = peer.Initiations[0];
        var second = peer.Initiations[1];

        // The first attempt carries no cookie, so mac2 is zero.
        Assert.Equal(new byte[WireGuardCrypto.MacSize], first[132..148]);

        // The retry carries mac2 = MAC(cookie, msg[0..132)); the fake peer verifies
        // it too, and would have failed the test if it were wrong.
        Assert.NotEqual(new byte[WireGuardCrypto.MacSize], second[132..148]);
        var expectedMac2 = new byte[WireGuardCrypto.MacSize];
        TestCrypto.Mac(peer.Cookie!, second.AsSpan(0, 132), expectedMac2);
        Assert.Equal(expectedMac2, second[132..148]);
    }

    [Fact]
    public async Task AnUnansweredInitiationIsRetriedAndThenAbandonedWithAClearError()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey) { IgnoreInitiations = true };
        await using var session = new WireGuardSession(
            Options(peer, maxTimerHandshakes: 3, rekeyTimeout: TimeSpan.FromMilliseconds(50)),
            peer.CreateClientTransport());

        var failure = await Assert
            .ThrowsAsync<ClashException>(() => session.SendKeepaliveAsync().AsTask())
            ;

        Assert.Contains("did not complete the handshake", failure.Message, StringComparison.Ordinal);
        Assert.Equal(3, peer.Initiations.Count);
        Assert.False(session.IsEstablished);
    }

    [Fact]
    public async Task ReachingRekeyAfterMessagesForcesAFreshHandshakeBeforeTheNextSend()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(
            Options(peer, rekeyAfterMessages: 1),
            peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(peer.Initiations);

        var packet = InnerPacket("fresh!!!");
        await session.SendAsync(packet);
        await peer.WaitForAsync(() => peer.InnerPackets.Count == 1);

        Assert.Equal(2, peer.Initiations.Count);
        Assert.Equal(packet, peer.InnerPackets[0]);
    }

    [Fact]
    public async Task TheRawPacketConnectionRefusesAPayloadThatIsNotAnIpv4Datagram()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());
        await using var connection = new WireGuardPacketConnection(session);

        Assert.False(connection.SupportsMultipleDestinations);

        var failure = await Assert
            .ThrowsAsync<ClashException>(() =>
                connection.SendAsync("not an ip packet"u8.ToArray(), peer.OuterEndPoint).AsTask())
            ;

        Assert.Contains("complete IPv4 datagram", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AKeepaliveIsOwedWhenDataArrivesAndNothingHasBeenSentForKeepaliveTimeout()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(
            Options(peer, keepaliveTimeout: TimeSpan.FromMilliseconds(20)),
            peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await peer.WaitForAsync(() => peer.TransportMessages.Count == 1);

        // Let the keepalive interval elapse, then have the peer speak: the receive
        // path is where the "received but have not sent" rule is evaluated.
        await Task.Delay(TimeSpan.FromMilliseconds(60));

        var inner = InnerPacket("peer-pkt");
        peer.SendInnerPacket(inner);

        var buffer = new byte[2048];
        var read = await session.ReceiveAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(inner, buffer[..read]);

        await peer.WaitForAsync(() => peer.TransportMessages.Count == 2);

        Assert.Equal(WireGuardSession.KeepaliveSize, peer.TransportMessages[1].Length);
        Assert.Equal(1UL, peer.Counters[1]);
        Assert.Empty(peer.Plaintexts[1]);
    }

    [Fact]
    public async Task ASessionOlderThanRekeyAfterTimeIsReplacedBeforeTheNextSend()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(
            Options(peer, rekeyAfterTime: TimeSpan.FromMilliseconds(30)),
            peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Single(peer.Initiations);

        await Task.Delay(TimeSpan.FromMilliseconds(80));

        var packet = InnerPacket("fresh!!!");
        await session.SendAsync(packet);

        await peer.WaitForAsync(() => peer.InnerPackets.Count == 1);

        // Only the initiator rekeys on time, and it must do so before it sends
        // anything under the ageing key.
        Assert.Equal(2, peer.Initiations.Count);
        Assert.Equal(packet, peer.InnerPackets[0]);
    }

    [Fact]
    public async Task AReplayedTransportMessageIsRefusedByTheReplayWindow()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        var buffer = new byte[2048];
        var first = InnerPacket("first!!!");
        peer.SendInnerPacket(first);
        var read = await session.ReceiveAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(first, buffer[..read]);

        // Counter 0 again, byte for byte: a valid tag over a counter that has
        // already been accepted. It must be dropped after the tag check, not before.
        peer.ReplayLastSent();

        var second = InnerPacket("second!!");
        peer.SendInnerPacket(second);
        read = await session.ReceiveAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(second, buffer[..read]);
    }

    /// <summary>
    /// Session options tuned for a test: a fixed sender index, no jitter, and a
    /// retry window generous enough that a cold JIT cannot turn a prompt answer into
    /// a retry. Tests that need the retry to happen quickly pass a shorter
    /// <c>rekeyTimeout</c>.
    /// </summary>
    private static WireGuardSessionOptions Options(
        FakeWireGuardPeer peer,
        ulong rekeyAfterMessages = 1UL << 60,
        int maxTimerHandshakes = 18,
        TimeSpan? keepaliveTimeout = null,
        TimeSpan? rekeyAfterTime = null,
        TimeSpan? rekeyTimeout = null)
        => new()
        {
            LocalPrivateKey = ClientPrivateKey,
            PeerPublicKey = peer.PublicKey,
            PresharedKey = PresharedKey,
            SenderIndex = 0x11223344,
            RekeyTimeout = rekeyTimeout ?? TimeSpan.FromMilliseconds(500),
            RekeyTimeoutJitterMaxMs = 1,
            RekeyAttemptTime = TimeSpan.FromSeconds(5),
            MaxTimerHandshakes = maxTimerHandshakes,
            RekeyAfterMessages = rekeyAfterMessages,
            KeepaliveTimeout = keepaliveTimeout ?? TimeSpan.FromSeconds(10),
            RekeyAfterTime = rekeyAfterTime ?? TimeSpan.FromSeconds(120),
        };

    /// <summary>
    /// Builds an inner IPv4/TCP datagram whose total length is a multiple of 16, so
    /// the session's PaddingMultiple adds nothing and the byte comparison is exact.
    /// </summary>
    private static byte[] InnerPacket(string payload)
    {
        var bytes = Encoding.ASCII.GetBytes(payload);
        Assert.Equal(8, bytes.Length);

        return TestPackets.Build(
            TestPackets.Address("10.0.0.2"),
            TestPackets.Address("93.184.216.34"),
            40000,
            443,
            1000,
            1,
            (byte)(TestPackets.FlagAck | TestPackets.FlagPsh),
            bytes);
    }
}
