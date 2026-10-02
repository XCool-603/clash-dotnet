using System.Buffers.Binary;
using System.Net;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Netstack;
using Xunit;

namespace Clash.Tests.Netstack;

/// <summary>
/// End-to-end tests of the TCP client against a hand-written peer. Nothing here
/// touches a socket, binds a port, or sleeps: the peer answers through the host's
/// packet sink, and every wait is event-driven with a bounded timeout.
/// </summary>
public class TcpConnectionTests
{
    private const byte Syn = TestPackets.FlagSyn;
    private const byte Ack = TestPackets.FlagAck;
    private const byte Psh = TestPackets.FlagPsh;

    private static readonly IPEndPoint Remote = new(IPAddress.Parse("93.184.216.34"), 80);

    private static NetstackOptions Options(int retransmitMilliseconds = 40, int attempts = 4) => new()
    {
        LocalAddress = IPAddress.Parse("10.7.0.2"),
        Mss = 1400,
        ReceiveWindowSize = 65535,
        InitialRetransmitTimeout = TimeSpan.FromMilliseconds(retransmitMilliseconds),
        MaxRetransmitTimeout = TimeSpan.FromMilliseconds(200),
        MaxRetransmitAttempts = attempts,
        CloseTimeout = TimeSpan.FromSeconds(2),
    };

    [Fact]
    public async Task HandshakePutsSynOnTheWireAndAcknowledgesTheSynAck()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host) { AutoHandshake = false };
        var connecting = host.ConnectAsync(Remote).AsTask();

        var syn = await peer.WaitForAsync(packet => packet.Syn);

        Assert.False(syn.Ack);
        Assert.False(syn.Fin);
        Assert.False(syn.Psh);
        Assert.False(syn.Rst);
        Assert.True(syn.ChecksumValid);
        Assert.True(syn.IpChecksumValid);
        Assert.Equal("10.7.0.2", syn.SourceText);
        Assert.Equal("93.184.216.34", syn.DestinationText);
        Assert.Equal(80, syn.DestinationPort);
        Assert.Equal(20, syn.IpHeaderLength);
        Assert.Equal(65535, syn.Window);
        Assert.Equal(1400, syn.Mss);
        Assert.Equal(0u, syn.Acknowledgment);
        Assert.Empty(syn.Payload);
        Assert.InRange(syn.SourcePort, 49152, 65535);

        const uint serverIss = 0x4000_0000;
        peer.Send(serverIss, syn.Sequence + 1, (byte)(Syn | Ack), default, 65535, mss: 1400);

        var stream = await connecting;

        var acknowledgment = await peer.WaitForAsync(packet => packet.Ack && !packet.Syn);
        Assert.Equal(syn.Sequence + 1, acknowledgment.Sequence);
        Assert.Equal(serverIss + 1, acknowledgment.Acknowledgment);
        Assert.Equal(syn.SourcePort, acknowledgment.SourcePort);
        Assert.Equal(80, acknowledgment.DestinationPort);
        Assert.Empty(acknowledgment.Payload);
        Assert.True(acknowledgment.ChecksumValid);
        Assert.True(acknowledgment.IpChecksumValid);
        Assert.True(peer.HandshakeComplete);

        Assert.Equal(1, host.ConnectionCount);
        Assert.Equal(Remote, ((TcpFlowStream)stream).RemoteEndPoint);
        Assert.Equal(syn.SourcePort, ((TcpFlowStream)stream).LocalPort);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task FullDuplexRoundTripCarriesPayloadBothWaysAndDropsACorruptSegment()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);

        await stream.WriteAsync("ping"u8.ToArray());

        var received = await peer.WaitForDataAsync();
        Assert.Equal("ping", received.Text);
        Assert.Equal(peer.ClientInitialSequence + 1, received.Sequence);
        Assert.Equal(peer.ServerInitialSequence + 1, received.Acknowledgment);
        Assert.True(received.Psh);
        Assert.True(received.Ack);
        Assert.True(received.ChecksumValid);
        Assert.True(received.IpChecksumValid);
        Assert.Equal(peer.ClientPort, received.SourcePort);
        Assert.Equal(80, received.DestinationPort);

        peer.SendData("pong"u8.ToArray());

        var buffer = new byte[4];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(4, read);
        Assert.Equal("pong", Encoding.ASCII.GetString(buffer));

        var acknowledgment = await peer.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == peer.ServerNextSequence);
        Assert.Equal(peer.ClientNextSequence, acknowledgment.Sequence);

        // A segment whose checksum does not verify must never reach the stream.
        var corruptSequence = peer.ServerNextSequence;
        peer.Send(corruptSequence, peer.ClientNextSequence, (byte)(Ack | Psh), "bad!"u8, corruptChecksum: true);
        peer.SendData("good"u8.ToArray());

        var second = new byte[4];
        var secondRead = await stream.ReadAsync(second).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(4, secondRead);
        Assert.Equal("good", Encoding.ASCII.GetString(second));

        var finalAck = await peer.WaitForAsync(
            packet => packet.Ack && packet.Acknowledgment == corruptSequence + 4);
        Assert.Equal(peer.ClientNextSequence, finalAck.Sequence);
        Assert.DoesNotContain(peer.Received, packet => packet.Ack && packet.Acknowledgment == corruptSequence + 8);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task ADroppedSegmentIsRetransmittedAndThePayloadStillArrivesIntact()
    {
        var host = new NetstackHost(Options(retransmitMilliseconds: 60, attempts: 5));
        await using var peer = new FakeTcpPeer(host) { AutoAcknowledgeData = false };
        var stream = await host.ConnectAsync(Remote);

        var payload = "the quick brown fox"u8.ToArray();
        await stream.WriteAsync(payload);

        var first = await peer.WaitForTextAsync("the quick brown fox");
        Assert.Equal(peer.ClientInitialSequence + 1, first.Sequence);

        // The peer stays silent, so only the retransmission timer can make the
        // payload arrive again, with the same sequence number and the same bytes.
        var retransmission = await peer.WaitForTextAsync("the quick brown fox", skip: 1, timeoutMilliseconds: 3000);
        Assert.Equal(first.Sequence, retransmission.Sequence);
        Assert.Equal(first.Flags, retransmission.Flags);
        Assert.Equal(payload, retransmission.Payload);
        Assert.True(retransmission.ChecksumValid);

        peer.SendAck(retransmission.Sequence + (uint)payload.Length);

        await stream.WriteAsync("second"u8.ToArray());
        var second = await peer.WaitForTextAsync("second");
        Assert.Equal(retransmission.Sequence + (uint)payload.Length, second.Sequence);
        Assert.Equal(peer.ServerInitialSequence + 1, second.Acknowledgment);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task OutOfOrderSegmentsAreBufferedAndDeliveredInOrder()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);

        var sequence = peer.ServerNextSequence;
        peer.Send(sequence + 4, peer.ClientNextSequence, (byte)(Ack | Psh), "EFGH"u8);

        // The client may only acknowledge up to the hole: the handshake
        // acknowledgement is the first such segment, the duplicate is the second.
        var duplicate = await peer.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == sequence,
            skip: 1);
        Assert.Equal(peer.ClientNextSequence, duplicate.Sequence);
        Assert.Empty(duplicate.Payload);

        peer.Send(sequence, peer.ClientNextSequence, (byte)(Ack | Psh), "ABCD"u8);

        var buffer = new byte[8];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(8, read);
        Assert.Equal("ABCDEFGH", Encoding.ASCII.GetString(buffer));

        var acknowledgment = await peer.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == sequence + 8);
        Assert.Equal(peer.ClientNextSequence, acknowledgment.Sequence);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task CleanCloseExchangesFinInBothDirections()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);

        ((IHalfCloseable)stream).ShutdownSend();

        var fin = await peer.WaitForAsync(packet => packet.Fin);
        Assert.True(fin.Ack);
        Assert.False(fin.Syn);
        Assert.Equal(peer.ClientInitialSequence + 1, fin.Sequence);
        Assert.Empty(fin.Payload);
        Assert.True(fin.ChecksumValid);

        peer.SendFin();

        var buffer = new byte[16];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, read);

        var finalAck = await peer.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == peer.ServerNextSequence);
        Assert.Equal(peer.ClientNextSequence, finalAck.Sequence);

        await WaitUntilAsync(() => host.ConnectionCount == 0, TimeSpan.FromSeconds(3));

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task PeerResetSurfacesAsAFailedReadRatherThanAHang()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);

        peer.SendReset();

        var failure = await Assert.ThrowsAsync<IOException>(
            () => stream.ReadAsync(new byte[16]).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Contains("reset", failure.Message, StringComparison.OrdinalIgnoreCase);

        await Assert.ThrowsAsync<IOException>(
            () => stream.WriteAsync("x"u8.ToArray()).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        await WaitUntilAsync(() => host.ConnectionCount == 0, TimeSpan.FromSeconds(3));

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task ResetDuringTheHandshakeFailsTheConnect()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host) { AutoHandshake = false };
        var connecting = host.ConnectAsync(Remote).AsTask();

        var syn = await peer.WaitForAsync(packet => packet.Syn);
        peer.Send(0, syn.Sequence + 1, TestPackets.FlagRst);

        await Assert.ThrowsAsync<IOException>(() => connecting.WaitAsync(TimeSpan.FromSeconds(5)));
        await WaitUntilAsync(() => host.ConnectionCount == 0, TimeSpan.FromSeconds(3));

        await host.DisposeAsync();
    }

    [Fact]
    public async Task UnacknowledgedHandshakeGivesUpInsteadOfHanging()
    {
        var host = new NetstackHost(Options(retransmitMilliseconds: 20, attempts: 2));
        await using var peer = new FakeTcpPeer(host) { AutoHandshake = false };
        var connecting = host.ConnectAsync(Remote).AsTask();

        await peer.WaitForAsync(packet => packet.Syn);
        var retransmission = await peer.WaitForAsync(packet => packet.Syn, skip: 1, timeoutMilliseconds: 3000);
        Assert.True(retransmission.Syn);

        await Assert.ThrowsAsync<IOException>(() => connecting.WaitAsync(TimeSpan.FromSeconds(5)));
        await WaitUntilAsync(() => host.ConnectionCount == 0, TimeSpan.FromSeconds(3));

        await host.DisposeAsync();
    }

    [Fact]
    public async Task SegmentForAnUnknownFlowIsAnsweredWithAReset()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);

        var syn = TestPackets.Build(
            TestPackets.Address("93.184.216.34"),
            TestPackets.Address("10.7.0.2"),
            80,
            51234,
            500,
            0,
            Syn,
            default,
            65535,
            1400);
        host.ProcessPacket(syn);

        var reset = await peer.WaitForAsync(packet => packet.Rst);
        Assert.True(reset.Ack);
        Assert.Equal(0u, reset.Sequence);
        Assert.Equal(501u, reset.Acknowledgment);
        Assert.Equal(51234, reset.SourcePort);
        Assert.Equal(80, reset.DestinationPort);
        Assert.True(reset.ChecksumValid);
        Assert.Equal(0, host.ConnectionCount);

        await host.DisposeAsync();
    }

    [Fact]
    public async Task MalformedPacketsAreIgnoredByTheHost()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);
        var before = peer.ReceivedCount;

        // Too short, then all zeroes (version 0).
        host.ProcessPacket(new byte[3]);
        host.ProcessPacket(new byte[40]);

        // A well-formed SYN addressed somewhere that is not this host.
        host.ProcessPacket(TestPackets.Build(
            TestPackets.Address("93.184.216.34"),
            TestPackets.Address("10.9.9.9"),
            80,
            51234,
            1,
            0,
            Syn,
            default,
            65535,
            1400));

        // A SYN whose checksum does not verify.
        host.ProcessPacket(TestPackets.Build(
            TestPackets.Address("93.184.216.34"),
            TestPackets.Address("10.7.0.2"),
            80,
            51234,
            1,
            0,
            Syn,
            default,
            65535,
            1400,
            corruptChecksum: true));

        // A UDP datagram, which this stack does not carry.
        var udp = TestPackets.Build(
            TestPackets.Address("93.184.216.34"),
            TestPackets.Address("10.7.0.2"),
            80,
            51234,
            1,
            0,
            Syn,
            default,
            65535,
            1400);
        udp[9] = 17;
        var udpHeader = udp.AsSpan(0, TestPackets.IpHeaderLength);
        BinaryPrimitives.WriteUInt16BigEndian(udpHeader[10..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(udpHeader[10..], (ushort)~TestPackets.Sum(udpHeader, 0));
        host.ProcessPacket(udp);

        await stream.WriteAsync("still here"u8.ToArray());
        var data = await peer.WaitForTextAsync("still here");
        Assert.True(data.ChecksumValid);
        Assert.True(peer.ReceivedCount > before);
        Assert.Equal(1, host.ConnectionCount);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task LargeWritesAreSplitOnTheMssWithConsecutiveSequenceNumbers()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);

        var payload = new byte[3000];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index % 251);
        }

        await stream.WriteAsync(payload);

        var first = await peer.WaitForDataAsync();
        var second = await peer.WaitForDataAsync(skip: 1);
        var third = await peer.WaitForDataAsync(skip: 2);

        Assert.Equal(1400, first.Payload.Length);
        Assert.Equal(1400, second.Payload.Length);
        Assert.Equal(200, third.Payload.Length);
        Assert.Equal(peer.ClientInitialSequence + 1, first.Sequence);
        Assert.Equal(first.Sequence + 1400, second.Sequence);
        Assert.Equal(second.Sequence + 1400, third.Sequence);

        var reassembled = new byte[payload.Length];
        first.Payload.CopyTo(reassembled, 0);
        second.Payload.CopyTo(reassembled, first.Payload.Length);
        third.Payload.CopyTo(reassembled, first.Payload.Length + second.Payload.Length);
        Assert.Equal(payload, reassembled);
        Assert.All(peer.Received, packet => Assert.True(packet.Payload.Length <= 1400));
        Assert.True(first.Psh);
        Assert.True(third.Psh);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task SeparateWritesAreEmittedImmediatelyWithoutCoalescing()
    {
        var host = new NetstackHost(Options());
        await using var peer = new FakeTcpPeer(host);
        var stream = await host.ConnectAsync(Remote);

        await stream.WriteAsync("one"u8.ToArray());
        await stream.WriteAsync("two"u8.ToArray());

        var first = await peer.WaitForTextAsync("one");
        var second = await peer.WaitForTextAsync("two");

        // Nothing is held back to fill a segment: the second write leaves at once,
        // on the next sequence number.
        Assert.Equal(first.Sequence + 3, second.Sequence);
        Assert.Equal(2, peer.Received.Count(packet => packet.Payload.Length > 0));
        Assert.True(first.Psh);
        Assert.True(second.Psh);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (!condition())
        {
            if (Environment.TickCount64 > deadline)
            {
                throw new TimeoutException("the condition was never met");
            }

            await Task.Delay(5).ConfigureAwait(false);
        }
    }
}
