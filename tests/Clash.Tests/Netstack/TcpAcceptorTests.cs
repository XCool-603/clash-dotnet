using System.Buffers.Binary;
using System.Net;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Netstack;
using Xunit;

namespace Clash.Tests.Netstack;

/// <summary>
/// Tests of the passive (server) half of the userspace TCP stack, driven by
/// hand-built IPv4/TCP packets through <see cref="TcpAcceptor.ProcessPacket"/> and
/// observed through its packet sink. Nothing here touches a socket, binds a port,
/// opens a TUN interface, or needs administrator rights: the operating system is
/// replaced by <see cref="FakeTcpClient"/>, and every wait is event-driven with a
/// bounded timeout.
/// <para>
/// The packets are built and parsed by <see cref="TestPackets"/>, an independent
/// codec, so a mistake in the sequence or checksum arithmetic under test cannot
/// hide behind a shared implementation.
/// </para>
/// </summary>
public class TcpAcceptorTests
{
    private const byte Fin = TestPackets.FlagFin;
    private const byte Syn = TestPackets.FlagSyn;
    private const byte Rst = TestPackets.FlagRst;
    private const byte Psh = TestPackets.FlagPsh;
    private const byte Ack = TestPackets.FlagAck;

    /// <summary>The address the TUN interface owns.</summary>
    private static readonly uint ServerAddress = TestPackets.Address("10.7.0.2");

    /// <summary>The address of the host that opened the connection.</summary>
    private static readonly uint ClientAddress = TestPackets.Address("10.7.0.9");

    private const ushort ServerPort = 443;
    private const ushort ClientPort = 51000;

    /// <summary>
    /// The retransmit timeout is deliberately far longer than any test: only the
    /// tests that are about retransmission shorten it, so an assertion can never
    /// race a duplicate segment.
    /// </summary>
    private static NetstackOptions Options(
        int retransmitMilliseconds = 30_000,
        int attempts = 4,
        int closeTimeoutMilliseconds = 2_000) => new()
        {
            LocalAddress = IPAddress.Parse("10.7.0.2"),
            Mss = 1400,
            ReceiveWindowSize = 65535,
            InitialRetransmitTimeout = TimeSpan.FromMilliseconds(retransmitMilliseconds),
            MaxRetransmitTimeout = TimeSpan.FromMilliseconds(retransmitMilliseconds * 2),
            MaxRetransmitAttempts = attempts,
            CloseTimeout = TimeSpan.FromMilliseconds(closeTimeoutMilliseconds),
        };

    [Fact]
    public async Task SynIsAnsweredWithAValidSynAckAndARetransmittedSynGetsTheSameOne()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x1122_3344;

        client.Send(clientIsn, 0, Syn, default, mss: 1460);

        var synAck = await client.WaitForAsync(packet => packet.Syn);

        Assert.True(synAck.Ack);
        Assert.False(synAck.Fin);
        Assert.False(synAck.Rst);
        Assert.False(synAck.Psh);
        Assert.True(synAck.ChecksumValid);
        Assert.True(synAck.IpChecksumValid);
        Assert.Equal("10.7.0.2", synAck.SourceText);
        Assert.Equal("10.7.0.9", synAck.DestinationText);
        Assert.Equal(ServerPort, synAck.SourcePort);
        Assert.Equal(ClientPort, synAck.DestinationPort);
        Assert.Equal(clientIsn + 1, synAck.Acknowledgment);
        Assert.Empty(synAck.Payload);

        // The MSS this stack advertises is its own, not the peer's.
        Assert.Equal(1400, synAck.Mss);
        Assert.Equal(65535, synAck.Window);
        Assert.Equal(1, acceptor.ConnectionCount);

        // A retransmitted SYN means the SYN-ACK was lost: the same sequence and
        // acknowledgement must come back, not a second connection.
        client.Send(clientIsn, 0, Syn, default, mss: 1460);
        var repeat = await client.WaitForAsync(packet => packet.Syn, skip: 1);

        Assert.Equal(synAck.Sequence, repeat.Sequence);
        Assert.Equal(synAck.Acknowledgment, repeat.Acknowledgment);
        Assert.Equal(1, acceptor.ConnectionCount);
        Assert.Equal(0, acceptor.AcceptedCount);
    }

    [Fact]
    public async Task HandshakeCompletesAndTheFlowIsAccepted()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        var (stream, synAck) = await OpenAsync(acceptor, client, 0x2000_0000);

        Assert.Equal(new IPEndPoint(IPAddress.Parse("10.7.0.9"), ClientPort), stream.RemoteEndPoint);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("10.7.0.2"), ServerPort), stream.LocalEndPoint);
        Assert.Equal(ServerPort, stream.LocalPort);
        Assert.True(stream.CanRead);
        Assert.True(stream.CanWrite);
        Assert.False(stream.CanSeek);
        Assert.Equal(1, acceptor.ConnectionCount);
        Assert.Equal(1, acceptor.AcceptedCount);
        Assert.Equal(0, acceptor.RejectedCount);

        // The SYN-ACK is the only thing on the wire: the handshake acknowledgement
        // is not itself acknowledged, and there is nothing to say until data arrives.
        Assert.Single(client.Received);
        Assert.Equal(synAck.Sequence, client.Received[0].Sequence);
    }

    [Fact]
    public async Task PayloadFlowsBothWaysAfterTheHandshake()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x3000_0000;

        var (stream, synAck) = await OpenAsync(acceptor, client, clientIsn);
        var serverNext = synAck.Sequence + 1;

        // Inbound: the application answers on the accepted stream.
        await stream.WriteAsync("pong"u8.ToArray());

        var outbound = await client.WaitForDataAsync();
        Assert.Equal("pong", outbound.Text);
        Assert.Equal(serverNext, outbound.Sequence);
        Assert.Equal(clientIsn + 1, outbound.Acknowledgment);
        Assert.True(outbound.Ack);
        Assert.True(outbound.Psh);
        Assert.False(outbound.Syn);
        Assert.True(outbound.ChecksumValid);
        Assert.True(outbound.IpChecksumValid);
        Assert.Equal(ServerPort, outbound.SourcePort);
        Assert.Equal(ClientPort, outbound.DestinationPort);

        // Outbound: a segment from the peer reaches the stream and is acknowledged.
        client.Send(clientIsn + 1, serverNext + 4, (byte)(Ack | Psh), "ping"u8);

        var buffer = new byte[4];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(4, read);
        Assert.Equal("ping", Encoding.ASCII.GetString(buffer));

        var acknowledgment = await client.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == clientIsn + 5);
        Assert.Equal(serverNext + 4, acknowledgment.Sequence);
        Assert.True(acknowledgment.ChecksumValid);
        Assert.Empty(acknowledgment.Payload);

        await stream.DisposeAsync();
    }

    [Fact]
    public async Task OutOfOrderDataIsBufferedAndDeliveredInOrder()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x4000_0000;

        var (stream, synAck) = await OpenAsync(acceptor, client, clientIsn);
        var serverNext = synAck.Sequence + 1;

        // The second half arrives first; the only correct answer is a duplicate
        // acknowledgement of the byte that is still missing.
        client.Send(clientIsn + 5, serverNext, (byte)(Ack | Psh), "EFGH"u8);

        var duplicate = await client.WaitForAsync(
            packet => packet.Ack && !packet.Syn && !packet.Fin && packet.Acknowledgment == clientIsn + 1);
        Assert.Equal(serverNext, duplicate.Sequence);

        client.Send(clientIsn + 1, serverNext, (byte)(Ack | Psh), "ABCD"u8);

        var buffer = new byte[8];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(8, read);
        Assert.Equal("ABCDEFGH", Encoding.ASCII.GetString(buffer));

        var acknowledgment = await client.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == clientIsn + 9);
        Assert.Equal(serverNext, acknowledgment.Sequence);

        await stream.DisposeAsync();
    }

    [Fact]
    public async Task WritesAreSplitOnTheMssThePeerAdvertised()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        var (stream, synAck) = await OpenAsync(acceptor, client, 0x5000_0000, mss: 500);

        var payload = new byte[1200];
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] = (byte)(index % 251);
        }

        await stream.WriteAsync(payload);

        var first = await client.WaitForDataAsync();
        var second = await client.WaitForDataAsync(skip: 1);
        var third = await client.WaitForDataAsync(skip: 2);

        Assert.Equal(500, first.Payload.Length);
        Assert.Equal(500, second.Payload.Length);
        Assert.Equal(200, third.Payload.Length);
        Assert.Equal(synAck.Sequence + 1, first.Sequence);
        Assert.Equal(first.Sequence + 500, second.Sequence);
        Assert.Equal(second.Sequence + 500, third.Sequence);
        Assert.All(client.Received, packet => Assert.True(packet.Payload.Length <= 500));
        Assert.True(first.Psh);
        Assert.True(third.Psh);

        var reassembled = new byte[payload.Length];
        first.Payload.CopyTo(reassembled, 0);
        second.Payload.CopyTo(reassembled, first.Payload.Length);
        third.Payload.CopyTo(reassembled, first.Payload.Length + second.Payload.Length);
        Assert.Equal(payload, reassembled);

        await stream.DisposeAsync();
    }

    [Fact]
    public async Task TheHandshakeAckMayCarryPayload()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x6000_0000;

        client.Send(clientIsn, 0, Syn, default, mss: 1400);
        var synAck = await client.WaitForAsync(packet => packet.Syn);

        // A single segment finishes the handshake and delivers the request.
        client.Send(clientIsn + 1, synAck.Sequence + 1, (byte)(Ack | Psh), "GET"u8);

        var stream = await acceptor.AcceptAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        var buffer = new byte[3];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(3, read);
        Assert.Equal("GET", Encoding.ASCII.GetString(buffer));

        var acknowledgment = await client.WaitForAsync(
            packet => packet.Ack && packet.Acknowledgment == clientIsn + 4);
        Assert.Equal(synAck.Sequence + 1, acknowledgment.Sequence);

        await stream.DisposeAsync();
    }

    [Fact]
    public async Task PeerFinIsAcknowledgedAndTheStreamReportsEof()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x7000_0000;

        var (stream, synAck) = await OpenAsync(acceptor, client, clientIsn);
        var serverNext = synAck.Sequence + 1;

        client.Send(clientIsn + 1, serverNext, (byte)(Fin | Ack));

        var acknowledgment = await client.WaitForAsync(
            packet => packet.Ack && !packet.Fin && packet.Acknowledgment == clientIsn + 2);
        Assert.Equal(serverNext, acknowledgment.Sequence);

        var buffer = new byte[16];
        var read = await stream.ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, read);

        // The connection is only half closed: the response direction still works,
        // which is what lets a request/response relay finish.
        await stream.WriteAsync("bye"u8.ToArray());
        var data = await client.WaitForTextAsync("bye");
        Assert.Equal(clientIsn + 2, data.Acknowledgment);

        await stream.DisposeAsync();
    }

    [Fact]
    public async Task FourWayCloseReclaimsTheConnection()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x0800_0000;

        var (stream, synAck) = await OpenAsync(acceptor, client, clientIsn);
        var serverNext = synAck.Sequence + 1;

        client.Send(clientIsn + 1, serverNext, (byte)(Fin | Ack));
        await client.WaitForAsync(packet => packet.Ack && packet.Acknowledgment == clientIsn + 2);

        ((IHalfCloseable)stream).ShutdownSend();

        var fin = await client.WaitForAsync(packet => packet.Fin);
        Assert.True(fin.Ack);
        Assert.Equal(serverNext, fin.Sequence);
        Assert.Equal(clientIsn + 2, fin.Acknowledgment);
        Assert.True(fin.ChecksumValid);
        Assert.True(fin.IpChecksumValid);
        Assert.False(stream.CanWrite);
        Assert.Equal(1, acceptor.ConnectionCount);

        // The peer acknowledges the FIN, which is the last thing either side has
        // to say: the flow must be forgotten, not left in a close wait.
        client.Send(clientIsn + 2, fin.Sequence + 1, Ack);

        await WaitUntilAsync(() => acceptor.ConnectionCount == 0, TimeSpan.FromSeconds(3));
        Assert.Equal(0, acceptor.ConnectionCount);

        await stream.DisposeAsync();
    }

    [Fact]
    public async Task ACloseThatIsNeverAcknowledgedIsReclaimedByTheCloseTimeout()
    {
        await using var acceptor = new TcpAcceptor(Options(closeTimeoutMilliseconds: 250));
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x0900_0000;

        var (stream, synAck) = await OpenAsync(acceptor, client, clientIsn);
        var serverNext = synAck.Sequence + 1;

        client.Send(clientIsn + 1, serverNext, (byte)(Fin | Ack));
        await client.WaitForAsync(packet => packet.Ack && packet.Acknowledgment == clientIsn + 2);

        await stream.WriteAsync("last"u8.ToArray());
        ((IHalfCloseable)stream).ShutdownSend();
        await client.WaitForAsync(packet => packet.Fin);

        // The peer vanishes without acknowledging the FIN. The flow must still be
        // released, which is the only thing standing between a lost final segment
        // and a permanently leaked connection.
        await WaitUntilAsync(() => acceptor.ConnectionCount == 0, TimeSpan.FromSeconds(5));
        Assert.Equal(0, acceptor.ConnectionCount);
    }

    [Fact]
    public async Task PeerResetFailsTheStreamAndReclaimsTheConnection()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        var (stream, _) = await OpenAsync(acceptor, client, 0x0A00_0000);

        client.Send(0x0A00_0001, 0x1234, (byte)(Rst | Ack));

        var failure = await Assert.ThrowsAsync<IOException>(
            () => stream.ReadAsync(new byte[16]).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Contains("reset", failure.Message, StringComparison.OrdinalIgnoreCase);

        await Assert.ThrowsAsync<IOException>(
            () => stream.WriteAsync("x"u8.ToArray()).AsTask().WaitAsync(TimeSpan.FromSeconds(5)));

        await WaitUntilAsync(() => acceptor.ConnectionCount == 0, TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task SegmentForAnUnknownFlowIsAnsweredWithAReset()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        // No ACK: RFC 9293 acknowledges the sequence space it just consumed.
        client.Send(500, 0, Psh, "x"u8);

        var reset = await client.WaitForAsync(packet => packet.Rst);
        Assert.True(reset.Ack);
        Assert.Equal(0u, reset.Sequence);
        Assert.Equal(501u, reset.Acknowledgment);
        Assert.Equal(ServerPort, reset.SourcePort);
        Assert.Equal(ClientPort, reset.DestinationPort);
        Assert.True(reset.ChecksumValid);
        Assert.True(reset.IpChecksumValid);
        Assert.Equal(0, acceptor.ConnectionCount);

        // With ACK set the reset carries the acknowledgement as its sequence and
        // drops the ACK flag, so a peer cannot mistake it for an answer.
        client.Send(700, 900, (byte)(Ack | Psh), "y"u8);

        var second = await client.WaitForAsync(packet => packet.Rst, skip: 1);
        Assert.False(second.Ack);
        Assert.Equal(900u, second.Sequence);
        Assert.Equal(0u, second.Acknowledgment);
        Assert.True(second.ChecksumValid);
        Assert.Equal(0, acceptor.ConnectionCount);
    }

    [Fact]
    public async Task MalformedAndMisaddressedPacketsAreIgnored()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        // Too short, then all zeroes (version 0).
        acceptor.ProcessPacket(new byte[3]);
        acceptor.ProcessPacket(new byte[40]);

        // A SYN whose checksum does not verify.
        client.Send(1, 0, Syn, default, mss: 1400, corruptChecksum: true);

        // A well-formed SYN addressed somewhere this stack does not own.
        acceptor.ProcessPacket(TestPackets.Build(
            ClientAddress,
            TestPackets.Address("10.9.9.9"),
            ClientPort,
            ServerPort,
            1,
            0,
            Syn,
            default,
            65535,
            1400));

        // A UDP datagram, which this stack does not carry.
        var udp = TestPackets.Build(
            ClientAddress,
            ServerAddress,
            ClientPort,
            ServerPort,
            1,
            0,
            Syn,
            default,
            65535,
            1400);
        udp[9] = 17;
        var header = udp.AsSpan(0, TestPackets.IpHeaderLength);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], (ushort)~TestPackets.Sum(header, 0));
        acceptor.ProcessPacket(udp);

        Assert.Empty(client.Received);
        Assert.Equal(0, acceptor.ConnectionCount);

        // The pump survived all of it.
        client.Send(0x1000, 0, Syn, default, mss: 1400);
        var synAck = await client.WaitForAsync(packet => packet.Syn);
        Assert.True(synAck.ChecksumValid);
        Assert.Equal(1, acceptor.ConnectionCount);
    }

    [Fact]
    public async Task AnUnacknowledgedSynAckIsRetransmittedThenTheFlowIsReclaimed()
    {
        await using var acceptor = new TcpAcceptor(Options(retransmitMilliseconds: 30, attempts: 3));
        var client = new FakeTcpClient(acceptor);
        const uint clientIsn = 0x0B00_0000;

        client.Send(clientIsn, 0, Syn, default, mss: 1400);

        var first = await client.WaitForAsync(packet => packet.Syn);
        var second = await client.WaitForAsync(packet => packet.Syn, skip: 1, timeoutMilliseconds: 3000);

        Assert.Equal(first.Sequence, second.Sequence);
        Assert.Equal(first.Acknowledgment, second.Acknowledgment);
        Assert.Equal(first.Flags, second.Flags);
        Assert.Equal(clientIsn + 1, second.Acknowledgment);
        Assert.True(second.ChecksumValid);

        // The peer never answers, so the half-open flow must be given up on
        // rather than held forever, and the refusal must be visible on the wire.
        await WaitUntilAsync(() => acceptor.ConnectionCount == 0, TimeSpan.FromSeconds(5));
        var reset = await client.WaitForAsync(packet => packet.Rst, timeoutMilliseconds: 3000);
        Assert.Equal(first.Sequence + 1, reset.Sequence);
        Assert.Equal(0, acceptor.AcceptedCount);
    }

    [Fact]
    public async Task AFullAcceptBacklogResetsTheNewestHandshake()
    {
        await using var acceptor = new TcpAcceptor(Options(), backlog: 1);
        var client = new FakeTcpClient(acceptor);

        // The first flow completes its handshake and stays in the queue: nothing
        // accepts it, which is exactly how a backlog becomes full.
        client.SourcePort = 51001;
        await HandshakeAsync(client, 0x0C00_0000);
        Assert.Equal(1, acceptor.AcceptedCount);
        Assert.Equal(1, acceptor.ConnectionCount);

        // The second completes its handshake but has nowhere to go, so it is
        // refused instead of being queued behind a consumer that may never come.
        client.SourcePort = 51002;
        const uint secondIsn = 0x0D00_0000;
        client.Send(secondIsn, 0, Syn, default, mss: 1400);
        var synAck = await client.WaitForAsync(packet => packet.Syn && packet.DestinationPort == 51002);
        client.Send(secondIsn + 1, synAck.Sequence + 1, Ack);

        var reset = await client.WaitForAsync(packet => packet.Rst && packet.DestinationPort == 51002);
        Assert.Equal(synAck.Sequence + 1, reset.Sequence);
        Assert.Equal(secondIsn + 1, reset.Acknowledgment);
        Assert.True(reset.ChecksumValid);

        Assert.Equal(1, acceptor.RejectedCount);
        Assert.Equal(1, acceptor.AcceptedCount);
        Assert.Equal(1, acceptor.ConnectionCount);
        Assert.Equal(51001, (await acceptor.AcceptAsync()).RemoteEndPoint.Port);
    }

    [Fact]
    public async Task DisposalReclaimsEveryFlowAndReleasesWaitingConsumers()
    {
        var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        var (stream, _) = await OpenAsync(acceptor, client, 0x0E00_0000);
        var pending = acceptor.AcceptAsync().AsTask();
        Assert.Equal(1, acceptor.ConnectionCount);

        await acceptor.DisposeAsync();

        Assert.Equal(0, acceptor.ConnectionCount);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => pending);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => acceptor.AcceptAsync().AsTask());
        Assert.Equal(0, acceptor.ConnectionCount);
        await stream.DisposeAsync();
    }

    [Fact]
    public async Task DefaultAddressFilterRejectsSyntheticDestinations()
    {
        await using var acceptor = new TcpAcceptor(Options());
        var client = new FakeTcpClient(acceptor);

        // Without a filter this stack only answers for the address it owns, so a
        // fake-ip destination is dropped rather than answered.
        client.Send(0x0F00_0000, 0, Syn, default, mss: 1400, destinationAddress: TestPackets.Address("198.18.0.5"));

        Assert.Empty(client.Received);
        Assert.Equal(0, acceptor.ConnectionCount);
    }

    [Fact]
    public async Task DestinationFilterAnswersForSyntheticDestinations()
    {
        var options = Options();
        await using var acceptor = new TcpAcceptor(options)
        {
            DestinationFilter = address => (address & 0xFFFF_0000) == TestPackets.Address("198.18.0.0"),
        };

        var client = new FakeTcpClient(acceptor);
        var synthetic = TestPackets.Address("198.18.0.5");

        client.Send(0x1100_0000, 0, Syn, default, mss: 1400, destinationAddress: synthetic);

        var synAck = await client.WaitForAsync(packet => packet.Syn);

        // The reply must come from the address the SYN was sent to, otherwise the
        // operating system drops it and never matches it to its socket.
        Assert.Equal("198.18.0.5", synAck.SourceText);
        Assert.Equal("10.7.0.9", synAck.DestinationText);
        Assert.True(synAck.ChecksumValid);

        client.Send(0x1100_0001, synAck.Sequence + 1, Ack, default, destinationAddress: synthetic);
        var stream = await acceptor.AcceptAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(new IPEndPoint(IPAddress.Parse("198.18.0.5"), ServerPort), stream.LocalEndPoint);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("10.7.0.9"), ClientPort), stream.RemoteEndPoint);

        await stream.WriteAsync("ok"u8.ToArray());
        var data = await client.WaitForDataAsync();
        Assert.Equal("198.18.0.5", data.SourceText);
        Assert.Equal("ok", data.Text);
        Assert.True(data.ChecksumValid);

        await stream.DisposeAsync();
    }

    /// <summary>
    /// Runs the client half of the handshake against the acceptor and returns the
    /// SYN-ACK it was answered with, without accepting the resulting flow.
    /// </summary>
    private static async Task<ParsedPacket> HandshakeAsync(
        FakeTcpClient client,
        uint clientIsn,
        ushort window = 65535,
        int mss = 1400)
    {
        client.Send(clientIsn, 0, Syn, default, window, mss);
        var synAck = await client.WaitForAsync(packet => packet.Syn);
        client.Send(clientIsn + 1, synAck.Sequence + 1, Ack, default, window);
        return synAck;
    }

    /// <summary>
    /// Runs the client half of the handshake against the acceptor and returns the
    /// accepted stream with the SYN-ACK it was answered with.
    /// </summary>
    private static async Task<(TcpAcceptStream Stream, ParsedPacket SynAck)> OpenAsync(
        TcpAcceptor acceptor,
        FakeTcpClient client,
        uint clientIsn,
        ushort window = 65535,
        int mss = 1400)
    {
        var synAck = await HandshakeAsync(client, clientIsn, window, mss);

        var stream = await acceptor.AcceptAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        return (stream, synAck);
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

    /// <summary>
    /// The operating system's half of a TUN flow, hand-written: it records every
    /// packet the acceptor emits through its sink and injects hand-built packets
    /// back into <see cref="TcpAcceptor.ProcessPacket"/>.
    /// <para>
    /// Parsing happens inside the sink, which the connection calls while holding
    /// its lock, so nothing here ever calls back into the stack.
    /// </para>
    /// </summary>
    private sealed class FakeTcpClient
    {
        private readonly TcpAcceptor _acceptor;
        private readonly Lock _gate = new();
        private readonly List<ParsedPacket> _received = [];
        private readonly SemaphoreSlim _signal = new(0);

        public FakeTcpClient(TcpAcceptor acceptor)
        {
            _acceptor = acceptor;
            acceptor.PacketSink = packet =>
            {
                if (!TestPackets.TryParse(packet.ToArray(), out var parsed))
                {
                    return;
                }

                lock (_gate)
                {
                    _received.Add(parsed);
                    _signal.Release();
                }
            };
        }

        /// <summary>The source port of the next segment; vary it for a second flow.</summary>
        public ushort SourcePort { get; set; } = ClientPort;

        /// <summary>A snapshot of everything the client has parsed.</summary>
        public IReadOnlyList<ParsedPacket> Received
        {
            get
            {
                lock (_gate)
                {
                    return [.. _received];
                }
            }
        }

        /// <summary>Sends one segment to the acceptor.</summary>
        public void Send(
            uint sequence,
            uint acknowledgment,
            byte flags,
            ReadOnlySpan<byte> payload = default,
            ushort window = 65535,
            int mss = -1,
            bool corruptChecksum = false,
            ushort? sourcePort = null,
            uint? destinationAddress = null)
        {
            var packet = TestPackets.Build(
                ClientAddress,
                destinationAddress ?? ServerAddress,
                sourcePort ?? SourcePort,
                ServerPort,
                sequence,
                acknowledgment,
                flags,
                payload,
                window,
                mss,
                corruptChecksum);
            _acceptor.ProcessPacket(packet);
        }

        /// <summary>
        /// Waits until the <paramref name="skip"/>-th (zero-based) segment matching
        /// <paramref name="predicate"/> has arrived. This is an event-driven wait
        /// with a bounded timeout, so a missing packet fails the test instead of
        /// hanging it.
        /// </summary>
        public async Task<ParsedPacket> WaitForAsync(
            Func<ParsedPacket, bool> predicate,
            int skip = 0,
            int timeoutMilliseconds = 5000)
        {
            var deadline = Environment.TickCount64 + timeoutMilliseconds;
            while (true)
            {
                lock (_gate)
                {
                    var matches = 0;
                    foreach (var packet in _received)
                    {
                        if (!predicate(packet))
                        {
                            continue;
                        }

                        if (matches == skip)
                        {
                            return packet;
                        }

                        matches++;
                    }
                }

                var remaining = (int)(deadline - Environment.TickCount64);
                if (remaining <= 0)
                {
                    throw new TimeoutException($"the client never saw the expected segment ({Received.Count} received)");
                }

                await _signal.WaitAsync(remaining).ConfigureAwait(false);
            }
        }

        /// <summary>Waits for the <paramref name="skip"/>-th payload segment.</summary>
        public Task<ParsedPacket> WaitForDataAsync(int skip = 0, int timeoutMilliseconds = 5000)
            => WaitForAsync(static packet => packet.Payload.Length > 0, skip, timeoutMilliseconds);

        /// <summary>Waits for the <paramref name="skip"/>-th payload segment carrying exactly this text.</summary>
        public Task<ParsedPacket> WaitForTextAsync(string text, int skip = 0, int timeoutMilliseconds = 5000)
            => WaitForAsync(packet => packet.Payload.Length > 0 && packet.Text == text, skip, timeoutMilliseconds);
    }
}
