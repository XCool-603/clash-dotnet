using System.Net;
using System.Text;
using Clash.Core.Crypto;
using Clash.Core.Netstack;
using Clash.Core.Proxies.Outbound;
using Clash.Tests.Netstack;
using Xunit;

namespace Clash.Tests.WireGuard;

/// <summary>
/// The test that proves the whole stack works together: Noise handshake, transport
/// encryption, IPv4, TCP and the userspace stack, with the fake peer playing the
/// internet at the far end.
/// </summary>
public class WireGuardTunnelTests
{
    private static readonly byte[] ClientPrivateKey =
        Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

    private static readonly byte[] PresharedKey =
        Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    private static readonly IPAddress TunnelAddress = IPAddress.Parse("10.0.0.2");
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("93.184.216.34"), 443);

    [Fact]
    public async Task ATcpFlowRidesTheWireGuardTunnelEndToEnd()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());
        await using var connection = new WireGuardPacketConnection(session);

        var host = new NetstackHost(Netstack());
        await using var bridge = new NetstackPacketConnectionAdapter(host, connection, peer.OuterEndPoint);

        // The application-level dial: nothing here knows about WireGuard.
        var stream = await host.ConnectAsync(Remote).AsTask().WaitAsync(TimeSpan.FromSeconds(10));

        var request = Encoding.ASCII.GetBytes("hello wireguard");
        await stream.WriteAsync(request);

        var buffer = new byte[256];
        var read = await stream
            .ReadAsync(buffer)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ;

        Assert.Equal("hello wireguard", Encoding.ASCII.GetString(buffer, 0, read));

        // The peer must have seen a real, checksum-valid inner IPv4/TCP SYN and the
        // payload as its own segment, not just a stream of bytes.
        Assert.Contains(
            peer.InnerPackets,
            packet => TestPackets.TryParse(packet, out var segment) && segment.Syn && segment.ChecksumValid && segment.IpChecksumValid);

        Assert.Contains(
            peer.InnerPackets,
            packet => TestPackets.TryParse(packet, out var segment) && segment.Text == "hello wireguard");

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task TheUdpViewWrapsPayloadsIntoInnerUdpAndUnwrapsTheAnswers()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());
        await using var connection = new WireGuardPacketConnection(session);
        var udp = connection.CreateUdpView(TunnelAddress);

        Assert.True(udp.SupportsMultipleDestinations);

        var destination = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
        var query = Encoding.ASCII.GetBytes("dns-query");
        await udp.SendAsync(query, destination);

        await peer.WaitForAsync(() => peer.InnerPackets.Count == 1);

        var inner = peer.InnerPackets[0];
        Assert.True(TestUdp.TryParse(inner, out var parsed));
        Assert.True(parsed.IpChecksumValid);
        Assert.True(parsed.UdpChecksumValid);
        Assert.Equal("10.0.0.2", parsed.SourceText);
        Assert.Equal("1.1.1.1", parsed.DestinationText);
        Assert.Equal(53, parsed.DestinationPort);
        Assert.Equal(query, parsed.Payload);

        // The peer answers to the ephemeral inner source port it saw.
        var answer = Encoding.ASCII.GetBytes("dns-answer");
        peer.SendInnerPacket(TestUdp.Build(
            parsed.DestinationAddress,
            parsed.SourceAddress,
            53,
            parsed.SourcePort,
            answer));

        var buffer = new byte[256];
        var received = await udp
            .ReceiveAsync(buffer)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ;

        Assert.Equal(answer.Length, received.BytesRead);
        Assert.Equal(answer, buffer[..received.BytesRead]);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53), received.Remote);
    }

    [Fact]
    public async Task InnerTcpPacketsAreRoutedToTheNetstackAndUdpPacketsAreNot()
    {
        await using var peer = new FakeWireGuardPeer(PresharedKey);
        await using var session = new WireGuardSession(Options(peer), peer.CreateClientTransport());
        await using var connection = new WireGuardPacketConnection(session);

        await session.SendKeepaliveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));

        // A UDP datagram must be routed away from the TCP queue, so the netstack
        // never sees it; the following TCP packet must come through untouched.
        peer.SendInnerPacket(TestUdp.Build(
            TestPackets.Address("93.184.216.34"),
            TestPackets.Address("10.0.0.2"),
            53,
            40000,
            "not-for-the-netstack"u8));

        var tcp = TestPackets.Build(
            TestPackets.Address("93.184.216.34"),
            TestPackets.Address("10.0.0.2"),
            443,
            40000,
            1,
            1,
            TestPackets.FlagAck,
            default);

        peer.SendInnerPacket(tcp);

        var buffer = new byte[2048];
        var received = await connection
            .ReceiveAsync(buffer)
            .AsTask()
            .WaitAsync(TimeSpan.FromSeconds(10))
            ;

        Assert.Equal(tcp.Length, received.BytesRead);
        Assert.Equal(tcp, buffer[..received.BytesRead]);
    }

    private static WireGuardSessionOptions Options(FakeWireGuardPeer peer) => new()
    {
        LocalPrivateKey = ClientPrivateKey,
        PeerPublicKey = peer.PublicKey,
        PresharedKey = PresharedKey,
        SenderIndex = 0x11223344,
        RekeyTimeout = TimeSpan.FromMilliseconds(50),
        RekeyTimeoutJitterMaxMs = 1,
        RekeyAttemptTime = TimeSpan.FromSeconds(5),
    };

    private static NetstackOptions Netstack() => new()
    {
        LocalAddress = TunnelAddress,
        Mss = 1360,
        InitialRetransmitTimeout = TimeSpan.FromMilliseconds(50),
        CloseTimeout = TimeSpan.FromSeconds(2),
    };
}
