using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;
using Clash.Core.Tun;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Tun;

/// <summary>
/// The TUN UDP relay and its DNS hijack.
/// <para>
/// Every test here drives the relay with <b>synthetic IP packets</b>, so nothing
/// in this file needs the Wintun driver, an administrator process or a real
/// network: the device is a queue, and the tunnel is a stand-in that records what
/// it was handed. The reply packets the relay produces are parsed by the
/// independent codec below, which recomputes both checksums with its own
/// arithmetic, so a bug shared with the production writer cannot hide.
/// </para>
/// </summary>
public sealed class TunUdpRelayTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);

    // ── The datagram path ───────────────────────────────────────────────────

    [Fact]
    public async Task AUdpDatagramIsHandedToTheTunnelAndTheReplyIsAFramedIpUdpPacket()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel
        {
            Reply = (inbound, remote, _) => inbound.SendAsync("pong"u8.ToArray(), remote, CancellationToken.None).AsTask(),
        };

        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig { DnsHijack = ["any:53"] });
        var pump = relay.Start();

        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 443, "ping"));

        // The tunnel is handed the datagram, addressed as the client addressed it.
        await WaitUntilAsync(() => tunnel.ReceivedCount == 1, "the tunnel to receive the datagram");
        var (remote, payload) = tunnel.Received[0];
        Assert.Equal("1.1.1.1:443", remote.ToString());
        Assert.Equal("ping", Encoding.ASCII.GetString(payload));

        // And its reply comes back out as a complete IP/UDP packet for the client.
        var written = device.NextWritten(TestTimeout);
        Assert.NotNull(written);

        Assert.True(UdpPackets.TryParse(written!, out var reply));
        Assert.Equal("1.1.1.1", reply.SourceText);
        Assert.Equal(443, reply.SourcePort);
        Assert.Equal("10.0.0.2", reply.DestinationText);
        Assert.Equal(40000, reply.DestinationPort);
        Assert.Equal("pong", reply.Text);
        Assert.True(reply.IpChecksumValid, "the IPv4 header checksum must be correct");
        Assert.True(reply.UdpChecksumValid, "the UDP checksum must be correct");

        Assert.Equal(1L, relay.DatagramsForwarded);
        Assert.Equal(1L, relay.RepliesWritten);
        Assert.Equal(0L, relay.QueriesHijacked);

        await relay.DisposeAsync();
        await pump.WaitAsync(TestTimeout);
    }

    [Fact]
    public async Task EachReplyGoesToTheClientThatAddressedThatRemote()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel
        {
            // Echo, so the reply's payload identifies which datagram it answers.
            Reply = (inbound, remote, payload) => inbound.SendAsync(payload, remote, CancellationToken.None).AsTask(),
        };

        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig());
        _ = relay.Start();

        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 1000, "first"));
        device.Inject(UdpPackets.BuildText("10.0.0.3", "9.9.9.9", 50000, 2000, "second"));

        var replies = new List<UdpDatagram>();
        for (var i = 0; i < 2; i++)
        {
            var written = device.NextWritten(TestTimeout);
            Assert.NotNull(written);
            Assert.True(UdpPackets.TryParse(written!, out var parsed));
            Assert.True(parsed.IpChecksumValid);
            Assert.True(parsed.UdpChecksumValid);
            replies.Add(parsed);
        }

        var first = Assert.Single(replies, r => r.Text == "first");
        Assert.Equal("1.1.1.1", first.SourceText);
        Assert.Equal(1000, first.SourcePort);
        Assert.Equal("10.0.0.2", first.DestinationText);
        Assert.Equal(40000, first.DestinationPort);

        var second = Assert.Single(replies, r => r.Text == "second");
        Assert.Equal("9.9.9.9", second.SourceText);
        Assert.Equal(2000, second.SourcePort);
        Assert.Equal("10.0.0.3", second.DestinationText);
        Assert.Equal(50000, second.DestinationPort);
    }

    [Fact]
    public async Task TheTunnelSeesATunUdpInbound()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel();
        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig(), inboundName: "tun-in");
        _ = relay.Start();

        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 443, "ping"));

        var metadata = await tunnel.UdpStarted.WaitAsync(TestTimeout);
        Assert.Equal(Network.Udp, metadata.Network);
        Assert.Equal("tun", metadata.InboundType);
        Assert.Equal("tun-in", metadata.InboundName);
        Assert.True(relay.IsRunning);
        Assert.True(relay.DnsHijackEnabled);
    }

    [Fact]
    public async Task TheTunnelCannotPushAReplyBeforeAnyClientIsKnown()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel
        {
            // Push a reply before reading anything: there is no client to send it to.
            OnStart = inbound => inbound.SendAsync("nobody"u8.ToArray(), new IPEndPoint(IPAddress.Parse("1.1.1.1"), 443), CancellationToken.None).AsTask(),
        };

        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig());
        _ = relay.Start();

        await WaitUntilAsync(() => relay.PacketsDropped == 1, "the orphan reply to be dropped");

        Assert.Null(device.NextWritten(TimeSpan.FromMilliseconds(200)));
        Assert.Equal(0L, relay.RepliesWritten);
    }

    // ── DNS hijack ──────────────────────────────────────────────────────────

    [Fact]
    public async Task AHijackedQueryIsAnsweredLocallyAndAnUnlistedQueryIsNot()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel();
        var hijacked = new ConcurrentQueue<byte[]>();
        var answer = new byte[] { 0xAB, 0xCD, 0x01, 0x02 };

        var handler = new TunDnsHijackHandler((query, source, _) =>
        {
            hijacked.Enqueue(query.ToArray());
            Assert.Equal("10.0.0.2", source.Address.ToString());
            return Task.FromResult<ReadOnlyMemory<byte>?>(answer);
        });

        await using var relay = new TunUdpRelay(
            device,
            tunnel,
            new TunConfig { DnsHijack = ["8.8.8.8:53"] },
            handler);
        _ = relay.Start();

        device.Inject(UdpPackets.BuildText("10.0.0.2", "8.8.8.8", 40000, 53, "hijack me"));
        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40001, 53, "tunnel me"));

        // The listed address is answered in place: the handler sees the query and
        // the answer leaves as a packet from the server the client asked.
        await WaitUntilAsync(() => hijacked.Count == 1, "the hijacked query to be answered");
        Assert.True(hijacked.TryDequeue(out var captured));
        Assert.Equal("hijack me", Encoding.ASCII.GetString(captured));

        var written = device.NextWritten(TestTimeout);
        Assert.NotNull(written);
        Assert.True(UdpPackets.TryParse(written!, out var reply));
        Assert.Equal("8.8.8.8", reply.SourceText);
        Assert.Equal(53, reply.SourcePort);
        Assert.Equal("10.0.0.2", reply.DestinationText);
        Assert.Equal(40000, reply.DestinationPort);
        Assert.Equal(answer, reply.Payload);
        Assert.True(reply.IpChecksumValid, "the IPv4 header checksum must be correct");
        Assert.True(reply.UdpChecksumValid, "the UDP checksum must be correct");

        // The unlisted one still goes to the tunnel, and never to the resolver.
        await WaitUntilAsync(() => tunnel.ReceivedCount == 1, "the unlisted query to reach the tunnel");
        Assert.Equal("1.1.1.1:53", tunnel.Received[0].Remote.ToString());
        Assert.Equal("tunnel me", Encoding.ASCII.GetString(tunnel.Received[0].Payload));

        Assert.Equal(1L, relay.QueriesHijacked);
        Assert.Equal(1L, relay.DatagramsForwarded);
        Assert.Equal(0, tunnel.QueriesAnswered);
    }

    [Fact]
    public async Task AFakeIpResolverAnswersAHijackedQueryWithoutAnUpstreamExchange()
    {
        var upstream = new CountingUpstream();
        var dnsConfig = new DnsConfig
        {
            EnhancedMode = "fake-ip",
            FakeIpRange = "198.18.0.1/16",
            Nameserver = ["counting://"],
        };

        using var resolver = new DnsResolver(
            dnsConfig,
            new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase),
            NullLogger<DnsResolver>.Instance,
            (_, _, _, _) => upstream);

        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel(resolver);
        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig { DnsHijack = ["any:53"] });
        _ = relay.Start();

        var query = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 0x1234);
        var queryWire = new DnsCodec().Encode(query);
        device.Inject(UdpPackets.Build("10.0.0.2", "8.8.8.8", 40000, 53, queryWire));

        var written = device.NextWritten(TestTimeout);
        Assert.NotNull(written);
        Assert.True(UdpPackets.TryParse(written!, out var reply));
        Assert.True(reply.IpChecksumValid, "the IPv4 header checksum must be correct");
        Assert.True(reply.UdpChecksumValid, "the UDP checksum must be correct");
        Assert.Equal("8.8.8.8", reply.SourceText);
        Assert.Equal(53, reply.SourcePort);
        Assert.Equal("10.0.0.2", reply.DestinationText);
        Assert.Equal(40000, reply.DestinationPort);

        var response = new DnsCodec().Decode(reply.Payload);
        Assert.True(response.IsResponse);
        Assert.Equal(0x1234, response.Id);
        Assert.Equal(DnsResponseCode.NoError, response.ResponseCode);

        var record = Assert.Single(response.Answers);
        Assert.Equal("example.com", record.Name);
        Assert.NotNull(record.Address);
        Assert.True(resolver.IsFakeIp(record.Address!), $"{record.Address} must come from the fake-ip range");
        Assert.Equal("example.com", resolver.ReverseFakeIp(record.Address!));

        // The whole point of the hijack: no upstream query, no tunnel flow.
        Assert.Equal(0, upstream.Calls);
        Assert.Equal(0, tunnel.ReceivedCount);
        Assert.Equal(1L, relay.QueriesHijacked);
        Assert.Equal(0L, relay.DatagramsForwarded);
    }

    [Fact]
    public async Task AMalformedDnsQueryIsDroppedInsteadOfAnswered()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel();
        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig { DnsHijack = ["any:53"] });
        _ = relay.Start();

        // A hijacked destination, but the payload is not a DNS message.
        device.Inject(UdpPackets.Build("10.0.0.2", "8.8.8.8", 40000, 53, [0xFF, 0xFF, 0xFF]));

        // The sentinel proves the pump kept running and nothing was answered.
        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40001, 443, "sentinel"));
        await WaitUntilAsync(() => tunnel.ReceivedCount == 1, "the sentinel datagram to reach the tunnel");

        Assert.Equal("sentinel", Encoding.ASCII.GetString(tunnel.Received[0].Payload));
        Assert.Equal(0L, relay.RepliesWritten);
        Assert.Equal(1L, relay.QueriesHijacked);
    }

    // ── What the relay refuses to carry ─────────────────────────────────────

    [Fact]
    public async Task TcpMalformedAndTruncatedPacketsAreDroppedWithoutReachingTheTunnel()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel();
        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig());
        _ = relay.Start();

        // A TCP packet: the acceptor's traffic, not the relay's.
        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 80, "tcp", protocol: UdpPackets.TcpProtocol));

        // Not an IP packet at all.
        device.Inject([0x00, 0x01, 0x02]);

        // An IP fragment carries no ports.
        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 80, "fragment", fragmented: true));

        // A UDP length field that promises less than a header.
        var truncated = UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 80, "truncated");
        truncated[24] = 0;
        truncated[25] = 4;
        device.Inject(truncated);

        // An IP header checksum that does not add up.
        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 80, "bad ip checksum", corruptIpChecksum: true));

        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 443, "sentinel"));
        await WaitUntilAsync(() => tunnel.ReceivedCount == 1, "the sentinel datagram to reach the tunnel");

        Assert.Equal("sentinel", Encoding.ASCII.GetString(tunnel.Received[0].Payload));
        Assert.Equal(1L, relay.DatagramsForwarded);
        Assert.Equal(5L, relay.PacketsDropped);
        Assert.Equal(0L, relay.RepliesWritten);
    }

    [Fact]
    public async Task PacketsTheRelayDoesNotCarryAreHandedToTheObserver()
    {
        var observed = new ConcurrentQueue<byte[]>();
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel();

        var observer = new TunPacketObserver(packet => observed.Enqueue(packet.ToArray()));

        await using var relay = new TunUdpRelay(device, tunnel, new TunConfig(), observer: observer);
        _ = relay.Start();

        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 80, "tcp", protocol: UdpPackets.TcpProtocol));
        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 443, "udp"));

        await WaitUntilAsync(() => tunnel.ReceivedCount == 1, "the UDP datagram to reach the tunnel");
        await WaitUntilAsync(() => observed.Count == 1, "the TCP packet to reach the observer");

        Assert.True(observed.TryDequeue(out var tcp));
        Assert.Equal(UdpPackets.TcpProtocol, tcp[9]);
        Assert.Equal(0L, relay.PacketsDropped);
    }

    [Fact]
    public async Task ThePumpStopsWhenTheRelayIsDisposed()
    {
        using var device = new FakeTunDevice();
        var tunnel = new ScriptedTunnel();
        var relay = new TunUdpRelay(device, tunnel, new TunConfig());
        var pump = relay.Start();

        device.Inject(UdpPackets.BuildText("10.0.0.2", "1.1.1.1", 40000, 443, "ping"));
        await WaitUntilAsync(() => tunnel.ReceivedCount == 1, "the datagram to be read");

        await relay.DisposeAsync();
        await pump.WaitAsync(TestTimeout);

        Assert.False(relay.IsRunning);
        Assert.True(pump.IsCompletedSuccessfully, $"the pump ended as {pump.Status}");
    }

    // ── The dns-hijack pattern matcher ──────────────────────────────────────

    [Theory]
    [InlineData("any:53", "8.8.8.8", 53, true)]
    [InlineData("any:53", "8.8.8.8", 54, false)]
    [InlineData("any", "8.8.8.8", 5353, true)]
    [InlineData("0.0.0.0:53", "10.1.2.3", 53, true)]
    [InlineData("8.8.8.8:53", "8.8.8.8", 53, true)]
    [InlineData("8.8.8.8:53", "8.8.4.4", 53, false)]
    [InlineData("8.8.8.8:53", "8.8.8.8", 5353, false)]
    [InlineData("198.18.0.0/16:53", "198.18.7.7", 53, true)]
    [InlineData("198.18.0.0/16:53", "198.19.7.7", 53, false)]
    [InlineData("udp://any:53", "8.8.8.8", 53, true)]
    [InlineData("tcp://any:53", "8.8.8.8", 53, false)]
    [InlineData("ANY:53", "8.8.8.8", 53, true)]
    public void TheHijackMatcherUnderstandsTheDocumentedForms(string pattern, string address, int port, bool expected)
    {
        var matcher = DnsHijackMatcher.Parse([pattern]);

        Assert.Equal(expected, matcher.Matches(new IPEndPoint(IPAddress.Parse(address), port)));
    }

    [Fact]
    public void AnUnparsableHijackEntryIsReportedAndTheOthersStillApply()
    {
        var problems = new List<string>();
        var matcher = DnsHijackMatcher.Parse(["not an address", "any:53"], problems.Add);

        Assert.Single(problems);
        Assert.Contains("not an address", problems[0], StringComparison.Ordinal);
        Assert.Equal(1, matcher.Count);
        Assert.True(matcher.Matches(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53)));
    }

    [Fact]
    public void AnIpv6HijackEntryIsReportedAsHavingNoEffectOnTheIpv4Relay()
    {
        var problems = new List<string>();
        var matcher = DnsHijackMatcher.Parse(["[::1]:53", "tcp://8.8.8.8:53"], problems.Add);

        Assert.Single(problems);
        Assert.Contains("IPv6", problems[0], StringComparison.Ordinal);
        Assert.True(matcher.IsEmpty);
    }

    [Fact]
    public void AnEmptyConfigurationHijacksNothing()
    {
        Assert.True(DnsHijackMatcher.Parse([]).IsEmpty);
        Assert.True(DnsHijackMatcher.Parse(null).IsEmpty);
        Assert.False(DnsHijackMatcher.Parse(["any:53"]).IsEmpty);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static async Task WaitUntilAsync(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + TestTimeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(10);
        }

        Assert.Fail($"timed out waiting for {what}");
    }
}

/// <summary>
/// A hand-written IPv4/UDP codec used only by the tests. It works on plain
/// arrays with its own long-based checksum arithmetic, so a mistake shared with
/// <c>Clash.Core.Tun.TunUdpPacket</c> cannot hide behind it.
/// </summary>
internal static class UdpPackets
{
    public const int IpHeaderLength = 20;
    public const int UdpHeaderLength = 8;
    public const byte UdpProtocol = 17;
    public const byte TcpProtocol = 6;

    /// <summary>Parses a dotted quad into the numeric value the stack uses.</summary>
    public static uint Address(string dotted)
    {
        var value = 0u;
        foreach (var part in dotted.Split('.'))
        {
            value = (value << 8) | byte.Parse(part);
        }

        return value;
    }

    /// <summary>Formats a numeric address as a dotted quad.</summary>
    public static string Format(uint address)
        => $"{(address >> 24) & 0xFF}.{(address >> 16) & 0xFF}.{(address >> 8) & 0xFF}.{address & 0xFF}";

    /// <summary>The independent checksum: a long accumulator, folded at the end.</summary>
    public static ushort Sum(ReadOnlySpan<byte> data, long seed)
    {
        var sum = seed;
        var index = 0;
        for (; index + 1 < data.Length; index += 2)
        {
            sum += (data[index] << 8) | data[index + 1];
        }

        if (index < data.Length)
        {
            sum += data[index] << 8;
        }

        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (ushort)sum;
    }

    /// <summary>The IPv4 pseudo-header, as a seed for <see cref="Sum"/>.</summary>
    public static long PseudoSeed(uint source, uint destination, byte protocol, int length)
        => (source >> 16) + (source & 0xFFFF) + (destination >> 16) + (destination & 0xFFFF) + protocol + length;

    /// <summary>Builds a complete IPv4/UDP packet from scratch.</summary>
    public static byte[] Build(
        string source,
        string destination,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> payload,
        byte protocol = UdpProtocol,
        bool fragmented = false,
        bool corruptIpChecksum = false,
        bool corruptUdpChecksum = false)
    {
        var packet = new byte[IpHeaderLength + UdpHeaderLength + payload.Length];
        var sourceAddress = Address(source);
        var destinationAddress = Address(destination);

        packet[0] = 0x45;
        WriteUInt16(packet, 2, (ushort)packet.Length);
        WriteUInt16(packet, 6, fragmented ? (ushort)0x2000 : (ushort)0x4000);
        packet[8] = 64;
        packet[9] = protocol;
        WriteUInt32(packet, 12, sourceAddress);
        WriteUInt32(packet, 16, destinationAddress);

        var udp = packet.AsSpan(IpHeaderLength);
        WriteUInt16(packet, 20, sourcePort);
        WriteUInt16(packet, 22, destinationPort);
        WriteUInt16(packet, 24, (ushort)udp.Length);
        payload.CopyTo(udp[UdpHeaderLength..]);

        var udpChecksum = (ushort)~Sum(udp, PseudoSeed(sourceAddress, destinationAddress, protocol, udp.Length));
        if (udpChecksum == 0)
        {
            udpChecksum = 0xFFFF;
        }

        if (corruptUdpChecksum)
        {
            udpChecksum ^= 0x00FF;
        }

        WriteUInt16(packet, 26, udpChecksum);

        var ipChecksum = (ushort)~Sum(packet.AsSpan(0, IpHeaderLength), 0);
        if (corruptIpChecksum)
        {
            ipChecksum ^= 0x00FF;
        }

        WriteUInt16(packet, 10, ipChecksum);
        return packet;
    }

    /// <summary>Builds a packet whose payload is ASCII text.</summary>
    public static byte[] BuildText(
        string source,
        string destination,
        ushort sourcePort,
        ushort destinationPort,
        string payload,
        byte protocol = UdpProtocol,
        bool fragmented = false,
        bool corruptIpChecksum = false)
        => Build(source, destination, sourcePort, destinationPort, Encoding.ASCII.GetBytes(payload), protocol, fragmented, corruptIpChecksum);

    /// <summary>Parses a packet without trusting anything about it, checksums included.</summary>
    public static bool TryParse(byte[] packet, out UdpDatagram datagram)
    {
        datagram = default!;

        if (packet.Length < IpHeaderLength + UdpHeaderLength || (packet[0] >> 4) != 4)
        {
            return false;
        }

        var ihl = (packet[0] & 0x0F) * 4;
        if (ihl < IpHeaderLength || packet.Length < ihl)
        {
            return false;
        }

        var totalLength = ReadUInt16(packet, 2);
        if (totalLength < ihl + UdpHeaderLength || totalLength > packet.Length)
        {
            return false;
        }

        if (packet[9] != UdpProtocol)
        {
            return false;
        }

        var source = ReadUInt32(packet, 12);
        var destination = ReadUInt32(packet, 16);
        var udp = packet.AsSpan(ihl, totalLength - ihl);
        var udpLength = Math.Min(ReadUInt16(udp, 4), udp.Length);
        var payloadLength = udpLength >= UdpHeaderLength ? udpLength - UdpHeaderLength : 0;

        datagram = new UdpDatagram(
            source,
            destination,
            ReadUInt16(udp, 0),
            ReadUInt16(udp, 2),
            udp.Slice(UdpHeaderLength, payloadLength).ToArray(),
            ihl,
            Sum(packet.AsSpan(0, ihl), 0) == 0xFFFF,
            Sum(udp[..udpLength], PseudoSeed(source, destination, UdpProtocol, udpLength)) == 0xFFFF);

        return true;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset)
        => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static uint ReadUInt32(byte[] data, int offset)
        => ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) | ((uint)data[offset + 2] << 8) | data[offset + 3];

    private static void WriteUInt16(byte[] data, int offset, ushort value)
    {
        data[offset] = (byte)(value >> 8);
        data[offset + 1] = (byte)value;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value >> 24);
        data[offset + 1] = (byte)(value >> 16);
        data[offset + 2] = (byte)(value >> 8);
        data[offset + 3] = (byte)value;
    }
}

/// <summary>One datagram as the test codec saw it.</summary>
internal sealed record UdpDatagram(
    uint SourceAddress,
    uint DestinationAddress,
    ushort SourcePort,
    ushort DestinationPort,
    byte[] Payload,
    int IpHeaderLength,
    bool IpChecksumValid,
    bool UdpChecksumValid)
{
    /// <summary>The source address as a dotted quad.</summary>
    public string SourceText => UdpPackets.Format(SourceAddress);

    /// <summary>The destination address as a dotted quad.</summary>
    public string DestinationText => UdpPackets.Format(DestinationAddress);

    /// <summary>The payload decoded as ASCII, for assertions.</summary>
    public string Text => Encoding.ASCII.GetString(Payload);
}

/// <summary>
/// A TUN device that is a pair of queues: packets injected by the test are read
/// by the relay, and packets the relay writes are collected for inspection.
/// </summary>
internal sealed class FakeTunDevice : ITunPacketDevice, IDisposable
{
    private readonly BlockingCollection<byte[]> _inbound = new();
    private readonly BlockingCollection<byte[]> _written = new();
    private int _reads;

    /// <summary>How many times the relay asked for a packet.</summary>
    public int ReadCalls => Volatile.Read(ref _reads);

    /// <summary>Number of packets written but not yet collected.</summary>
    public int PendingWrites => _written.Count;

    /// <summary>Queues a packet for the relay to read, as the driver would.</summary>
    public void Inject(byte[] packet) => _inbound.Add(packet);

    /// <inheritdoc />
    public int Read(Span<byte> destination, int timeoutMilliseconds)
    {
        Interlocked.Increment(ref _reads);

        if (!_inbound.TryTake(out var packet, timeoutMilliseconds))
        {
            return 0;
        }

        var length = Math.Min(packet.Length, destination.Length);
        packet.AsSpan(0, length).CopyTo(destination);
        return length;
    }

    /// <inheritdoc />
    public void Write(ReadOnlySpan<byte> packet) => _written.Add(packet.ToArray());

    /// <summary>The next packet the relay wrote, or null when none arrived in time.</summary>
    public byte[]? NextWritten(TimeSpan timeout) => _written.TryTake(out var packet, timeout) ? packet : null;

    /// <summary>Stops accepting packets; the collections are left for the GC.</summary>
    public void Dispose()
    {
        _inbound.CompleteAdding();
        _written.CompleteAdding();
    }
}

/// <summary>
/// A tunnel stand-in for the relay: it records the datagrams it is handed and
/// can answer them, which is all the relay's contract with
/// <see cref="ITunnel.HandleUdpAsync"/> requires.
/// </summary>
internal sealed class ScriptedTunnel : ITunnel
{
    private readonly IDnsResolver? _dns;
    private readonly List<(EndPoint Remote, byte[] Payload)> _received = [];
    private readonly Lock _gate = new();
    private readonly TaskCompletionSource<Metadata> _started = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _udpCalls;
    private int _queriesAnswered;

    public ScriptedTunnel(IDnsResolver? dns = null) => _dns = dns;

    /// <summary>Sends one reply per datagram, when set.</summary>
    public Func<IPacketConnection, EndPoint, byte[], Task>? Reply { get; set; }

    /// <summary>Runs before the receive loop, for tests that need to talk first.</summary>
    public Func<IPacketConnection, Task>? OnStart { get; set; }

    public ClashConfig Config { get; } = new();

    public IDnsResolver Dns => _dns ?? throw new NotSupportedException("this test tunnel has no resolver");

    public IGeoData Geo => throw new NotSupportedException();

    public IProxyManager Proxies => throw new NotSupportedException();

    public ConnectionManager Connections { get; } = new(new TrafficTracker());

    public IRuleEngine Rules => throw new NotSupportedException();

    public TrafficTracker Traffic { get; } = new();

    public IDelayTester DelayTester => throw new NotSupportedException();

    public Mode Mode { get; set; } = Mode.Rule;

    /// <summary>Datagrams the relay handed over, in arrival order.</summary>
    public IReadOnlyList<(EndPoint Remote, byte[] Payload)> Received
    {
        get
        {
            lock (_gate)
            {
                return [.. _received];
            }
        }
    }

    /// <summary>How many datagrams the relay handed over.</summary>
    public int ReceivedCount
    {
        get
        {
            lock (_gate)
            {
                return _received.Count;
            }
        }
    }

    /// <summary>How many datagrams this tunnel answered through the reply path.</summary>
    public int QueriesAnswered => Volatile.Read(ref _queriesAnswered);

    /// <summary>How many times the relay entered <see cref="HandleUdpAsync"/>.</summary>
    public int HandleUdpCalls => Volatile.Read(ref _udpCalls);

    /// <summary>The metadata of the association, once it started.</summary>
    public Metadata? UdpMetadata { get; private set; }

    /// <summary>Completes when the relay hands over its first association.</summary>
    public Task<Metadata> UdpStarted => _started.Task;

    public event Action<string, string>? LogEmitted;

    public Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult<RuleMatch?>(null);

    public Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public async Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _udpCalls);
        UdpMetadata = metadata;
        _started.TrySetResult(metadata);

        if (OnStart is not null)
        {
            await OnStart(inbound).ConfigureAwait(false);
        }

        var buffer = new byte[65_535];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var received = await inbound.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (received.BytesRead <= 0 || received.Remote is null)
                {
                    return;
                }

                var payload = buffer.AsMemory(0, received.BytesRead).ToArray();
                lock (_gate)
                {
                    _received.Add((received.Remote, payload));
                }

                if (Reply is not null)
                {
                    await Reply(inbound, received.Remote, payload).ConfigureAwait(false);
                    Interlocked.Increment(ref _queriesAnswered);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // The relay is shutting down.
        }
    }

    public void Log(string level, string message) => LogEmitted?.Invoke(level, message);
}

/// <summary>An upstream that never answers usefully and counts every exchange.</summary>
internal sealed class CountingUpstream : IDnsUpstream
{
    private int _calls;

    public CountingUpstream(string name = "counting://") => Name = name;

    public string Name { get; }

    /// <summary>How many queries reached the network path.</summary>
    public int Calls => Volatile.Read(ref _calls);

    public Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);

        var name = query.Questions.Count > 0 ? query.Questions[0].Name : "unused";
        var record = DnsCodec.CreateAddressRecord(name, IPAddress.Parse("93.184.216.34"), 60);
        return Task.FromResult(DnsCodec.WithAnswers(query, [record], 60));
    }

    public void Dispose()
    {
    }
}
