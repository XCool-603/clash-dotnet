using System.Net;
using System.Threading.Channels;
using Clash.Core.Common;
using Clash.Core.Netstack;
using Xunit;

namespace Clash.Tests.Netstack;

/// <summary>
/// Tests the bridge between the host and a UDP-like packet association, which is
/// how a WireGuard outbound would carry this stack's packets. The association is
/// faked with a channel; no socket is involved.
/// </summary>
public class NetstackAdapterTests
{
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("93.184.216.34"), 80);
    private static readonly EndPoint Peer = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 51820);

    private static NetstackOptions Options() => new()
    {
        LocalAddress = IPAddress.Parse("10.7.0.2"),
        Mss = 1400,
        InitialRetransmitTimeout = TimeSpan.FromMilliseconds(40),
        CloseTimeout = TimeSpan.FromSeconds(2),
    };

    [Fact]
    public async Task AdapterCarriesPacketsBetweenTheHostAndTheAssociation()
    {
        var host = new NetstackHost(Options());
        var connection = new FakePacketConnection();
        await using var adapter = new NetstackPacketConnectionAdapter(host, connection, Peer);

        var connecting = host.ConnectAsync(Remote).AsTask();

        var syn = await connection.WaitForAsync(packet => packet.Syn);
        Assert.True(syn.ChecksumValid);
        Assert.Equal("10.7.0.2", syn.SourceText);
        Assert.Equal("93.184.216.34", syn.DestinationText);
        Assert.Equal(1400, syn.Mss);

        // Answer the way a WireGuard peer would: a raw datagram back into the association.
        connection.Deliver(TestPackets.Build(
            syn.DestinationAddress,
            syn.SourceAddress,
            syn.DestinationPort,
            syn.SourcePort,
            5000,
            syn.Sequence + 1,
            (byte)(TestPackets.FlagSyn | TestPackets.FlagAck),
            default,
            65535,
            1400));

        var stream = await connecting;
        await stream.WriteAsync("hello wireguard"u8.ToArray());

        var data = await connection.WaitForAsync(packet => packet.Payload.Length > 0);
        Assert.Equal("hello wireguard", data.Text);
        Assert.Equal(syn.Sequence + 1, data.Sequence);
        Assert.Equal(5001u, data.Acknowledgment);
        Assert.True(data.ChecksumValid);
        Assert.True(data.IpChecksumValid);

        // The acknowledgement of the peer's SYN-ACK must have been sent too.
        Assert.Contains(connection.Sent, raw => TestPackets.TryParse(raw, out var packet) && packet.Ack && !packet.Syn);

        await stream.DisposeAsync();
        await host.DisposeAsync();
    }

    [Fact]
    public async Task DisposingTheAdapterStopsTheHostFromEmitting()
    {
        var host = new NetstackHost(Options());
        var connection = new FakePacketConnection();
        var adapter = new NetstackPacketConnectionAdapter(host, connection, Peer);

        var connecting = host.ConnectAsync(Remote).AsTask();
        await connection.WaitForAsync(packet => packet.Syn);

        await adapter.DisposeAsync();

        Assert.Null(host.PacketSink);

        // The host is what owns the pending flow, so disposing it is what ends it.
        await host.DisposeAsync();
        Assert.Equal(0, host.ConnectionCount);
        await Assert.ThrowsAnyAsync<Exception>(() => connecting.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    /// <summary>A packet association backed by an in-memory queue.</summary>
    private sealed class FakePacketConnection : IPacketConnection
    {
        private readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>();
        private readonly List<byte[]> _sent = [];
        private readonly SemaphoreSlim _sentSignal = new(0);
        private readonly Lock _gate = new();

        /// <inheritdoc />
        public bool SupportsMultipleDestinations => true;

        /// <inheritdoc />
        public EndPoint? LocalEndPoint => null;

        /// <summary>Everything the host has emitted, in order.</summary>
        public IReadOnlyList<byte[]> Sent
        {
            get
            {
                lock (_gate)
                {
                    return [.. _sent];
                }
            }
        }

        /// <summary>Pushes a datagram into the association, as the tunnel would.</summary>
        public void Deliver(byte[] packet) => _inbound.Writer.TryWrite(packet);

        /// <summary>Waits for the <paramref name="skip"/>-th emitted packet matching a predicate.</summary>
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
                    foreach (var raw in _sent)
                    {
                        if (!TestPackets.TryParse(raw, out var packet) || !predicate(packet))
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
                    throw new TimeoutException("the host never emitted the expected packet");
                }

                await _sentSignal.WaitAsync(remaining).ConfigureAwait(false);
            }
        }

        /// <inheritdoc />
        public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var packet = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            packet.CopyTo(buffer);
            return new PacketResult(packet.Length, Peer);
        }

        /// <inheritdoc />
        public ValueTask<int> SendAsync(
            ReadOnlyMemory<byte> payload,
            EndPoint destination,
            CancellationToken cancellationToken = default)
        {
            lock (_gate)
            {
                _sent.Add(payload.ToArray());
                _sentSignal.Release();
            }

            return ValueTask.FromResult(payload.Length);
        }

        /// <inheritdoc />
        public ValueTask DisposeAsync()
        {
            _inbound.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}
