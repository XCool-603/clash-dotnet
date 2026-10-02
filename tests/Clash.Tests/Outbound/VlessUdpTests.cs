using System.Buffers.Binary;
using System.Net;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Outbound;

/// <summary>
/// VLESS UDP coverage: the classic "UDP over TCP" form, in which the request header
/// switches to command <c>0x02</c> with an empty flow and every datagram on that
/// connection is framed as <c>length(2, big-endian) || payload</c>.
/// <para>
/// As in <see cref="VlessTests"/>, the fake server reassembles the header from the
/// reference field order instead of calling the adapter's own helpers, so the
/// assertions describe what an Xray-core VLESS server would actually receive.
/// </para>
/// </summary>
public class VlessUdpTests
{
    private const string UuidText = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// <summary>
    /// Where the command byte sits in a header that carries no addons:
    /// version(1) + uuid(16) + addons-length(1).
    /// </summary>
    private const int CommandOffset = 18;

    /// <summary>The request header as a VLESS server parses it, plus the raw bytes.</summary>
    private sealed record RequestHeader(byte[] Raw, byte[] Addons, byte Command, int Port, byte AddressType, string Host);

    // ── the request header ───────────────────────────────────────────────────

    [Fact]
    public async Task UdpRequestHeaderCarriesCommandTwoAtTheDocumentedOffset()
    {
        RequestHeader? seen = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-udp", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("udp", true)));

        Assert.True(adapter.SupportUdp);

        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53));
        await server.WaitAsync();

        var header = Assert.IsType<RequestHeader>(seen);

        // The command byte itself, at the offset the layout puts it.
        Assert.Equal(0x02, header.Raw[CommandOffset]);
        Assert.Equal(VlessCrypto.CommandUdp, header.Command);

        // No flow is sent for a UDP connection, so the addons block is empty.
        Assert.Empty(header.Addons);

        // The destination still lives in the header, which is the only place a VLESS
        // UDP association names it.
        Assert.Equal(53, header.Port);
        Assert.Equal(1, header.AddressType); // ATYP 1 = IPv4
        Assert.Equal("127.0.0.1", header.Host);

        // One destination per connection: no frame repeats the address.
        Assert.False(connection.SupportsMultipleDestinations);
    }

    [Fact]
    public async Task TcpRequestHeaderStillCarriesCommandOne()
    {
        RequestHeader? seen = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-tcp-guard", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("127.0.0.1", 443));
        await outbound.DisposeAsync();
        await server.WaitAsync();

        var header = Assert.IsType<RequestHeader>(seen);
        Assert.Equal(0x01, header.Raw[CommandOffset]);
        Assert.Equal(VlessCrypto.CommandTcp, header.Command);
    }

    // ── datagram framing ─────────────────────────────────────────────────────

    [Fact]
    public async Task DatagramIsFramedAsTwoByteBigEndianLengthThenPayload()
    {
        var shortPayload = ByteAssert.Ascii("hello");
        var longPayload = new byte[300];
        for (var i = 0; i < longPayload.Length; i++) longPayload[i] = (byte)i;

        byte[]? shortFrame = null;
        byte[]? longFrame = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);
            shortFrame = await ReadExactlyAsync(stream, 2 + shortPayload.Length, ct);
            longFrame = await ReadExactlyAsync(stream, 2 + longPayload.Length, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-udp-frame", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("udp", true)));

        var destination = new IPEndPoint(IPAddress.Loopback, 53);
        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53));

        Assert.Equal(shortPayload.Length, await connection.SendAsync(shortPayload, destination));
        Assert.Equal(longPayload.Length, await connection.SendAsync(longPayload, destination));

        await server.WaitAsync();

        // Exactly length(2, BE) || payload, with nothing in between and nothing after.
        var expectedShort = new byte[2 + shortPayload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(expectedShort, (ushort)shortPayload.Length);
        shortPayload.CopyTo(expectedShort, 2);
        Assert.Equal(expectedShort, shortFrame);

        var expectedLong = new byte[2 + longPayload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(expectedLong, (ushort)longPayload.Length);
        longPayload.CopyTo(expectedLong, 2);
        Assert.Equal(expectedLong, longFrame);

        // 300 is 0x012C: the high byte leads, so the length is big-endian and not
        // little-endian (which would have written 0x2C 0x01).
        Assert.Equal(0x01, longFrame![0]);
        Assert.Equal(0x2C, longFrame[1]);
    }

    [Fact]
    public async Task ZeroLengthDatagramIsFramedAsTwoZeroBytesAndKeepsTheStreamInStep()
    {
        var payload = ByteAssert.Ascii("after the empty datagram");

        byte[]? emptyFrame = null;
        byte[]? nextFrame = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);
            emptyFrame = await ReadExactlyAsync(stream, 2, ct);
            nextFrame = await ReadExactlyAsync(stream, 2 + payload.Length, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-udp-empty", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("udp", true)));

        var destination = new IPEndPoint(IPAddress.Loopback, 53);
        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53));

        // An empty datagram is legal UDP and still costs one two-byte frame.
        Assert.Equal(0, await connection.SendAsync(ReadOnlyMemory<byte>.Empty, destination));
        Assert.Equal(payload.Length, await connection.SendAsync(payload, destination));

        await server.WaitAsync();

        Assert.Equal(new byte[] { 0x00, 0x00 }, emptyFrame);

        // The empty frame must not swallow or shift the next datagram.
        var expected = new byte[2 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(expected, (ushort)payload.Length);
        payload.CopyTo(expected, 2);
        Assert.Equal(expected, nextFrame);
    }

    // ── the receive path ─────────────────────────────────────────────────────

    [Fact]
    public async Task AZeroLengthFrameFromTheServerIsReportedAndDoesNotDesynchroniseTheStream()
    {
        var payload = ByteAssert.Ascii("the frame after the empty one");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);

            // The response header comes first, then an empty datagram, then a real one.
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);

            var frame = new byte[2 + payload.Length];
            BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)payload.Length);
            payload.CopyTo(frame, 2);
            await stream.WriteAsync(frame, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-udp-recv-empty", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("udp", true)));

        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53));

        var buffer = new byte[1024];
        var first = await connection.ReceiveAsync(buffer);
        await server.WaitAsync();

        // The empty datagram is surfaced as a zero-length packet — the same shape the
        // Trojan and Shadowsocks associations use — rather than skipped.
        Assert.Equal(0, first.BytesRead);

        // The next frame is still read whole, so the zero-length one left the stream
        // exactly in step. Without the explicit empty-frame branch the two length
        // bytes would have been consumed as payload and this read would return the
        // *third* frame's header instead.
        var second = await connection.ReceiveAsync(buffer);
        Assert.Equal(payload.Length, second.BytesRead);
        Assert.Equal(payload, buffer[..second.BytesRead]);

        // A VLESS UDP frame carries no address, so the reply is attributed to the
        // destination the request header named.
        Assert.Equal(new IPEndPoint(IPAddress.Loopback, 53), second.Remote);
    }

    [Fact]
    public async Task ResponseAddonsAreConsumedBeforeTheDatagramFrames()
    {
        var payload = ByteAssert.Ascii("payload behind a non-empty addons block");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);

            // version 0, addons length 3, three addon bytes the client must skip, and
            // only then the first length-prefixed datagram.
            await stream.WriteAsync(new byte[] { 0x00, 0x03, 0xAA, 0xBB, 0xCC }, ct);

            var frame = new byte[2 + payload.Length];
            BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)payload.Length);
            payload.CopyTo(frame, 2);
            await stream.WriteAsync(frame, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-udp-response-addons", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("udp", true)));

        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53));

        var buffer = new byte[1024];
        var received = await connection.ReceiveAsync(buffer);
        await server.WaitAsync();

        Assert.Equal(payload.Length, received.BytesRead);
        Assert.Equal(payload, buffer[..received.BytesRead]);
    }

    // ── configuration ────────────────────────────────────────────────────────

    [Theory]
    [InlineData(false)]
    [InlineData(null)]
    public async Task UdpIsRefusedWhenTheConfigurationDoesNotEnableIt(bool? udp)
    {
        var entry = udp is null
            ? OutboundHarness.Entry(
                "vless-no-udp", "vless",
                ("server", "127.0.0.1"),
                ("port", 443),
                ("uuid", UuidText))
            : OutboundHarness.Entry(
                "vless-no-udp", "vless",
                ("server", "127.0.0.1"),
                ("port", 443),
                ("uuid", UuidText),
                ("udp", udp));

        var adapter = OutboundHarness.Build(entry);

        // `udp` defaults to off, and the flag is what the tunnel routes on.
        Assert.False(adapter.SupportUdp);

        var error = await Assert.ThrowsAsync<NotSupportedException>(
            () => adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53)));

        Assert.Contains("vless-no-udp", error.Message, StringComparison.Ordinal);
        Assert.Contains("UDP disabled", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UdpEnabledConfigurationDropsTheVisionFlowAndSendsNoPadding()
    {
        RequestHeader? seen = null;
        byte[]? frame = null;
        var payload = ByteAssert.Ascii("udp");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);
            frame = await ReadExactlyAsync(stream, 2 + payload.Length, ct);
        });

        // 'flow' plus 'tls: true' is the configuration vision needs for TCP; a UDP
        // dial on the same proxy must not apply it.
        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-udp-vision", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("udp", true),
            ("tls", true),
            ("flow", "xtls-rprx-vision")));

        Assert.True(adapter.SupportUdp);

        await using var connection = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("127.0.0.1", 53));
        await connection.SendAsync(payload, new IPEndPoint(IPAddress.Loopback, 53));
        await server.WaitAsync();

        var header = Assert.IsType<RequestHeader>(seen);

        // Command 2 and an empty flow: vision is TCP-only, so the flow is dropped
        // rather than refused and never reaches the header.
        Assert.Equal(VlessCrypto.CommandUdp, header.Command);
        Assert.Empty(header.Addons);

        // A vision write would open with the 16-byte UUID of a padding block; the
        // bytes on the wire are a bare length-prefixed datagram instead.
        Assert.Equal(new byte[] { 0x00, 0x03, (byte)'u', (byte)'d', (byte)'p' }, frame);
    }

    // ── helpers: the wire format, reassembled by hand ─────────────────────────

    /// <summary>
    /// Reads a VLESS request header straight off the socket in the reference field
    /// order, keeping every byte so a test can assert an offset in it directly.
    /// </summary>
    private static async Task<RequestHeader> ReadRequestHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        var raw = new List<byte>();

        var version = await ReadIntoAsync(stream, raw, 1, cancellationToken);
        Assert.Equal(0, version[0]);

        await ReadIntoAsync(stream, raw, 16, cancellationToken); // uuid

        var addonsLength = (await ReadIntoAsync(stream, raw, 1, cancellationToken))[0];
        var addons = await ReadIntoAsync(stream, raw, addonsLength, cancellationToken);

        var command = (await ReadIntoAsync(stream, raw, 1, cancellationToken))[0];
        var port = BinaryPrimitives.ReadUInt16BigEndian(await ReadIntoAsync(stream, raw, 2, cancellationToken));

        var addressType = (await ReadIntoAsync(stream, raw, 1, cancellationToken))[0];
        string host;
        switch (addressType)
        {
            case 1: // IPv4
                host = new IPAddress(await ReadIntoAsync(stream, raw, 4, cancellationToken)).ToString();
                break;
            case 2: // domain name, length-prefixed
                var nameLength = (await ReadIntoAsync(stream, raw, 1, cancellationToken))[0];
                host = System.Text.Encoding.ASCII.GetString(await ReadIntoAsync(stream, raw, nameLength, cancellationToken));
                break;
            case 3: // IPv6
                host = new IPAddress(await ReadIntoAsync(stream, raw, 16, cancellationToken)).ToString();
                break;
            default:
                throw new InvalidOperationException($"unknown VLESS address type {addressType}");
        }

        return new RequestHeader(raw.ToArray(), addons, command, port, addressType, host);
    }

    private static async Task<byte[]> ReadIntoAsync(Stream stream, List<byte> sink, int count, CancellationToken cancellationToken)
    {
        var buffer = await ReadExactlyAsync(stream, count, cancellationToken);
        sink.AddRange(buffer);
        return buffer;
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }
}
