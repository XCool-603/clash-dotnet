using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Clash.Core.Transport;
using Clash.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Outbound;

/// <summary>
/// VLESS coverage. The fake server never calls into the adapter's own framing
/// helpers: it reassembles the request header, the vision padding block and the
/// response header byte by byte from the reference layout, so the assertions are
/// about what a VLESS server would actually receive.
/// <para>
/// The layouts asserted here come from mihomo's own client
/// (<c>transport/vless/vless.go</c>: <c>AtypIPv4 = 1</c>, <c>AtypDomainName = 2</c>,
/// <c>AtypIPv6 = 3</c>; <c>transport/vless/conn.go</c>: version, UUID, addons
/// length, addons, command, big-endian port, address type, address) and from
/// sing-vmess (<c>vless_protocol.go</c>, <c>vless_vision.go</c>).
/// </para>
/// </summary>
public class VlessTests
{
    private const string UuidText = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// <summary>The request header as a VLESS server parses it, field by field.</summary>
    private sealed record RequestHeader(byte[] Uuid, byte[] Addons, byte Command, int Port, byte AddressType, string Host);

    // ── request header ───────────────────────────────────────────────────────

    [Fact]
    public async Task RequestHeaderIsVersionUuidAddonsCommandPortThenAddress()
    {
        var expectedUuid = ClashHex.ParseUuid(UuidText);
        var payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };
        var reply = ByteAssert.Ascii("hello from the far side");

        RequestHeader? seen = null;
        byte[]? seenPayload = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);
            seenPayload = await ReadExactlyAsync(stream, payload.Length, ct);

            // Response: version 0, no addons, then the payload.
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);
            await stream.WriteAsync(reply, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-plain", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(payload);

        var echoed = new byte[reply.Length];
        await outbound.ReadExactlyAsync(echoed);

        var header = Assert.IsType<RequestHeader>(seen);

        // version(1) = 0, then the raw 16 UUID bytes.
        Assert.Equal(expectedUuid, header.Uuid);

        // addons-length(1) then the protobuf Addons message; no flow, so it is empty.
        Assert.Empty(header.Addons);

        // command(1) = 1 (TCP), port(2, big-endian), then the address.
        Assert.Equal(1, header.Command);
        Assert.Equal(443, header.Port);

        // ATYP 2 = domain name, then a one-byte length and the name itself. The port
        // came before the address, which is the order that distinguishes VLESS from
        // the SOCKS5 address block.
        Assert.Equal(2, header.AddressType);
        Assert.Equal("example.com", header.Host);

        Assert.Equal(payload, seenPayload);
        Assert.Equal(reply, echoed);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public async Task FlowIsEncodedAsProtobufFieldOneInsideTheAddonsBlock()
    {
        var expectedUuid = ClashHex.ParseUuid(UuidText);
        RequestHeader? seen = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);

            // The client never reads a response here, so the server must consume
            // whatever it sends before closing: an unread byte on either side turns
            // the close into an RST.
            await OutboundHarness.DrainAsync(stream, ct);
        });

        // Vision needs 'tls: true' and the default 'tcp' network to get past the
        // adapter's precondition checks; the plain composer carries no TLS, which is
        // fine because the header is written before any padding block.
        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-vision", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("tls", true),
            ("flow", "xtls-rprx-vision")));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(new byte[] { 0x01 });

        // The server's handler captures the header, so wait for it before asserting.
        await outbound.DisposeAsync();
        await server.WaitAsync();

        var header = Assert.IsType<RequestHeader>(seen);
        Assert.Equal(expectedUuid, header.Uuid);

        // protobuf: field 1, wire type 2 -> 0x0A, then the length, then the flow.
        var flow = ByteAssert.Ascii("xtls-rprx-vision");
        Assert.Equal(2 + flow.Length, header.Addons.Length);
        Assert.Equal(0x0A, header.Addons[0]);
        Assert.Equal(flow.Length, header.Addons[1]);
        Assert.Equal(flow, header.Addons[2..]);

        Assert.Equal(1, header.Command);
        Assert.Equal(443, header.Port);
        Assert.Equal(2, header.AddressType);
        Assert.Equal("example.com", header.Host);
    }

    [Theory]
    [InlineData("1.2.3.4", 1)]
    [InlineData("2001:db8::1", 3)]
    public async Task AddressTypeFollowsTheDestinationFamily(string destination, byte expectedType)
    {
        RequestHeader? seen = null;
        byte[]? afterHeader = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);

            // Whatever follows the header must be the client's payload: reading it
            // back proves the address block was exactly as wide as it claimed.
            afterHeader = await ReadExactlyAsync(stream, 1, ct);

            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-ip", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow(destination, 8443));
        await outbound.WriteAsync(new byte[] { 0x5A });

        await outbound.DisposeAsync();
        await server.WaitAsync();

        var header = Assert.IsType<RequestHeader>(seen);
        Assert.Equal(expectedType, header.AddressType);
        Assert.Equal(IPAddress.Parse(destination).ToString(), header.Host);
        Assert.Equal(8443, header.Port);
        Assert.Equal(new byte[] { 0x5A }, afterHeader);
    }

    [Fact]
    public async Task NonUuidIdentityIsHashedIntoTheReferenceUuidV5()
    {
        RequestHeader? seen = null;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-derived", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", "example-user")));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        await outbound.WriteAsync(new byte[] { 0x01 });

        await outbound.DisposeAsync();
        await server.WaitAsync();

        // SHA-1(nil-namespace || "example-user")[0..16] with the version-5 and
        // RFC 9562 variant bits forced, i.e. mihomo's utils.NewUUIDV5(uuid.Nil, s).
        var header = Assert.IsType<RequestHeader>(seen);
        Assert.Equal("83f813e81b935c42a9a0b5e49d98fabb", Convert.ToHexString(header.Uuid).ToLowerInvariant());
    }

    // ── response header ──────────────────────────────────────────────────────

    [Fact]
    public async Task ShutdownSendHalfClosesATransportThatSupportsIt()
    {
        var sawEof = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var body = ByteAssert.Ascii("after eof");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);

            // The server answers only once the client's send direction is closed.
            var scratch = new byte[64];
            while (await stream.ReadAsync(scratch, ct) > 0)
            {
            }

            sawEof.SetResult(true);
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);
            await stream.WriteAsync(body, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        // The production TCP layer hands out a NetworkStream, which cannot half-close;
        // SocketStream is the type in this build that can, so the composer below uses
        // it to prove the adapter forwards the half-close instead of swallowing it.
        var context = new AdapterBuildContext
        {
            Config = new FakeTunnel().Config,
            Tunnel = new FakeTunnelAccessor(new FakeTunnel()),
            Transports = new HalfCloseComposer(),
            LoggerFactory = NullLoggerFactory.Instance,
        };

        var adapter = AdapterRegistry.Create(
            OutboundHarness.Entry(
                "vless-halfclose", "vless",
                ("server", "127.0.0.1"),
                ("port", server.Port),
                ("uuid", UuidText)),
            context);

        var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        Assert.True(outbound.SupportsHalfClose);
        outbound.ShutdownSend();

        Assert.True(await sawEof.Task.WaitAsync(TimeSpan.FromSeconds(10)));

        var echoed = new byte[body.Length];
        await outbound.ReadExactlyAsync(echoed);
        Assert.Equal(body, echoed);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public async Task ResponseAddonsAreConsumedAndDiscardedBeforeThePayload()
    {
        var body = ByteAssert.Ascii("payload after a non-empty addons block");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);

            // version 0, addons length 3, three addon bytes the client must skip,
            // and only then the payload.
            await stream.WriteAsync(new byte[] { 0x00, 0x03, 0xAA, 0xBB, 0xCC }, ct);
            await stream.WriteAsync(body, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-addons", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        await outbound.WriteAsync(new byte[] { 0x01 });

        var echoed = new byte[body.Length];
        await outbound.ReadExactlyAsync(echoed);
        Assert.Equal(body, echoed);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public async Task NonZeroResponseVersionIsRejectedOnTheFirstRead()
    {
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);
            await stream.WriteAsync(new byte[] { 0x07, 0x00, 0x41 }, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-badversion", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        var buffer = new byte[16];
        var error = await Assert.ThrowsAsync<ClashException>(() => outbound.ReadAsync(buffer).AsTask());
        Assert.Contains("version", error.Message, StringComparison.OrdinalIgnoreCase);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    // ── xtls-rprx-vision ─────────────────────────────────────────────────────

    [Fact]
    public async Task VisionWrapsWritesInReferencePaddingBlocksAndUnpadsTheResponse()
    {
        var expectedUuid = ClashHex.ParseUuid(UuidText);
        var request = ByteAssert.Ascii("ping");
        var reply = ByteAssert.Ascii("pong");
        var raw = ByteAssert.Ascii("unpadded");
        var second = ByteAssert.Ascii("again");

        RequestHeader? seen = null;
        byte[]? firstBlockUuid = null;
        byte[]? firstBlockContent = null;
        int firstBlockCommand = -1;
        int firstBlockContentLength = -1;
        byte[]? secondBlockContent = null;
        int secondBlockCommand = -1;

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            seen = await ReadRequestHeaderAsync(stream, ct);

            // First padding block: 16 UUID bytes, command, content length, padding
            // length, content, padding.
            (firstBlockUuid, firstBlockCommand, firstBlockContentLength, firstBlockContent) =
                await ReadVisionBlockAsync(stream, includeUuid: true, ct);

            // The server's response header is unpadded, then its own padding block
            // carries the payload and closes padding with command 1 (end). Everything
            // after that block is raw.
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);
            await WriteVisionBlockAsync(stream, expectedUuid, command: 1, reply, paddingLength: 5, ct);
            await stream.WriteAsync(raw, ct);

            // Later blocks omit the UUID.
            (_, secondBlockCommand, _, secondBlockContent) = await ReadVisionBlockAsync(stream, includeUuid: false, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-vision-rt", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("tls", true),
            ("flow", "xtls-rprx-vision")));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(request);

        var echoed = new byte[reply.Length];
        await outbound.ReadExactlyAsync(echoed);
        Assert.Equal(reply, echoed);

        // Command 1 (end) closed padding, so the bytes the server writes next arrive
        // verbatim, with no block header in front of them.
        var tail = new byte[raw.Length];
        await outbound.ReadExactlyAsync(tail);
        Assert.Equal(raw, tail);

        await outbound.WriteAsync(second);

        await outbound.DisposeAsync();
        await server.WaitAsync();

        var header = Assert.IsType<RequestHeader>(seen);
        Assert.Equal(0x0A, header.Addons[0]);

        // The UUID opens the first block only.
        Assert.Equal(expectedUuid, firstBlockUuid);
        Assert.Equal(0, firstBlockCommand); // continue
        Assert.Equal(request.Length, firstBlockContentLength);
        Assert.Equal(request, firstBlockContent);

        // Plaintext traffic never looks like TLS, so the reference keeps padding
        // until its eight-packet filter window has almost run out; the second write
        // is therefore still a continue block carrying the whole payload.
        Assert.Equal(0, secondBlockCommand);
        Assert.Equal(second, secondBlockContent);
    }

    [Fact]
    public async Task VisionPassesThroughVerbatimWhenTheServerDoesNotPad()
    {
        var body = ByteAssert.Ascii("this server is not padding at all");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);
            await ReadVisionBlockAsync(stream, includeUuid: true, ct);

            // No padding block: the response header is followed by raw payload, which
            // does not open with the client's UUID.
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);
            await stream.WriteAsync(body, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-vision-unpadded", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("tls", true),
            ("flow", "xtls-rprx-vision")));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(ByteAssert.Ascii("ping"));

        var echoed = new byte[body.Length];
        await outbound.ReadExactlyAsync(echoed);
        Assert.Equal(body, echoed);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public async Task VisionRefusesTheServerDirectCopySwitch()
    {
        var expectedUuid = ClashHex.ParseUuid(UuidText);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);
            await ReadVisionBlockAsync(stream, includeUuid: true, ct);

            // command 2 = direct: the sender wants to stop framing and splice raw
            // bytes, which this build cannot do. The client refuses on the spot and
            // tears the flow down, so the server must not wait for a clean close.
            await stream.WriteAsync(new byte[] { 0x00, 0x00 }, ct);
            await WriteVisionBlockAsync(stream, expectedUuid, command: 2, ByteAssert.Ascii("raw"), paddingLength: 0, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-vision-direct", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("tls", true),
            ("flow", "xtls-rprx-vision")));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(ByteAssert.Ascii("ping"));

        var buffer = new byte[16];
        var error = await Assert.ThrowsAsync<ClashException>(() => outbound.ReadAsync(buffer).AsTask());
        Assert.Contains("direct", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SslStream", error.Message, StringComparison.Ordinal);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public async Task VisionIsAcceptedAtConstructionButRefusedWithoutTls()
    {
        var entry = OutboundHarness.Entry(
            "vless-vision-notls", "vless",
            ("server", "127.0.0.1"),
            ("port", 443),
            ("uuid", UuidText),
            ("flow", "xtls-rprx-vision"));

        var adapter = OutboundHarness.Build(entry);
        Assert.Equal("Vless", adapter.TypeName);

        var error = await Assert.ThrowsAsync<ClashException>(
            () => adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443)));
        Assert.Contains("tls", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("xtls-rprx-vision", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task VisionIsRefusedOverANonTcpNetwork()
    {
        var entry = OutboundHarness.Entry(
            "vless-vision-ws", "vless",
            ("server", "127.0.0.1"),
            ("port", 443),
            ("uuid", UuidText),
            ("tls", true),
            ("network", "ws"),
            ("flow", "xtls-rprx-vision"));

        var adapter = OutboundHarness.Build(entry);

        var error = await Assert.ThrowsAsync<ClashException>(
            () => adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443)));
        Assert.Contains("tcp", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("xtls-rprx-vision", error.Message, StringComparison.Ordinal);
    }

    // ── configuration validation ─────────────────────────────────────────────

    [Fact]
    public void MissingUuidIsRejectedAtConstruction()
    {
        var entry = OutboundHarness.Entry(
            "vless-nouuid", "vless",
            ("server", "127.0.0.1"),
            ("port", 443));

        var error = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry));
        Assert.Contains("uuid", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("vless-nouuid", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RealityIsRefusedWithAClearMessage()
    {
        var entry = OutboundHarness.Entry(
            "vless-reality", "vless",
            ("server", "127.0.0.1"),
            ("port", 443),
            ("uuid", UuidText),
            ("tls", true),
            ("reality-opts", new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["public-key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ["short-id"] = "0123456789abcdef",
            }));

        var error = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry));
        Assert.Contains("REALITY", error.Message, StringComparison.Ordinal);
        Assert.Contains("reality-opts", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownFlowIsRejectedAtConstruction()
    {
        var entry = OutboundHarness.Entry(
            "vless-flow", "vless",
            ("server", "127.0.0.1"),
            ("port", 443),
            ("uuid", UuidText),
            ("tls", true),
            ("flow", "xtls-rprx-direct"));

        var error = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry));
        Assert.Contains("xtls-rprx-direct", error.Message, StringComparison.Ordinal);
    }

    // ── registration and transports ──────────────────────────────────────────

    [Fact]
    public void VlessIsRegisteredAndReportsItsApiType()
    {
        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "vless-api", "vless",
            ("server", "vless.example.org"),
            ("port", 8443),
            ("uuid", UuidText)));

        Assert.Equal(ProxyType.Vless, adapter.Type);
        Assert.Equal("Vless", adapter.TypeName);
        Assert.False(adapter.SupportUdp);

        var outbound = Assert.IsAssignableFrom<IOutboundProxy>(adapter);
        Assert.Equal("vless.example.org", outbound.ServerHost);
        Assert.Equal(8443, outbound.ServerPort);
    }

    [Fact]
    public async Task TheWholeEntryMapIsHandedToTheTransportComposer()
    {
        var composer = new RecordingComposer();
        var context = new AdapterBuildContext
        {
            Config = new FakeTunnel().Config,
            Tunnel = new FakeTunnelAccessor(new FakeTunnel()),
            Transports = composer,
            LoggerFactory = NullLoggerFactory.Instance,
        };

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            await ReadRequestHeaderAsync(stream, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var entry = OutboundHarness.Entry(
            "vless-ws", "vless",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("uuid", UuidText),
            ("tls", true),
            ("servername", "cdn.example.org"),
            ("skip-cert-verify", true),
            ("client-fingerprint", "chrome"),
            ("network", "ws"),
            ("ws-opts", new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["path"] = "/ws" }));

        var adapter = AdapterRegistry.Create(entry, context);
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        await outbound.WriteAsync(new byte[] { 0x01 });

        var handed = Assert.IsType<YamlMap>(composer.Last);
        Assert.Equal("ws", handed.GetString("network"));
        Assert.True(handed.GetBool("tls"));
        Assert.Equal("cdn.example.org", handed.GetString("servername"));
        Assert.True(handed.GetBool("skip-cert-verify"));
        Assert.Equal("chrome", handed.GetString("client-fingerprint"));
        Assert.Equal("/ws", handed.GetMap("ws-opts").GetString("path"));

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    // ── helpers: the wire format, reassembled by hand ─────────────────────────

    /// <summary>
    /// Reads a VLESS request header straight off the socket, using the reference's
    /// field order and address-family bytes rather than the adapter's helpers.
    /// </summary>
    private static async Task<RequestHeader> ReadRequestHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        var version = await ReadExactlyAsync(stream, 1, cancellationToken);
        Assert.Equal(0, version[0]);

        var uuid = await ReadExactlyAsync(stream, 16, cancellationToken);

        var addonsLength = (await ReadExactlyAsync(stream, 1, cancellationToken))[0];
        var addons = await ReadExactlyAsync(stream, addonsLength, cancellationToken);

        var command = (await ReadExactlyAsync(stream, 1, cancellationToken))[0];
        var port = BinaryPrimitives.ReadUInt16BigEndian(await ReadExactlyAsync(stream, 2, cancellationToken));

        var addressType = (await ReadExactlyAsync(stream, 1, cancellationToken))[0];
        string host;
        switch (addressType)
        {
            case 1: // IPv4
                host = new IPAddress(await ReadExactlyAsync(stream, 4, cancellationToken)).ToString();
                break;
            case 2: // domain name, length-prefixed
                var nameLength = (await ReadExactlyAsync(stream, 1, cancellationToken))[0];
                host = System.Text.Encoding.ASCII.GetString(await ReadExactlyAsync(stream, nameLength, cancellationToken));
                break;
            case 3: // IPv6
                host = new IPAddress(await ReadExactlyAsync(stream, 16, cancellationToken)).ToString();
                break;
            default:
                throw new InvalidOperationException($"unknown VLESS address type {addressType}");
        }

        return new RequestHeader(uuid, addons, command, port, addressType, host);
    }

    /// <summary>
    /// Reads one vision padding block:
    /// <c>[uuid(16)] | command(1) | content-length(2, BE) | padding-length(2, BE) | content | padding</c>.
    /// </summary>
    private static async Task<(byte[] Uuid, int Command, int ContentLength, byte[] Content)> ReadVisionBlockAsync(
        Stream stream,
        bool includeUuid,
        CancellationToken cancellationToken)
    {
        var header = await ReadExactlyAsync(stream, includeUuid ? 21 : 5, cancellationToken);
        var uuid = includeUuid ? header[..16] : [];
        var offset = includeUuid ? 16 : 0;
        var command = header[offset];
        var contentLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(offset + 1));
        var paddingLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(offset + 3));

        var content = await ReadExactlyAsync(stream, contentLength, cancellationToken);
        await ReadExactlyAsync(stream, paddingLength, cancellationToken);

        return (uuid, command, contentLength, content);
    }

    /// <summary>Writes one vision padding block, including the leading UUID.</summary>
    private static async Task WriteVisionBlockAsync(
        Stream stream,
        byte[] uuid,
        byte command,
        byte[] content,
        int paddingLength,
        CancellationToken cancellationToken)
    {
        var block = new byte[16 + 5 + content.Length + paddingLength];
        uuid.CopyTo(block, 0);
        block[16] = command;
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(17), (ushort)content.Length);
        BinaryPrimitives.WriteUInt16BigEndian(block.AsSpan(19), (ushort)paddingLength);
        content.CopyTo(block, 21);
        await stream.WriteAsync(block, cancellationToken);
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }

    /// <summary>A composer that opens a real TCP socket but remembers the options it was handed.</summary>
    private sealed class RecordingComposer : ITransportComposer
    {
        private readonly TcpTransport _tcp = new();

        internal YamlMap? Last { get; private set; }

        public IReadOnlyList<ITransportLayer> Compose(YamlMap proxyOptions) => [_tcp];

        public Task<ProxyStream> ConnectAsync(DialContext context, YamlMap proxyOptions, CancellationToken cancellationToken = default)
        {
            Last = proxyOptions;
            return _tcp.WrapAsync(null, context, proxyOptions, cancellationToken);
        }
    }

    /// <summary>
    /// A composer whose TCP layer is a <see cref="SocketStream"/>, the one stream type
    /// in this build that can half-close.
    /// </summary>
    private sealed class HalfCloseComposer : ITransportComposer
    {
        public IReadOnlyList<ITransportLayer> Compose(YamlMap proxyOptions) => [];

        public async Task<ProxyStream> ConnectAsync(
            DialContext context,
            YamlMap proxyOptions,
            CancellationToken cancellationToken = default)
        {
            var client = new TcpClient();
            try
            {
                await client.ConnectAsync(context.Host!, context.Port, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                client.Dispose();
                throw;
            }

            var socket = client.Client;
            return new ProxyStream(new SocketStream(socket), socket.LocalEndPoint, socket.RemoteEndPoint, owner: client);
        }
    }
}
