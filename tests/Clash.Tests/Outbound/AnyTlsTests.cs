using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
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
/// AnyTLS wire coverage. The server side here is written straight from the protocol
/// document - the command numbering, the seven-byte frame header, the SOCKS5 address
/// block and the auth block are all re-derived by hand in this file rather than
/// borrowed from the adapter, so a wrong choice in the adapter fails the comparison
/// instead of being mirrored by the test.
/// <para>
/// The transport is an in-memory duplex channel rather than a loopback socket: the
/// adapter only ever sees the byte pipe the transport stack hands it, so a pipe is
/// enough to exercise the protocol, and it keeps the tests hermetic and free of
/// ports, timing and OS socket state. Every client-side read carries a short
/// cancellation guard and every server-side result is awaited with a timeout, so a
/// protocol bug fails the test instead of hanging it.
/// </para>
/// </summary>
public class AnyTlsTests
{
    private const string Password = "anytls-test-password";

    /// <summary>Command bytes, from the protocol document's <c>cmd*</c> list.</summary>
    private const byte CmdWaste = 0;
    private const byte CmdSyn = 1;
    private const byte CmdPsh = 2;
    private const byte CmdFin = 3;
    private const byte CmdSettings = 4;
    private const byte CmdAlert = 5;
    private const byte CmdUpdatePaddingScheme = 6;
    private const byte CmdSynAck = 7;
    private const byte CmdHeartRequest = 8;
    private const byte CmdHeartResponse = 9;
    private const byte CmdServerSettings = 10;

    /// <summary>Framing overhead: command (1) + streamId (4) + data length (2).</summary>
    private const int FrameHeaderSize = 7;

    /// <summary>The largest data block a single frame's u16 length can describe.</summary>
    private const int MaxFrameData = 65535;

    /// <summary>The default scheme, verbatim from the document, and its md5.</summary>
    private const string DefaultSchemeText =
        "stop=8\n"
        + "0=30-30\n"
        + "1=100-400\n"
        + "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        + "3=9-9,500-1000\n"
        + "4=500-1000\n"
        + "5=500-1000\n"
        + "6=500-1000\n"
        + "7=500-1000";

    private const string DefaultSchemeMd5 = "75cff2ad89aadf5e257059ee571ebe11";

    /// <summary>The <c>client=</c> value this build is expected to report truthfully.</summary>
    private const string ClientName = "Clash.NET/1.0.0";

    /// <summary>A scheme with no session-level padding, so packet 1 is byte-exact.</summary>
    private const string AuthOnlyScheme = "stop=1\n0=30-30";

    /// <summary>md5 of <see cref="AuthOnlyScheme"/>, the digest it must advertise.</summary>
    private const string AuthOnlySchemeMd5 = "4caf70510662fcb25a851bc47113784c";

    /// <summary>A guard that turns a stalled read into a failed test.</summary>
    private static CancellationTokenSource Guard() => new(TimeSpan.FromSeconds(5));

    /// <summary>
    /// Awaits a result the spec-side handler publishes, failing rather than hanging
    /// when the handler never gets that far.
    /// </summary>
    private static async Task<T> AwaitServerAsync<T>(TaskCompletionSource<T> source)
    {
        var completed = await Task.WhenAny(source.Task, Task.Delay(TimeSpan.FromSeconds(10))).ConfigureAwait(false);
        if (completed != source.Task) throw new TimeoutException("the anytls test server did not publish its result in time");
        return await source.Task.ConfigureAwait(false);
    }

    // ---- auth block ----------------------------------------------------------

    [Fact]
    public async Task AuthBlockIsTheRawSha256ThenABigEndianPaddingLengthAndThePadding()
    {
        // A non-default scheme proves the padding length is read from the
        // configuration rather than hard-coded.
        var seen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var composer = new MemoryTransportComposer(async stream =>
        {
            seen.SetResult(await ReadAuthBlockAsync(stream));
            await OutboundHarness.DrainAsync(stream, CancellationToken.None);
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", "stop=1\n0=16-16"));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        var block = await AwaitServerAsync(seen);

        // 32 bytes of digest, then a big-endian u16 length, then that many bytes of
        // padding: 34 bytes of overhead on top of padding0.
        Assert.Equal(32 + 2 + 16, block.Length);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(Password)), block[..32]);
        Assert.Equal([0x00, 0x10], block[32..34]);
        Assert.All(block[34..], b => Assert.Equal(0, b));

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task DefaultSchemePutsThirtyBytesOfPaddingInTheAuthBlock()
    {
        var seen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var composer = new MemoryTransportComposer(async stream =>
        {
            seen.SetResult(await ReadAuthBlockAsync(stream));
            await OutboundHarness.DrainAsync(stream, CancellationToken.None);
        });

        var adapter = BuildAdapter(composer);
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        var block = await AwaitServerAsync(seen);

        // The document's `0=30-30`, i.e. 64 bytes on the wire for 34 bytes of
        // overhead.
        Assert.Equal(64, block.Length);
        Assert.Equal([0x00, 0x1E], block[32..34]);

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    // ---- session frames ------------------------------------------------------

    [Fact]
    public async Task SettingsIsTheFirstFrameAfterAuthAndAdvertisesTheDefaultPaddingDigest()
    {
        var seen = new TaskCompletionSource<WireFrame>(TaskCreationOptions.RunContinuationsAsynchronously);
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            seen.SetResult(await ReadFrameAsync(stream));
            await OutboundHarness.DrainAsync(stream, CancellationToken.None);
        });

        var adapter = BuildAdapter(composer);
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        var frame = await AwaitServerAsync(seen);

        // The server rejects a session whose first frame is cmdSYN, so this
        // ordering is part of the protocol rather than a detail.
        Assert.Equal(CmdSettings, frame.Command);
        Assert.Equal(0u, frame.StreamId);

        // The digest is md5 of the documented default scheme text; the literal is
        // the well-known digest for exactly those bytes.
        Assert.Equal(
            DefaultSchemeMd5,
            Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(DefaultSchemeText))));

        Assert.Equal(
            $"v=2\nclient={ClientName}\npadding-md5={DefaultSchemeMd5}",
            Encoding.UTF8.GetString(frame.Data));

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task SettingsSynAndAddressPshAreWrittenInOnePacketWithTheDocumentedLayout()
    {
        var settings = Encoding.UTF8.GetBytes($"v=2\nclient={ClientName}\npadding-md5={AuthOnlySchemeMd5}");

        // The digest the client advertises is md5 of the scheme it was configured
        // with, not of the default one.
        Assert.Equal(
            AuthOnlySchemeMd5,
            Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(AuthOnlyScheme))));

        // The address is a SOCKS5 block: 0x03 for a domain, a length byte, the name
        // and a big-endian port. Built here from RFC 1928 rather than from the
        // adapter's encoder.
        var address = new List<byte> { 0x03, (byte)"example.com".Length };
        address.AddRange(Encoding.ASCII.GetBytes("example.com"));
        address.AddRange([0x01, 0xBB]); // port 443

        var expected = new List<byte>();
        expected.AddRange(Encode(CmdSettings, 0, settings));
        expected.AddRange(Encode(CmdSyn, 1, []));
        expected.AddRange(Encode(CmdPsh, 1, [.. address]));

        var seen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);

            // `stop=1` leaves packet 1 unpadded, so exactly these bytes are on the
            // wire and nothing else until the stream closes.
            var packet = new byte[expected.Count];
            await stream.ReadExactlyAsync(packet);
            seen.SetResult(packet);
            await OutboundHarness.DrainAsync(stream, CancellationToken.None);
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 443));
        var packet = await AwaitServerAsync(seen);

        Assert.Equal(Convert.ToHexString([.. expected]), Convert.ToHexString(packet));

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task PacketOneIsPaddedWithCmdWasteFramesUpToTheSchemeTarget()
    {
        var seen = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);

            // `1=300-300` names a single target size, so the whole packet-1 write is
            // exactly 300 bytes.
            var packet = new byte[300];
            await stream.ReadExactlyAsync(packet);
            seen.SetResult(packet);
            await OutboundHarness.DrainAsync(stream, CancellationToken.None);
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", "stop=2\n0=30-30\n1=300-300"));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        var packet = await AwaitServerAsync(seen);

        var frames = SplitFrames(packet);
        Assert.Equal(CmdSettings, frames[0].Command);
        Assert.Equal(0u, frames[0].StreamId);
        Assert.Equal(CmdSyn, frames[1].Command);
        Assert.Equal(1u, frames[1].StreamId);
        Assert.Equal(CmdPsh, frames[2].Command);
        Assert.Equal(1u, frames[2].StreamId);
        Assert.True(Socks5Address.TryParse(frames[2].Data, out _, out var host, out var port));
        Assert.Equal("example.com", host);
        Assert.Equal(80, port);

        // Everything after the three real frames is padding: cmdWaste on stream 0
        // with zero-filled data.
        Assert.True(frames.Count > 3, "the packet was not padded to the target size");
        for (var i = 3; i < frames.Count; i++)
        {
            Assert.Equal(CmdWaste, frames[i].Command);
            Assert.Equal(0u, frames[i].StreamId);
            Assert.All(frames[i].Data, b => Assert.Equal(0, b));
        }

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    // ---- relay ---------------------------------------------------------------

    [Fact]
    public async Task FullDuplexRoundTripCarriesPayloadBothWaysAndClosesTheStreamWithFin()
    {
        var payload = Pattern(4096);
        var sawFin = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var sawStreamId = new TaskCompletionSource<uint>(TaskCreationOptions.RunContinuationsAsynchronously);

        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream); // cmdSettings
            var syn = await ReadFrameAsync(stream);
            await ReadFrameAsync(stream); // cmdPSH carrying the address

            var body = await ReadStreamDataAsync(stream, syn.StreamId, payload.Length);
            sawStreamId.SetResult(syn.StreamId);

            // Echo it back on the same stream id, the way a server relays the
            // destination's reply.
            await stream.WriteAsync(Encode(CmdPsh, syn.StreamId, body));

            // The client must retire the stream with cmdFIN before it drops the
            // session.
            while (true)
            {
                var frame = await ReadFrameAsync(stream);
                if (frame.Command == CmdFin && frame.StreamId == syn.StreamId)
                {
                    sawFin.SetResult(true);
                    return;
                }
            }
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        await outbound.WriteAsync(payload, guard.Token);
        var echoed = new byte[payload.Length];
        await outbound.ReadExactlyAsync(echoed, guard.Token);

        Assert.Equal(payload, echoed);
        Assert.Equal(1u, await AwaitServerAsync(sawStreamId));

        await outbound.DisposeAsync();
        Assert.True(await AwaitServerAsync(sawFin), "the client did not send cmdFIN for its stream");
        await composer.WaitAsync();
    }

    [Fact]
    public async Task PayloadLargerThanTheFrameLengthIsSplitIntoSeveralPshFrames()
    {
        var payload = Pattern(70000); // one frame holds at most 65535 bytes
        var seenLengths = new TaskCompletionSource<List<int>>(TaskCreationOptions.RunContinuationsAsynchronously);

        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream); // cmdSettings
            var syn = await ReadFrameAsync(stream);
            await ReadFrameAsync(stream); // cmdPSH carrying the address

            var lengths = new List<int>();
            var body = new List<byte>(payload.Length);
            while (body.Count < payload.Length)
            {
                var frame = await ReadFrameAsync(stream);
                if (frame.Command != CmdPsh || frame.StreamId != syn.StreamId) continue;
                lengths.Add(frame.Data.Length);
                body.AddRange(frame.Data);
            }

            seenLengths.SetResult(lengths);

            // Echo the collected bytes back in frames the u16 length can describe.
            var offset = 0;
            while (offset < body.Count)
            {
                var size = Math.Min(MaxFrameData, body.Count - offset);
                await stream.WriteAsync(Encode(CmdPsh, syn.StreamId, body.GetRange(offset, size).ToArray()));
                offset += size;
            }
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        await outbound.WriteAsync(payload, guard.Token);
        var echoed = new byte[payload.Length];
        await outbound.ReadExactlyAsync(echoed, guard.Token);

        // The round trip proves the split frames reassemble to what was sent.
        Assert.Equal(payload, echoed);
        Assert.Equal([MaxFrameData, 4465], await AwaitServerAsync(seenLengths));

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task AFrameLargerThanTheCallersBufferIsDeliveredAcrossSeveralReads()
    {
        var body = Pattern(100);
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await stream.WriteAsync(Encode(CmdPsh, 1, body));
            await stream.WriteAsync(Encode(CmdFin, 1, []));
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        var received = new List<byte>();
        var buffer = new byte[16];
        while (true)
        {
            var read = await outbound.ReadAsync(buffer, guard.Token);
            if (read == 0) break;
            received.AddRange(buffer.AsSpan(0, read));
        }

        Assert.Equal(body, received.ToArray());

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    // ---- failure surfaces ----------------------------------------------------

    [Fact]
    public async Task ServerAlertFailsTheStreamInsteadOfHanging()
    {
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await stream.WriteAsync(Encode(CmdAlert, 0, Encoding.UTF8.GetBytes("client did not send its settings")));
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        var buffer = new byte[256];
        var error = await Assert.ThrowsAsync<ClashException>(
            () => outbound.ReadAsync(buffer, guard.Token).AsTask());

        Assert.Contains("client did not send its settings", error.Message, StringComparison.Ordinal);
        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task ServerSynAckWithAnErrorTextFailsTheStream()
    {
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await stream.WriteAsync(Encode(CmdSynAck, 1, Encoding.UTF8.GetBytes("connect: connection refused")));
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        var buffer = new byte[256];
        var error = await Assert.ThrowsAsync<ClashException>(
            () => outbound.ReadAsync(buffer, guard.Token).AsTask());

        Assert.Contains("connect: connection refused", error.Message, StringComparison.Ordinal);
        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task ServerFinOnTheStreamIsReportedAsEof()
    {
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await stream.WriteAsync(Encode(CmdPsh, 1, "half"u8.ToArray()));
            await stream.WriteAsync(Encode(CmdFin, 1, []));
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        var buffer = new byte[16];
        var read = await outbound.ReadAsync(buffer, guard.Token);
        Assert.Equal("half", Encoding.ASCII.GetString(buffer, 0, read));
        Assert.Equal(0, await outbound.ReadAsync(buffer, guard.Token));

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    [Fact]
    public async Task ServerHeartRequestIsAnsweredWithAHeartResponse()
    {
        var seen = new TaskCompletionSource<WireFrame>(TaskCreationOptions.RunContinuationsAsynchronously);
        var composer = new MemoryTransportComposer(async stream =>
        {
            await ReadAuthBlockAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);
            await ReadFrameAsync(stream);

            // Version negotiation and a keepalive probe, then EOF so the client's
            // read returns once it has answered.
            await stream.WriteAsync(Encode(CmdServerSettings, 0, "v=2"u8.ToArray()));
            await stream.WriteAsync(Encode(CmdHeartRequest, 0, []));
            await stream.WriteAsync(Encode(CmdFin, 1, []));

            seen.SetResult(await ReadFrameAsync(stream));
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));
        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        using var guard = Guard();
        var buffer = new byte[16];
        Assert.Equal(0, await outbound.ReadAsync(buffer, guard.Token));

        var reply = await AwaitServerAsync(seen);
        Assert.Equal(CmdHeartResponse, reply.Command);
        Assert.Equal(0u, reply.StreamId);
        Assert.Empty(reply.Data);

        await outbound.DisposeAsync();
        await composer.WaitAsync();
    }

    // ---- padding scheme updates ----------------------------------------------

    [Fact]
    public async Task AServerPushedPaddingSchemeAppliesToTheNextSession()
    {
        const string pushed = "stop=1\n0=8-8";
        var connection = 0;
        var firstAuth = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondAuth = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        var composer = new MemoryTransportComposer(async stream =>
        {
            var auth = await ReadAuthBlockAsync(stream);
            if (Interlocked.Increment(ref connection) == 1)
            {
                firstAuth.SetResult(auth);

                // The server only pushes a scheme when the advertised digest
                // differs; it takes effect on the next session.
                await stream.WriteAsync(Encode(CmdUpdatePaddingScheme, 0, Encoding.UTF8.GetBytes(pushed)));
                await stream.WriteAsync(Encode(CmdFin, 1, []));
                await OutboundHarness.DrainAsync(stream, CancellationToken.None);
                return;
            }

            secondAuth.SetResult(auth);
            await OutboundHarness.DrainAsync(stream, CancellationToken.None);
        });

        var adapter = BuildAdapter(composer, ("padding-scheme", AuthOnlyScheme));

        using var guard = Guard();
        await using (var first = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80)))
        {
            var buffer = new byte[16];
            Assert.Equal(0, await first.ReadAsync(buffer, guard.Token)); // consumes the update, then EOF
        }

        await using (var second = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80)))
        {
            var auth = await AwaitServerAsync(secondAuth);
            Assert.Equal(8, BinaryPrimitives.ReadUInt16BigEndian(auth.AsSpan(32)));
        }

        // The first session used the scheme it started with.
        Assert.Equal(30, BinaryPrimitives.ReadUInt16BigEndian((await AwaitServerAsync(firstAuth)).AsSpan(32)));
        await composer.WaitAsync();
    }

    // ---- registration and configuration --------------------------------------

    [Fact]
    public void AnyTlsIsRegisteredAndReportedAsATcpOnlyAdapter()
    {
        var composer = new MemoryTransportComposer(_ => Task.CompletedTask);
        var adapter = BuildAdapter(composer, ("udp", true));

        Assert.True(AdapterRegistry.IsKnown("anytls"));
        Assert.Equal(ProxyType.AnyTls, adapter.Type);
        Assert.Equal("AnyTLS", adapter.TypeName);

        // UDP would mean speaking sing-box udp-over-tcp v2; this build refuses it
        // rather than advertising a capability it does not have.
        Assert.False(adapter.SupportUdp);
        Assert.False((bool)adapter.ApiExtra["udp"]!);
        Assert.Equal(443, ((IOutboundProxy)adapter).ServerPort);
    }

    [Fact]
    public async Task UdpAssociationIsRefused()
    {
        var composer = new MemoryTransportComposer(_ => Task.CompletedTask);
        var adapter = BuildAdapter(composer, ("udp", true));

        await Assert.ThrowsAsync<NotSupportedException>(() => adapter.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53)));
    }

    [Fact]
    public void AMissingPasswordIsRefusedAtBuildTime()
    {
        var composer = new MemoryTransportComposer(_ => Task.CompletedTask);
        var tunnel = new FakeTunnel();
        var context = new AdapterBuildContext
        {
            Config = tunnel.Config,
            Tunnel = new FakeTunnelAccessor(tunnel),
            Transports = composer,
            LoggerFactory = NullLoggerFactory.Instance,
        };

        var entry = new ProxyConfigEntry(new YamlMap(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = "anytls-nopassword",
            ["type"] = "anytls",
            ["server"] = "127.0.0.1",
            ["port"] = 443,
        }));

        Assert.Throws<ProxyCreationException>(() => AdapterRegistry.Create(entry, context));
    }

    [Fact]
    public void AMalformedPaddingSchemeIsRefusedAtBuildTime()
    {
        var composer = new MemoryTransportComposer(_ => Task.CompletedTask);
        Assert.Throws<ProxyCreationException>(
            () => BuildAdapter(composer, ("padding-scheme", "stop=8\n0=30")));
    }

    // ---- spec-side wire helpers ----------------------------------------------

    /// <summary>One frame, reassembled by hand from the byte stream.</summary>
    private readonly record struct WireFrame(byte Command, uint StreamId, byte[] Data);

    /// <summary>
    /// Builds a frame exactly as the document lays it out:
    /// <c>command u8 | streamId u32 BE | length u16 BE | data</c>.
    /// </summary>
    private static byte[] Encode(byte command, uint streamId, byte[] data)
    {
        var frame = new byte[FrameHeaderSize + data.Length];
        frame[0] = command;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(1), streamId);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(5), (ushort)data.Length);
        data.CopyTo(frame, FrameHeaderSize);
        return frame;
    }

    /// <summary>Reads one frame, header first, then exactly the declared data length.</summary>
    private static async Task<WireFrame> ReadFrameAsync(Stream stream)
    {
        var header = new byte[FrameHeaderSize];
        await stream.ReadExactlyAsync(header);

        var data = new byte[BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(5))];
        await stream.ReadExactlyAsync(data);

        return new WireFrame(header[0], BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1)), data);
    }

    /// <summary>
    /// Reads <c>sha256(password) | padding0 length u16 BE | padding0</c> and returns
    /// all of it, so a test can check the digest, the length and the padding.
    /// </summary>
    private static async Task<byte[]> ReadAuthBlockAsync(Stream stream)
    {
        var digest = new byte[32];
        await stream.ReadExactlyAsync(digest);

        var lengthBytes = new byte[2];
        await stream.ReadExactlyAsync(lengthBytes);

        var padding = new byte[BinaryPrimitives.ReadUInt16BigEndian(lengthBytes)];
        await stream.ReadExactlyAsync(padding);

        return [.. digest, .. lengthBytes, .. padding];
    }

    /// <summary>Splits a captured packet into frames using only the documented header layout.</summary>
    private static List<WireFrame> SplitFrames(byte[] packet)
    {
        var frames = new List<WireFrame>();
        var offset = 0;
        while (offset < packet.Length)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(offset + 5));
            frames.Add(new WireFrame(
                packet[offset],
                BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset + 1)),
                packet[(offset + FrameHeaderSize)..(offset + FrameHeaderSize + length)]));
            offset += FrameHeaderSize + length;
        }

        return frames;
    }

    /// <summary>Collects <paramref name="count"/> payload bytes for <paramref name="streamId"/>.</summary>
    private static async Task<byte[]> ReadStreamDataAsync(Stream stream, uint streamId, int count)
    {
        var body = new List<byte>(count);
        while (body.Count < count)
        {
            var frame = await ReadFrameAsync(stream);
            if (frame.Command != CmdPsh || frame.StreamId != streamId) continue;
            body.AddRange(frame.Data);
        }

        return body.ToArray();
    }

    /// <summary>A deterministic, non-repeating payload.</summary>
    private static byte[] Pattern(int length)
    {
        var payload = new byte[length];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)((i * 31 + 7) & 0xFF);
        return payload;
    }

    // ---- adapter construction ------------------------------------------------

    /// <summary>
    /// Builds the <c>anytls</c> adapter through the registry, with the in-memory
    /// transport in place of the real stack.
    /// </summary>
    private static IProxy BuildAdapter(MemoryTransportComposer composer, params (string Key, object? Value)[] pairs)
    {
        var tunnel = new FakeTunnel();
        var context = new AdapterBuildContext
        {
            Config = tunnel.Config,
            Tunnel = new FakeTunnelAccessor(tunnel),
            Transports = composer,
            LoggerFactory = NullLoggerFactory.Instance,
        };

        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = "anytls",
            ["type"] = "anytls",
            ["server"] = "127.0.0.1",
            ["port"] = 443,
            ["password"] = Password,
        };

        foreach (var (key, value) in pairs) map[key] = value;
        return AdapterRegistry.Create(new ProxyConfigEntry(new YamlMap(map)), context);
    }
}

/// <summary>
/// A transport composer that hands the adapter an in-memory duplex channel and runs
/// the spec-side handler on the other end. The TLS flag the adapter forces is
/// deliberately ignored: the TLS layer belongs to the transport stack, and the
/// adapter under test only ever sees the byte pipe it is handed.
/// </summary>
internal sealed class MemoryTransportComposer : ITransportComposer
{
    private readonly Func<Stream, Task> _server;
    private readonly List<Task> _handlers = [];

    internal MemoryTransportComposer(Func<Stream, Task> server) => _server = server;

    public IReadOnlyList<ITransportLayer> Compose(YamlMap proxyOptions) => [];

    public Task<ProxyStream> ConnectAsync(DialContext context, YamlMap proxyOptions, CancellationToken cancellationToken = default)
    {
        var duplex = new MemoryDuplex();
        _handlers.Add(Task.Run(() => _server(duplex.Server), CancellationToken.None));
        return Task.FromResult(ProxyStream.Wrap(duplex.Client));
    }

    /// <summary>Waits for every handler, surfacing its failure instead of hanging the test.</summary>
    internal async Task WaitAsync()
    {
        foreach (var handler in _handlers)
        {
            var completed = await Task.WhenAny(handler, Task.Delay(TimeSpan.FromSeconds(10))).ConfigureAwait(false);
            if (completed != handler) throw new TimeoutException("the anytls test server did not finish in time");
            await handler.ConfigureAwait(false);
        }
    }
}

/// <summary>
/// A full-duplex, in-memory byte channel: two one-way buffers, one per direction.
/// It replaces a loopback socket so the tests need no ports, no OS socket state and
/// no timing assumptions.
/// </summary>
internal sealed class MemoryDuplex
{
    private readonly MemoryChannel _toServer = new();
    private readonly MemoryChannel _toClient = new();

    internal MemoryDuplex()
    {
        Client = new MemoryChannelEnd(_toClient, _toServer);
        Server = new MemoryChannelEnd(_toServer, _toClient);
    }

    /// <summary>The end the adapter writes to and reads from.</summary>
    internal Stream Client { get; }

    /// <summary>The end the spec-side handler drives.</summary>
    internal Stream Server { get; }
}

/// <summary>One direction of a <see cref="MemoryDuplex"/>.</summary>
internal sealed class MemoryChannel
{
    private readonly Queue<byte[]> _chunks = new();
    private readonly SemaphoreSlim _available = new(0);
    private readonly Lock _gate = new();
    private byte[]? _head;
    private int _headOffset;
    private bool _closed;

    /// <summary>Queues a copy of <paramref name="data"/>; writes never block.</summary>
    internal void Write(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;

        lock (_gate)
        {
            if (_closed) return;
            _chunks.Enqueue(data.ToArray());
        }

        _available.Release();
    }

    /// <summary>
    /// Returns the next bytes, or 0 once the writer end has been closed. Spurious
    /// wake-ups are handled by looping rather than by counting permits exactly.
    /// </summary>
    internal async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            lock (_gate)
            {
                if (_head is null && _chunks.Count > 0)
                {
                    _head = _chunks.Dequeue();
                    _headOffset = 0;
                }

                if (_head is not null)
                {
                    var take = Math.Min(buffer.Length, _head.Length - _headOffset);
                    _head.AsSpan(_headOffset, take).CopyTo(buffer.Span);
                    _headOffset += take;
                    if (_headOffset >= _head.Length)
                    {
                        _head = null;
                        _headOffset = 0;
                    }

                    return take;
                }

                if (_closed) return 0;
            }

            await _available.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Signals end-of-stream to the reader and refuses later writes.</summary>
    internal void Close()
    {
        lock (_gate) _closed = true;
        _available.Release();
    }
}

/// <summary>One end of a <see cref="MemoryDuplex"/>.</summary>
internal sealed class MemoryChannelEnd : Stream
{
    private readonly MemoryChannel _read;
    private readonly MemoryChannel _write;

    internal MemoryChannelEnd(MemoryChannel read, MemoryChannel write)
    {
        _read = read;
        _write = write;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count)
        => _read.ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _read.ReadAsync(buffer, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count) => _write.Write(buffer.AsSpan(offset, count));

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        _write.Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing) _write.Close();
        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync()
    {
        _write.Close();
        return ValueTask.CompletedTask;
    }
}
