using System.Buffers.Binary;
using System.Text;
using Clash.Core.Transport;
using Xunit;

namespace Clash.Tests.Transport;

/// <summary>
/// RFC 6455 framing and handshake tests. Everything here drives byte buffers and
/// an in-memory duplex stream, so no network is involved.
/// </summary>
public class WebSocketFramingTests
{
    // ---- accept key -------------------------------------------------------------

    [Fact]
    public void ComputeAcceptMatchesTheRfc6455Example()
    {
        Assert.Equal("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", WebSocketFraming.ComputeAccept("dGhlIHNhbXBsZSBub25jZQ=="));
    }

    [Fact]
    public void CreateKeyIsSixteenRandomBytesInBase64()
    {
        var first = WebSocketFraming.CreateKey();
        var second = WebSocketFraming.CreateKey();
        Assert.NotEqual(first, second);
        Assert.Equal(16, Convert.FromBase64String(first).Length);
    }

    // ---- frame encoding ---------------------------------------------------------

    [Fact]
    public void MaskedClientFrameHasTheExpectedBytes()
    {
        var payload = Encoding.ASCII.GetBytes("Hello");
        var buffer = new byte[64];
        var written = WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Binary, payload, mask: true, maskKey: 0x04030201);

        // FIN + opcode 0x2, MASK + length 5, then the four mask bytes.
        Assert.Equal(0x82, buffer[0]);
        Assert.Equal(0x85, buffer[1]);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, buffer.AsSpan(2, 4).ToArray());
        Assert.Equal(11, written);

        for (var i = 0; i < payload.Length; i++)
        {
            Assert.Equal((byte)(payload[i] ^ (byte)(0x04030201u >> ((i & 3) * 8))), buffer[6 + i]);
        }
    }

    [Fact]
    public void MaskedClientFrameRoundTripsThroughTheDecoder()
    {
        var payload = new byte[300];
        for (var i = 0; i < payload.Length; i++) payload[i] = (byte)i;

        var buffer = new byte[400];
        var written = WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Binary, payload, mask: true, maskKey: 0xDEADBEEF);

        Assert.True(WebSocketFraming.TryReadFrame(buffer.AsSpan(0, written), out var frame, out var consumed));
        Assert.Equal(written, consumed);
        Assert.Equal(WebSocketOpcode.Binary, frame.Opcode);
        Assert.True(frame.Fin);
        Assert.True(frame.Masked);
        Assert.Equal(payload, frame.Payload);
    }

    [Fact]
    public void UnmaskedServerFrameRoundTrips()
    {
        var payload = Encoding.ASCII.GetBytes("server data");
        var buffer = new byte[64];
        var written = WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Text, payload, mask: false);

        Assert.Equal(0x81, buffer[0]);
        Assert.Equal(payload.Length, buffer[1]);

        Assert.True(WebSocketFraming.TryReadFrame(buffer.AsSpan(0, written), out var frame, out _));
        Assert.False(frame.Masked);
        Assert.Equal(WebSocketOpcode.Text, frame.Opcode);
        Assert.Equal(payload, frame.Payload);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(125)]
    [InlineData(126)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(200_000)]
    public void FrameHeaderSizeMatchesTheEncodedLength(int payloadLength)
    {
        var payload = new byte[payloadLength];
        var buffer = new byte[payloadLength + 16];
        var written = WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Binary, payload, mask: false);

        Assert.Equal(WebSocketFraming.FrameHeaderSize(payloadLength, mask: false) + payloadLength, written);

        var expectedCode = payloadLength < 126 ? payloadLength : payloadLength <= ushort.MaxValue ? 126 : 127;
        Assert.Equal(expectedCode, buffer[1]);

        Assert.True(WebSocketFraming.TryReadFrame(buffer.AsSpan(0, written), out var frame, out _));
        Assert.Equal(payloadLength, frame.Payload.Length);
    }

    [Fact]
    public void SixtyFourBitLengthFramesAreEncodedBigEndian()
    {
        var payload = new byte[70_000];
        var buffer = new byte[payload.Length + 16];
        WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Binary, payload, mask: false);

        Assert.Equal(127, buffer[1]);
        Assert.Equal(70_000UL, BinaryPrimitives.ReadUInt64BigEndian(buffer.AsSpan(2)));
    }

    [Fact]
    public void TruncatedFramesAreRejected()
    {
        var payload = Encoding.ASCII.GetBytes("truncated");
        var buffer = new byte[64];
        var written = WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Binary, payload, mask: true, maskKey: 1);

        for (var length = 0; length < written; length++)
        {
            Assert.False(WebSocketFraming.TryReadFrame(buffer.AsSpan(0, length), out _, out _));
        }

        Assert.True(WebSocketFraming.TryReadFrame(buffer.AsSpan(0, written), out _, out _));
    }

    [Fact]
    public void ControlFramesRejectOversizedOrFragmentedPayloads()
    {
        var buffer = new byte[256];
        Assert.Throws<ArgumentException>(() => WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Ping, new byte[126], mask: false));
        Assert.Throws<ArgumentException>(() => WebSocketFraming.WriteFrame(buffer, WebSocketOpcode.Ping, new byte[1], mask: false, fin: false));
    }

    // ---- handshake --------------------------------------------------------------

    [Fact]
    public void HandshakeRequestCarriesTheWebSocketKeyDance()
    {
        var options = new WebSocketOptions { Path = "/ws", Headers = { ["X-Test"] = "1" } };
        var request = Encoding.ASCII.GetString(WebSocketFraming.BuildHandshakeRequest("example.com", 443, options, "a2V5", []));

        Assert.StartsWith("GET /ws HTTP/1.1\r\n", request);
        Assert.Contains("Host: example.com\r\n", request);
        Assert.Contains("Upgrade: websocket\r\n", request);
        Assert.Contains("Connection: Upgrade\r\n", request);
        Assert.Contains("Sec-WebSocket-Key: a2V5\r\n", request);
        Assert.Contains("Sec-WebSocket-Version: 13\r\n", request);
        Assert.Contains("X-Test: 1\r\n", request);
        Assert.EndsWith("\r\n\r\n", request);
    }

    [Fact]
    public void HandshakeRequestFormatsNonDefaultPorts()
    {
        var request = Encoding.ASCII.GetString(
            WebSocketFraming.BuildHandshakeRequest("example.com", 8443, new WebSocketOptions(), "a2V5", []));
        Assert.Contains("Host: example.com:8443\r\n", request);

        var defaultPort = Encoding.ASCII.GetString(
            WebSocketFraming.BuildHandshakeRequest("example.com", 80, new WebSocketOptions(), "a2V5", []));
        Assert.Contains("Host: example.com\r\n", defaultPort);
    }

    [Fact]
    public void V2rayHttpUpgradeOmitsTheWebSocketKeyDance()
    {
        var options = new WebSocketOptions { Path = "/up", V2rayHttpUpgrade = true };
        var request = Encoding.ASCII.GetString(WebSocketFraming.BuildHandshakeRequest("example.com", 443, options, "a2V5", []));

        Assert.Contains("Upgrade: websocket\r\n", request);
        Assert.DoesNotContain("Sec-WebSocket-Key", request);
        Assert.DoesNotContain("Sec-WebSocket-Version", request);
    }

    [Fact]
    public void EarlyDataRidesInABase64UrlProtocolHeader()
    {
        var options = new WebSocketOptions { MaxEarlyData = 8 };
        var early = new byte[] { 0xFB, 0xFF, 0x00, 0x01 };
        var request = Encoding.ASCII.GetString(WebSocketFraming.BuildHandshakeRequest("example.com", 443, options, "a2V5", early));

        Assert.Contains("Sec-WebSocket-Protocol: -_8AAQ\r\n", request);

        var custom = new WebSocketOptions { MaxEarlyData = 8, EarlyDataHeaderName = "X-Data" };
        var customRequest = Encoding.ASCII.GetString(WebSocketFraming.BuildHandshakeRequest("example.com", 443, custom, "a2V5", early));
        Assert.Contains("X-Data: -_8AAQ\r\n", customRequest);
    }

    [Fact]
    public void HandshakeResponseIsParsedAndValidated()
    {
        var key = "dGhlIHNhbXBsZSBub25jZQ==";
        var response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
            + "leftover");

        Assert.True(WebSocketFraming.ValidateHandshakeResponse(response, key, requireAccept: true, out var headerLength, out var failure));
        Assert.Equal(string.Empty, failure);
        Assert.Equal(response.Length - "leftover".Length, headerLength);

        Assert.True(WebSocketFraming.TryParseHandshakeResponse(response, out _, out var startLine, out var accept, out var upgrade, out var success));
        Assert.Equal("HTTP/1.1 101 Switching Protocols", startLine);
        Assert.Equal("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", accept);
        Assert.Equal("websocket", upgrade);
        Assert.True(success);
    }

    [Fact]
    public void HandshakeResponseWithTheWrongAcceptIsRejected()
    {
        var response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: wrong\r\n\r\n");

        Assert.False(WebSocketFraming.ValidateHandshakeResponse(response, "a2V5", requireAccept: true, out _, out var failure));
        Assert.Contains("Sec-WebSocket-Accept", failure);

        // httpupgrade does not send a key, so the accept check is skipped.
        Assert.True(WebSocketFraming.ValidateHandshakeResponse(response, "a2V5", requireAccept: false, out _, out _));
    }

    [Fact]
    public void HandshakeResponseWithANon101StatusIsRejected()
    {
        var response = Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        Assert.False(WebSocketFraming.ValidateHandshakeResponse(response, "a2V5", requireAccept: false, out _, out var failure));
        Assert.Contains("403", failure);
    }

    [Fact]
    public void IncompleteHandshakeResponseIsReportedAsMalformed()
    {
        var partial = Encoding.ASCII.GetBytes("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n");
        Assert.False(WebSocketFraming.ValidateHandshakeResponse(partial, "a2V5", requireAccept: false, out _, out var failure));
        Assert.Equal("malformed handshake response", failure);
    }

    // ---- the stream facade ------------------------------------------------------

    [Fact]
    public async Task StreamPerformsTheHandshakeOnFirstUse()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions { Path = "/x" }, "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        var buffer = new byte[16];
        scripted.Append(Frame(WebSocketOpcode.Binary, "hi"));
        var read = await stream.ReadAsync(buffer);

        Assert.Equal(2, read);
        Assert.Equal("hi", Encoding.ASCII.GetString(buffer, 0, read));
        Assert.True(stream.HandshakeCompleted);

        var request = Encoding.ASCII.GetString(scripted.Written);
        Assert.StartsWith("GET /x HTTP/1.1\r\n", request);
    }

    [Fact]
    public async Task FragmentedMessageIsReassembled()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        scripted.Append(Frame(WebSocketOpcode.Binary, "hello ", fin: false));
        scripted.Append(Frame(WebSocketOpcode.Continuation, "fragmented ", fin: false));
        scripted.Append(Frame(WebSocketOpcode.Continuation, "world", fin: true));

        var buffer = new byte[64];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal("hello fragmented world", Encoding.ASCII.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task ControlFramesMayInterleaveAFragmentedMessage()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        scripted.Append(Frame(WebSocketOpcode.Binary, "abc", fin: false));
        scripted.Append(Frame(WebSocketOpcode.Ping, "ping"));
        scripted.Append(Frame(WebSocketOpcode.Continuation, "def", fin: true));

        var buffer = new byte[16];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal("abcdef", Encoding.ASCII.GetString(buffer, 0, read));

        Assert.Contains(WebSocketOpcode.Pong, ReadWrittenOpcodes(scripted));
    }

    [Fact]
    public async Task PingIsAnsweredWithAMaskedPong()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        scripted.Append(Frame(WebSocketOpcode.Ping, "are-you-there"));
        scripted.Append(Frame(WebSocketOpcode.Binary, "data"));

        var buffer = new byte[16];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal("data", Encoding.ASCII.GetString(buffer, 0, read));

        var frames = ReadWrittenFrames(scripted);
        var pong = Assert.Single(frames, f => f.Opcode == WebSocketOpcode.Pong);
        Assert.True(pong.Masked, "clients must mask every frame they send");
        Assert.Equal("are-you-there", Encoding.ASCII.GetString(pong.Payload));
    }

    [Fact]
    public async Task PongFramesAreIgnored()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        scripted.Append(Frame(WebSocketOpcode.Pong, "unsolicited"));
        scripted.Append(Frame(WebSocketOpcode.Binary, "payload"));

        var buffer = new byte[16];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal("payload", Encoding.ASCII.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task CloseFrameEndsTheStreamAndIsEchoed()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        scripted.Append(Frame(WebSocketOpcode.Close, [0x03, 0xE8]));

        var buffer = new byte[16];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal(0, read);

        var close = Assert.Single(ReadWrittenFrames(scripted), f => f.Opcode == WebSocketOpcode.Close);
        Assert.Equal(new byte[] { 0x03, 0xE8 }, close.Payload);
    }

    [Fact]
    public async Task WritesAreMaskedBinaryFrames()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        await stream.WriteAsync(Encoding.ASCII.GetBytes("outbound"));

        var frame = Assert.Single(ReadWrittenFrames(scripted), f => f.Opcode == WebSocketOpcode.Binary);
        Assert.True(frame.Masked);
        Assert.Equal("outbound", Encoding.ASCII.GetString(frame.Payload));
    }

    [Fact]
    public async Task LargeWritesAreSplitIntoBoundedFrames()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        var payload = new byte[WebSocketStream.OutgoingChunkSize * 2 + 5];
        await stream.WriteAsync(payload);

        var frames = ReadWrittenFrames(scripted).Where(f => f.Opcode == WebSocketOpcode.Binary).ToList();
        Assert.Equal(3, frames.Count);
        Assert.All(frames, f => Assert.True(f.Fin));
        Assert.Equal(WebSocketStream.OutgoingChunkSize, frames[0].Payload.Length);
        Assert.Equal(5, frames[2].Payload.Length);
    }

    [Fact]
    public async Task EarlyDataIsSentInsideTheHandshakeInsteadOfAFrame()
    {
        var scripted = new ScriptedStream();
        var options = new WebSocketOptions { MaxEarlyData = 32 };
        await using var stream = new WebSocketStream(scripted, options, "example.com", 443);
        scripted.Append(HandshakeResponse(stream.Key));

        var early = Encoding.ASCII.GetBytes("EARLYDATA");
        await stream.WriteAsync(early);

        var request = Encoding.ASCII.GetString(scripted.Written);
        Assert.Contains("Sec-WebSocket-Protocol: ", request);

        var header = request.Split("\r\n").Single(l => l.StartsWith("Sec-WebSocket-Protocol:", StringComparison.Ordinal));
        var encoded = header["Sec-WebSocket-Protocol: ".Length..];
        Assert.Equal(early, Clash.Core.Crypto.ClashBase64.Decode(encoded));

        Assert.DoesNotContain(WebSocketOpcode.Binary, ReadWrittenOpcodes(scripted));
    }

    [Fact]
    public async Task BytesArrivingWithTheHandshakeAreNotLost()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);

        // The server sends the handshake response and the first frame in one write.
        var combined = new List<byte>();
        combined.AddRange(HandshakeResponse(stream.Key));
        combined.AddRange(Frame(WebSocketOpcode.Binary, "pipelined"));
        scripted.Append(combined.ToArray());

        var buffer = new byte[32];
        var read = await stream.ReadAsync(buffer);
        Assert.Equal("pipelined", Encoding.ASCII.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task RejectedHandshakeSurfacesAClashError()
    {
        var scripted = new ScriptedStream();
        await using var stream = new WebSocketStream(scripted, new WebSocketOptions(), "example.com", 443);
        scripted.Append(Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"));

        await Assert.ThrowsAsync<Clash.Core.Common.ClashException>(
            () => stream.ReadExactlyAsync(new byte[8]).AsTask());
    }

    // ---- helpers ----------------------------------------------------------------

    private static byte[] HandshakeResponse(string key)
    {
        var accept = WebSocketFraming.ComputeAccept(key);
        return Encoding.ASCII.GetBytes(
            "HTTP/1.1 101 Switching Protocols\r\n"
            + "Upgrade: websocket\r\n"
            + "Connection: Upgrade\r\n"
            + $"Sec-WebSocket-Accept: {accept}\r\n\r\n");
    }

    private static byte[] Frame(WebSocketOpcode opcode, string payload, bool fin = true)
        => Frame(opcode, Encoding.ASCII.GetBytes(payload), fin);

    private static byte[] Frame(WebSocketOpcode opcode, byte[] payload, bool fin = true)
    {
        var buffer = new byte[WebSocketFraming.FrameHeaderSize(payload.Length, mask: false) + payload.Length];
        var written = WebSocketFraming.WriteFrame(buffer, opcode, payload, mask: false, fin: fin);
        return buffer.AsSpan(0, written).ToArray();
    }

    /// <summary>Every frame the client wrote, skipping the handshake request.</summary>
    private static List<WebSocketFrame> ReadWrittenFrames(ScriptedStream scripted)
    {
        var written = scripted.Written;
        var terminator = written.AsSpan().IndexOf("\r\n\r\n"u8);
        Assert.True(terminator >= 0, "the handshake request was never written");

        var frames = new List<WebSocketFrame>();
        var offset = terminator + 4;
        while (offset < written.Length)
        {
            Assert.True(WebSocketFraming.TryReadFrame(written.AsSpan(offset), out var frame, out var consumed));
            frames.Add(frame);
            offset += consumed;
        }

        return frames;
    }

    private static List<WebSocketOpcode> ReadWrittenOpcodes(ScriptedStream scripted)
        => [.. ReadWrittenFrames(scripted).Select(static f => f.Opcode)];
}

/// <summary>
/// A duplex <see cref="Stream"/> for tests: reads come from a byte script that can
/// be appended to, writes are captured.
/// </summary>
internal sealed class ScriptedStream : Stream
{
    private byte[] _inbound = [];
    private int _position;
    private readonly MemoryStream _outbound = new();

    public byte[] Written => _outbound.ToArray();

    public void Append(byte[] data)
    {
        var combined = new byte[_inbound.Length + data.Length];
        Array.Copy(_inbound, combined, _inbound.Length);
        Array.Copy(data, 0, combined, _inbound.Length, data.Length);
        _inbound = combined;
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
    {
        var take = Math.Min(count, _inbound.Length - _position);
        Array.Copy(_inbound, _position, buffer, offset, take);
        _position += take;
        return take;
    }

    public override int Read(Span<byte> buffer)
    {
        var take = Math.Min(buffer.Length, _inbound.Length - _position);
        _inbound.AsSpan(_position, take).CopyTo(buffer);
        _position += take;
        return take;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => new(Read(buffer.Span));

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) => _outbound.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => _outbound.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        _outbound.Write(buffer.Span);
        return ValueTask.CompletedTask;
    }
}
