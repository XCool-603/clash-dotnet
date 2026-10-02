using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Outbound;

/// <summary>
/// Shadowsocks TCP, UDP, 2022 and plugin coverage. The fake server decrypts with
/// the same frozen primitives the adapter uses but reassembles the framing by hand
/// from <see cref="ShadowsocksAeadFraming"/>, so the assertions are about the bytes
/// on the wire rather than about the adapter's own reader.
/// </summary>
public class ShadowsocksTests
{
    private const string Password = "correct horse battery staple";

    // ── TCP: AEAD ────────────────────────────────────────────────────────────

    [Fact]
    public async Task AeadTcpSendsSaltThenLengthPrefixedChunksAndTheAddress()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey(Password, cipher.KeySize);

        var payload = new byte[40000]; // larger than one 0x3FFF chunk
        Random.Shared.NextBytes(payload);

        var seenAddress = new TaskCompletionSource<(string Host, int Port)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var seenChunkCount = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var seenSalt = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var salt = new byte[cipher.SaltSize];
            await stream.ReadExactlyAsync(salt, ct);
            seenSalt.SetResult(salt.Length);
            var subkey = cipher.DeriveSubkey(master, salt);
            var counter = new AeadCounter();

            var first = await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter);
            if (!Socks5Address.TryParse(first, out var addressLength, out var host, out var port))
            {
                throw new InvalidOperationException($"the first chunk did not start with a SOCKS5 address: {Convert.ToHexString(first)}");
            }

            seenAddress.SetResult((host, port));

            var body = new List<byte>(first[addressLength..]);
            var chunks = 1;
            while (body.Count < payload.Length)
            {
                body.AddRange(await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter));
                chunks++;
            }

            seenChunkCount.SetResult(chunks);
            Assert.Equal(payload, body.ToArray());

            // Reply the way a server does: its own salt, then the same framing.
            var serverSalt = RandomNumberGenerator.GetBytes(cipher.SaltSize);
            await stream.WriteAsync(serverSalt, ct);
            var serverSubkey = cipher.DeriveSubkey(master, serverSalt);
            await WriteAeadChunksAsync(stream, cipher, serverSubkey, body.ToArray(), ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-aead", "ss",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("cipher", "aes-256-gcm"),
            ("password", Password)));

        var flow = OutboundHarness.Flow("example.com", 80);
        await using var outbound = await adapter.DialTcpAsync(flow);

        await outbound.WriteAsync(payload);
        var echoed = new byte[payload.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(payload, echoed);
        Assert.Equal(cipher.SaltSize, await seenSalt.Task);
        Assert.Equal(("example.com", 80), await seenAddress.Task);

        // 0x3FFF bytes per chunk: 40000 needs three.
        Assert.Equal(3, await seenChunkCount.Task);

        // The handler drains until the client closes, so close before waiting.
        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public async Task AeadTcpSendsTheAddressAsADomainWhenTheDestinationIsAName()
    {
        var cipher = AeadCiphers.Get("chacha20-ietf-poly1305");
        var master = ShadowsocksKey.DeriveMasterKey(Password, cipher.KeySize);
        var firstChunk = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var salt = new byte[cipher.SaltSize];
            await stream.ReadExactlyAsync(salt, ct);
            var subkey = cipher.DeriveSubkey(master, salt);
            var counter = new AeadCounter();
            var chunk = await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter);
            firstChunk.SetResult(chunk);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-domain", "ss",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("cipher", "chacha20-ietf-poly1305"),
            ("password", Password)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("www.example.org", 8443));
        await outbound.WriteAsync(new byte[] { 0x01, 0x02, 0x03 });

        var chunk = await firstChunk.Task;
        Assert.Equal(Socks5Address.TypeDomain, chunk[0]);
        Assert.Equal("www.example.org".Length, chunk[1]);
        Assert.True(Socks5Address.TryParse(chunk, out _, out var host, out var port));
        Assert.Equal("www.example.org", host);
        Assert.Equal(8443, port);
        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    // ── TCP: legacy stream cipher ────────────────────────────────────────────

    [Fact]
    public async Task StreamCipherTcpSendsAnIvThenTheKeystreamOverAddressAndPayload()
    {
        const string cipherName = "aes-256-cfb";
        var master = ShadowsocksKey.DeriveMasterKey(Password, 32);
        var payload = new byte[9000];
        Random.Shared.NextBytes(payload);

        var seenAddress = new TaskCompletionSource<(string Host, int Port)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var seenIvLength = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var iv = new byte[16];
            await stream.ReadExactlyAsync(iv, ct);
            seenIvLength.SetResult(iv.Length);
            var decryptor = StreamCipherFactory.CreateDecryptor(cipherName, master, iv);

            var buffer = new byte[8192];
            var plaintext = new List<byte>();
            var addressLength = -1;
            var read = 0;
            while (plaintext.Count < payload.Length + 5)
            {
                read = await stream.ReadAsync(buffer, ct);
                if (read <= 0) break;

                var slice = buffer.AsSpan(0, read).ToArray();
                decryptor.Process(slice, slice);
                plaintext.AddRange(slice);

                if (addressLength < 0 && plaintext.Count >= 5)
                {
                    if (!Socks5Address.TryParse(plaintext.ToArray(), out addressLength, out var host, out var port))
                    {
                        throw new InvalidOperationException("the plaintext did not start with a SOCKS5 address");
                    }

                    seenAddress.SetResult((host, port));
                }
            }

            var body = plaintext.ToArray();
            Assert.Equal(payload, body[addressLength..]);

            var serverIv = RandomNumberGenerator.GetBytes(16);
            await stream.WriteAsync(serverIv, ct);
            var encryptor = StreamCipherFactory.CreateEncryptor(cipherName, master, serverIv);
            var response = body[addressLength..];
            encryptor.Process(response, response);
            await stream.WriteAsync(response, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-stream", "ss",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("cipher", cipherName),
            ("password", Password)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("1.2.3.4", 53));
        await outbound.WriteAsync(payload);

        var echoed = new byte[payload.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(payload, echoed);
        Assert.Equal(16, await seenIvLength.Task);
        Assert.Equal(("1.2.3.4", 53), await seenAddress.Task);
        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    // ── UDP ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AeadUdpWrapsEachDatagramInItsOwnSaltAndZeroNonce()
    {
        var cipher = AeadCiphers.Get("aes-128-gcm");
        var master = ShadowsocksKey.DeriveMasterKey(Password, cipher.KeySize);
        var payload = System.Text.Encoding.ASCII.GetBytes("udp-payload");

        // The handler needs the server to signal completion, but the server needs
        // the handler to be constructed: the capture is filled in right after.
        FakeUdpServer? server0 = null;
        var server = new FakeUdpServer((datagram, from) =>
        {
            var salt = datagram.AsSpan(0, cipher.SaltSize).ToArray();
            var subkey = cipher.DeriveSubkey(master, salt);
            var sealedBody = datagram.AsSpan(cipher.SaltSize).ToArray();
            var plaintext = new byte[sealedBody.Length - cipher.TagSize];
            Span<byte> nonce = stackalloc byte[ShadowsocksAeadFraming.NonceSize];

            Assert.True(cipher.Decrypt(subkey, nonce, sealedBody, plaintext), "the datagram failed authentication");
            Assert.True(Socks5Address.TryParse(plaintext, out var addressLength, out var host, out var port));
            Assert.Equal("9.9.9.9", host);
            Assert.Equal(53, port);
            Assert.Equal(payload, plaintext[addressLength..]);

            // Reply with the echoed payload under the server's own salt.
            var replySalt = RandomNumberGenerator.GetBytes(cipher.SaltSize);
            var replySubkey = cipher.DeriveSubkey(master, replySalt);
            var replyBody = new byte[plaintext.Length];
            plaintext.CopyTo(replyBody, 0);
            var reply = new byte[replySalt.Length + replyBody.Length + cipher.TagSize];
            replySalt.CopyTo(reply, 0);
            Span<byte> replyNonce = stackalloc byte[ShadowsocksAeadFraming.NonceSize];
            cipher.Encrypt(replySubkey, replyNonce, replyBody, reply.AsSpan(replySalt.Length));

            server0!.Done.TrySetResult(true);
            return reply;
        });

        await using var registered = server;
        server0 = server;

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-udp", "ss",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("cipher", "aes-128-gcm"),
            ("password", Password),
            ("udp", true)));

        Assert.True(adapter.SupportUdp);
        await using var association = await adapter.DialUdpAsync(OutboundHarness.UdpFlow("9.9.9.9", 53));

        await association.SendAsync(payload, new IPEndPoint(IPAddress.Parse("9.9.9.9"), 53));

        var buffer = new byte[2048];
        var result = await association.ReceiveAsync(buffer);

        Assert.Equal(payload.Length, result.BytesRead);
        Assert.Equal(payload, buffer.AsSpan(0, result.BytesRead).ToArray());
        await server.WaitAsync();
    }

    // ── Shadowsocks 2022 ─────────────────────────────────────────────────────

    [Fact]
    public async Task Shadowsocks2022TcpCarriesTheBodyHeaderInsideTheFirstChunk()
    {
        const string cipherName = "2022-blake3-aes-256-gcm";
        var cipher = AeadCiphers.Get(cipherName);
        var psk = RandomNumberGenerator.GetBytes(cipher.KeySize);
        var encodedPsk = Convert.ToBase64String(psk);

        var seenType = new TaskCompletionSource<Shadowsocks2022PacketType>(TaskCreationOptions.RunContinuationsAsynchronously);
        var seenAddress = new TaskCompletionSource<(string Host, int Port)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var payload = System.Text.Encoding.ASCII.GetBytes("2022 round trip");

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var salt = new byte[cipher.SaltSize];
            await stream.ReadExactlyAsync(salt, ct);
            var subkey = cipher.DeriveSubkey(psk, salt);
            var counter = new AeadCounter();

            var first = await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter);
            Assert.True(Shadowsocks2022.TryReadUdpBodyHeader(first, out var type, out _, out var paddingLength));
            seenType.SetResult(type);

            var afterHeader = first.AsSpan(Shadowsocks2022.UdpBodyHeaderSize + paddingLength);
            Assert.True(Socks5Address.TryParse(afterHeader, out var addressLength, out var host, out var port));
            seenAddress.SetResult((host, port));

            var body = new List<byte>(afterHeader[addressLength..].ToArray());
            while (body.Count < payload.Length)
            {
                body.AddRange(await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter));
            }

            Assert.Equal(payload, body.ToArray());

            // Server response: its own salt, a ServerStream header, then the payload.
            var serverSalt = RandomNumberGenerator.GetBytes(cipher.SaltSize);
            await stream.WriteAsync(serverSalt, ct);
            var serverSubkey = cipher.DeriveSubkey(psk, serverSalt);
            var header = new byte[Shadowsocks2022.UdpBodyHeaderSize];
            Shadowsocks2022.WriteUdpBodyHeader(header, Shadowsocks2022PacketType.ServerStream, Shadowsocks2022.NowUnixSeconds(), 0);
            var response = new byte[header.Length + body.Count];
            header.CopyTo(response, 0);
            body.CopyTo(response, header.Length);
            await WriteAeadChunksAsync(stream, cipher, serverSubkey, response, ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-2022", "ss",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("cipher", cipherName),
            ("password", encodedPsk)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.net", 443));
        await outbound.WriteAsync(payload);

        var echoed = new byte[payload.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(payload, echoed);
        Assert.Equal(Shadowsocks2022PacketType.ClientStream, await seenType.Task);
        Assert.Equal(("example.net", 443), await seenAddress.Task);
        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    // ── plugins ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ObfsPluginPutsAnHttpRequestInFrontOfTheCiphertext()
    {
        var cipher = AeadCiphers.Get("aes-256-gcm");
        var master = ShadowsocksKey.DeriveMasterKey(Password, cipher.KeySize);
        var payload = System.Text.Encoding.ASCII.GetBytes("obfuscated");
        var seenRequestLine = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var seenHostHeader = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var header = new List<byte>();
            var one = new byte[1];
            while (true)
            {
                await stream.ReadExactlyAsync(one, ct);
                header.Add(one[0]);
                if (header.Count >= 4 && header[^4] == '\r' && header[^3] == '\n' && header[^2] == '\r' && header[^1] == '\n') break;
            }

            var text = System.Text.Encoding.ASCII.GetString(header.ToArray());
            seenRequestLine.SetResult(text.Split("\r\n")[0]);
            seenHostHeader.SetResult(text.Split("\r\n").First(l => l.StartsWith("Host:", StringComparison.Ordinal)));

            Assert.True(ShadowsocksObfs.TryParseHttpSimpleRequest(header.ToArray(), out _, out _, out var embedded),
                "the request line must be a parseable http_simple request");

            // The embedded bytes are the head of the ciphertext stream; the rest follows.
            var salt = embedded;
            Assert.Equal(cipher.SaltSize, salt.Length);
            var subkey = cipher.DeriveSubkey(master, salt);
            var counter = new AeadCounter();

            var first = await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter);
            Assert.True(Socks5Address.TryParse(first, out var addressLength, out _, out _));
            var body = new List<byte>(first[addressLength..]);
            while (body.Count < payload.Length)
            {
                body.AddRange(await ReadAeadChunkAsync(stream, cipher, subkey, ct, counter));
            }

            Assert.Equal(payload, body.ToArray());

            // The response is an HTTP response header followed by the ciphertext.
            var responseHeader = System.Text.Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n");
            await stream.WriteAsync(responseHeader, ct);

            var serverSalt = RandomNumberGenerator.GetBytes(cipher.SaltSize);
            await stream.WriteAsync(serverSalt, ct);
            var serverSubkey = cipher.DeriveSubkey(master, serverSalt);
            await WriteAeadChunksAsync(stream, cipher, serverSubkey, body.ToArray(), ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-obfs", "ss",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("cipher", "aes-256-gcm"),
            ("password", Password),
            ("plugin", "obfs"),
            ("plugin-opts", new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["mode"] = "http",
                ["host"] = "www.bing.com",
            })));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));
        await outbound.WriteAsync(payload);

        var echoed = new byte[payload.Length];
        await outbound.ReadExactlyAsync(echoed);

        Assert.Equal(payload, echoed);
        Assert.StartsWith("GET /", await seenRequestLine.Task);
        Assert.Equal($"Host: www.bing.com:{server.Port}", await seenHostHeader.Task);
        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    [Fact]
    public void LegacySingleStringPluginFormIsUnderstood()
    {
        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-legacy-plugin", "ss",
            ("server", "127.0.0.1"),
            ("port", 8388),
            ("cipher", "aes-256-gcm"),
            ("password", Password),
            ("plugin", "obfs-local;obfs=http;obfs-host=legacy.example")));

        Assert.Equal("Shadowsocks", adapter.TypeName);
        Assert.Equal(8388, ((IOutboundProxy)adapter).ServerPort);
    }

    [Fact]
    public void ShadowTlsPluginIsRefusedRatherThanSilentlySkipped()
    {
        var entry = OutboundHarness.Entry(
            "ss-shadowtls", "ss",
            ("server", "127.0.0.1"),
            ("port", 8388),
            ("cipher", "aes-256-gcm"),
            ("password", Password),
            ("plugin", "shadow-tls"),
            ("plugin-opts", new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["host"] = "example.com" }));

        Assert.ThrowsAny<Exception>(() => OutboundHarness.Build(entry));
    }

    [Fact]
    public async Task UdpDisabledConfigurationRefusesTheAssociation()
    {
        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "ss-noudp", "ss",
            ("server", "127.0.0.1"),
            ("port", 8388),
            ("cipher", "aes-256-gcm"),
            ("password", Password)));

        Assert.False(adapter.SupportUdp);
        await Assert.ThrowsAsync<NotSupportedException>(() => adapter.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53)));
    }

    // ── framing helpers, written against the frozen primitives ───────────────

    /// <summary>
    /// The AEAD nonce counter. A class rather than a <c>ref long</c> because the
    /// reader is asynchronous and <c>ref</c> parameters are not allowed there.
    /// </summary>
    private sealed class AeadCounter
    {
        public long Value;
    }

    private static async Task<byte[]> ReadAeadChunkAsync(
        Stream stream,
        IAeadCipher cipher,
        byte[] subkey,
        CancellationToken cancellationToken,
        AeadCounter counter)
    {
        var lengthBlock = new byte[ShadowsocksAeadFraming.EncryptedLengthSize(cipher)];
        await stream.ReadExactlyAsync(lengthBlock, cancellationToken);

        if (!ShadowsocksAeadFraming.TryReadLength(cipher, subkey, ref counter.Value, lengthBlock, out var length))
        {
            throw new InvalidOperationException("the chunk length failed authentication");
        }

        var framed = new byte[length + cipher.TagSize];
        await stream.ReadExactlyAsync(framed, cancellationToken);

        var plaintext = new byte[length];
        if (!ShadowsocksAeadFraming.TryReadPayload(cipher, subkey, ref counter.Value, framed, length, plaintext))
        {
            throw new InvalidOperationException("the chunk payload failed authentication");
        }

        return plaintext;
    }

    private static async Task WriteAeadChunksAsync(
        Stream stream,
        IAeadCipher cipher,
        byte[] subkey,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        long counter = 0;
        var offset = 0;
        while (offset < payload.Length)
        {
            var size = Math.Min(ShadowsocksAeadFraming.MaxChunkSize, payload.Length - offset);
            var framed = new byte[ShadowsocksAeadFraming.FramedSize(cipher, size)];
            var written = ShadowsocksAeadFraming.WriteChunk(cipher, subkey, ref counter, payload.Span.Slice(offset, size), framed);
            await stream.WriteAsync(framed.AsMemory(0, written), cancellationToken);
            offset += size;
        }
    }
}
