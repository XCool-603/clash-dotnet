using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Outbound;

/// <summary>
/// The mieru TCP underlay. The fake server below is written from the factsheet's
/// metadata field tables and carries its own copy of the key schedule
/// (<see cref="Spec"/>), so the assertions are about the bytes on the wire rather
/// than about the adapter's own reader. The only thing shared with the adapter is
/// the frozen XChaCha20-Poly1305 primitive, exactly as the Shadowsocks tests share
/// <c>AeadCiphers</c>.
/// </summary>
public class MieruTests
{
    private const string Username = "alice";
    private const string Password = "hunter2";

    // ── key schedule and nonce construction ─────────────────────────────────

    /// <summary>
    /// The chain spelled out from the protocol document, not by calling the
    /// production helper: <c>SHA-256(password || 0x00 || username)</c>, then
    /// <c>SHA-256(uint64_BE(round(unixTime, 120s)))</c>, then 64 PBKDF2-SHA256
    /// iterations to 32 bytes.
    /// </summary>
    [Fact]
    public void DerivedKeyMatchesTheSpecChainAtAFixedClock()
    {
        // 2023-11-14T22:13:20Z: deliberately 80 seconds into a two-minute bucket, so
        // the rounding direction is unambiguous.
        const long now = 1_700_000_000;

        var material = new List<byte>();
        material.AddRange(Encoding.UTF8.GetBytes(Password));
        material.Add(0x00);
        material.AddRange(Encoding.UTF8.GetBytes(Username));
        var hashedPassword = SHA256.HashData(material.ToArray());

        var rounded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(rounded, 1_700_000_040);
        var timeSalt = SHA256.HashData(rounded);

        var expected = Rfc2898DeriveBytes.Pbkdf2(
            hashedPassword,
            timeSalt,
            64,
            HashAlgorithmName.SHA256,
            32);

        Assert.Equal(hashedPassword, MieruCrypto.HashPassword(Password, Username));
        Assert.Equal(timeSalt, MieruCrypto.TimeSalt(now));
        Assert.Equal(expected, MieruCrypto.DeriveKey(Password, Username, now));

        // A fixed clock is deterministic.
        Assert.Equal(MieruCrypto.DeriveKey(Password, Username, now), MieruCrypto.DeriveKey(Password, Username, now));

        // The username is part of the password hash, so it changes the key too.
        Assert.NotEqual(MieruCrypto.DeriveKey(Password, Username, now), MieruCrypto.DeriveKey(Password, "bob", now));
    }

    /// <summary>
    /// The time-salt window. This is the silent-failure mode of the protocol: when
    /// the client's clock is outside the server's three salts the first segment
    /// simply fails to authenticate, which looks exactly like a wrong password.
    /// </summary>
    [Fact]
    public void TimeSaltRoundsToTheNearestTwoMinuteBucketAndTheServerWindowIsThreeSalts()
    {
        const long now = 1_700_000_000; // 80 s into a bucket: +20 s stays, -40 s moves back

        Assert.Equal(1_700_000_040, MieruCrypto.RoundUnixTime(now));
        Assert.Equal(MieruCrypto.TimeSalt(now), MieruCrypto.TimeSalt(now + 20));

        // Rounding is to the *nearest* bucket, so the cliff sits at the midpoint.
        Assert.Equal(1_699_999_920, MieruCrypto.RoundUnixTime(now - 40));
        Assert.NotEqual(MieruCrypto.TimeSalt(now), MieruCrypto.TimeSalt(now - 40));

        // The server tries rounded - 2min, rounded and rounded + 2min.
        byte[][] serverWindow =
        [
            MieruCrypto.TimeSalt(now - 120),
            MieruCrypto.TimeSalt(now),
            MieruCrypto.TimeSalt(now + 120),
        ];

        // 20 seconds of drift is inside the window...
        Assert.Contains(serverWindow, salt => salt.SequenceEqual(MieruCrypto.TimeSalt(now + 20)));

        // ...4 minutes is not, and the client cannot tell from the reply: there is none.
        Assert.DoesNotContain(serverWindow, salt => salt.SequenceEqual(MieruCrypto.TimeSalt(now + 240)));
        Assert.DoesNotContain(serverWindow, salt => salt.SequenceEqual(MieruCrypto.TimeSalt(now - 240)));
        Assert.NotEqual(
            MieruCrypto.DeriveKey(Password, Username, now),
            MieruCrypto.DeriveKey(Password, Username, now + 240));
    }

    /// <summary>
    /// The nonce is 24 random bytes whose last four are replaced by
    /// <c>SHA-256(username || nonce[0..16])[0..4]</c> — the server's user-lookup hint.
    /// </summary>
    [Fact]
    public void NonceKeepsTheFirstTwentyBytesAndOverwritesTheLastFourWithTheUsernameHash()
    {
        var random = new byte[24];
        for (var i = 0; i < random.Length; i++) random[i] = (byte)(0xA0 + i);

        var nonce = new byte[24];
        MieruCrypto.BuildNonce(Username, random, nonce);

        Assert.Equal(random[..20], nonce[..20]);

        byte[] hint = [.. Encoding.UTF8.GetBytes(Username), .. random[..16]];
        Assert.Equal(SHA256.HashData(hint)[..4], nonce[20..24]);

        // The hint depends on the username, the random part does not.
        var other = new byte[24];
        MieruCrypto.BuildNonce("bob", random, other);
        Assert.Equal(random[..20], other[..20]);
        Assert.NotEqual(nonce[20..24], other[20..24]);

        // The counter is big-endian: the last byte carries towards index 0.
        var counter = (byte[])nonce.Clone();
        counter[23] = 0xFF;
        MieruCrypto.IncrementNonce(counter);
        Assert.Equal(0, (int)counter[23]);
        Assert.Equal((byte)(nonce[22] + 1), counter[22]);
    }

    // ── the first segment ───────────────────────────────────────────────────

    /// <summary>
    /// The whole first segment, byte by byte: the nonce goes out in the clear, the
    /// metadata that follows is an <c>openSessionRequest</c>, and the payload is the
    /// SOCKS5 CONNECT request. The payload is decrypted with the nonce <em>after</em>
    /// the metadata consumed one, and not with the metadata's own nonce.
    /// </summary>
    [Fact]
    public async Task FirstSegmentCarriesTheNonceThenMetadataThenTheSocks5Request()
    {
        var seen = new TaskCompletionSource<SpecSegment>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var peer = new SpecPeer(stream, Username, Password);
            seen.SetResult(await peer.ReadSegmentAsync(ct).ConfigureAwait(false));
            await peer.WriteSegmentAsync(3, Spec.Socks5Reply(0x00), ct).ConfigureAwait(false);
            await OutboundHarness.DrainAsync(stream, ct).ConfigureAwait(false);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "mieru-first", "mieru",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("username", Username),
            ("password", Password),
            ("transport", "TCP")));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("1.2.3.4", 443));

        var segment = await seen.Task;

        // The nonce on the wire is the one the metadata was sealed with.
        byte[] hint = [.. Encoding.UTF8.GetBytes(Username), .. segment.MetadataNonce[..16]];
        Assert.Equal(SHA256.HashData(hint)[..4], segment.MetadataNonce[20..24]);

        // openSessionRequest, statusOK, and no padding 2 (suffix length is the byte
        // at offset 17; session metadata has no prefix-length field at all).
        Assert.Equal(2, (int)segment.Metadata[0]);
        Assert.Equal(0, (int)segment.Metadata[14]);
        Assert.Equal(0, (int)segment.Metadata[17]);
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32BigEndian(segment.Metadata.AsSpan(6)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(segment.Metadata.AsSpan(10)));

        // The timestamp is minutes since the epoch; ±1 absorbs a minute-boundary race.
        var minutes = (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60);
        Assert.InRange(
            (long)BinaryPrimitives.ReadUInt32BigEndian(segment.Metadata.AsSpan(2)),
            minutes - 1,
            minutes + 1);

        // The exact SOCKS5 CONNECT bytes: [05][01][00][01][1.2.3.4][443].
        byte[] expectedRequest = [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB];
        Assert.Equal(expectedRequest, segment.Payload);
        Assert.Equal(expectedRequest.Length, BinaryPrimitives.ReadUInt16BigEndian(segment.Metadata.AsSpan(15)));

        // Metadata and payload consume separate counter steps.
        Assert.Equal(Spec.Increment(segment.MetadataNonce), segment.PayloadNonce);
        Assert.False(
            DecryptsWith(segment.MetadataNonce, segment),
            "the payload must not decrypt under the metadata's own nonce: the two operations use consecutive nonces");

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    /// <summary>
    /// The nonce appears once per direction. The second client segment therefore
    /// starts with encrypted metadata at the very next byte, and its nonce is the
    /// one after the first segment's payload — the counter carries across segments.
    /// The same test drives a full duplex round trip, because the reply is a data
    /// segment sealed by the server's own independent counter.
    /// </summary>
    [Fact]
    public async Task LaterSegmentsContinueTheCounterWithoutRepeatingTheNonce()
    {
        var first = new TaskCompletionSource<SpecSegment>(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = new TaskCompletionSource<SpecSegment>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var peer = new SpecPeer(stream, Username, Password);
            first.SetResult(await peer.ReadSegmentAsync(ct));
            await peer.WriteSegmentAsync(3, Spec.Socks5Reply(0x00), ct);

            // No nonce here: if the client repeated it, the metadata would not decrypt.
            second.SetResult(await peer.ReadSegmentAsync(ct));

            await peer.WriteSegmentAsync(7, Encoding.ASCII.GetBytes("pong"), ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "mieru-duplex", "mieru",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("username", Username),
            ("password", Password)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("10.0.0.1", 80));

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"));
        var echoed = new byte[4];
        await outbound.ReadExactlyAsync(echoed);
        Assert.Equal("pong", Encoding.ASCII.GetString(echoed));

        var openSegment = await first.Task;
        var dataSegment = await second.Task;

        // dataClientToServer, sequence 2, no padding 1 and no padding 2.
        Assert.Equal(6, (int)dataSegment.Metadata[0]);
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32BigEndian(dataSegment.Metadata.AsSpan(10)));
        Assert.Equal(0, (int)dataSegment.Metadata[21]);
        Assert.Equal(0, (int)dataSegment.Metadata[24]);
        Assert.Equal("ping", Encoding.ASCII.GetString(dataSegment.Payload));

        // One step for the metadata, one for the payload, continuing from segment one.
        Assert.Equal(Spec.Increment(openSegment.PayloadNonce), dataSegment.MetadataNonce);
        Assert.Equal(Spec.Increment(dataSegment.MetadataNonce), dataSegment.PayloadNonce);
        Assert.False(
            DecryptsWith(dataSegment.MetadataNonce, dataSegment),
            "the payload must not decrypt under the metadata's own nonce");

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    /// <summary>A domain destination must use ATYP 3 with a length-prefixed name.</summary>
    [Fact]
    public async Task DomainDestinationsAreEncodedAsFqdnSocks5Requests()
    {
        var seen = new TaskCompletionSource<SpecSegment>(TaskCreationOptions.RunContinuationsAsynchronously);

        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var peer = new SpecPeer(stream, Username, Password);
            seen.SetResult(await peer.ReadSegmentAsync(ct));
            await peer.WriteSegmentAsync(3, Spec.Socks5Reply(0x00), ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "mieru-domain", "mieru",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("username", Username),
            ("password", Password)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("example.com", 80));

        byte[] expected = [0x05, 0x01, 0x00, 0x03, 0x0B, .. Encoding.ASCII.GetBytes("example.com"), 0x00, 0x50];
        Assert.Equal(expected, (await seen.Task).Payload);

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    /// <summary>
    /// A non-zero <c>REP</c> is the only way mieru can reject a client, so the dial
    /// itself must fail rather than deferring the check to the first read.
    /// </summary>
    [Fact]
    public async Task NonZeroSocks5ReplyFailsTheDial()
    {
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var peer = new SpecPeer(stream, Username, Password);
            await peer.ReadSegmentAsync(ct);
            await peer.WriteSegmentAsync(3, Spec.Socks5Reply(0x05), ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "mieru-refused", "mieru",
            ("server", "127.0.0.1"),
            ("port", server.Port),
            ("username", Username),
            ("password", Password)));

        var error = await Assert.ThrowsAsync<ClashException>(
            () => adapter.DialTcpAsync(OutboundHarness.Flow("1.2.3.4", 443)));

        Assert.Contains("REP", error.Message);
        Assert.False(adapter.Alive);

        await server.WaitAsync();
    }

    // ── configuration ───────────────────────────────────────────────────────

    /// <summary><c>type: mieru</c> must be a registered proxy that reports <c>Mieru</c>.</summary>
    [Fact]
    public void MieruIsRegisteredAndReportedAsMieru()
    {
        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "mieru-api", "mieru",
            ("server", "example.com"),
            ("port", 8964),
            ("username", Username),
            ("password", Password)));

        Assert.True(AdapterRegistry.IsKnown("mieru"));
        Assert.Equal(ProxyType.Mieru, adapter.Type);
        Assert.Equal("Mieru", adapter.TypeName);
        Assert.Equal(8964, ((IOutboundProxy)adapter).ServerPort);
        Assert.Equal("example.com", ((IOutboundProxy)adapter).ServerHost);

        // UDP is not implemented, so it must not be advertised either.
        Assert.False(adapter.SupportUdp);
        Assert.False((bool)adapter.ApiExtra["udp"]!);
    }

    /// <summary>
    /// Multiplexing changes the session layout, so a level this client does not
    /// implement is refused instead of silently ignored.
    /// </summary>
    [Theory]
    [InlineData("MULTIPLEXING_LOW")]
    [InlineData("MULTIPLEXING_MIDDLE")]
    [InlineData("MULTIPLEXING_HIGH")]
    public void MultiplexingOtherThanOffIsRefused(string level)
    {
        var error = Assert.ThrowsAny<Exception>(() => OutboundHarness.Build(Entry("mieru-mux", ("multiplexing", level))));
        Assert.Contains("multiplexing", error.Message);
    }

    /// <summary>The off value, however it is spelled, is accepted.</summary>
    [Theory]
    [InlineData("MULTIPLEXING_OFF")]
    [InlineData("off")]
    public void MultiplexingOffIsAccepted(string level)
    {
        var adapter = OutboundHarness.Build(Entry("mieru-mux-off", ("multiplexing", level)));
        Assert.Equal("Mieru", adapter.TypeName);
    }

    /// <summary>
    /// The transport values are case-sensitive, and an unknown one must not fall
    /// back to TCP silently.
    /// </summary>
    [Fact]
    public void UnknownTransportValuesAreRefused()
    {
        var error = Assert.ThrowsAny<Exception>(() => OutboundHarness.Build(Entry("mieru-lower-tcp", ("transport", "tcp"))));
        Assert.Contains("transport", error.Message);
    }

    /// <summary>
    /// The UDP underlay needs a reliability layer this build does not have, so both
    /// dial paths refuse it loudly rather than losing datagrams.
    /// </summary>
    [Fact]
    public async Task TheUdpUnderlayIsRefusedOnBothDialPaths()
    {
        var udpConfigured = OutboundHarness.Build(Entry("mieru-udp", ("transport", "UDP")));
        Assert.False(udpConfigured.SupportUdp);

        await Assert.ThrowsAsync<NotSupportedException>(
            () => udpConfigured.DialTcpAsync(OutboundHarness.Flow("1.2.3.4", 443)));

        await Assert.ThrowsAsync<NotSupportedException>(
            () => udpConfigured.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53)));

        // Even with transport: TCP there is no datagram path to hand out.
        var tcpConfigured = OutboundHarness.Build(Entry("mieru-tcp", ("transport", "TCP")));
        await Assert.ThrowsAsync<NotSupportedException>(
            () => tcpConfigured.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53)));
    }

    /// <summary>
    /// A <c>port-range</c> replaces the configured port per connection; here the
    /// range is a single port, so the dial can only succeed by honouring it.
    /// </summary>
    [Fact]
    public async Task PortRangeOverridesTheConfiguredPort()
    {
        await using var server = new FakeTcpServer(async (stream, ct) =>
        {
            var peer = new SpecPeer(stream, Username, Password);
            await peer.ReadSegmentAsync(ct);
            await peer.WriteSegmentAsync(3, Spec.Socks5Reply(0x00), ct);
            await OutboundHarness.DrainAsync(stream, ct);
        });

        var adapter = OutboundHarness.Build(OutboundHarness.Entry(
            "mieru-range", "mieru",
            ("server", "127.0.0.1"),
            ("port", 1), // deliberately unusable: only the range can reach the server
            ("port-range", $"{server.Port}-{server.Port}"),
            ("username", Username),
            ("password", Password)));

        await using var outbound = await adapter.DialTcpAsync(OutboundHarness.Flow("1.2.3.4", 443));

        await outbound.DisposeAsync();
        await server.WaitAsync();
    }

    /// <summary>A malformed range is a configuration error, not a silent fallback.</summary>
    [Fact]
    public void MalformedPortRangeIsRefused()
    {
        var error = Assert.ThrowsAny<Exception>(
            () => OutboundHarness.Build(Entry("mieru-bad-range", ("port-range", "9000-8000"))));
        Assert.Contains("port-range", error.Message);
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    /// <summary>A configuration entry with the credentials the tests use.</summary>
    private static ProxyConfigEntry Entry(string name, params (string Key, object? Value)[] extra)
    {
        var pairs = new List<(string Key, object? Value)>
        {
            ("server", "127.0.0.1"),
            ("port", 8964),
            ("username", Username),
            ("password", Password),
        };

        pairs.AddRange(extra);
        return OutboundHarness.Entry(name, "mieru", [.. pairs]);
    }

    /// <summary>True when <paramref name="segment"/>'s payload opens under <paramref name="nonce"/>.</summary>
    private static bool DecryptsWith(byte[] nonce, SpecSegment segment)
    {
        var plaintext = new byte[segment.Payload.Length];
        return XChaCha20Poly1305.TryDecrypt(
            segment.Key,
            nonce,
            segment.SealedPayload.AsSpan(0, segment.Payload.Length),
            segment.SealedPayload.AsSpan(segment.Payload.Length, 16),
            plaintext,
            default);
    }

    /// <summary>One segment as the server side saw it, with the nonces it used.</summary>
    private sealed record SpecSegment(
        byte[] Metadata,
        byte[] Payload,
        byte[] SealedPayload,
        byte[] MetadataNonce,
        byte[] PayloadNonce,
        byte[] Key);

    /// <summary>
    /// The key schedule, nonce construction and metadata layout written straight
    /// from the protocol document. Deliberately independent of
    /// <c>MieruCrypto</c>/<c>MieruSegment</c>: a bug shared by both sides of a test
    /// is a bug the test cannot see.
    /// </summary>
    private static class Spec
    {
        internal const int MetadataSize = 32;
        internal const int TagSize = 16;
        internal const int NonceSize = 24;

        /// <summary>PBKDF2 needs the SHA-256 of <c>password || 0x00 || username</c> as its password.</summary>
        internal static byte[] HashedPassword(string password, string username)
        {
            var material = new List<byte>();
            material.AddRange(Encoding.UTF8.GetBytes(password));
            material.Add(0x00);
            material.AddRange(Encoding.UTF8.GetBytes(username));
            return SHA256.HashData(material.ToArray());
        }

        /// <summary>"Round the time to the nearest 2 minutes", to the nearest second.</summary>
        internal static long RoundedSeconds(long unixTime)
            => (long)(Math.Round(unixTime / 120.0, MidpointRounding.AwayFromZero) * 120);

        /// <summary><c>SHA-256(uint64_BE(bucket))</c> for an already rounded bucket.</summary>
        internal static byte[] TimeSaltAtBucket(long bucket)
        {
            var encoded = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(encoded, (ulong)bucket);
            return SHA256.HashData(encoded);
        }

        /// <summary>The connection key at an explicit, already rounded salt bucket.</summary>
        internal static byte[] KeyAtBucket(string password, string username, long bucket)
            => Rfc2898DeriveBytes.Pbkdf2(
                HashedPassword(password, username),
                TimeSaltAtBucket(bucket),
                64,
                HashAlgorithmName.SHA256,
                32);

        /// <summary>24 random bytes with the last four replaced by the username hint.</summary>
        internal static byte[] Nonce(string username, byte[] random)
        {
            var nonce = (byte[])random.Clone();
            byte[] hint = [.. Encoding.UTF8.GetBytes(username), .. nonce[..16]];
            SHA256.HashData(hint).AsSpan(0, 4).CopyTo(nonce.AsSpan(20));
            return nonce;
        }

        /// <summary>One big-endian step of the implicit TCP nonce counter.</summary>
        internal static byte[] Increment(byte[] nonce)
        {
            var next = (byte[])nonce.Clone();
            for (var i = next.Length - 1; i >= 0; i--)
            {
                if (++next[i] != 0) break;
            }

            return next;
        }

        /// <summary>Session metadata (protocol types 2-5): no prefix-length field exists.</summary>
        internal static byte[] SessionMetadata(byte type, uint sessionId, uint sequence, int payloadLength)
        {
            var metadata = new byte[MetadataSize];
            metadata[0] = type;
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(2), Minutes());
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(6), sessionId);
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(10), sequence);
            metadata[14] = 0; // statusOK
            BinaryPrimitives.WriteUInt16BigEndian(metadata.AsSpan(15), (ushort)payloadLength);
            metadata[17] = 0; // suffix length
            return metadata;
        }

        /// <summary>Data metadata (protocol types 6-9).</summary>
        internal static byte[] DataMetadata(byte type, uint sessionId, uint sequence, int payloadLength)
        {
            var metadata = new byte[MetadataSize];
            metadata[0] = type;
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(2), Minutes());
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(6), sessionId);
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(10), sequence);
            BinaryPrimitives.WriteUInt32BigEndian(metadata.AsSpan(14), 0); // unacknowledged
            BinaryPrimitives.WriteUInt16BigEndian(metadata.AsSpan(18), 0); // window
            metadata[20] = 0; // fragment number: the last one
            metadata[21] = 0; // prefix length
            BinaryPrimitives.WriteUInt16BigEndian(metadata.AsSpan(22), (ushort)payloadLength);
            metadata[24] = 0; // suffix length
            return metadata;
        }

        /// <summary>A SOCKS5 reply with an IPv4 bound address, as literal bytes.</summary>
        internal static byte[] Socks5Reply(byte reply)
            => [0x05, reply, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];

        private static uint Minutes() => (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60);
    }

    /// <summary>
    /// The mieru TCP server side of the wire tests. It reads one segment at a time
    /// from the field tables, keeps its own nonce counters, and resolves the key by
    /// trying the same three salts a real server tries.
    /// </summary>
    private sealed class SpecPeer
    {
        private readonly Stream _stream;
        private readonly string _username;
        private readonly string _password;
        private byte[] _readNonce = new byte[Spec.NonceSize];
        private byte[] _writeNonce;
        private bool _readFirst = true;
        private bool _writeFirst = true;
        private uint _writeSequence;

        internal SpecPeer(Stream stream, string username, string password)
        {
            _stream = stream;
            _username = username;
            _password = password;
            _writeNonce = Spec.Nonce(username, RandomNumberGenerator.GetBytes(Spec.NonceSize));
        }

        internal byte[]? Key { get; private set; }

        internal uint SessionId { get; private set; }

        /// <summary>Reads and authenticates one segment.</summary>
        internal async Task<SpecSegment> ReadSegmentAsync(CancellationToken cancellationToken)
        {
            if (_readFirst)
            {
                await _stream.ReadExactlyAsync(_readNonce, cancellationToken).ConfigureAwait(false);
                _readFirst = false;
            }

            var metadataNonce = (byte[])_readNonce.Clone();

            var sealedMetadata = new byte[Spec.MetadataSize + Spec.TagSize];
            await _stream.ReadExactlyAsync(sealedMetadata, cancellationToken).ConfigureAwait(false);

            var metadata = new byte[Spec.MetadataSize];
            if (!TryOpenMetadata(metadataNonce, sealedMetadata, metadata))
            {
                throw new InvalidOperationException(
                    "the segment metadata did not decrypt: the implicit nonce counter is wrong, a 24-byte nonce was repeated, "
                    + "or the key does not match the client's");
            }

            // The payload of this segment uses the next counter value.
            var payloadNonce = Spec.Increment(metadataNonce);

            var type = metadata[0];
            var session = type is >= 2 and <= 5;
            var sequence = BinaryPrimitives.ReadUInt32BigEndian(metadata.AsSpan(10));
            var prefixLength = session ? 0 : metadata[21];
            var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(metadata.AsSpan(session ? 15 : 22));
            var suffixLength = metadata[session ? 17 : 24];

            if (SessionId == 0) SessionId = BinaryPrimitives.ReadUInt32BigEndian(metadata.AsSpan(6));

            if (prefixLength > 0) await SkipAsync(prefixLength, cancellationToken).ConfigureAwait(false);

            var sealedPayload = new byte[payloadLength + (payloadLength > 0 ? Spec.TagSize : 0)];
            var payload = new byte[payloadLength];
            if (payloadLength > 0)
            {
                await _stream.ReadExactlyAsync(sealedPayload, cancellationToken).ConfigureAwait(false);
                if (!XChaCha20Poly1305.TryDecrypt(
                        Key!,
                        payloadNonce,
                        sealedPayload.AsSpan(0, payloadLength),
                        sealedPayload.AsSpan(payloadLength, Spec.TagSize),
                        payload,
                        default))
                {
                    throw new InvalidOperationException(
                        "the segment payload did not decrypt with the metadata nonce + 1");
                }
            }

            if (suffixLength > 0) await SkipAsync(suffixLength, cancellationToken).ConfigureAwait(false);

            _readNonce = payloadLength > 0 ? Spec.Increment(payloadNonce) : payloadNonce;

            return new SpecSegment(metadata, payload, sealedPayload, metadataNonce, payloadNonce, Key!);
        }

        /// <summary>Writes one segment with the server's own counter.</summary>
        internal async Task WriteSegmentAsync(byte type, byte[] payload, CancellationToken cancellationToken)
        {
            _writeSequence++;
            var metadata = type is >= 2 and <= 5
                ? Spec.SessionMetadata(type, SessionId, _writeSequence, payload.Length)
                : Spec.DataMetadata(type, SessionId, _writeSequence, payload.Length);

            var frame = new byte[
                (_writeFirst ? Spec.NonceSize : 0)
                + Spec.MetadataSize
                + Spec.TagSize
                + payload.Length
                + (payload.Length > 0 ? Spec.TagSize : 0)];

            var offset = 0;
            if (_writeFirst)
            {
                _writeNonce.CopyTo(frame, 0);
                offset = Spec.NonceSize;
                _writeFirst = false;
            }

            var metadataNonce = (byte[])_writeNonce.Clone();
            XChaCha20Poly1305.Encrypt(
                Key!,
                metadataNonce,
                metadata,
                frame.AsSpan(offset, Spec.MetadataSize),
                frame.AsSpan(offset + Spec.MetadataSize, Spec.TagSize),
                default);
            _writeNonce = Spec.Increment(metadataNonce);
            offset += Spec.MetadataSize + Spec.TagSize;

            if (payload.Length > 0)
            {
                XChaCha20Poly1305.Encrypt(
                    Key!,
                    _writeNonce,
                    payload,
                    frame.AsSpan(offset, payload.Length),
                    frame.AsSpan(offset + payload.Length, Spec.TagSize),
                    default);
                _writeNonce = Spec.Increment(_writeNonce);
            }

            await _stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Opens the metadata, resolving the key on the first segment by trying the
        /// three salts a server tries: rounded - 2min, rounded, rounded + 2min.
        /// </summary>
        private bool TryOpenMetadata(byte[] nonce, byte[] sealedMetadata, byte[] metadata)
        {
            if (Key is not null)
            {
                return XChaCha20Poly1305.TryDecrypt(
                    Key,
                    nonce,
                    sealedMetadata.AsSpan(0, Spec.MetadataSize),
                    sealedMetadata.AsSpan(Spec.MetadataSize, Spec.TagSize),
                    metadata,
                    default);
            }

            var bucket = Spec.RoundedSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            foreach (var candidate in new[] { bucket - 120, bucket, bucket + 120 })
            {
                var key = Spec.KeyAtBucket(_password, _username, candidate);
                if (XChaCha20Poly1305.TryDecrypt(
                        key,
                        nonce,
                        sealedMetadata.AsSpan(0, Spec.MetadataSize),
                        sealedMetadata.AsSpan(Spec.MetadataSize, Spec.TagSize),
                        metadata,
                        default))
                {
                    Key = key;
                    return true;
                }
            }

            return false;
        }

        private async Task SkipAsync(int count, CancellationToken cancellationToken)
        {
            var scratch = new byte[count];
            await _stream.ReadExactlyAsync(scratch, cancellationToken).ConfigureAwait(false);
        }
    }
}
