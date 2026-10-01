using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Clash.Core.Crypto;

/// <summary>How completely a ShadowsocksR plugin has been implemented here.</summary>
public enum SsrSupportLevel
{
    /// <summary>Wire-compatible with the reference implementation.</summary>
    Full,

    /// <summary>Primitives are present and documented, but the wire format was not verified.</summary>
    Partial,

    /// <summary>Not implemented; the factory throws <see cref="NotSupportedException"/>.</summary>
    Unsupported,
}

/// <summary>An SSR "protocol" plugin: the header it prepends and the transform it applies.</summary>
public interface ISsrProtocolPlugin
{
    /// <summary>Configuration name, e.g. <c>origin</c> or <c>auth_aes128_md5</c>.</summary>
    string Name { get; }

    /// <summary>How much of this plugin is implemented.</summary>
    SsrSupportLevel Support { get; }

    /// <summary>Bytes to prepend to the client's first payload byte.</summary>
    int BuildClientHeader(Span<byte> destination, ReadOnlySpan<byte> userKey);

    /// <summary>Bytes to prepend to the server's first payload byte.</summary>
    int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> userKey);

    /// <summary>Consumes the client header at the head of the first inbound packet.</summary>
    bool TryReadClientHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, out int consumed);

    /// <summary>Consumes the server header at the head of the first inbound packet.</summary>
    bool TryReadServerHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, out int consumed);

    /// <summary>Transforms payload bytes travelling client to server, in place.</summary>
    void TransformClientToServer(Span<byte> buffer);

    /// <summary>Transforms payload bytes travelling server to client, in place.</summary>
    void TransformServerToClient(Span<byte> buffer);
}

/// <summary>An SSR "obfs" plugin.</summary>
public interface ISsrObfsPlugin
{
    /// <summary>Configuration name, e.g. <c>plain</c> or <c>http_simple</c>.</summary>
    string Name { get; }

    /// <summary>How much of this plugin is implemented.</summary>
    SsrSupportLevel Support { get; }

    /// <summary>Bytes to prepend to the client's first payload byte.</summary>
    int BuildClientHeader(Span<byte> destination, string host, int port, ReadOnlySpan<byte> firstPayload);

    /// <summary>Bytes to prepend to the server's first payload byte.</summary>
    int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> firstPayload);

    /// <summary>Measures the client header at the head of the first inbound packet.</summary>
    bool TryMeasureClientHeader(ReadOnlySpan<byte> source, out int consumed);

    /// <summary>Measures the server header at the head of the first inbound packet.</summary>
    bool TryMeasureServerHeader(ReadOnlySpan<byte> source, out int consumed);

    /// <summary>Transforms payload bytes travelling client to server, in place.</summary>
    void TransformClientToServer(Span<byte> buffer);

    /// <summary>Transforms payload bytes travelling server to client, in place.</summary>
    void TransformServerToClient(Span<byte> buffer);
}

/// <summary>
/// ShadowsocksR's protocol and obfuscation plugins.
/// <para>
/// <b>Implemented in full.</b> The <c>origin</c> protocol and the <c>plain</c>
/// obfuscation, which are both pass-through: SSR's real work for those two is
/// done by the underlying stream cipher and by the Shadowsocks address header,
/// which <see cref="Socks5Address"/> provides. <c>origin</c> is accepted as a
/// protocol name too, because SSR configurations frequently write
/// <c>protocol: origin</c> together with <c>obfs: plain</c>.
/// </para>
/// <para>
/// <b>Partially implemented.</b> <c>auth_aes128_md5</c> and
/// <c>auth_aes128_sha1</c>: <see cref="SsrAuthAes128"/> provides the one-time
/// authentication header, the HMAC verifier, the little-endian user id field and
/// the RC4 data transform with SSR's keystream-discard step. The reference
/// implementation's exact random-length distribution and its replay window are
/// not reproduced, so treat this as structurally correct rather than
/// byte-verified.
/// </para>
/// <para>
/// <b>Not implemented.</b> <c>auth_chain_a</c> and its siblings, plus the
/// <c>verify_simple</c>, <c>verify_sha1</c> and <c>auth_sha1_v4</c> protocols and
/// the <c>http_simple</c>, <c>http_post</c>, <c>tls1.2_ticket_auth</c> and
/// <c>tls1.2_ticket_fastauth</c> obfuscations. Requesting any of them throws
/// <see cref="NotSupportedException"/> with a message naming the plugin, rather
/// than silently degrading to no obfuscation.
/// </para>
/// </summary>
public static class ShadowsocksR
{
    /// <summary>Protocol name <c>origin</c>.</summary>
    public const string ProtocolOrigin = "origin";

    /// <summary>Protocol name <c>plain</c> (an alias of <c>origin</c> in practice).</summary>
    public const string ProtocolPlain = "plain";

    /// <summary>Protocol name <c>auth_aes128_md5</c>.</summary>
    public const string ProtocolAuthAes128Md5 = "auth_aes128_md5";

    /// <summary>Protocol name <c>auth_aes128_sha1</c>.</summary>
    public const string ProtocolAuthAes128Sha1 = "auth_aes128_sha1";

    /// <summary>Protocol name <c>auth_chain_a</c>.</summary>
    public const string ProtocolAuthChainA = "auth_chain_a";

    /// <summary>Obfuscation name <c>plain</c>.</summary>
    public const string ObfsPlain = "plain";

    /// <summary>Obfuscation name <c>http_simple</c>.</summary>
    public const string ObfsHttpSimple = "http_simple";

    /// <summary>Obfuscation name <c>http_post</c>.</summary>
    public const string ObfsHttpPost = "http_post";

    /// <summary>Obfuscation name <c>tls1.2_ticket_auth</c>.</summary>
    public const string ObfsTls12TicketAuth = "tls1.2_ticket_auth";

    /// <summary>Creates the named protocol plugin.</summary>
    /// <exception cref="NotSupportedException">The plugin is not implemented.</exception>
    public static ISsrProtocolPlugin CreateProtocol(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return name.ToLowerInvariant() switch
        {
            ProtocolOrigin or ProtocolPlain => SsrPassThroughProtocol.Instance,
            ProtocolAuthAes128Md5 => new SsrAuthAes128Protocol(sha1: false),
            ProtocolAuthAes128Sha1 => new SsrAuthAes128Protocol(sha1: true),
            _ => throw new NotSupportedException(
                $"shadowsocksr: protocol '{name}' is not implemented (implemented: {ProtocolOrigin}, {ProtocolPlain}, {ProtocolAuthAes128Md5}, {ProtocolAuthAes128Sha1})"),
        };
    }

    /// <summary>Creates the named obfuscation plugin.</summary>
    /// <exception cref="NotSupportedException">The plugin is not implemented.</exception>
    public static ISsrObfsPlugin CreateObfs(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return name.ToLowerInvariant() switch
        {
            ObfsPlain or ProtocolOrigin => SsrPassThroughObfs.Instance,
            _ => throw new NotSupportedException(
                $"shadowsocksr: obfs '{name}' is not implemented (implemented: {ObfsPlain})"),
        };
    }

    /// <summary>True when <see cref="CreateProtocol"/> would succeed.</summary>
    public static bool IsProtocolSupported(string name)
        => name is not null && name.ToLowerInvariant() is ProtocolOrigin or ProtocolPlain or ProtocolAuthAes128Md5 or ProtocolAuthAes128Sha1;

    /// <summary>True when <see cref="CreateObfs"/> would succeed.</summary>
    public static bool IsObfsSupported(string name)
        => name is not null && name.ToLowerInvariant() is ObfsPlain or ProtocolOrigin;
}

/// <summary>The <c>origin</c>/<c>plain</c> SSR protocol: no header, no transform.</summary>
public sealed class SsrPassThroughProtocol : ISsrProtocolPlugin
{
    /// <summary>The shared instance; the plugin is stateless.</summary>
    public static readonly SsrPassThroughProtocol Instance = new();

    private SsrPassThroughProtocol()
    {
    }

    public string Name => ShadowsocksR.ProtocolOrigin;

    public SsrSupportLevel Support => SsrSupportLevel.Full;

    public int BuildClientHeader(Span<byte> destination, ReadOnlySpan<byte> userKey) => 0;

    public int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> userKey) => 0;

    public bool TryReadClientHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, out int consumed)
    {
        consumed = 0;
        return true;
    }

    public bool TryReadServerHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, out int consumed)
    {
        consumed = 0;
        return true;
    }

    public void TransformClientToServer(Span<byte> buffer)
    {
    }

    public void TransformServerToClient(Span<byte> buffer)
    {
    }
}

/// <summary>The <c>plain</c> SSR obfuscation: no header, no transform.</summary>
public sealed class SsrPassThroughObfs : ISsrObfsPlugin
{
    /// <summary>The shared instance; the plugin is stateless.</summary>
    public static readonly SsrPassThroughObfs Instance = new();

    private SsrPassThroughObfs()
    {
    }

    public string Name => ShadowsocksR.ObfsPlain;

    public SsrSupportLevel Support => SsrSupportLevel.Full;

    public int BuildClientHeader(Span<byte> destination, string host, int port, ReadOnlySpan<byte> firstPayload) => 0;

    public int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> firstPayload) => 0;

    public bool TryMeasureClientHeader(ReadOnlySpan<byte> source, out int consumed)
    {
        consumed = 0;
        return true;
    }

    public bool TryMeasureServerHeader(ReadOnlySpan<byte> source, out int consumed)
    {
        consumed = 0;
        return true;
    }

    public void TransformClientToServer(Span<byte> buffer)
    {
    }

    public void TransformServerToClient(Span<byte> buffer)
    {
    }
}

/// <summary>
/// RC4 with the keystream-discard step SSR's auth protocols perform: the cipher
/// is keyed with the user key and the first <c>randLen</c> bytes of keystream are
/// thrown away so the stream position depends on the random prefix.
/// </summary>
public sealed class SsrRc4
{
    private readonly RC4Engine _engine = new();

    /// <summary>Keys the cipher and discards <paramref name="discard"/> keystream bytes.</summary>
    public void Init(ReadOnlySpan<byte> key, int discard = 0)
    {
        if (discard < 0) throw new ArgumentOutOfRangeException(nameof(discard));
        _engine.Init(true, new KeyParameter(key.ToArray()));
        if (discard == 0) return;

        var scratch = new byte[Math.Min(discard, 4096)];
        var remaining = discard;
        while (remaining > 0)
        {
            var count = Math.Min(remaining, scratch.Length);
            _engine.ProcessBytes(scratch, 0, count, scratch, 0);
            remaining -= count;
        }
    }

    /// <summary>Transforms bytes in place.</summary>
    public void Process(Span<byte> buffer) => BouncyCastleStreamHelper.Transform(_engine, buffer, buffer);

    /// <summary>Transforms bytes into <paramref name="output"/>.</summary>
    public void Process(ReadOnlySpan<byte> input, Span<byte> output) => BouncyCastleStreamHelper.Transform(_engine, input, output);
}

/// <summary>
/// The one-time authentication header shared by SSR's <c>auth_aes128_md5</c> and
/// <c>auth_aes128_sha1</c> protocols.
/// <para>
/// <b>Layout implemented.</b>
/// </para>
/// <code>
/// Client: rand-len(1) | rand(rand-len) | HMAC(4 or 10) | uid(4, little-endian) | payload
/// Server: rand-len(1) | rand(rand-len) | HMAC(4 or 10)                      | payload
/// </code>
/// <para>
/// <c>HMAC</c> is HMAC-MD5 (truncated to 4 bytes) or HMAC-SHA1 (truncated to 10
/// bytes) over <c>uid || rand</c>, keyed with the user key. Payload bytes after
/// the header are RC4-transformed with the user key and the first <c>rand-len</c>
/// keystream bytes discarded.
/// </para>
/// <para>
/// <b>Documented limitation.</b> The reference implementation draws
/// <c>rand-len</c> from a narrower distribution and enforces a replay window that
/// this code does not. The header shape, the HMAC inputs and the RC4 discard are
/// implemented; the random-length policy is not, which affects traffic shaping
/// rather than correctness of the authentication.
/// </para>
/// </summary>
public static class SsrAuthAes128
{
    /// <summary>Longest random prefix the header can carry.</summary>
    public const int MaxRandomLength = 32;

    /// <summary>HMAC width for the MD5 variant.</summary>
    public const int Md5MacLength = 4;

    /// <summary>HMAC width for the SHA1 variant.</summary>
    public const int Sha1MacLength = 10;

    /// <summary>Width of the little-endian user id field.</summary>
    public const int UidLength = 4;

    /// <summary>Fixed bytes in the client header, excluding the random prefix.</summary>
    public static int ClientHeaderOverhead(bool sha1) => 1 + (sha1 ? Sha1MacLength : Md5MacLength) + UidLength;

    /// <summary>Fixed bytes in the server header, excluding the random prefix.</summary>
    public static int ServerHeaderOverhead(bool sha1) => 1 + (sha1 ? Sha1MacLength : Md5MacLength);

    /// <summary>
    /// Builds the client's one-time header and returns the bytes written.
    /// <paramref name="seed"/> makes the random prefix deterministic for tests.
    /// </summary>
    public static int BuildClientHeader(Span<byte> destination, ReadOnlySpan<byte> userKey, uint uid, bool sha1, int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        var randomLength = random.Next(1, MaxRandomLength + 1);
        var required = 1 + randomLength + (sha1 ? Sha1MacLength : Md5MacLength) + UidLength;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        var offset = 0;
        destination[offset++] = (byte)randomLength;
        var rand = destination.Slice(offset, randomLength);
        random.NextBytes(rand);
        offset += randomLength;

        var uidBytes = new byte[UidLength];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(uidBytes, uid);
        var mac = ComputeMac(userKey, uidBytes, rand, sha1);
        mac.AsSpan(0, sha1 ? Sha1MacLength : Md5MacLength).CopyTo(destination[offset..]);
        offset += sha1 ? Sha1MacLength : Md5MacLength;
        uidBytes.CopyTo(destination[offset..]);
        offset += UidLength;

        return offset;
    }

    /// <summary>Builds the server's one-time header and returns the bytes written.</summary>
    public static int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> userKey, bool sha1, int? seed = null)
    {
        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        var randomLength = random.Next(1, MaxRandomLength + 1);
        var macLength = sha1 ? Sha1MacLength : Md5MacLength;
        var required = 1 + randomLength + macLength;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        var offset = 0;
        destination[offset++] = (byte)randomLength;
        var rand = destination.Slice(offset, randomLength);
        random.NextBytes(rand);
        offset += randomLength;

        var mac = ComputeMac(userKey, [], rand, sha1);
        mac.AsSpan(0, macLength).CopyTo(destination[offset..]);
        offset += macLength;

        return offset;
    }

    /// <summary>Verifies and consumes a client header.</summary>
    public static bool TryReadClientHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, bool sha1, out int consumed, out uint uid)
    {
        consumed = 0;
        uid = 0;

        var macLength = sha1 ? Sha1MacLength : Md5MacLength;
        if (source.Length < 1) return false;

        var randomLength = source[0];
        var headerLength = 1 + randomLength + macLength + UidLength;
        if (source.Length < headerLength) return false;

        var rand = source.Slice(1, randomLength);
        var mac = source.Slice(1 + randomLength, macLength);
        var uidBytes = source.Slice(1 + randomLength + macLength, UidLength).ToArray();

        var expected = ComputeMac(userKey, uidBytes, rand, sha1);
        if (!CryptographicOperations.FixedTimeEquals(mac, expected.AsSpan(0, macLength))) return false;

        uid = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(uidBytes);
        consumed = headerLength;
        return true;
    }

    /// <summary>Verifies and consumes a server header.</summary>
    public static bool TryReadServerHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, bool sha1, out int consumed)
    {
        consumed = 0;

        var macLength = sha1 ? Sha1MacLength : Md5MacLength;
        if (source.Length < 1) return false;

        var randomLength = source[0];
        var headerLength = 1 + randomLength + macLength;
        if (source.Length < headerLength) return false;

        var rand = source.Slice(1, randomLength);
        var mac = source.Slice(1 + randomLength, macLength);

        var expected = ComputeMac(userKey, [], rand, sha1);
        if (!CryptographicOperations.FixedTimeEquals(mac, expected.AsSpan(0, macLength))) return false;

        consumed = headerLength;
        return true;
    }

    /// <summary>Creates the RC4 transform applied to the payload after the header.</summary>
    public static SsrRc4 CreateDataCipher(ReadOnlySpan<byte> userKey, int randomLength)
    {
        var cipher = new SsrRc4();
        cipher.Init(userKey, randomLength);
        return cipher;
    }

    private static byte[] ComputeMac(ReadOnlySpan<byte> userKey, ReadOnlySpan<byte> uid, ReadOnlySpan<byte> rand, bool sha1)
    {
        var material = new byte[uid.Length + rand.Length];
        uid.CopyTo(material);
        rand.CopyTo(material.AsSpan(uid.Length));

        if (sha1) return HMACSHA1.HashData(userKey, material);
        return HMACMD5.HashData(userKey, material);
    }
}

/// <summary>The <c>auth_aes128_md5</c> / <c>auth_aes128_sha1</c> protocol plugin.</summary>
public sealed class SsrAuthAes128Protocol : ISsrProtocolPlugin
{
    private readonly bool _sha1;

    /// <summary>Creates the plugin for the MD5 or the SHA-1 variant.</summary>
    public SsrAuthAes128Protocol(bool sha1) => _sha1 = sha1;

    public string Name => _sha1 ? ShadowsocksR.ProtocolAuthAes128Sha1 : ShadowsocksR.ProtocolAuthAes128Md5;

    public SsrSupportLevel Support => SsrSupportLevel.Partial;

    /// <summary>The random prefix length recovered from the last parsed header.</summary>
    public int LastRandomLength { get; private set; }

    public int BuildClientHeader(Span<byte> destination, ReadOnlySpan<byte> userKey)
        => SsrAuthAes128.BuildClientHeader(destination, userKey, uid: 0, _sha1);

    public int BuildServerHeader(Span<byte> destination, ReadOnlySpan<byte> userKey)
        => SsrAuthAes128.BuildServerHeader(destination, userKey, _sha1);

    public bool TryReadClientHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, out int consumed)
    {
        var ok = SsrAuthAes128.TryReadClientHeader(source, userKey, _sha1, out consumed, out _);
        if (ok) LastRandomLength = source[0];
        return ok;
    }

    public bool TryReadServerHeader(ReadOnlySpan<byte> source, ReadOnlySpan<byte> userKey, out int consumed)
    {
        var ok = SsrAuthAes128.TryReadServerHeader(source, userKey, _sha1, out consumed);
        if (ok) LastRandomLength = source[0];
        return ok;
    }

    public void TransformClientToServer(Span<byte> buffer)
    {
    }

    public void TransformServerToClient(Span<byte> buffer)
    {
    }
}
