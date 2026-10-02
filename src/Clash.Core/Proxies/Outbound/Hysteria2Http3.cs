using System.Globalization;
using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Proxies.Outbound;

/// <summary>One HTTP/3 field line, already QPACK-decoded.</summary>
internal readonly record struct Hysteria2HeaderField(string Name, string Value);

/// <summary>
/// The QPACK subset hysteria2's <c>POST /auth</c> needs (RFC 9204).
/// <para>
/// <b>Why the subset is safe.</b> The client advertises
/// <c>SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0</c> and
/// <c>SETTINGS_QPACK_BLOCKED_STREAMS = 0</c> on its control stream. A conforming peer
/// may then never insert into a dynamic table, never reference one, and never block a
/// field section, so every field line it emits is either an indexed static entry or a
/// literal. That is exactly what <see cref="DecodeFieldSection"/> implements:
/// indexed field line (static only), literal with name reference (static only) and
/// literal with literal name. Everything else — the post-base forms, dynamic indices,
/// and every encoder instruction — is <em>refused loudly</em> rather than
/// mis-decoded, because a silent mis-parse here would corrupt the auth headers.
/// </para>
/// <para>
/// <b>Encoding.</b> The encoder only ever emits static indexed lines, static name
/// references and plain (non-Huffman) literals. It never emits an encoder instruction
/// because it never inserts, so the QPACK encoder stream this client opens stays
/// empty, as RFC 9204 §4.2 permits.
/// </para>
/// </summary>
internal static class Hysteria2Qpack
{
    /// <summary>The static table of RFC 9204 Appendix A, indexed by its table index.</summary>
    internal static readonly Hysteria2HeaderField[] StaticTable =
    [
        new(":authority", ""),
        new(":path", "/"),
        new("age", "0"),
        new("content-disposition", ""),
        new("content-length", "0"),
        new("cookie", ""),
        new("date", ""),
        new("etag", ""),
        new("if-modified-since", ""),
        new("if-none-match", ""),
        new("last-modified", ""),
        new("link", ""),
        new("location", ""),
        new("referer", ""),
        new("set-cookie", ""),
        new(":method", "CONNECT"),
        new(":method", "DELETE"),
        new(":method", "GET"),
        new(":method", "HEAD"),
        new(":method", "OPTIONS"),
        new(":method", "POST"),
        new(":method", "PUT"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "103"),
        new(":status", "200"),
        new(":status", "304"),
        new(":status", "404"),
        new(":status", "503"),
        new("accept", "*/*"),
        new("accept", "application/dns-message"),
        new("accept-encoding", "gzip, deflate, br"),
        new("accept-ranges", "bytes"),
        new("access-control-allow-headers", "cache-control"),
        new("access-control-allow-headers", "content-type"),
        new("access-control-allow-origin", "*"),
        new("cache-control", "max-age=0"),
        new("cache-control", "max-age=2592000"),
        new("cache-control", "max-age=604800"),
        new("cache-control", "no-cache"),
        new("cache-control", "no-store"),
        new("cache-control", "public, max-age=31536000"),
        new("content-encoding", "br"),
        new("content-encoding", "gzip"),
        new("content-type", "application/dns-message"),
        new("content-type", "application/javascript"),
        new("content-type", "application/json"),
        new("content-type", "application/x-www-form-urlencoded"),
        new("content-type", "image/gif"),
        new("content-type", "image/jpeg"),
        new("content-type", "image/png"),
        new("content-type", "text/css"),
        new("content-type", "text/html; charset=utf-8"),
        new("content-type", "text/plain"),
        new("content-type", "text/plain;charset=utf-8"),
        new("range", "bytes=0-"),
        new("strict-transport-security", "max-age=31536000"),
        new("strict-transport-security", "max-age=31536000; includesubdomains"),
        new("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        new("vary", "accept-encoding"),
        new("vary", "origin"),
        new("x-content-type-options", "nosniff"),
        new("x-xss-protection", "1; mode=block"),
        new(":status", "100"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "302"),
        new(":status", "400"),
        new(":status", "403"),
        new(":status", "421"),
        new(":status", "425"),
        new(":status", "500"),
        new("accept-language", ""),
        new("access-control-allow-credentials", "FALSE"),
        new("access-control-allow-credentials", "TRUE"),
        new("access-control-allow-headers", "*"),
        new("access-control-allow-methods", "get"),
        new("access-control-allow-methods", "get, post, options"),
        new("access-control-allow-methods", "options"),
        new("access-control-expose-headers", "content-length"),
        new("access-control-request-headers", "content-type"),
        new("access-control-request-method", "get"),
        new("access-control-request-method", "post"),
        new("alt-svc", "clear"),
        new("authorization", ""),
        new("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        new("early-data", "1"),
        new("expect-ct", ""),
        new("forwarded", ""),
        new("if-range", ""),
        new("origin", ""),
        new("purpose", "prefetch"),
        new("server", ""),
        new("timing-allow-origin", "*"),
        new("upgrade-insecure-requests", "1"),
        new("user-agent", ""),
        new("x-forwarded-for", ""),
        new("x-frame-options", "deny"),
        new("x-frame-options", "sameorigin"),
    ];

    /// <summary>The exact static index for a name/value pair, or -1 when there is none.</summary>
    internal static int FindStaticIndex(string name, string value)
    {
        for (var i = 0; i < StaticTable.Length; i++)
        {
            if (StaticTable[i].Name == name && StaticTable[i].Value == value) return i;
        }

        return -1;
    }

    /// <summary>The lowest static index carrying <paramref name="name"/>, or -1 when there is none.</summary>
    internal static int FindStaticName(string name)
    {
        for (var i = 0; i < StaticTable.Length; i++)
        {
            if (StaticTable[i].Name == name) return i;
        }

        return -1;
    }

    /// <summary>
    /// Encodes a whole field section: the two zero prefix bytes, then one field line per
    /// field. Pseudo-headers must already be first, as RFC 9114 §4.3 requires.
    /// </summary>
    internal static byte[] EncodeFieldSection(IReadOnlyList<Hysteria2HeaderField> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        var encoded = new List<byte>(64);

        // Encoded Field Section Prefix: Required Insert Count (8-bit prefix) = 0 and
        // Delta Base (sign + 7-bit prefix) = 0. Both are zero because the section
        // references no dynamic table entry — the whole point of advertising a
        // zero-capacity table.
        encoded.Add(0x00);
        encoded.Add(0x00);

        foreach (var field in fields)
        {
            var exact = FindStaticIndex(field.Name, field.Value);
            if (exact >= 0)
            {
                // 1 T Index(6+): an indexed field line against the static table.
                WriteInteger(encoded, 0xC0, 6, (ulong)exact);
                continue;
            }

            var name = FindStaticName(field.Name);
            if (name >= 0)
            {
                // 0 1 N T NameIndex(4+): N = 0 (not never-indexed), T = 1 (static).
                // T is the bit above the 4-bit index, so it belongs in the pattern:
                // 0x50, not 0x40. With plain 0x40 an :authority field (index 0)
                // came out as a DYNAMIC name reference, which no conforming peer
                // can resolve.
                WriteInteger(encoded, 0x50, 4, (ulong)name);
            }
            else
            {
                // 0 0 1 N H NameLength(3+): N = 0, H = 0, then the literal name.
                WriteInteger(encoded, 0x20, 3, (ulong)Encoding.ASCII.GetByteCount(field.Name));
                encoded.AddRange(Encoding.ASCII.GetBytes(field.Name));
            }

            // H | ValueLength(7+): H = 0, then the literal value.
            WriteInteger(encoded, 0x00, 7, (ulong)Encoding.ASCII.GetByteCount(field.Value));
            encoded.AddRange(Encoding.ASCII.GetBytes(field.Value));
        }

        return [.. encoded];
    }

    /// <summary>
    /// Decodes a field section produced by a peer that honoured the zero-capacity
    /// settings. Throws <see cref="ClashException"/> for anything outside the subset.
    /// </summary>
    internal static List<Hysteria2HeaderField> DecodeFieldSection(ReadOnlySpan<byte> source)
    {
        var offset = 0;
        var fields = new List<Hysteria2HeaderField>(8);

        var requiredInsertCount = ReadInteger(source, ref offset, 8);
        if (requiredInsertCount != 0)
        {
            throw new ClashException(
                $"hysteria2: the QPACK field section requires dynamic table insert count {requiredInsertCount}, but this client "
                + "advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 and implements no dynamic table");
        }

        // Delta Base is a sign bit followed by a 7-bit prefix integer. A negative base
        // only makes sense with a dynamic table, so the sign bit is refused up front.
        if (offset >= source.Length) throw Truncated();
        if ((source[offset] & 0x80) != 0)
        {
            throw new ClashException("hysteria2: the QPACK field section carries a negative Delta Base, which this client cannot resolve");
        }

        var deltaBase = ReadInteger(source, ref offset, 7);
        if (deltaBase != 0)
        {
            throw new ClashException($"hysteria2: the QPACK field section declares Delta Base {deltaBase}, which requires a dynamic table");
        }

        while (offset < source.Length)
        {
            var first = source[offset];

            if ((first & 0x80) != 0)
            {
                // 1 T Index(6+)
                var index = ReadInteger(source, ref offset, 6);
                if ((first & 0x40) == 0)
                {
                    throw new ClashException($"hysteria2: the QPACK field section references dynamic table index {index}");
                }

                fields.Add(Static(index));
                continue;
            }

            if ((first & 0x40) != 0)
            {
                // 0 1 N T NameIndex(4+): T (bit 4) selects the table, and T = 1 is
                // the STATIC table - so a clear bit is the dynamic reference this
                // zero-capacity client can never resolve. (The check used to be
                // inverted, which made the decoder reject the encoder's own
                // static-name literals.)
                var index = ReadInteger(source, ref offset, 4);
                if ((first & 0x10) == 0)
                {
                    throw new ClashException($"hysteria2: the QPACK field section references dynamic name index {index}");
                }

                var value = ReadString(source, ref offset, 7);
                fields.Add(new Hysteria2HeaderField(Static(index).Name, value));
                continue;
            }

            if ((first & 0x20) != 0)
            {
                // 0 0 1 N H NameLength(3+)
                var name = ReadString(source, ref offset, 3);
                var value = ReadString(source, ref offset, 7);
                fields.Add(new Hysteria2HeaderField(name, value));
                continue;
            }

            throw new ClashException(
                $"hysteria2: the peer sent QPACK instruction 0x{first:X2}, which is outside the static-table-only subset this "
                + "client implements (post-base indices and dynamic references are not supported)");
        }

        return fields;
    }

    /// <summary>Reads an N-bit-prefix integer (RFC 7541 §5.1) from <paramref name="source"/>.</summary>
    private static ulong ReadInteger(ReadOnlySpan<byte> source, ref int offset, int prefixBits)
    {
        if (offset >= source.Length) throw Truncated();

        var mask = (1 << prefixBits) - 1;
        var value = (ulong)(source[offset] & mask);
        offset++;
        if (value < (ulong)mask) return value;

        var shift = 0;
        while (true)
        {
            if (offset >= source.Length) throw Truncated();
            var b = source[offset++];
            value += (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return value;

            shift += 7;
            if (shift > 56)
            {
                throw new ClashException("hysteria2: the QPACK field section contains an over-long integer");
            }
        }
    }

    /// <summary>Reads an <c>H | Length(prefix+)</c> string, Huffman-decoding it when the H bit is set.</summary>
    private static string ReadString(ReadOnlySpan<byte> source, ref int offset, int prefixBits)
    {
        if (offset >= source.Length) throw Truncated();

        var huffman = (source[offset] & (1 << prefixBits)) != 0;
        var length = (int)ReadInteger(source, ref offset, prefixBits);
        if (length < 0 || offset + length > source.Length) throw Truncated();

        var bytes = source.Slice(offset, length);
        offset += length;
        return huffman
            ? Encoding.ASCII.GetString(Hysteria2Huffman.Decode(bytes))
            : Encoding.ASCII.GetString(bytes);
    }

    /// <summary>Appends an N-bit-prefix integer whose leading bits are <paramref name="pattern"/>.</summary>
    private static void WriteInteger(List<byte> destination, byte pattern, int prefixBits, ulong value)
    {
        var max = (1UL << prefixBits) - 1;
        if (value < max)
        {
            destination.Add((byte)(pattern | value));
            return;
        }

        destination.Add((byte)(pattern | max));
        value -= max;
        while (value >= 128)
        {
            destination.Add((byte)(0x80 | (value & 0x7F)));
            value >>= 7;
        }

        destination.Add((byte)value);
    }

    /// <summary>Resolves a static table index, refusing one the table does not have.</summary>
    private static Hysteria2HeaderField Static(ulong index)
    {
        if (index >= (ulong)StaticTable.Length)
        {
            throw new ClashException($"hysteria2: the QPACK field section references static index {index}, past the end of the table");
        }

        return StaticTable[(int)index];
    }

    private static ClashException Truncated()
        => new("hysteria2: the QPACK field section ended in the middle of a field line");
}

/// <summary>
/// The minimum HTTP/3 this client speaks: the client control stream with its
/// SETTINGS frame, the two QPACK streams, and one HEADERS frame for
/// <c>POST /auth</c>.
/// <para>
/// <b>Why hand-rolled.</b> .NET has no HTTP/3 implementation, and the hysteria2
/// handshake is an HTTP/3 request that must ride the <em>same</em> <c>QuicConnection</c>
/// the later data streams use, so <c>HttpClient</c> (which would build its own
/// connection) is not an option. Only the frames the handshake touches are
/// implemented; a peer that sends anything else on the request stream gets it
/// skipped, which is what RFC 9114 §9 tells a receiver to do with unknown frames.
/// </para>
/// </summary>
internal static class Hysteria2Http3
{
    /// <summary>HTTP/3 frame type <c>HEADERS</c>.</summary>
    internal const ulong FrameHeaders = 0x01;

    /// <summary>HTTP/3 frame type <c>SETTINGS</c>.</summary>
    internal const ulong FrameSettings = 0x04;

    /// <summary>Unidirectional stream type <c>control</c>.</summary>
    internal const ulong StreamTypeControl = 0x00;

    /// <summary>Unidirectional stream type <c>QPACK encoder</c>.</summary>
    internal const ulong StreamTypeQpackEncoder = 0x02;

    /// <summary>Unidirectional stream type <c>QPACK decoder</c>.</summary>
    internal const ulong StreamTypeQpackDecoder = 0x03;

    /// <summary>SETTINGS identifier <c>SETTINGS_QPACK_MAX_TABLE_CAPACITY</c>.</summary>
    internal const ulong SettingsQpackMaxTableCapacity = 0x01;

    /// <summary>SETTINGS identifier <c>SETTINGS_QPACK_BLOCKED_STREAMS</c>.</summary>
    internal const ulong SettingsQpackBlockedStreams = 0x07;

    /// <summary>Largest frame payload this reader will buffer before giving up.</summary>
    internal const int MaxFrameLength = 64 * 1024;

    /// <summary>
    /// The client control stream: stream type <c>0x00</c> followed by the SETTINGS
    /// frame, which RFC 9114 §6.2.1 requires to be the very first frame on it.
    /// <para>
    /// The two settings are the ones that bound the QPACK work: a zero-capacity
    /// dynamic table and zero blocked streams. They are what makes
    /// <see cref="Hysteria2Qpack.DecodeFieldSection"/>'s subset complete rather than
    /// merely convenient.
    /// </para>
    /// </summary>
    internal static byte[] ControlStream()
    {
        var settings = new List<byte>(4);
        Hysteria2Varint.Append(settings, SettingsQpackMaxTableCapacity);
        Hysteria2Varint.Append(settings, 0);
        Hysteria2Varint.Append(settings, SettingsQpackBlockedStreams);
        Hysteria2Varint.Append(settings, 0);

        var frame = new List<byte>(settings.Count + 2);
        Hysteria2Varint.Append(frame, FrameSettings);
        Hysteria2Varint.Append(frame, (ulong)settings.Count);
        frame.AddRange(settings);

        var stream = new List<byte>(frame.Count + 1) { (byte)StreamTypeControl };
        stream.AddRange(frame);
        return [.. stream];
    }

    /// <summary>
    /// The QPACK encoder stream. It carries no encoder instructions — this client
    /// never inserts into a dynamic table — but RFC 9204 §4.2 wants the stream opened,
    /// and a peer is entitled to wait for it before it will decode anything.
    /// </summary>
    internal static byte[] QpackEncoderStream() => [(byte)StreamTypeQpackEncoder];

    /// <summary>The QPACK decoder stream, likewise empty: nothing is ever acknowledged.</summary>
    internal static byte[] QpackDecoderStream() => [(byte)StreamTypeQpackDecoder];

    /// <summary>Wraps an encoded field section in a <c>HEADERS</c> frame.</summary>
    internal static byte[] HeadersFrame(ReadOnlySpan<byte> fieldSection)
    {
        var frame = new List<byte>(fieldSection.Length + 4);
        Hysteria2Varint.Append(frame, FrameHeaders);
        Hysteria2Varint.Append(frame, (ulong)fieldSection.Length);
        frame.AddRange(fieldSection);
        return [.. frame];
    }

    /// <summary>
    /// Reads frames until the first <c>HEADERS</c> and decodes its field section.
    /// Unknown and <c>DATA</c> frames are skipped, as RFC 9114 §9 requires; a stream
    /// that ends first is an error, not an empty response.
    /// </summary>
    internal static async ValueTask<List<Hysteria2HeaderField>> ReadHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        while (true)
        {
            var type = await Hysteria2Varint.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
            var length = await Hysteria2Varint.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
            if (length > MaxFrameLength)
            {
                throw new ClashException($"hysteria2: the server sent an HTTP/3 frame of {length} bytes, over the {MaxFrameLength}-byte limit");
            }

            var payload = new byte[(int)length];
            await OutboundIo.ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false);

            if (type == FrameHeaders)
            {
                return Hysteria2Qpack.DecodeFieldSection(payload);
            }
        }
    }
}

/// <summary>
/// The hysteria2 authentication exchange of PROTOCOL.md §2, expressed as HTTP/3.
/// </summary>
internal static class Hysteria2Auth
{
    /// <summary>The reference server's success code. Anything else is a failure.</summary>
    internal const int SuccessStatus = 233;

    /// <summary>
    /// The <c>:authority</c> the server compares against its own <c>URLHost</c>
    /// constant. In HTTP/3 the request's host is carried as the <c>:authority</c>
    /// pseudo-header, which the Go server surfaces as <c>r.Host</c>.
    /// </summary>
    internal const string Authority = "hysteria";

    /// <summary>The request path, <c>URLPath</c> in the reference.</summary>
    internal const string Path = "/auth";

    /// <summary>The bearer string header. Field names go lowercase on the HTTP/3 wire.</summary>
    internal const string AuthHeader = "hysteria-auth";

    /// <summary>The client's maximum receive rate in bytes per second; <c>0</c> means unknown.</summary>
    internal const string CcRxHeader = "hysteria-cc-rx";

    /// <summary>An optional random ASCII string, ignored on receive.</summary>
    internal const string PaddingHeader = "hysteria-padding";

    /// <summary>The server's UDP-relay availability flag.</summary>
    internal const string UdpHeader = "hysteria-udp";

    /// <summary>Builds the <c>POST /auth</c> field section.</summary>
    internal static byte[] BuildRequest(string password, ulong ccRx, string padding)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(padding);

        List<Hysteria2HeaderField> fields =
        [
            new(":method", "POST"),
            new(":scheme", "https"),
            new(":authority", Authority),
            new(":path", Path),
            new(AuthHeader, password),
            new(CcRxHeader, ccRx.ToString(CultureInfo.InvariantCulture)),
            new(PaddingHeader, padding),
        ];

        return Hysteria2Qpack.EncodeFieldSection(fields);
    }

    /// <summary>
    /// Validates the server's reply. The only accepted outcome is <c>:status: 233</c>;
    /// every other status — including a missing one — is an authentication failure and
    /// is reported with the status it carried.
    /// </summary>
    internal static Hysteria2AuthResult ParseResponse(IReadOnlyList<Hysteria2HeaderField> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        var status = Find(fields, ":status");
        if (status is null)
        {
            throw new ClashException("hysteria2: the server's auth response carried no :status header");
        }

        if (!int.TryParse(status, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code))
        {
            throw new ClashException($"hysteria2: the server's auth response carried a non-numeric :status [{status}]");
        }

        if (code != SuccessStatus)
        {
            throw new ClashException(
                $"hysteria2: authentication failed - the server answered :status {code} instead of the expected {SuccessStatus} "
                + "(check the 'password')");
        }

        var udp = string.Equals(Find(fields, UdpHeader), "true", StringComparison.OrdinalIgnoreCase);
        var ccRxText = Find(fields, CcRxHeader);
        var ccRxAuto = string.Equals(ccRxText, "auto", StringComparison.OrdinalIgnoreCase);
        var ccRx = 0UL;
        if (!ccRxAuto && ccRxText is not null)
        {
            _ = ulong.TryParse(ccRxText, NumberStyles.Integer, CultureInfo.InvariantCulture, out ccRx);
        }

        return new Hysteria2AuthResult(code, udp, ccRx, ccRxAuto, Find(fields, PaddingHeader));
    }

    /// <summary>Case-insensitive lookup of a field by name, or null.</summary>
    internal static string? Find(IReadOnlyList<Hysteria2HeaderField> fields, string name)
    {
        foreach (var field in fields)
        {
            if (string.Equals(field.Name, name, StringComparison.OrdinalIgnoreCase)) return field.Value;
        }

        return null;
    }
}

/// <summary>What the server said about the session after a successful auth.</summary>
internal readonly record struct Hysteria2AuthResult(int Status, bool Udp, ulong CcRx, bool CcRxAuto, string? Padding);
