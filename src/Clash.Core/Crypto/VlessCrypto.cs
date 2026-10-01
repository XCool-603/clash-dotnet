using System.Buffers.Binary;
using System.Text;

namespace Clash.Core.Crypto;

/// <summary>
/// The VLESS request and response headers, plus the protobuf <c>Addons</c>
/// message that carries the <c>flow</c> and the vision padding seed.
/// <para>
/// <b>Wire layout implemented here.</b>
/// </para>
/// <code>
/// Request : version(1) | uuid(16) | addons-len(1) | addons(N) | cmd(1) | port(2, BE) | atyp(1) | addr | payload
/// Response: version(1) | addons-len(1) | addons(N) | payload
/// </code>
/// <para>
/// The address block reuses the SOCKS5 encoding (see <see cref="Socks5Address"/>),
/// and <c>version</c> is always 0. VLESS has no encryption of its own: it relies
/// entirely on the transport underneath (TLS or REALITY).
/// </para>
/// </summary>
public static class VlessCrypto
{
    /// <summary>The only version VLESS defines.</summary>
    public const byte Version = 0;

    /// <summary>Command for a proxied TCP stream.</summary>
    public const byte CommandTcp = 1;

    /// <summary>Command for a UDP association.</summary>
    public const byte CommandUdp = 2;

    /// <summary>Command opening an XUDP / mux session.</summary>
    public const byte CommandMux = 3;

    /// <summary>The flow value that turns on XTLS vision padding.</summary>
    public const string FlowVision = "xtls-rprx-vision";

    /// <summary>The historical flow value that turns on XTLS direct.</summary>
    public const string FlowXtlsDirect = "xtls-rprx-direct";

    /// <summary>Number of bytes the request header occupies before the address block.</summary>
    public const int RequestHeaderPrefixSize = 1 + 16 + 1;

    /// <summary>Encodes the request header, including the address block. Returns the bytes written.</summary>
    public static int WriteRequestHeader(
        Span<byte> destination,
        ReadOnlySpan<byte> uuid,
        byte command,
        string host,
        int port,
        ReadOnlySpan<byte> addons = default)
    {
        if (uuid.Length != 16) throw new ArgumentException("uuid must be 16 bytes", nameof(uuid));
        if (addons.Length > 255) throw new ArgumentException("addons must fit in one length byte", nameof(addons));

        var addressSize = Socks5Address.AddressSize(host);
        var required = RequestHeaderPrefixSize + addons.Length + 1 + 2 + addressSize;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        var offset = 0;
        destination[offset++] = Version;
        uuid.CopyTo(destination[offset..]);
        offset += 16;
        destination[offset++] = (byte)addons.Length;
        addons.CopyTo(destination[offset..]);
        offset += addons.Length;
        destination[offset++] = command;
        BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], (ushort)port);
        offset += 2;

        // VLESS carries the port separately, so the address block here is
        // ATYP || ADDR without a trailing port.
        offset += Socks5Address.WriteAddress(destination[offset..], host);

        return offset;
    }

    /// <summary>
    /// Measures the request header at the head of <paramref name="source"/> without
    /// decoding it. Returns false while the header is still incomplete.
    /// </summary>
    public static bool TryMeasureRequestHeader(ReadOnlySpan<byte> source, out int consumed, out byte command, out int port)
    {
        consumed = 0;
        command = 0;
        port = 0;

        if (source.Length < RequestHeaderPrefixSize) return false;
        var addonsLength = source[17];
        var afterAddons = RequestHeaderPrefixSize + addonsLength;
        if (source.Length < afterAddons + 1 + 2) return false;

        command = source[afterAddons];
        port = BinaryPrimitives.ReadUInt16BigEndian(source[(afterAddons + 1)..]);

        var addressOffset = afterAddons + 1 + 2;
        if (!Socks5Address.TryMeasureAddress(source[addressOffset..], out var addressLength)) return false;

        consumed = addressOffset + addressLength;
        return true;
    }

    /// <summary>Decodes the request header.</summary>
    public static bool TryReadRequestHeader(
        ReadOnlySpan<byte> source,
        out int consumed,
        out byte[] uuid,
        out byte command,
        out string host,
        out int port,
        out byte[] addons)
    {
        consumed = 0;
        uuid = [];
        command = 0;
        host = string.Empty;
        port = 0;
        addons = [];

        if (!TryMeasureRequestHeader(source, out consumed, out command, out port)) return false;

        uuid = source.Slice(1, 16).ToArray();
        var addonsLength = source[17];
        addons = source.Slice(RequestHeaderPrefixSize, addonsLength).ToArray();

        var addressOffset = RequestHeaderPrefixSize + addonsLength + 1 + 2;
        if (!Socks5Address.TryParseAddress(source[addressOffset..], out _, out host)) return false;

        return true;
    }

    /// <summary>Encodes a response header. Returns the bytes written.</summary>
    public static int WriteResponseHeader(Span<byte> destination, ReadOnlySpan<byte> addons = default)
    {
        if (addons.Length > 255) throw new ArgumentException("addons must fit in one length byte", nameof(addons));
        var required = 2 + addons.Length;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        destination[0] = Version;
        destination[1] = (byte)addons.Length;
        addons.CopyTo(destination[2..]);
        return required;
    }

    /// <summary>Decodes a response header.</summary>
    public static bool TryReadResponseHeader(ReadOnlySpan<byte> source, out int consumed, out byte[] addons)
    {
        consumed = 0;
        addons = [];
        if (source.Length < 2) return false;

        var addonsLength = source[1];
        if (source.Length < 2 + addonsLength) return false;

        consumed = 2 + addonsLength;
        addons = source.Slice(2, addonsLength).ToArray();
        return true;
    }

    /// <summary>
    /// Encodes the protobuf <c>Addons</c> message:
    /// <c>field 1 (string) = flow</c>, <c>field 2 (bytes) = seed</c>.
    /// </summary>
    public static byte[] EncodeAddons(string? flow, ReadOnlySpan<byte> seed = default)
    {
        var buffer = new List<byte>(32);
        if (!string.IsNullOrEmpty(flow))
        {
            var flowBytes = Encoding.UTF8.GetBytes(flow);
            buffer.Add(0x0A);            // field 1, wire type 2 (length-delimited)
            WriteVarint(buffer, flowBytes.Length);
            buffer.AddRange(flowBytes);
        }

        if (!seed.IsEmpty)
        {
            buffer.Add(0x12);            // field 2, wire type 2
            WriteVarint(buffer, seed.Length);
            buffer.AddRange(seed.ToArray());
        }

        return buffer.ToArray();
    }

    /// <summary>Decodes the protobuf <c>Addons</c> message.</summary>
    public static bool TryDecodeAddons(ReadOnlySpan<byte> addons, out string? flow, out byte[] seed)
    {
        flow = null;
        seed = [];

        var offset = 0;
        while (offset < addons.Length)
        {
            if (!TryReadVarint(addons, ref offset, out var tag)) return false;
            var field = (int)(tag >> 3);
            var wireType = (int)(tag & 0x7);
            if (wireType != 2) return false;

            if (!TryReadVarint(addons, ref offset, out var length)) return false;
            if (length < 0 || offset + length > addons.Length) return false;

            var value = addons.Slice(offset, (int)length);
            offset += (int)length;

            switch (field)
            {
                case 1:
                    flow = Encoding.UTF8.GetString(value);
                    break;
                case 2:
                    seed = value.ToArray();
                    break;
            }
        }

        return true;
    }

    private static void WriteVarint(List<byte> target, int value)
    {
        var remaining = (uint)value;
        while (remaining >= 0x80)
        {
            target.Add((byte)(remaining | 0x80));
            remaining >>= 7;
        }

        target.Add((byte)remaining);
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> source, ref int offset, out long value)
    {
        value = 0;
        var shift = 0;
        while (offset < source.Length)
        {
            var b = source[offset++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
            shift += 7;
            if (shift > 63) return false;
        }

        return false;
    }
}

/// <summary>
/// The XTLS <c>vision</c> padding block.
/// <para>
/// <b>Layout implemented.</b> A padding block is
/// <c>command(1) | content-length(2, big-endian) | content(content-length)</c>,
/// with <c>command = 0</c> meaning "more padding follows", <c>1</c> meaning "this
/// is the last padding block, real data follows" and <c>2</c> meaning "no padding
/// at all, real data follows immediately after the three-byte header".
/// </para>
/// <para>
/// <b>Documented limitation.</b> The reference implementation also derives a
/// length-dependent key from the <c>seed</c> addon so that the padding content of
/// a server response is unpredictable to a passive observer. That derivation is
/// not reproduced here: <see cref="NextPaddingLength"/> produces a
/// length-correlated but unauthenticated padding size, and the content is random.
/// Vision is an anti-fingerprinting measure rather than a security boundary, so
/// the omitted piece changes the traffic shape but not the confidentiality of the
/// payload, which still rides inside the outer TLS/REALITY record.
/// </para>
/// </summary>
public static class VlessVisionPadding
{
    /// <summary>More padding blocks follow.</summary>
    public const byte CommandContinue = 0;

    /// <summary>Last padding block; real data follows.</summary>
    public const byte CommandEnd = 1;

    /// <summary>No padding; real data follows the header.</summary>
    public const byte CommandDirect = 2;

    /// <summary>Bytes in a padding block header.</summary>
    public const int HeaderSize = 3;

    /// <summary>Largest content a padding block may carry.</summary>
    public const int MaxContentLength = ushort.MaxValue;

    /// <summary>Writes a padding block header. Returns the bytes written.</summary>
    public static int WriteHeader(Span<byte> destination, byte command, int contentLength)
    {
        if (destination.Length < HeaderSize) throw new ArgumentException($"destination must be at least {HeaderSize} bytes", nameof(destination));
        if (contentLength is < 0 or > MaxContentLength) throw new ArgumentOutOfRangeException(nameof(contentLength));

        destination[0] = command;
        BinaryPrimitives.WriteUInt16BigEndian(destination[1..], (ushort)contentLength);
        return HeaderSize;
    }

    /// <summary>Parses a padding block header.</summary>
    public static bool TryReadHeader(ReadOnlySpan<byte> source, out byte command, out int contentLength)
    {
        command = 0;
        contentLength = 0;
        if (source.Length < HeaderSize) return false;

        command = source[0];
        contentLength = BinaryPrimitives.ReadUInt16BigEndian(source[1..]);
        return command <= CommandDirect;
    }

    /// <summary>
    /// The padding length vision would choose for a first write of
    /// <paramref name="payloadLength"/> bytes. Vision pads the first few writes up
    /// to a 900-byte target and stops padding once the payload is already large.
    /// </summary>
    public static int NextPaddingLength(int payloadLength, int? seed = null)
    {
        if (payloadLength < 0) throw new ArgumentOutOfRangeException(nameof(payloadLength));

        const int target = 900;
        if (payloadLength >= target) return 0;

        var random = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        var basePadding = target - payloadLength;
        return Math.Max(0, basePadding + random.Next(0, 256) - 128);
    }
}
