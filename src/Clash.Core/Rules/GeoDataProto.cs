using System.Net;
using System.Text;

namespace Clash.Core.Rules;

/// <summary>
/// The smallest protobuf wire-format reader that can walk v2ray's <c>geosite.dat</c> and
/// <c>geoip.dat</c>. Pulling in a code generator for two fixed schemas would not pay for
/// itself, and the wire format is stable.
/// </summary>
internal static class ProtoReader
{
    /// <summary>Reads a field key, yielding its field number and wire type.</summary>
    public static bool TryReadTag(ReadOnlySpan<byte> data, ref int offset, out int field, out int wireType)
    {
        field = 0;
        wireType = 0;
        if (!TryReadVarint(data, ref offset, out var key)) return false;

        field = (int)(key >> 3);
        wireType = (int)(key & 7);
        return field > 0;
    }

    /// <summary>Reads a base-128 varint.</summary>
    public static bool TryReadVarint(ReadOnlySpan<byte> data, ref int offset, out ulong value)
    {
        value = 0;
        var shift = 0;

        while (offset < data.Length)
        {
            var current = data[offset++];
            value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0) return true;

            shift += 7;
            if (shift > 63) return false;
        }

        return false;
    }

    /// <summary>Reads a length-delimited field body.</summary>
    public static bool TryReadLengthDelimited(ReadOnlySpan<byte> data, ref int offset, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (!TryReadVarint(data, ref offset, out var length)) return false;
        if (length > (ulong)(data.Length - offset)) return false;

        value = data.Slice(offset, (int)length);
        offset += (int)length;
        return true;
    }

    /// <summary>Skips a field of the given wire type.</summary>
    public static bool TrySkip(ReadOnlySpan<byte> data, ref int offset, int wireType)
    {
        switch (wireType)
        {
            case 0:
                return TryReadVarint(data, ref offset, out _);
            case 1:
                offset += 8;
                return offset <= data.Length;
            case 2:
                return TryReadLengthDelimited(data, ref offset, out _);
            case 5:
                offset += 4;
                return offset <= data.Length;
            default:
                return false;
        }
    }

    /// <summary>Decodes a UTF-8 field body.</summary>
    public static string Utf8(ReadOnlySpan<byte> data) => data.IsEmpty ? string.Empty : Encoding.UTF8.GetString(data);
}

/// <summary>One geosite category: its domain entries and, for <c>@ipcidr</c>, its address lists.</summary>
internal sealed class GeoSiteCategory
{
    private string[]? _plain;

    /// <summary>Domain entries with the semantics each one carries.</summary>
    public List<(DomainMatchKind Kind, string Value)> Domains { get; } = [];

    /// <summary>Address prefixes attached to the category.</summary>
    public List<IpPrefix> Cidrs { get; } = [];

    /// <summary>The bare domain strings, used by <see cref="IGeoData.GetGeoSite"/>.</summary>
    public IReadOnlyList<string> PlainDomains => _plain ??= Domains.Select(d => d.Value).ToArray();

    /// <summary>Merges another category into this one.</summary>
    public void Merge(GeoSiteCategory other)
    {
        Domains.AddRange(other.Domains);
        Cidrs.AddRange(other.Cidrs);
        _plain = null;
    }
}

/// <summary>Decoders for the two v2ray data files.</summary>
internal static class GeoDataFiles
{
    /// <summary>
    /// Reads a <c>geosite.dat</c>: <c>GeoSiteList { repeated GeoSite entry = 1 }</c> where
    /// <c>GeoSite { string country_code = 1; repeated Domain domain = 2 }</c> and
    /// <c>Domain { Type type = 1; string value = 2 }</c>.
    /// </summary>
    public static Dictionary<string, GeoSiteCategory> ParseGeoSite(byte[] data)
    {
        var result = new Dictionary<string, GeoSiteCategory>(StringComparer.OrdinalIgnoreCase);
        var span = data.AsSpan();
        var offset = 0;

        while (offset < span.Length && ProtoReader.TryReadTag(span, ref offset, out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(span, ref offset, out var entry)) break;
                ParseGeoSiteEntry(entry, result);
                continue;
            }

            if (!ProtoReader.TrySkip(span, ref offset, wire)) break;
        }

        return result;
    }

    /// <summary>
    /// Reads a <c>geoip.dat</c>: <c>GeoIPList { repeated GeoIP entry = 1 }</c> where
    /// <c>GeoIP { string country_code = 1; repeated CIDR cidr = 2 }</c> and
    /// <c>CIDR { bytes ip = 1; uint32 prefix = 2 }</c>.
    /// </summary>
    public static Dictionary<string, List<IpPrefix>> ParseGeoIp(byte[] data)
    {
        var result = new Dictionary<string, List<IpPrefix>>(StringComparer.OrdinalIgnoreCase);
        var span = data.AsSpan();
        var offset = 0;

        while (offset < span.Length && ProtoReader.TryReadTag(span, ref offset, out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(span, ref offset, out var entry)) break;
                ParseGeoIpEntry(entry, result);
                continue;
            }

            if (!ProtoReader.TrySkip(span, ref offset, wire)) break;
        }

        return result;
    }

    private static void ParseGeoSiteEntry(ReadOnlySpan<byte> entry, Dictionary<string, GeoSiteCategory> result)
    {
        var code = string.Empty;
        var category = new GeoSiteCategory();
        var offset = 0;

        while (offset < entry.Length && ProtoReader.TryReadTag(entry, ref offset, out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(entry, ref offset, out var codeBytes)) return;
                code = ProtoReader.Utf8(codeBytes);
                continue;
            }

            if (field == 2 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(entry, ref offset, out var domain)) return;
                var (kind, value) = ParseDomain(domain);
                if (value.Length > 0) category.Domains.Add((kind, value));
                continue;
            }

            // Field 3 is not part of v2ray's schema; it lets an extended geosite.dat carry
            // the address lists that GEOSITE,<code>@ipcidr consumes.
            if (field == 3 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(entry, ref offset, out var cidr)) return;
                if (TryParseCidr(cidr, out var prefix)) category.Cidrs.Add(prefix);
                continue;
            }

            if (!ProtoReader.TrySkip(entry, ref offset, wire)) return;
        }

        if (code.Length == 0) return;
        code = code.ToUpperInvariant();

        if (result.TryGetValue(code, out var existing)) existing.Merge(category);
        else result[code] = category;
    }

    private static (DomainMatchKind Kind, string Value) ParseDomain(ReadOnlySpan<byte> data)
    {
        var type = 0;
        var value = string.Empty;
        var offset = 0;

        while (offset < data.Length && ProtoReader.TryReadTag(data, ref offset, out var field, out var wire))
        {
            if (field == 1 && wire == 0)
            {
                if (!ProtoReader.TryReadVarint(data, ref offset, out var raw)) break;
                type = (int)raw;
                continue;
            }

            if (field == 2 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(data, ref offset, out var text)) break;
                value = ProtoReader.Utf8(text);
                continue;
            }

            if (!ProtoReader.TrySkip(data, ref offset, wire)) break;
        }

        var kind = type switch
        {
            1 => DomainMatchKind.Regex,
            3 => DomainMatchKind.Full,
            _ => DomainMatchKind.Suffix,
        };

        return (kind, value.Trim());
    }

    private static void ParseGeoIpEntry(ReadOnlySpan<byte> entry, Dictionary<string, List<IpPrefix>> result)
    {
        var code = string.Empty;
        var prefixes = new List<IpPrefix>();
        var offset = 0;

        while (offset < entry.Length && ProtoReader.TryReadTag(entry, ref offset, out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(entry, ref offset, out var codeBytes)) return;
                code = ProtoReader.Utf8(codeBytes);
                continue;
            }

            if (field == 2 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(entry, ref offset, out var cidr)) return;
                if (TryParseCidr(cidr, out var prefix)) prefixes.Add(prefix);
                continue;
            }

            if (!ProtoReader.TrySkip(entry, ref offset, wire)) return;
        }

        if (code.Length == 0 || prefixes.Count == 0) return;
        code = code.ToUpperInvariant();

        if (result.TryGetValue(code, out var existing)) existing.AddRange(prefixes);
        else result[code] = prefixes;
    }

    private static bool TryParseCidr(ReadOnlySpan<byte> data, out IpPrefix prefix)
    {
        prefix = default;
        ReadOnlySpan<byte> address = default;
        var bits = 0;
        var offset = 0;

        while (offset < data.Length && ProtoReader.TryReadTag(data, ref offset, out var field, out var wire))
        {
            if (field == 1 && wire == 2)
            {
                if (!ProtoReader.TryReadLengthDelimited(data, ref offset, out address)) return false;
                continue;
            }

            if (field == 2 && wire == 0)
            {
                if (!ProtoReader.TryReadVarint(data, ref offset, out var raw)) return false;
                bits = (int)raw;
                continue;
            }

            if (!ProtoReader.TrySkip(data, ref offset, wire)) return false;
        }

        if (address.Length is not (4 or 16)) return false;

        var maxBits = address.Length * 8;
        if (bits < 0 || bits > maxBits) bits = maxBits;

        prefix = new IpPrefix(new IPAddress(address), bits);
        return true;
    }
}
