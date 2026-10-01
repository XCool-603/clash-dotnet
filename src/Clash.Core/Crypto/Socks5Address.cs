using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Clash.Core.Crypto;

/// <summary>
/// The SOCKS5 address block (<c>ATYP || ADDR || PORT</c>) that Shadowsocks,
/// Shadowsocks 2022 and Trojan all put on the wire to name a destination.
/// </summary>
public static class Socks5Address
{
    /// <summary>ATYP for a 4-byte IPv4 literal.</summary>
    public const byte TypeIpv4 = 0x01;

    /// <summary>ATYP for a length-prefixed domain name.</summary>
    public const byte TypeDomain = 0x03;

    /// <summary>ATYP for a 16-byte IPv6 literal.</summary>
    public const byte TypeIpv6 = 0x04;

    /// <summary>Largest domain name a single length byte can carry.</summary>
    public const int MaxDomainLength = 255;

    /// <summary>Bytes <see cref="Write(Span{byte},string,int)"/> will need for <paramref name="host"/>.</summary>
    public static int Size(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (IPAddress.TryParse(host, out var address)) return Size(address);
        var length = Encoding.UTF8.GetByteCount(host);
        if (length > MaxDomainLength) throw new ArgumentException($"domain name too long: {length} bytes", nameof(host));
        return 1 + 1 + length + 2;
    }

    /// <summary>
    /// Bytes the address-only block (<c>ATYP || ADDR</c>, no port) needs. VLESS
    /// transmits the port separately and uses this shape.
    /// </summary>
    public static int AddressSize(string host)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (IPAddress.TryParse(host, out var address))
        {
            return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 1 + 16 : 1 + 4;
        }

        var length = Encoding.UTF8.GetByteCount(host);
        if (length > MaxDomainLength) throw new ArgumentException($"domain name too long: {length} bytes", nameof(host));
        return 1 + 1 + length;
    }

    /// <summary>Writes the address-only block (<c>ATYP || ADDR</c>, no port).</summary>
    public static int WriteAddress(Span<byte> destination, string host)
    {
        ArgumentNullException.ThrowIfNull(host);

        if (IPAddress.TryParse(host, out var address))
        {
            Span<byte> raw = stackalloc byte[16];
            if (!address.TryWriteBytes(raw, out var written)) throw new ArgumentException("unusable address", nameof(host));
            var required = 1 + written;
            if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

            destination[0] = written == 4 ? TypeIpv4 : TypeIpv6;
            raw[..written].CopyTo(destination[1..]);
            return required;
        }

        var length = Encoding.UTF8.GetByteCount(host);
        if (length > MaxDomainLength) throw new ArgumentException($"domain name too long: {length} bytes", nameof(host));
        var size = 1 + 1 + length;
        if (destination.Length < size) throw new ArgumentException($"destination must be at least {size} bytes", nameof(destination));

        destination[0] = TypeDomain;
        destination[1] = (byte)length;
        Encoding.UTF8.GetBytes(host, destination[2..]);
        return size;
    }

    /// <summary>Measures an address-only block (<c>ATYP || ADDR</c>, no port).</summary>
    public static bool TryMeasureAddress(ReadOnlySpan<byte> source, out int length)
    {
        length = 0;
        if (source.IsEmpty) return false;

        switch (source[0])
        {
            case TypeIpv4:
                if (source.Length < 1 + 4) return false;
                length = 1 + 4;
                return true;

            case TypeIpv6:
                if (source.Length < 1 + 16) return false;
                length = 1 + 16;
                return true;

            case TypeDomain:
                if (source.Length < 2) return false;
                var nameLength = source[1];
                if (source.Length < 2 + nameLength) return false;
                length = 2 + nameLength;
                return true;

            default:
                return false;
        }
    }

    /// <summary>Decodes an address-only block into a host string.</summary>
    public static bool TryParseAddress(ReadOnlySpan<byte> source, out int consumed, out string host)
    {
        consumed = 0;
        host = string.Empty;
        if (!TryMeasureAddress(source, out var length)) return false;

        host = source[0] switch
        {
            TypeIpv4 => new IPAddress(source.Slice(1, 4)).ToString(),
            TypeIpv6 => new IPAddress(source.Slice(1, 16)).ToString(),
            _ => Encoding.UTF8.GetString(source.Slice(2, source[1])),
        };

        consumed = length;
        return true;
    }

    /// <summary>Bytes needed for an address literal.</summary>
    public static int Size(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 1 + 16 + 2 : 1 + 4 + 2;
    }

    /// <summary>Writes <paramref name="host"/>:<paramref name="port"/>, choosing the ATYP automatically.</summary>
    public static int Write(Span<byte> destination, string host, int port)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (port is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));

        if (IPAddress.TryParse(host, out var address)) return Write(destination, address, port);

        var length = Encoding.UTF8.GetByteCount(host);
        if (length > MaxDomainLength) throw new ArgumentException($"domain name too long: {length} bytes", nameof(host));
        var required = 1 + 1 + length + 2;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        destination[0] = TypeDomain;
        destination[1] = (byte)length;
        Encoding.UTF8.GetBytes(host, destination[2..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(2 + length)..], (ushort)port);
        return required;
    }

    /// <summary>Writes an address literal.</summary>
    public static int Write(Span<byte> destination, IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (port is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));

        Span<byte> raw = stackalloc byte[16];
        if (!address.TryWriteBytes(raw, out var written)) throw new ArgumentException("unusable address", nameof(address));

        var required = 1 + written + 2;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        destination[0] = written == 4 ? TypeIpv4 : TypeIpv6;
        raw[..written].CopyTo(destination[1..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(1 + written)..], (ushort)port);
        return required;
    }

    /// <summary>
    /// Measures the address block at the head of <paramref name="source"/> without
    /// decoding it.
    /// </summary>
    public static bool TryMeasure(ReadOnlySpan<byte> source, out int length)
    {
        length = 0;
        if (source.IsEmpty) return false;

        switch (source[0])
        {
            case TypeIpv4:
                if (source.Length < 1 + 4 + 2) return false;
                length = 1 + 4 + 2;
                return true;

            case TypeIpv6:
                if (source.Length < 1 + 16 + 2) return false;
                length = 1 + 16 + 2;
                return true;

            case TypeDomain:
                if (source.Length < 2) return false;
                var nameLength = source[1];
                if (source.Length < 1 + 1 + nameLength + 2) return false;
                length = 1 + 1 + nameLength + 2;
                return true;

            default:
                return false;
        }
    }

    /// <summary>Copies the raw address block (including ATYP and port) out of <paramref name="source"/>.</summary>
    public static bool TryRead(ReadOnlySpan<byte> source, out int consumed, out byte[] address)
    {
        consumed = 0;
        address = [];
        if (!TryMeasure(source, out var length)) return false;

        consumed = length;
        address = source[..length].ToArray();
        return true;
    }

    /// <summary>Decodes the address block into a host string and a port.</summary>
    public static bool TryParse(ReadOnlySpan<byte> source, out int consumed, out string host, out int port)
    {
        consumed = 0;
        host = string.Empty;
        port = 0;
        if (!TryMeasure(source, out var length)) return false;

        switch (source[0])
        {
            case TypeIpv4:
                host = new IPAddress(source.Slice(1, 4)).ToString();
                port = BinaryPrimitives.ReadUInt16BigEndian(source[5..]);
                break;

            case TypeIpv6:
                host = new IPAddress(source.Slice(1, 16)).ToString();
                port = BinaryPrimitives.ReadUInt16BigEndian(source[17..]);
                break;

            default:
                var nameLength = source[1];
                host = Encoding.UTF8.GetString(source.Slice(2, nameLength));
                port = BinaryPrimitives.ReadUInt16BigEndian(source[(2 + nameLength)..]);
                break;
        }

        consumed = length;
        return true;
    }

    /// <summary>Decodes a bare port, tolerating a truncated buffer.</summary>
    public static bool TryReadPort(ReadOnlySpan<byte> source, out int port)
    {
        if (source.Length < 2)
        {
            port = 0;
            return false;
        }

        port = BinaryPrimitives.ReadUInt16BigEndian(source);
        return true;
    }
}
