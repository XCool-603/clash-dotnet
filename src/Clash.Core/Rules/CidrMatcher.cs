using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Clash.Core.Rules;

/// <summary>
/// An IPv4 or IPv6 network prefix, e.g. <c>10.0.0.0/8</c>. Parsing goes through
/// <see cref="IPNetwork"/> (available since .NET 8); the host bits are cleared
/// afterwards so a line such as <c>192.168.1.5/24</c> behaves as <c>192.168.1.0/24</c>.
/// </summary>
public readonly struct IpPrefix : IEquatable<IpPrefix>
{
    /// <summary>Creates a prefix from an already masked network address.</summary>
    public IpPrefix(IPAddress network, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(network);
        Network = RuleAddresses.Normalize(network);
        PrefixLength = prefixLength;
    }

    /// <summary>The network address, with every host bit cleared.</summary>
    public IPAddress Network { get; }

    /// <summary>Number of significant leading bits.</summary>
    public int PrefixLength { get; }

    /// <summary>True for an IPv4 prefix.</summary>
    public bool IsIPv4 => Network.AddressFamily == AddressFamily.InterNetwork;

    /// <summary>32 for IPv4, 128 for IPv6.</summary>
    public int BitCount => IsIPv4 ? 32 : 128;

    /// <summary>Parses <c>address</c> or <c>address/length</c>; a bare address becomes a host route.</summary>
    public static bool TryParse(string? text, out IpPrefix prefix)
    {
        prefix = default;
        if (string.IsNullOrWhiteSpace(text)) return false;

        var value = text.Trim();
        var slash = value.IndexOf('/');
        var addressText = slash < 0 ? value : value[..slash].Trim();

        if (!IPAddress.TryParse(addressText, out var address)) return false;
        address = RuleAddresses.Normalize(address);

        var maxBits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var bits = maxBits;
        if (slash >= 0)
        {
            if (!int.TryParse(value[(slash + 1)..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out bits)) return false;
        }

        if (bits < 0 || bits > maxBits) return false;

        // IPNetwork validates the pair and normalises IPv4-mapped forms.
        if (IPNetwork.TryParse($"{address}/{bits}", out var network))
        {
            address = RuleAddresses.Normalize(network.BaseAddress);
            bits = network.PrefixLength;
        }

        prefix = new IpPrefix(Mask(address, bits), bits);
        return true;
    }

    /// <summary>True when <paramref name="address"/> falls inside this prefix.</summary>
    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var candidate = RuleAddresses.Normalize(address);
        if (candidate.AddressFamily != Network.AddressFamily) return false;

        var left = candidate.GetAddressBytes();
        var right = Network.GetAddressBytes();
        var wholeBytes = PrefixLength >> 3;

        for (var i = 0; i < wholeBytes; i++)
        {
            if (left[i] != right[i]) return false;
        }

        var remainder = PrefixLength & 7;
        if (remainder == 0) return true;

        var mask = (byte)(0xFF << (8 - remainder));
        return (left[wholeBytes] & mask) == (right[wholeBytes] & mask);
    }

    /// <summary>Clears every host bit of an address for the given prefix length.</summary>
    public static IPAddress Mask(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        var remaining = prefixLength;

        for (var i = 0; i < bytes.Length; i++)
        {
            if (remaining >= 8)
            {
                remaining -= 8;
                continue;
            }

            bytes[i] = remaining <= 0 ? (byte)0 : (byte)(bytes[i] & (0xFF << (8 - remaining)));
            remaining = 0;
        }

        return new IPAddress(bytes);
    }

    /// <inheritdoc />
    public bool Equals(IpPrefix other) => PrefixLength == other.PrefixLength && Network.Equals(other.Network);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is IpPrefix other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Network, PrefixLength);

    /// <inheritdoc />
    public override string ToString() => $"{Network}/{PrefixLength}";
}

/// <summary>
/// A trailing-bit matcher used by <c>IP-SUFFIX</c>: the address matches when its low
/// <see cref="BitLength"/> bits equal the payload's low bits.
/// <para>
/// A bare payload has as many significant bits as the address family has bits, so
/// <c>IP-SUFFIX,1.2.3.4</c> is the host route <c>1.2.3.4/32</c>. Write
/// <c>IP-SUFFIX,1.2.3.4/24</c> to match every address ending in <c>2.3.4</c>.
/// </para>
/// </summary>
public readonly struct IpSuffix : IEquatable<IpSuffix>
{
    /// <summary>Creates a suffix matcher from an address and a significant-bit count.</summary>
    public IpSuffix(IPAddress address, int bitLength)
    {
        ArgumentNullException.ThrowIfNull(address);
        Address = RuleAddresses.Normalize(address);
        BitLength = bitLength;
    }

    /// <summary>The address whose low bits must match.</summary>
    public IPAddress Address { get; }

    /// <summary>How many trailing bits are significant.</summary>
    public int BitLength { get; }

    /// <summary>Parses <c>address</c> or <c>address/length</c> as a trailing-bit pattern.</summary>
    public static bool TryParse(string? text, out IpSuffix suffix)
    {
        suffix = default;
        if (string.IsNullOrWhiteSpace(text)) return false;

        var value = text.Trim();
        var slash = value.IndexOf('/');
        var addressText = slash < 0 ? value : value[..slash].Trim();

        if (!IPAddress.TryParse(addressText, out var address)) return false;
        address = RuleAddresses.Normalize(address);

        var maxBits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var bits = maxBits;
        if (slash >= 0
            && !int.TryParse(value[(slash + 1)..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out bits))
        {
            return false;
        }

        if (bits < 0 || bits > maxBits) return false;

        suffix = new IpSuffix(address, bits);
        return true;
    }

    /// <summary>True when <paramref name="address"/> ends with this pattern's significant bits.</summary>
    public bool Matches(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var candidate = RuleAddresses.Normalize(address);
        if (candidate.AddressFamily != Address.AddressFamily) return false;

        var left = candidate.GetAddressBytes();
        var right = Address.GetAddressBytes();
        var totalBits = left.Length * 8;
        if (BitLength > totalBits) return false;

        for (var offset = 0; offset < BitLength; offset++)
        {
            var bitIndex = totalBits - 1 - offset;
            var mask = 1 << (7 - (bitIndex & 7));
            if ((left[bitIndex >> 3] & mask) != (right[bitIndex >> 3] & mask)) return false;
        }

        return true;
    }

    /// <inheritdoc />
    public bool Equals(IpSuffix other) => BitLength == other.BitLength && Address.Equals(other.Address);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is IpSuffix other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Address, BitLength);

    /// <inheritdoc />
    public override string ToString() => $"{Address}/{BitLength}";
}

/// <summary>
/// A binary radix (patricia) trie over IPv4 and IPv6 prefixes. Answers "which entry
/// matches this address" in one step per significant bit, using longest-prefix match.
/// Suffix entries live in a second trie keyed on the bit-reversed address, so
/// <c>IP-SUFFIX</c> costs the same as <c>IP-CIDR</c>.
/// </summary>
/// <remarks>Construction is not thread-safe; <see cref="Match"/> is once construction has finished.</remarks>
public sealed class CidrMatcher
{
    private sealed class Node
    {
        public Node? Zero;
        public Node? One;
        public int Index = -1;
    }

    private readonly Node _v4 = new();
    private readonly Node _v6 = new();
    private readonly Node _v4Suffix = new();
    private readonly Node _v6Suffix = new();
    private int _count;

    /// <summary>Number of entries added.</summary>
    public int Count => _count;

    /// <summary>True when no entry has been added.</summary>
    public bool IsEmpty => _count == 0;

    /// <summary>Adds a prefix entry.</summary>
    public void Add(IpPrefix prefix, int index)
    {
        Insert(prefix.IsIPv4 ? _v4 : _v6, prefix.Network.GetAddressBytes(), prefix.PrefixLength, index);
        _count++;
    }

    /// <summary>Adds a prefix entry given its parts.</summary>
    public void Add(IPAddress network, int prefixLength, int index)
        => Add(new IpPrefix(network, prefixLength), index);

    /// <summary>Adds a trailing-bit entry.</summary>
    public void AddSuffix(IpSuffix suffix, int index)
    {
        var reversed = ReverseBits(suffix.Address.GetAddressBytes());
        Insert(suffix.Address.AddressFamily == AddressFamily.InterNetwork ? _v4Suffix : _v6Suffix, reversed, suffix.BitLength, index);
        _count++;
    }

    /// <summary>
    /// Returns the index of the longest matching prefix, or of a matching suffix entry,
    /// or -1 when nothing matches.
    /// </summary>
    public int Match(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        var candidate = RuleAddresses.Normalize(address);
        var bytes = candidate.GetAddressBytes();
        var isV4 = candidate.AddressFamily == AddressFamily.InterNetwork;

        var best = LongestPrefix(isV4 ? _v4 : _v6, bytes);
        if (best >= 0) return best;

        return LongestPrefix(isV4 ? _v4Suffix : _v6Suffix, ReverseBits(bytes));
    }

    private static void Insert(Node root, ReadOnlySpan<byte> bytes, int prefixLength, int index)
    {
        var node = root;
        var bits = Math.Min(prefixLength, bytes.Length * 8);

        for (var i = 0; i < bits; i++)
        {
            if (BitAt(bytes, i) == 0)
            {
                node.Zero ??= new Node();
                node = node.Zero;
            }
            else
            {
                node.One ??= new Node();
                node = node.One;
            }
        }

        if (node.Index < 0 || index < node.Index) node.Index = index;
    }

    private static int LongestPrefix(Node root, ReadOnlySpan<byte> bytes)
    {
        var node = root;
        var best = node.Index;
        var bits = bytes.Length * 8;

        for (var i = 0; i < bits; i++)
        {
            node = BitAt(bytes, i) == 0 ? node.Zero : node.One;
            if (node is null) break;
            if (node.Index >= 0) best = node.Index;
        }

        return best;
    }

    private static int BitAt(ReadOnlySpan<byte> bytes, int index)
        => (bytes[index >> 3] >> (7 - (index & 7))) & 1;

    private static byte[] ReverseBits(ReadOnlySpan<byte> source)
    {
        var target = new byte[source.Length];
        var bits = source.Length * 8;

        for (var i = 0; i < bits; i++)
        {
            if (BitAt(source, i) != 0) target[i >> 3] |= (byte)(1 << (7 - (i & 7)));
        }

        return target;
    }
}
