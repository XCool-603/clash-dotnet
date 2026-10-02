using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using Clash.Core.Common;

namespace Clash.Core.Dns;

/// <summary>
/// Allocates and remembers fake addresses for the <c>fake-ip</c> enhanced mode.
/// </summary>
/// <remarks>
/// <para>
/// Two pools exist, one per family, derived from <c>fake-ip-range</c> and
/// <c>fake-ip-range-v6</c>. Allocation walks the pool from its first usable
/// address, wrapping around, and skips addresses that are already handed out, so
/// the mapping is stable for a given sequence of requests.
/// </para>
/// <para>
/// The forward map (address → host) and the reverse index (host → address) are
/// both bounded by <c>cache-max-size</c> and evicted in least-recently-used
/// order. Reads are lock-free through <see cref="ConcurrentDictionary{TKey,TValue}"/>;
/// mutations and LRU bookkeeping take a single lock.
/// </para>
/// <para>
/// <see cref="Contains"/> is a pure prefix test against the configured ranges, so
/// an address inside the range that was never allocated is still recognised as
/// fake. That is what the tunnel needs to decide whether a destination has to be
/// translated back to a domain.
/// </para>
/// </remarks>
public sealed class FakeIpPool
{
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<IPAddress, Entry> _byAddress = new();
    private readonly ConcurrentDictionary<string, IPAddress> _byHost = new(StringComparer.OrdinalIgnoreCase);
    private readonly LinkedList<string> _lru = new();

    private readonly UInt128 _v4Network;
    private readonly int _v4Prefix;
    private readonly UInt128 _v4Count;
    private readonly bool _v4Enabled;

    private readonly UInt128 _v6Network;
    private readonly int _v6Prefix;
    private readonly UInt128 _v6Count;
    private readonly bool _v6Enabled;

    private ulong _v4Offset;
    private UInt128 _v6Offset;

    /// <summary>Creates a pool from the configured CIDR ranges.</summary>
    /// <param name="fakeIpRangeV4">IPv4 range such as <c>198.18.0.1/16</c>; empty disables the IPv4 pool.</param>
    /// <param name="fakeIpRangeV6">IPv6 range such as <c>fdfe:dcba:9876::1/96</c>; empty disables the IPv6 pool.</param>
    /// <param name="cacheMaxSize">Upper bound on remembered mappings; 8192 when non-positive.</param>
    public FakeIpPool(string? fakeIpRangeV4, string? fakeIpRangeV6, int cacheMaxSize)
    {
        Capacity = cacheMaxSize > 0 ? cacheMaxSize : 8192;

        _v4Enabled = TryParseRange(fakeIpRangeV4, AddressFamily.InterNetwork, out _v4Network, out _v4Prefix);
        _v6Enabled = TryParseRange(fakeIpRangeV6, AddressFamily.InterNetworkV6, out _v6Network, out _v6Prefix);

        _v4Count = _v4Enabled ? UsableCount(_v4Prefix, 32) : UInt128.Zero;
        _v6Count = _v6Enabled ? UsableCount(_v6Prefix, 128) : UInt128.Zero;
    }

    /// <summary>Effective bound on remembered mappings.</summary>
    public int Capacity { get; }

    /// <summary>Number of live mappings.</summary>
    public int Count => _byAddress.Count;

    /// <summary>True when an IPv4 pool was configured.</summary>
    public bool HasIPv4 => _v4Enabled;

    /// <summary>True when an IPv6 pool was configured.</summary>
    public bool HasIPv6 => _v6Enabled;

    /// <summary>Base address of the IPv4 pool, or null when it is disabled.</summary>
    public IPAddress? IPv4Range => _v4Enabled ? FromUInt128(_v4Network, AddressFamily.InterNetwork) : null;

    /// <summary>Base address of the IPv6 pool, or null when it is disabled.</summary>
    public IPAddress? IPv6Range => _v6Enabled ? FromUInt128(_v6Network, AddressFamily.InterNetworkV6) : null;

    /// <summary>
    /// Returns the address standing for <paramref name="host"/>, allocating one
    /// when the host is new. <paramref name="preferred"/> is honoured when it
    /// lies inside the pool for its family and is still free; <paramref name="ipv6"/>
    /// selects the IPv6 pool when there is no usable hint.
    /// </summary>
    public IPAddress? Allocate(string host, IPAddress? preferred = null, bool ipv6 = false)
    {
        var key = Normalize(host);
        if (key.Length == 0) return null;

        var family = ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        if (preferred is not null && NormalizeAddress(preferred).AddressFamily == AddressFamily.InterNetworkV6)
        {
            family = AddressFamily.InterNetworkV6;
        }

        lock (_gate)
        {
            if (_byHost.TryGetValue(key, out var existing))
            {
                Touch(key);
                return existing;
            }

            var address = family == AddressFamily.InterNetworkV6 ? TakeV6(preferred) : TakeV4(preferred);
            if (address is null) return null;

            var node = _lru.AddLast(key);
            _byAddress[address] = new Entry(key, node);
            _byHost[key] = address;

            EvictOverflow();
            return address;
        }
    }

    /// <summary>Address previously allocated for <paramref name="host"/>, or null.</summary>
    public IPAddress? LookupHost(string host)
    {
        var key = Normalize(host);
        if (key.Length == 0) return null;

        if (!_byHost.TryGetValue(key, out var address)) return null;
        Touch(key);
        return address;
    }

    /// <summary>Host a fake address stands for, or null when it was never handed out.</summary>
    public string? Lookup(IPAddress? address)
    {
        if (address is null) return null;
        var normalized = NormalizeAddress(address);
        if (!_byAddress.TryGetValue(normalized, out var entry)) return null;
        Touch(entry.Host);
        return entry.Host;
    }

    /// <summary>
    /// True when <paramref name="address"/> falls inside either configured range,
    /// whether or not it was ever allocated.
    /// </summary>
    public bool Contains(IPAddress? address)
    {
        if (address is null) return false;
        var normalized = NormalizeAddress(address);

        return normalized.AddressFamily switch
        {
            AddressFamily.InterNetwork => _v4Enabled && InRange(ToUInt128(normalized), _v4Network, _v4Prefix, 32),
            AddressFamily.InterNetworkV6 => _v6Enabled && InRange(ToUInt128(normalized), _v6Network, _v6Prefix, 128),
            _ => false,
        };
    }

    /// <summary>Drops every mapping and restarts both allocation cursors.</summary>
    public void Flush()
    {
        lock (_gate)
        {
            _byAddress.Clear();
            _byHost.Clear();
            _lru.Clear();
            _v4Offset = 0;
            _v6Offset = UInt128.Zero;
        }
    }

    // ── Internals ───────────────────────────────────────────────────────────

    private IPAddress? TakeV4(IPAddress? preferred)
    {
        if (preferred is not null)
        {
            var normalized = NormalizeAddress(preferred);
            if (normalized.AddressFamily == AddressFamily.InterNetwork
                && Contains(normalized)
                && !_byAddress.ContainsKey(normalized))
            {
                return normalized;
            }
        }

        var attempts = _v4Count < 4096 ? (int)_v4Count : 4096;
        for (var i = 0; i < attempts; i++)
        {
            var offset = (UInt128)(_v4Offset++ % (ulong)_v4Count);
            var candidate = FromUInt128(_v4Network + UInt128.One + offset, AddressFamily.InterNetwork);
            if (!_byAddress.ContainsKey(candidate)) return candidate;
        }

        return null;
    }

    private IPAddress? TakeV6(IPAddress? preferred)
    {
        if (preferred is not null)
        {
            var normalized = NormalizeAddress(preferred);
            if (normalized.AddressFamily == AddressFamily.InterNetworkV6
                && Contains(normalized)
                && !_byAddress.ContainsKey(normalized))
            {
                return normalized;
            }
        }

        var attempts = _v6Count < 4096 ? _v6Count : (UInt128)4096;
        for (UInt128 i = UInt128.Zero; i < attempts; i++)
        {
            var offset = _v6Offset++ % _v6Count;
            var candidate = FromUInt128(_v6Network + UInt128.One + offset, AddressFamily.InterNetworkV6);
            if (!_byAddress.ContainsKey(candidate)) return candidate;
        }

        return null;
    }

    private void Touch(string host)
    {
        lock (_gate)
        {
            if (!_byHost.TryGetValue(host, out var address)) return;
            if (!_byAddress.TryGetValue(address, out var entry)) return;
            if (entry.Node.List is null) return;
            _lru.Remove(entry.Node);
            _lru.AddLast(entry.Node);
        }
    }

    private void EvictOverflow()
    {
        while (_byAddress.Count > Capacity && _lru.First is { } oldest)
        {
            _lru.RemoveFirst();
            if (_byHost.TryRemove(oldest.Value, out var address)) _byAddress.TryRemove(address, out _);
        }
    }

    private static string Normalize(string? host)
        => host is null ? string.Empty : host.Trim().TrimEnd('.').ToLowerInvariant();

    private static IPAddress NormalizeAddress(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool TryParseRange(string? cidr, AddressFamily family, out UInt128 network, out int prefix)
    {
        var bits = family == AddressFamily.InterNetwork ? 32 : 128;
        network = UInt128.Zero;
        prefix = bits;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var text = cidr.Trim();
        var slash = text.IndexOf('/');
        var addressPart = slash >= 0 ? text[..slash] : text;
        var prefixPart = slash >= 0 ? text[(slash + 1)..] : null;

        if (!IPAddress.TryParse(addressPart, out var address)) return false;
        if (NormalizeAddress(address).AddressFamily != family) return false;

        if (prefixPart is not null)
        {
            if (!int.TryParse(prefixPart, out prefix)) return false;
            if (prefix < 0 || prefix > bits) return false;
        }

        network = ToUInt128(address) & MaskFor(prefix, bits);
        return true;
    }

    private static UInt128 MaskFor(int prefix, int bits)
    {
        if (prefix <= 0) return UInt128.Zero;
        if (prefix >= bits) return UInt128.MaxValue;
        var host = (UInt128.One << (bits - prefix)) - UInt128.One;
        return UInt128.MaxValue & ~host;
    }

    private static bool InRange(UInt128 value, UInt128 network, int prefix, int bits)
    {
        if (prefix <= 0) return true;
        if (prefix > bits) prefix = bits;
        var shift = bits - prefix;
        return (value >> shift) == (network >> shift);
    }

    private static UInt128 UsableCount(int prefix, int bits)
    {
        if (prefix >= bits) return UInt128.One;
        var total = UInt128.One << (bits - prefix);
        return total <= 2 ? UInt128.One : total - 2;
    }

    private static UInt128 ToUInt128(IPAddress address)
    {
        UInt128 value = UInt128.Zero;
        foreach (var b in address.GetAddressBytes()) value = (value << 8) | b;
        return value;
    }

    private static IPAddress FromUInt128(UInt128 value, AddressFamily family)
    {
        var size = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = new byte[size];
        for (var i = size - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return new IPAddress(bytes);
    }

    private sealed class Entry(string host, LinkedListNode<string> node)
    {
        public string Host { get; } = host;

        public LinkedListNode<string> Node { get; } = node;
    }
}
