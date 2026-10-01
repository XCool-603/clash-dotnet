using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Clash.Core.Common;

namespace Clash.Core.Rules;

/// <summary>
/// Per-flow cache of the addresses produced by the engine's DNS resolution.
/// <para>
/// <see cref="IRule.Match"/> only ever sees a <see cref="Metadata"/>, whose
/// <see cref="Metadata.DestinationAddress"/> is contractually immutable, so the
/// resolved address set is attached out-of-band and keyed by the flow object.
/// The table holds the flow weakly, so nothing leaks when a connection ends.
/// </para>
/// </summary>
internal static class ResolvedAddresses
{
    private static readonly ConditionalWeakTable<Metadata, IPAddress[]> Table = new();

    /// <summary>Records the addresses resolved for a flow, replacing any previous set.</summary>
    public static void Set(Metadata metadata, IPAddress[] addresses) => Table.AddOrUpdate(metadata, addresses);

    /// <summary>Reads the addresses previously recorded for a flow.</summary>
    public static bool TryGet(Metadata metadata, out IPAddress[] addresses)
        => Table.TryGetValue(metadata, out addresses!);
}

/// <summary>Address plumbing shared by every IP-aware rule.</summary>
internal static class RuleAddresses
{
    private static readonly IPAddress[] None = [];

    /// <summary>
    /// The destination addresses a rule should test: the resolved set when the engine
    /// produced one, otherwise the literal destination address when it is an IP.
    /// </summary>
    public static IReadOnlyList<IPAddress> Destination(Metadata metadata)
    {
        if (ResolvedAddresses.TryGet(metadata, out var resolved) && resolved.Length > 0) return resolved;
        if (IPAddress.TryParse(metadata.DestinationAddress, out var literal)) return [literal];
        return None;
    }

    /// <summary>The client address as an <see cref="IPAddress"/>, or null when unknown.</summary>
    public static IPAddress? Source(Metadata metadata)
    {
        var text = metadata.SourceAddress;
        if (string.IsNullOrEmpty(text)) return null;
        return IPAddress.TryParse(text, out var address) ? address : null;
    }

    /// <summary>Normalises an address so IPv4-mapped IPv6 forms compare as IPv4.</summary>
    public static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>
    /// True for RFC1918 / loopback / link-local / CGNAT / ULA addresses. Backs the
    /// <c>GEOIP,LAN</c> and <c>GEOIP,PRIVATE</c> pseudo countries, which need no database.
    /// </summary>
    public static bool IsPrivate(IPAddress address)
    {
        var ip = Normalize(address);
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] == 0
                || bytes[0] == 10
                || bytes[0] == 127
                || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
                || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168);
        }

        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6Teredo) return true;
        var v6 = ip.GetAddressBytes();
        return (v6[0] & 0xFE) == 0xFC; // fc00::/7 unique local
    }
}
