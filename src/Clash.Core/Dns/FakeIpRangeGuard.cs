using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Dns;

/// <summary>Where a conflict with the configured fake-ip range was observed.</summary>
public enum FakeIpConflictSource
{
    /// <summary>A prefix in the host's IPv4/IPv6 routing table.</summary>
    Route,

    /// <summary>An address assigned to one of the host's network interfaces.</summary>
    InterfaceAddress,
}

/// <summary>One prefix of the local routing table, as read from the host.</summary>
/// <param name="Prefix">Destination prefix in CIDR form, e.g. <c>198.18.0.0/15</c>.</param>
/// <param name="InterfaceName">Interface the prefix is routed through; may be empty.</param>
/// <param name="NextHop">Gateway, or <c>On-link</c>/<c>Connected</c> for a directly attached prefix.</param>
/// <param name="Metric">Route metric; zero when unknown.</param>
public sealed record LocalRouteSnapshot(
    string Prefix,
    string? InterfaceName = null,
    string? NextHop = null,
    int Metric = 0);

/// <summary>One address assigned to a local network interface.</summary>
/// <param name="Address">The address, e.g. <c>198.19.255.1</c>.</param>
/// <param name="InterfaceName">Interface owning the address; may be empty.</param>
/// <param name="PrefixLength">Prefix length when the host reports one; otherwise -1.</param>
public sealed record LocalAddressSnapshot(
    string Address,
    string? InterfaceName = null,
    int PrefixLength = -1);

/// <summary>
/// A prefix or address that already occupies space the fake-ip pool wants to hand out.
/// </summary>
/// <param name="Source">Which part of the host state the conflict came from.</param>
/// <param name="Prefix">The offending prefix or address in CIDR form.</param>
/// <param name="FakeIpRange">The configured range it collides with.</param>
/// <param name="InterfaceName">Interface involved, when the source reported one.</param>
/// <param name="NextHop">Gateway involved, when the source is a route.</param>
/// <param name="Metric">Route metric, when the source is a route.</param>
public sealed record FakeIpRangeConflict(
    FakeIpConflictSource Source,
    string Prefix,
    string FakeIpRange,
    string? InterfaceName = null,
    string? NextHop = null,
    int Metric = 0)
{
    /// <summary>Human-readable, source-attributed description of the conflict.</summary>
    public string Describe()
    {
        var origin = Source switch
        {
            FakeIpConflictSource.Route => NextHop is { Length: > 0 } hop
                ? $"routing table entry {Prefix} (via {hop}, metric {Metric})"
                : $"routing table entry {Prefix}",
            FakeIpConflictSource.InterfaceAddress => $"local interface address {Prefix}",
            _ => Prefix,
        };

        if (InterfaceName is { Length: > 0 } name) origin += $" on interface \"{name}\"";

        return $"{origin} overlaps the configured fake-ip range {FakeIpRange}";
    }
}

/// <summary>
/// Detects at startup that the configured fake-ip range is already occupied by a
/// local route or interface address, and reports the collision with its source.
/// </summary>
/// <remarks>
/// <para>
/// The failure this exists for is silent: when another VPN/TUN client (Clash Verge,
/// for instance) already claims <c>198.18.0.0/15</c>, the default
/// <c>fake-ip-range: 198.18.0.1/16</c> lies inside it, the fake addresses are never
/// actually routed to this core, and every proxied request just times out. Nothing
/// in the log says why.
/// </para>
/// <para>
/// Probing and judging are separate on purpose: <see cref="Probe"/> reads the host,
/// while <see cref="Check"/> is a pure function over injected snapshots and is what
/// the tests drive. <see cref="Check"/> never throws — a malformed range or an
/// unparsable prefix simply produces no conflict.
/// </para>
/// <para>
/// This type only ever warns. It never blocks startup, never edits the routing
/// table, and never influences fake-ip allocation.
/// </para>
/// </remarks>
public static class FakeIpRangeGuard
{
    private const int ProbeTimeoutMs = 10_000;

    /// <summary>
    /// The address <c>TunInterface</c> gives this core's own Wintun adapter. It is
    /// outside the default fake-ip range on purpose, and it is how the probe
    /// recognises our own routes and addresses so they are not reported as
    /// conflicts with ourselves.
    /// </summary>
    private const string OwnAdapterAddress = "198.19.255.1";

    /// <summary>The netsh commands whose output is parsed into a route snapshot.</summary>
    private static readonly string[] RouteCommands =
    [
        "interface ipv4 show route",
        "interface ipv6 show route",
    ];

    /// <summary>
    /// Reports every injected route prefix and interface address that overlaps the
    /// configured fake-ip ranges. Pure: touches nothing outside its arguments.
    /// </summary>
    /// <param name="fakeIpRangeV4">IPv4 fake-ip range such as <c>198.18.0.1/16</c>; blank disables the check.</param>
    /// <param name="fakeIpRangeV6">IPv6 fake-ip range such as <c>fdfe:dcba:9876::1/96</c>; blank disables the check.</param>
    /// <param name="routes">Local routing-table snapshot to test; may be null.</param>
    /// <param name="addresses">Local interface-address snapshot to test; may be null.</param>
    /// <param name="ownInterfaces">
    /// Names of interfaces that belong to this core (its own TUN adapter). Routes and
    /// addresses there are the tunnel working as designed, not a conflict, so they
    /// are skipped. May be null.
    /// </param>
    public static IReadOnlyList<FakeIpRangeConflict> Check(
        string? fakeIpRangeV4,
        string? fakeIpRangeV6,
        IEnumerable<LocalRouteSnapshot>? routes,
        IEnumerable<LocalAddressSnapshot>? addresses,
        IEnumerable<string>? ownInterfaces = null)
    {
        var configured = new List<(string Text, UInt128 Network, int Prefix, int Bits)>();
        AddConfigured(configured, fakeIpRangeV4, AddressFamily.InterNetwork);
        AddConfigured(configured, fakeIpRangeV6, AddressFamily.InterNetworkV6);

        var conflicts = new List<FakeIpRangeConflict>();
        if (configured.Count == 0) return conflicts;

        var own = BuildOwnInterfaceSet(ownInterfaces, addresses);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var route in routes ?? [])
        {
            if (route is null || string.IsNullOrWhiteSpace(route.Prefix)) continue;
            if (IsOwnInterface(own, route.InterfaceName)) continue;
            if (!TryParseRange(route.Prefix, out var family, out var network, out var prefix)) continue;

            // A default route covers everything by definition, including the fake-ip
            // range, so treating it as a conflict would warn on every machine. What
            // actually steals the range is a more specific prefix or an interface
            // address, which is exactly what the rest of this loop looks for.
            if (prefix == 0) continue;

            var bits = Bits(family);
            foreach (var entry in configured)
            {
                if (entry.Bits != bits) continue;
                if (!Overlaps(network, prefix, entry.Network, entry.Prefix, bits)) continue;

                var text = ToCidr(network, prefix, family);
                if (!seen.Add($"route|{text}|{route.InterfaceName}")) continue;

                conflicts.Add(new FakeIpRangeConflict(
                    FakeIpConflictSource.Route,
                    text,
                    entry.Text,
                    route.InterfaceName,
                    route.NextHop,
                    route.Metric));
            }
        }

        foreach (var address in addresses ?? [])
        {
            if (address is null || string.IsNullOrWhiteSpace(address.Address)) continue;
            if (IsOwnInterface(own, address.InterfaceName)) continue;
            if (!IPAddress.TryParse(address.Address.Trim(), out var parsed)) continue;

            var normalized = Normalize(parsed);
            var family = normalized.AddressFamily;
            if (family != AddressFamily.InterNetwork && family != AddressFamily.InterNetworkV6) continue;

            var value = ToUInt128(normalized);
            var bits = Bits(family);
            var prefix = address.PrefixLength is >= 0 and <= 128 && address.PrefixLength <= bits
                ? address.PrefixLength
                : bits;

            foreach (var entry in configured)
            {
                if (entry.Bits != bits) continue;
                if (!InRange(value, entry.Network, entry.Prefix, bits)) continue;

                var text = ToCidr(value, prefix, family);
                if (!seen.Add($"address|{text}|{address.InterfaceName}")) continue;

                conflicts.Add(new FakeIpRangeConflict(
                    FakeIpConflictSource.InterfaceAddress,
                    text,
                    entry.Text,
                    address.InterfaceName,
                    null,
                    0));
            }
        }

        return conflicts;
    }

    /// <summary>
    /// Runs <see cref="Check"/> against the live host and writes one warning per
    /// conflict. Returns the conflicts it found; an empty list means silence.
    /// Never throws and never prevents startup.
    /// </summary>
    /// <param name="fakeIpRangeV4">Configured IPv4 fake-ip range.</param>
    /// <param name="fakeIpRangeV6">Configured IPv6 fake-ip range.</param>
    /// <param name="logger">Logger to warn on; may be null.</param>
    /// <param name="ownInterfaces">Interfaces owned by this core, which are never a conflict.</param>
    public static IReadOnlyList<FakeIpRangeConflict> LogConflicts(
        string? fakeIpRangeV4,
        string? fakeIpRangeV6,
        ILogger? logger,
        IEnumerable<string>? ownInterfaces = null)
        => LogConflicts(fakeIpRangeV4, fakeIpRangeV6, ProbeRoutes(), ProbeAddresses(), logger, ownInterfaces);

    /// <summary>
    /// <see cref="LogConflicts(string?, string?, ILogger?, IEnumerable{string}?)"/>
    /// against an injected snapshot instead of the live host, so the warning path
    /// itself is testable.
    /// </summary>
    /// <param name="fakeIpRangeV4">Configured IPv4 fake-ip range.</param>
    /// <param name="fakeIpRangeV6">Configured IPv6 fake-ip range.</param>
    /// <param name="routes">Routing-table snapshot to judge.</param>
    /// <param name="addresses">Interface-address snapshot to judge.</param>
    /// <param name="logger">Logger to warn on; may be null.</param>
    /// <param name="ownInterfaces">Interfaces owned by this core, which are never a conflict.</param>
    public static IReadOnlyList<FakeIpRangeConflict> LogConflicts(
        string? fakeIpRangeV4,
        string? fakeIpRangeV6,
        IEnumerable<LocalRouteSnapshot>? routes,
        IEnumerable<LocalAddressSnapshot>? addresses,
        ILogger? logger,
        IEnumerable<string>? ownInterfaces = null)
    {
        var conflicts = Check(fakeIpRangeV4, fakeIpRangeV6, routes, addresses, ownInterfaces);
        if (conflicts.Count == 0) return conflicts;

        foreach (var conflict in conflicts)
        {
            logger?.LogWarning(
                "fake-ip range conflict: {Detail}. Fake addresses in this range will not be routed to this core; "
                + "proxied traffic may time out with no other error. Free the range, or move "
                + "dns.fake-ip-range away from it.",
                conflict.Describe());
        }

        logger?.LogWarning(
            "fake-ip conflict check found {Count} overlapping prefix(es); startup continues",
            conflicts.Count);

        return conflicts;
    }

    /// <summary>
    /// Reads the host's routing table. Best-effort: an unparsable or unavailable
    /// route table yields an empty snapshot rather than an exception.
    /// </summary>
    public static IReadOnlyList<LocalRouteSnapshot> ProbeRoutes()
    {
        var routes = new List<LocalRouteSnapshot>();
        foreach (var command in RouteCommands)
        {
            foreach (var line in RunNetsh(command))
            {
                if (TryParseRouteLine(line, out var route)) routes.Add(route);
            }
        }

        return routes;
    }

    /// <summary>
    /// Reads the host's interface addresses. Best-effort: a failing enumeration
    /// yields an empty snapshot rather than an exception.
    /// </summary>
    public static IReadOnlyList<LocalAddressSnapshot> ProbeAddresses()
    {
        var addresses = new List<LocalAddressSnapshot>();
        try
        {
            foreach (var candidate in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPInterfaceProperties properties;
                try
                {
                    properties = candidate.GetIPProperties();
                }
                catch (NetworkInformationException)
                {
                    continue;
                }

                foreach (var unicast in properties.UnicastAddresses)
                {
                    var address = unicast.Address;
                    if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6LinkLocal) continue;

                    var prefix = -1;
                    if (unicast.PrefixLength > 0) prefix = unicast.PrefixLength;
                    else if (unicast.IPv4Mask is { } mask) prefix = PrefixLengthFromMask(mask);

                    addresses.Add(new LocalAddressSnapshot(address.ToString(), candidate.Name, prefix));
                }
            }
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            // A snapshot that cannot be taken is not a conflict.
        }

        return addresses;
    }

    /// <summary>
    /// Formats <c>netsh interface ipv4|ipv6 show route</c> output into snapshots.
    /// Exposed so the parsing can be pinned by tests without a live route table.
    /// </summary>
    /// <param name="lines">Lines of netsh output.</param>
    public static IReadOnlyList<LocalRouteSnapshot> ParseRouteLines(IEnumerable<string>? lines)
    {
        var routes = new List<LocalRouteSnapshot>();
        foreach (var line in lines ?? [])
        {
            if (TryParseRouteLine(line, out var route)) routes.Add(route);
        }

        return routes;
    }

    // ── Parsing ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Interfaces that belong to this core: the ones the caller named, plus whichever
    /// interface owns the adapter address <c>TunInterface</c> assigns. Traffic there
    /// is the tunnel doing its job, so it is never a conflict.
    /// </summary>
    private static HashSet<string> BuildOwnInterfaceSet(
        IEnumerable<string>? declared,
        IEnumerable<LocalAddressSnapshot>? addresses)
    {
        var own = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (declared is not null)
        {
            foreach (var name in declared)
            {
                if (!string.IsNullOrWhiteSpace(name)) own.Add(name.Trim());
            }
        }

        if (addresses is null) return own;

        foreach (var address in addresses)
        {
            if (address is null || string.IsNullOrWhiteSpace(address.InterfaceName)) continue;
            if (!IPAddress.TryParse(address.Address.Trim(), out var parsed)) continue;
            if (Normalize(parsed).ToString() != OwnAdapterAddress) continue;
            own.Add(address.InterfaceName.Trim());
        }

        return own;
    }

    private static bool IsOwnInterface(HashSet<string> own, string? interfaceName)
        => own.Count > 0 && interfaceName is { Length: > 0 } && own.Contains(interfaceName.Trim());

    private static bool TryParseRouteLine(string? line, out LocalRouteSnapshot route)
    {
        route = null!;
        if (string.IsNullOrWhiteSpace(line)) return false;

        var trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed[0] is '-' or '=' or '#') return false;
        if (trimmed.StartsWith("Publish", StringComparison.OrdinalIgnoreCase)) return false;
        if (trimmed.StartsWith("If ", StringComparison.OrdinalIgnoreCase)) return false;
        if (trimmed.StartsWith("None", StringComparison.OrdinalIgnoreCase)) return false;

        var tokens = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length < 2) return false;

        // The destination prefix is the only token carrying a '/'.
        var prefixIndex = -1;
        for (var i = 0; i < tokens.Length; i++)
        {
            if (tokens[i].Contains('/')) { prefixIndex = i; break; }
        }

        if (prefixIndex < 0) return false;
        if (!TryParseRange(tokens[prefixIndex], out _, out _, out _)) return false;

        // Layout is: Publish, Type, Met, Prefix, Idx, Gateway/Interface Name. The
        // metric therefore sits just before the prefix; a metric-less build is
        // tolerated and reads as 0. The index follows the prefix, and what comes
        // after it is the gateway address or, on a directly attached prefix, the
        // interface name itself — both are useful, so the name is carried through.
        var metric = prefixIndex >= 1 && int.TryParse(tokens[prefixIndex - 1], out var m) ? m : 0;
        var interfaceIndex = prefixIndex + 1 < tokens.Length && int.TryParse(tokens[prefixIndex + 1], out var idx)
            ? idx
            : -1;
        var nextHop = prefixIndex + 2 < tokens.Length ? tokens[prefixIndex + 2] : null;
        var name = interfaceIndex >= 0 ? $"if{interfaceIndex}" : null;
        if (!string.IsNullOrWhiteSpace(nextHop) && !IPAddress.TryParse(nextHop, out _)) name = nextHop;

        route = new LocalRouteSnapshot(tokens[prefixIndex], name, nextHop, metric);

        return true;
    }

    private static void AddConfigured(
        List<(string Text, UInt128 Network, int Prefix, int Bits)> configured,
        string? cidr,
        AddressFamily family)
    {
        if (!TryParseRange(cidr, out var parsedFamily, out var network, out var prefix)) return;
        if (parsedFamily != family) return;

        configured.Add((cidr!.Trim(), network, prefix, Bits(family)));
    }

    /// <summary>
    /// Parses <c>address/prefix</c> into a masked network. A bare address is taken
    /// as a host route. Invalid input returns false rather than throwing.
    /// </summary>
    private static bool TryParseRange(string? cidr, out AddressFamily family, out UInt128 network, out int prefix)
    {
        family = AddressFamily.InterNetwork;
        network = UInt128.Zero;
        prefix = 32;
        if (string.IsNullOrWhiteSpace(cidr)) return false;

        var text = cidr.Trim();
        var slash = text.IndexOf('/');
        var addressPart = slash >= 0 ? text[..slash] : text;
        var prefixPart = slash >= 0 ? text[(slash + 1)..] : null;

        if (!IPAddress.TryParse(addressPart.Trim(), out var address)) return false;

        var normalized = Normalize(address);
        family = normalized.AddressFamily;
        if (family != AddressFamily.InterNetwork && family != AddressFamily.InterNetworkV6) return false;

        var bits = Bits(family);
        if (prefixPart is not null)
        {
            if (!int.TryParse(prefixPart.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix)) return false;
            if (prefix < 0 || prefix > bits) return false;
        }
        else
        {
            prefix = bits;
        }

        network = ToUInt128(normalized) & MaskFor(prefix, bits);
        return true;
    }

    // ── Address arithmetic ──────────────────────────────────────────────────

    private static int Bits(AddressFamily family)
        => family == AddressFamily.InterNetwork ? 32 : 128;

    private static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool Overlaps(UInt128 aNetwork, int aPrefix, UInt128 bNetwork, int bPrefix, int bits)
    {
        var prefix = Math.Min(aPrefix, bPrefix);
        return InRange(aNetwork, bNetwork, prefix, bits);
    }

    private static bool InRange(UInt128 value, UInt128 network, int prefix, int bits)
    {
        if (prefix <= 0) return true;
        if (prefix > bits) prefix = bits;
        var shift = bits - prefix;
        return (value >> shift) == (network >> shift);
    }

    private static UInt128 MaskFor(int prefix, int bits)
    {
        if (prefix <= 0) return UInt128.Zero;
        if (prefix >= bits) return UInt128.MaxValue;
        var host = (UInt128.One << (bits - prefix)) - UInt128.One;
        return UInt128.MaxValue & ~host;
    }

    private static UInt128 ToUInt128(IPAddress address)
    {
        UInt128 value = UInt128.Zero;
        foreach (var b in address.GetAddressBytes()) value = (value << 8) | b;
        return value;
    }

    private static string ToCidr(UInt128 value, int prefix, AddressFamily family)
    {
        var size = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = new byte[size];
        for (var i = size - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return $"{new IPAddress(bytes)}/{prefix}";
    }

    private static int PrefixLengthFromMask(IPAddress mask)
    {
        var bits = 0;
        foreach (var b in mask.GetAddressBytes())
        {
            for (var i = 7; i >= 0; i--)
            {
                if ((b & (1 << i)) == 0) return bits;
                bits++;
            }
        }

        return bits;
    }

    // ── Probing ─────────────────────────────────────────────────────────────

    private static IEnumerable<string> RunNetsh(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            });

            if (process is null) return [];

            var stdout = process.StandardOutput.ReadToEnd();
            // Drained so a chatty stderr cannot fill its pipe and stall the child.
            _ = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(ProbeTimeoutMs))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
                {
                    // The process already exited between the timeout and the kill.
                }

                return [];
            }

            return process.ExitCode == 0 ? stdout.Split('\n') : [];
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or PlatformNotSupportedException)
        {
            return [];
        }
    }
}
