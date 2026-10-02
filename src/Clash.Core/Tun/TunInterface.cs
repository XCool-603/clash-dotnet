using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Clash.Core.Common;

namespace Clash.Core.Tun;

/// <summary>
/// Route and interface configuration for the TUN adapter.
/// <para>
/// The driver hands back a bare layer-3 interface with no address and no routes,
/// so it carries nothing until the host is told to send traffic to it. This type
/// owns that configuration and, just as importantly, its removal.
/// </para>
/// <para>
/// It drives <c>netsh</c> rather than the <c>iphlpapi</c> forwarding-table API:
/// the rows involved (<c>MIB_IPFORWARD_ROW2</c>, <c>MIB_UNICASTIPADDRESS_ROW</c>)
/// are large blittable structures whose layout is easy to get subtly wrong, and a
/// wrong routing table is exactly the failure that takes a machine's networking
/// down. Every change uses <c>store=active</c>, so nothing is written to
/// persistent storage and a crash cannot leave a route behind across a reboot.
/// </para>
/// </summary>
internal static class TunInterface
{
    /// <summary>
    /// The two halves of the IPv4 default route. Adding 0.0.0.0/1 and 128.0.0.0/1
    /// is the standard way to take over the default route without deleting it:
    /// both are more specific than 0.0.0.0/0, so they win, and removing them
    /// restores the previous behaviour exactly.
    /// </summary>
    private static readonly string[] DefaultRouteHalves = ["0.0.0.0/1", "128.0.0.0/1"];

    /// <summary>The IPv4 address given to the adapter. /32 keeps it from claiming a subnet.</summary>
    public const string AdapterAddress = "198.19.255.1";

    /// <summary>Assigns the adapter's own address, without which it cannot carry traffic.</summary>
    public static void SetAddress(string adapterName, string address = AdapterAddress)
        => Run($"interface ipv4 set address name=\"{adapterName}\" static {address} 255.255.255.255");

    /// <summary>
    /// Drops the adapter's address. Best-effort, because the usual case is an
    /// adapter that has already been removed with its address.
    /// </summary>
    public static bool TryClearAddress(string adapterName)
        => TryRun($"interface ipv4 delete address name=\"{adapterName}\" addr={AdapterAddress} store=active");

    /// <summary>Points the IPv4 default route at the adapter.</summary>
    public static void AddDefaultRoutes(string adapterName, int metric)
    {
        foreach (var prefix in DefaultRouteHalves)
        {
            Run($"interface ipv4 add route prefix={prefix} interface=\"{adapterName}\" metric={metric} store=active");
        }
    }

    /// <summary>Removes what <see cref="AddDefaultRoutes"/> added. Safe to call when nothing was added.</summary>
    public static void RemoveDefaultRoutes(string adapterName)
    {
        foreach (var prefix in DefaultRouteHalves)
        {
            // A missing route is the normal case on a second cleanup, so the exit
            // code is deliberately ignored.
            TryRun($"interface ipv4 delete route prefix={prefix} interface=\"{adapterName}\" store=active");
        }
    }

    /// <summary>Sends one prefix to the adapter, e.g. the fake-IP range.</summary>
    public static void AddRouteToTun(string adapterName, string prefix, int metric = 1)
        => Run($"interface ipv4 add route prefix={prefix} interface=\"{adapterName}\" metric={metric} store=active");

    /// <summary>Removes a prefix added by <see cref="AddRouteToTun"/>.</summary>
    public static void RemoveRouteFromTun(string adapterName, string prefix)
        => TryRun($"interface ipv4 delete route prefix={prefix} interface=\"{adapterName}\" store=active");

    /// <summary>
    /// Keeps one destination out of the tunnel by pinning it to the physical
    /// default route.
    /// <para>
    /// This is what stops the proxy server's own address from being routed into
    /// the interface that carries its traffic. Without it the core dials itself:
    /// the route table sends the outbound connection back into the tunnel, the
    /// tunnel tries to proxy it, and the connection never establishes. The
    /// exclusion has to name the physical interface explicitly, because the
    /// 0.0.0.0/1 takeover has already claimed the default route.
    /// </para>
    /// </summary>
    /// <returns>False when no physical default route could be identified.</returns>
    public static bool AddExclusion(string address)
    {
        var route = FindPhysicalDefaultRoute();
        if (route is null) return false;

        var (interfaceName, gateway) = route.Value;
        return TryRun(
            $"interface ipv4 add route prefix={address}/32 interface=\"{interfaceName}\" nexthop={gateway} metric=1 store=active");
    }

    /// <summary>Removes an exclusion added by <see cref="AddExclusion"/>.</summary>
    public static bool RemoveExclusion(string address) => TryRun($"interface ipv4 delete route prefix={address}/32 store=active");

    /// <summary>
    /// The interface and next hop the machine used before the tunnel took the
    /// default route, identified by having a gateway and not being the tunnel.
    /// </summary>
    private static (string InterfaceName, string Gateway)? FindPhysicalDefaultRoute()
    {
        foreach (var candidate in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (candidate.OperationalStatus != OperationalStatus.Up) continue;

            // The TUN adapter has no gateway, but excluding it explicitly keeps the
            // lookup honest if that ever changes.
            if (candidate.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

            var properties = candidate.GetIPProperties();
            var gateway = properties.GatewayAddresses
                .FirstOrDefault(entry => entry.Address.AddressFamily == AddressFamily.InterNetwork);

            if (gateway is not null) return (candidate.Name, gateway.Address.ToString());
        }

        return null;
    }

    /// <summary>The adapter's interface index, as Windows reports it.</summary>
    public static int? FindInterfaceIndex(string adapterName)
        => NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, adapterName, StringComparison.OrdinalIgnoreCase))
            ?.GetIPProperties().GetIPv4Properties()?.Index;

    private static void Run(string arguments)
    {
        if (!TryRun(arguments)) throw new ClashException($"netsh {arguments} failed");
    }

    private static bool TryRun(string arguments)
    {
        using var process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });

        if (process is null) return false;
        process.WaitForExit(15_000);
        return process.HasExited && process.ExitCode == 0;
    }
}
