using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for the WireGuard outbound. It lives in its own file, with its
/// own module initializer, so the group A/B/C registration files stay untouched and
/// a protocol can be added or removed without editing a shared list.
/// </summary>
internal static class WireGuardOutboundRegistration
{
    /// <summary>Registers the <c>wireguard</c> factory exactly once, at assembly load.</summary>
    // CA2255 warns that ModuleInitializer is meant for applications. It is the
    // pattern this repository's protocol registration already uses (see the group A,
    // B and C registration files), and the warning is suppressed here only so this
    // protocol adds no new warning to the build.
#pragma warning disable CA2255
    [ModuleInitializer]
    internal static void Register() => AdapterRegistry.Register(new WireGuardAdapterFactory());
#pragma warning restore CA2255
}
