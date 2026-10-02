using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for the VMess outbound adapter. Kept in its own file, and
/// deliberately registering nothing but its own factory, so the protocol groups
/// stay independent of one another: <see cref="AdapterRegistry"/> never has to
/// reference a protocol type and the core keeps compiling before any protocol
/// exists.
/// </summary>
internal static class VmessOutboundRegistration
{
    /// <summary>Registers the <c>vmess</c> factory exactly once, at assembly load.</summary>
    [ModuleInitializer]
    internal static void Register() => AdapterRegistry.Register(new VmessAdapterFactory());
}
