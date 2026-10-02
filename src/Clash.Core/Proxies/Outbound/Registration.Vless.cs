using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for the <c>vless</c> outbound. The module initializer runs
/// when this assembly is loaded, so <see cref="AdapterRegistry"/> never has to
/// reference the protocol type and the core keeps compiling before the protocol
/// exists.
/// <para>
/// This mirrors <c>Registration.Shadowsocks.cs</c> rather than editing it: each
/// protocol group owns its own registration entry point, so groups can be added
/// without touching each other.
/// </para>
/// </summary>
internal static class VlessOutboundRegistration
{
    /// <summary>Registers the VLESS factory exactly once, at assembly load.</summary>
    [ModuleInitializer]
    internal static void Register() => AdapterRegistry.Register(new VlessAdapterFactory());
}
