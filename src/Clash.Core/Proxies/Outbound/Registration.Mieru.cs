using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for the <c>mieru</c> outbound adapter. The module initializer
/// runs when this assembly is loaded, so <see cref="AdapterRegistry"/> never has to
/// reference the protocol type and this protocol can be added without touching the
/// other protocol groups' registration files.
/// </summary>
internal static class MieruOutboundRegistration
{
    /// <summary>Registers the mieru factory exactly once, at assembly load.</summary>
#pragma warning disable CA2255 // a library module initializer is this assembly's registration mechanism
    [ModuleInitializer]
    internal static void Register() => AdapterRegistry.Register(new MieruAdapterFactory());
#pragma warning restore CA2255
}
