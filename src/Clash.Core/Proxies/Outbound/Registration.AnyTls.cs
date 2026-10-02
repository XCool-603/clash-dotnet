using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for the AnyTLS adapter. It lives in its own file, next to the
/// protocol, so the group-A registration that ships with this build
/// (<c>Registration.Shadowsocks.cs</c>) stays untouched: a module initializer runs
/// when this assembly is loaded, which is exactly how every other protocol group
/// joins <see cref="AdapterRegistry"/> without the core referencing it.
/// </summary>
internal static class AnyTlsOutboundRegistration
{
    /// <summary>Registers the <c>anytls</c> factory exactly once, at assembly load.</summary>
    // CA2255 warns that module initializers are for application code; here the
    // attribute is the assembly's established self-registration mechanism (see
    // Registration.Shadowsocks.cs), so the suppression is deliberate rather than
    // an oversight. It is local to this file to keep the build warning-free.
#pragma warning disable CA2255
    [ModuleInitializer]
    internal static void Register() => AdapterRegistry.Register(new AnyTlsAdapterFactory());
#pragma warning restore CA2255
}
