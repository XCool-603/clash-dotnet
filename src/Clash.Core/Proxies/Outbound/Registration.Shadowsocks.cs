using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for protocol group A: Shadowsocks, ShadowsocksR, Trojan,
/// HTTP, SOCKS5, Snell and SSH. The module initializer runs when this assembly is
/// loaded, so <see cref="AdapterRegistry"/> never has to reference a protocol
/// type and the core keeps compiling before any protocol exists.
/// <para>
/// Each protocol group owns its own registration entry point; this file
/// deliberately registers only group A so another group can add its factories
/// without touching it.
/// </para>
/// </summary>
internal static class ShadowsocksOutboundRegistration
{
    /// <summary>Registers the group A factories exactly once, at assembly load.</summary>
    [ModuleInitializer]
    internal static void Register()
    {
        AdapterRegistry.Register(new ShadowsocksAdapterFactory());
        AdapterRegistry.Register(new ShadowsocksRAdapterFactory());
        AdapterRegistry.Register(new TrojanAdapterFactory());
        AdapterRegistry.Register(new HttpAdapterFactory());
        AdapterRegistry.Register(new Socks5AdapterFactory());
        AdapterRegistry.Register(new SnellAdapterFactory());
        AdapterRegistry.Register(new SshAdapterFactory());
    }
}
