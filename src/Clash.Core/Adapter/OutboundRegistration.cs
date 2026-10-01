namespace Clash.Core.Adapter;

/// <summary>
/// Registration hook for the outbound protocol adapters (Shadowsocks, VMess,
/// VLESS, Trojan, Snell, WireGuard, Hysteria, TUIC, SSH).
/// <para>
/// Protocol implementations live under <c>Proxies/Outbound/</c> and register
/// themselves from a <see cref="System.Runtime.CompilerServices.ModuleInitializerAttribute"/>
/// so that <see cref="AdapterRegistry"/> never references them directly and the
/// core keeps compiling before any protocol exists. This method exists only as a
/// deterministic ordering point: <see cref="AdapterRegistry.EnsureInitialised"/>
/// calls it after the built-ins are registered.
/// </para>
/// </summary>
internal static class OutboundAdapterRegistration
{
    internal static void Register()
    {
        // Protocol adapters self-register through module initializers; nothing to do here.
    }
}
