using System.Runtime.CompilerServices;
using Clash.Core.Adapter;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// Self-registration for the hysteria2 outbound. Like the other protocol groups this
/// is a <see cref="ModuleInitializer"/> so <see cref="AdapterRegistry"/> never has to
/// name a protocol type and the core still compiles before any protocol exists.
/// <para>
/// The factory answers to <c>hysteria2</c> and its <c>hy2</c> alias. It deliberately
/// does <em>not</em> answer to <c>hysteria</c>: that is hysteria 1.x, a different and
/// incompatible protocol whose share links this parser emits with an
/// <c>auth-str</c>/<c>protocol</c> pair rather than a <c>password</c>.
/// </para>
/// </summary>
internal static class Hysteria2OutboundRegistration
{
    /// <summary>Registers the hysteria2 factory exactly once, at assembly load.</summary>
    [ModuleInitializer]
    internal static void Register() => AdapterRegistry.Register(new Hysteria2AdapterFactory());
}
