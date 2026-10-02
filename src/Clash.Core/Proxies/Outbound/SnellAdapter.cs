using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The <c>snell</c> factory.
/// <para>
/// <b>Snell is not supported by this build.</b> Snell's wire format is
/// proprietary: the v2/v3 handshake mixes a length-obfuscated record layer with a
/// per-version key schedule that no public specification describes, and the
/// reference implementation's obfuscation modes (<c>http</c>/<c>tls</c>) add a
/// second layer on top of it. Emitting bytes that only look plausible would make
/// every connection fail in a way that is very hard to diagnose, so the factory
/// validates the entry and then refuses.
/// </para>
/// <para>
/// Registering the type (rather than leaving it unknown) is deliberate: the
/// failure is then a precise "not supported by this build" instead of a confusing
/// "unsupported proxy type".
/// </para>
/// </summary>
internal sealed class SnellAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "snell";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        // Validate first so a configuration mistake is reported as a configuration
        // mistake rather than being masked by the unsupported-protocol message.
        _ = OutboundOptions.RequireEndpoint(entry);

        var psk = entry.Map.GetNonEmptyString("psk");
        if (psk is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (snell) requires a non-empty 'psk'");
        }

        var version = entry.Map.GetInt("version", 2);
        if (version is not (2 or 3))
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (snell) has version {version}; only 2 and 3 exist");
        }

        throw new ProxyCreationException(
            $"proxy [{entry.Name}] (snell): Snell is not supported by this build. The protocol's wire format is "
            + "proprietary (a length-obfuscated record layer plus a per-version key schedule that no public "
            + "specification describes), so this build refuses the node instead of emitting bytes that cannot work. "
            + "Remove the node, or route to it through a protocol that is supported.");
    }
}
