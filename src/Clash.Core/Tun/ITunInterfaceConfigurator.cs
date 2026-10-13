namespace Clash.Core.Tun;

/// <summary>
/// The interface and routing changes a TUN session needs, as one injectable
/// seam.
/// <para>
/// The driver hands back a bare layer-3 adapter with no address and no routes,
/// so a session carries nothing until the host is told to send traffic to it.
/// In production those changes are made by
/// <see cref="NetshTunInterfaceConfigurator"/>; the seam exists for the same
/// reason <see cref="TunListener"/>'s device factory does — an injected packet
/// device has no interface on this machine for <c>netsh</c> to address, so
/// running the real configuration against it fails for a reason that has
/// nothing to do with what the test is asking.
/// </para>
/// <para>
/// The operations are deliberately the ones <see cref="TunInterface"/> already
/// exposes, rather than a single "configure" call: the listener keeps the policy
/// (which prefixes are excluded, which warnings are worth logging) and this type
/// only carries out the changes, so a test can observe exactly what the listener
/// asked the machine to do.
/// </para>
/// </summary>
internal interface ITunInterfaceConfigurator
{
    /// <summary>Assigns the adapter's own address, without which it cannot carry traffic.</summary>
    /// <param name="adapterName">The adapter's name, as Windows reports it.</param>
    /// <param name="address">The IPv4 address to assign.</param>
    void SetAddress(string adapterName, string address);

    /// <summary>Points the IPv4 default route at the adapter.</summary>
    /// <param name="adapterName">The adapter's name.</param>
    /// <param name="metric">The route metric; lower wins.</param>
    void AddDefaultRoutes(string adapterName, int metric);

    /// <summary>Keeps one destination out of the tunnel by pinning it to the physical route.</summary>
    /// <param name="address">The bare IPv4 address to exclude.</param>
    /// <returns>False when no physical default route could be identified.</returns>
    bool AddExclusion(string address);

    /// <summary>Removes what <see cref="AddDefaultRoutes"/> added. Safe to call when nothing was added.</summary>
    /// <param name="adapterName">The adapter's name.</param>
    void RemoveDefaultRoutes(string adapterName);

    /// <summary>Removes an exclusion added by <see cref="AddExclusion"/>.</summary>
    /// <param name="address">The bare IPv4 address to stop excluding.</param>
    /// <returns>False when the route could not be removed.</returns>
    bool RemoveExclusion(string address);

    /// <summary>Drops the adapter's address. Best-effort, because the adapter is usually gone already.</summary>
    /// <param name="adapterName">The adapter's name.</param>
    /// <returns>False when there was nothing to clear or the change was refused.</returns>
    bool TryClearAddress(string adapterName);
}

/// <summary>
/// The production configurator: every call goes to <c>netsh</c> through
/// <see cref="TunInterface"/>, which is the only implementation here that
/// touches the machine's real interfaces and routing table.
/// </summary>
internal sealed class NetshTunInterfaceConfigurator : ITunInterfaceConfigurator
{
    /// <summary>The single instance the listeners share. It holds no state.</summary>
    public static readonly NetshTunInterfaceConfigurator Instance = new();

    /// <inheritdoc />
    public void SetAddress(string adapterName, string address) => TunInterface.SetAddress(adapterName, address);

    /// <inheritdoc />
    public void AddDefaultRoutes(string adapterName, int metric) => TunInterface.AddDefaultRoutes(adapterName, metric);

    /// <inheritdoc />
    public bool AddExclusion(string address) => TunInterface.AddExclusion(address);

    /// <inheritdoc />
    public void RemoveDefaultRoutes(string adapterName) => TunInterface.RemoveDefaultRoutes(adapterName);

    /// <inheritdoc />
    public bool RemoveExclusion(string address) => TunInterface.RemoveExclusion(address);

    /// <inheritdoc />
    public bool TryClearAddress(string adapterName) => TunInterface.TryClearAddress(adapterName);
}
