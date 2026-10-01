using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Transport;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Adapter;

/// <summary>Everything an adapter factory needs while building one outbound.</summary>
public sealed class AdapterBuildContext
{
    public required ClashConfig Config { get; init; }

    public required ITunnelAccessor Tunnel { get; init; }

    public required ITransportComposer Transports { get; init; }

    public required ILoggerFactory LoggerFactory { get; init; }

    /// <summary>Raised by adapters when a connection attempt fails, for <c>/logs</c>.</summary>
    public Action<string, string>? Log { get; init; }
}

/// <summary>
/// Builds one outbound protocol from its configuration entry. Implementations
/// live beside the protocol they build and register themselves with
/// <see cref="AdapterRegistry"/>.
/// </summary>
public interface IAdapterFactory
{
    /// <summary>The lower-case <c>type</c> value from the configuration, e.g. <c>ss</c>, <c>vmess</c>.</summary>
    string Type { get; }

    /// <summary>Every alias this factory also answers to, e.g. <c>shadowsocks</c> for <c>ss</c>.</summary>
    IReadOnlyList<string> Aliases { get; }

    /// <summary>Constructs the adapter, or throws <see cref="ProxyCreationException"/>.</summary>
    IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context);
}

/// <summary>
/// Maps a configuration <c>type</c> to the factory that builds it. Protocols are
/// discovered at runtime so the core has no compile-time dependency on them.
/// </summary>
public static class AdapterRegistry
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, IAdapterFactory> Factories =
        new(StringComparer.OrdinalIgnoreCase);

    private static int _initialised;

    /// <summary>Registers a factory under its type and every alias.</summary>
    public static void Register(IAdapterFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        Factories[factory.Type] = factory;
        foreach (var alias in factory.Aliases) Factories[alias] = factory;
    }

    /// <summary>Registers every built-in protocol factory exactly once.</summary>
    public static void EnsureInitialised()
    {
        if (Interlocked.Exchange(ref _initialised, 1) == 0) BuiltinAdapterRegistration.Register();
    }

    public static bool IsKnown(string type)
    {
        EnsureInitialised();
        return Factories.ContainsKey(type);
    }

    public static IReadOnlyCollection<string> KnownTypes
    {
        get
        {
            EnsureInitialised();
            return Factories.Keys.ToList();
        }
    }

    /// <summary>Builds the adapter named by the entry.</summary>
    public static IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);
        EnsureInitialised();

        if (!Factories.TryGetValue(entry.Type, out var factory))
        {
            throw new ProxyCreationException(
                $"unsupported proxy type [{entry.Type}] for proxy [{entry.Name}] (known: {string.Join(", ", KnownTypes)})");
        }

        try
        {
            var proxy = factory.Create(entry, context)
                ?? throw new ProxyCreationException($"factory for [{entry.Type}] returned null");
            return proxy;
        }
        catch (ProxyCreationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ProxyCreationException($"failed to build proxy [{entry.Name}] of type [{entry.Type}]: {ex.Message}");
        }
    }
}

/// <summary>
/// Registers the built-in adapters and then hands off to the outbound protocol
/// registration, which lives beside the protocols themselves so the core has no
/// compile-time dependency on them.
/// </summary>
internal static class BuiltinAdapterRegistration
{
    internal static void Register()
    {
        AdapterRegistry.Register(new DirectAdapterFactory());
        AdapterRegistry.Register(new RejectAdapterFactory());
        AdapterRegistry.Register(new DnsAdapterFactory());

        OutboundAdapterRegistration.Register();
    }
}
