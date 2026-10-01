using System.Collections.Concurrent;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Adapter;

/// <summary>
/// The <c>GLOBAL</c> selector. Its membership is the live proxy registry rather
/// than a fixed list, so provider refreshes show up immediately.
/// </summary>
public sealed class GlobalGroup : SelectorGroup
{
    private readonly Func<IReadOnlyList<IProxy>> _source;

    public GlobalGroup(ITunnelAccessor tunnel, ILogger logger, Func<IReadOnlyList<IProxy>> source)
        : base(
            new ProxyGroupConfig { Name = WellKnown.Global, Type = "select" },
            tunnel,
            logger)
    {
        _source = source;
    }

    public override IReadOnlyList<IProxy> Members => _source();

    public override bool SupportUdp => Members.Any(m => m.SupportUdp);
}

/// <summary>
/// The live adapter registry: concrete outbounds, groups and provider-supplied
/// nodes, plus the <c>GLOBAL</c> selector that spans all of them.
/// </summary>
public sealed class ProxyManager : IProxyManager, IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, IProxy> _proxies = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, List<IProxy>> _providerMembers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _providerOf = new(StringComparer.Ordinal);
    private readonly ILogger<ProxyManager> _logger;
    private readonly GlobalGroup _global;

    public ProxyManager(ITunnelAccessor tunnel, ILoggerFactory loggerFactory)
    {
        _logger = loggerFactory.CreateLogger<ProxyManager>();
        Direct = new DirectAdapter(WellKnown.Direct, tunnel, loggerFactory.CreateLogger<DirectAdapter>());
        Reject = new RejectAdapter(WellKnown.Reject);

        // GLOBAL spans every real outbound. The built-in adapters are excluded so
        // that global mode does not default to DIRECT, which would make the mode
        // appear broken on a fresh config.
        _global = new GlobalGroup(tunnel, loggerFactory.CreateLogger<GlobalGroup>(), () =>
        {
            var candidates = All.Where(p => p.Type is not (ProxyType.Direct or ProxyType.Reject or ProxyType.Dns)).ToList();
            return candidates.Count > 0 ? candidates : All;
        });

        _proxies[Direct.Name] = Direct;
        _proxies[Reject.Name] = Reject;
        _proxies[WellKnown.RejectDrop] = new RejectAdapter(WellKnown.RejectDrop, drop: true);
        _proxies[WellKnown.Global] = _global;
    }

    public IReadOnlyDictionary<string, IProxy> Proxies => _proxies;

    /// <summary>Every adapter except <c>GLOBAL</c>, in insertion order.</summary>
    public IReadOnlyList<IProxy> All => _proxies
        .Where(kv => !string.Equals(kv.Key, WellKnown.Global, StringComparison.Ordinal))
        .Select(kv => kv.Value)
        .ToList();

    public IReadOnlyDictionary<string, IReadOnlyList<IProxy>> ProviderProxies
        => _providerMembers.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<IProxy>)kv.Value.ToArray(), StringComparer.Ordinal);

    public IProxy Global => _global;

    public IProxy Direct { get; }

    public IProxy Reject { get; }

    public event Action? Changed;

    public IProxy? Get(string name) => _proxies.TryGetValue(name, out var proxy) ? proxy : null;

    public IProxy MustGet(string name)
        => Get(name) ?? throw new ProxyNotFoundException(name);

    public bool Add(IProxy proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        var added = _proxies.TryAdd(proxy.Name, proxy);
        if (added)
        {
            if (proxy is ProxyGroupBase group) group.StartHealthCheck();
            RaiseChanged();
        }
        return added;
    }

    /// <summary>Adds a proxy and records which provider contributed it.</summary>
    public bool AddFromProvider(string providerName, IProxy proxy)
    {
        if (!Add(proxy)) return false;

        _providerOf[proxy.Name] = providerName;
        _providerMembers.AddOrUpdate(
            providerName,
            _ => [proxy],
            (_, list) =>
            {
                lock (list) list.Add(proxy);
                return list;
            });
        return true;
    }

    public bool Remove(string name)
    {
        if (string.Equals(name, WellKnown.Global, StringComparison.Ordinal) ||
            string.Equals(name, WellKnown.Direct, StringComparison.Ordinal) ||
            string.Equals(name, WellKnown.Reject, StringComparison.Ordinal))
        {
            return false;
        }

        if (!_proxies.TryRemove(name, out var removed)) return false;

        if (_providerOf.TryRemove(name, out var provider) && _providerMembers.TryGetValue(provider, out var list))
        {
            lock (list) list.RemoveAll(p => string.Equals(p.Name, name, StringComparison.Ordinal));
        }

        if (removed is IAsyncDisposable asyncDisposable)
        {
            _ = asyncDisposable.DisposeAsync().AsTask().ContinueWith(
                t => _logger.LogDebug(t.Exception, "disposing proxy {Name} failed", name),
                TaskContinuationOptions.OnlyOnFaulted);
        }

        RaiseChanged();
        return true;
    }

    /// <summary>Removes every proxy contributed by a provider, before a refresh.</summary>
    public void RemoveProvider(string providerName)
    {
        if (!_providerMembers.TryRemove(providerName, out var list)) return;
        lock (list)
        {
            foreach (var proxy in list)
            {
                _proxies.TryRemove(proxy.Name, out _);
                _providerOf.TryRemove(proxy.Name, out _);
            }
        }
        RaiseChanged();
    }

    public void Clear()
    {
        foreach (var name in _proxies.Keys.ToList())
        {
            if (name is WellKnown.Global or WellKnown.Direct or WellKnown.Reject) continue;
            _proxies.TryRemove(name, out _);
        }
        _providerMembers.Clear();
        _providerOf.Clear();
        RaiseChanged();
    }

    /// <summary>Rebuilds every group's membership after a registry change.</summary>
    public void RefreshGroupMembership(IReadOnlyDictionary<string, IReadOnlyList<IProxy>> groupMembers)
    {
        foreach (var (groupName, members) in groupMembers)
        {
            if (Get(groupName) is ProxyGroupBase group) group.SetMembers(members);
        }
        RaiseChanged();
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var proxy in _proxies.Values)
        {
            if (proxy is IAsyncDisposable asyncDisposable)
            {
                try { await asyncDisposable.DisposeAsync().ConfigureAwait(false); } catch { /* shutting down */ }
            }
        }
        _proxies.Clear();
        _providerMembers.Clear();
    }

    private void RaiseChanged()
    {
        try { Changed?.Invoke(); } catch (Exception ex) { _logger.LogDebug(ex, "proxy change observer threw"); }
    }
}
