using System.Text.RegularExpressions;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Providers;
using Clash.Core.Transport;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Adapter;

/// <summary>
/// Turns a parsed <see cref="ClashConfig"/> into a fully wired
/// <see cref="ProxyManager"/>: concrete outbounds, provider-supplied nodes, and
/// every group with its membership resolved.
/// </summary>
public sealed class ProxyFactory
{
    private readonly AdapterBuildContext _context;
    private readonly ILogger<ProxyFactory> _logger;
    private readonly ISelectionStore _selectionStore;
    private readonly IProxyProviderLoader? _providerLoader;

    public ProxyFactory(
        AdapterBuildContext context,
        ISelectionStore selectionStore,
        IProxyProviderLoader? providerLoader = null)
    {
        _context = context;
        _logger = context.LoggerFactory.CreateLogger<ProxyFactory>();
        _selectionStore = selectionStore;
        _providerLoader = providerLoader;
    }

    /// <summary>Builds the whole registry for a configuration.</summary>
    public async Task<ProxyManager> BuildAsync(ClashConfig config, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);

        var manager = new ProxyManager(_context.Tunnel, _context.LoggerFactory);

        AddConfiguredProxies(config, manager);
        await AddProviderProxiesAsync(config, manager, cancellationToken).ConfigureAwait(false);
        CreateGroups(config, manager);
        ResolveGroupMembership(config, manager);
        StartHealthChecks(manager);

        _logger.LogInformation(
            "proxy registry built: {Total} adapters, {Groups} groups",
            manager.All.Count,
            config.ProxyGroups.Count);

        return manager;
    }

    // ── Step 1: the proxies list ─────────────────────────────────────────────

    private void AddConfiguredProxies(ClashConfig config, ProxyManager manager)
    {
        foreach (var entry in config.Proxies)
        {
            try
            {
                manager.Add(AdapterRegistry.Create(entry, _context));
            }
            catch (Exception ex)
            {
                // One bad node must not prevent the rest of the config loading.
                _logger.LogWarning("skipping proxy [{Name}]: {Message}", entry.Name, ex.Message);
                _context.Log?.Invoke("warning", $"skipping proxy [{entry.Name}]: {ex.Message}");
            }
        }
    }

    // ── Step 2: proxy-providers ──────────────────────────────────────────────

    private async Task AddProviderProxiesAsync(ClashConfig config, ProxyManager manager, CancellationToken cancellationToken)
    {
        if (config.ProxyProviders.Count == 0) return;

        if (_providerLoader is null)
        {
            _logger.LogWarning("the configuration declares proxy-providers but no provider loader is registered");
            return;
        }

        foreach (var (name, providerConfig) in config.ProxyProviders)
        {
            try
            {
                var result = await _providerLoader.LoadAsync(name, providerConfig, cancellationToken).ConfigureAwait(false);
                foreach (var entry in ApplyFilters(result.Proxies, providerConfig, name))
                {
                    var effective = ApplyOverride(entry, providerConfig.Override);
                    try
                    {
                        manager.AddFromProvider(name, AdapterRegistry.Create(effective, _context));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning("provider [{Provider}] node [{Name}] skipped: {Message}", name, effective.Name, ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning("proxy provider [{Provider}] failed: {Message}", name, ex.Message);
                _context.Log?.Invoke("warning", $"proxy provider [{name}] failed: {ex.Message}");
            }
        }
    }

    /// <summary>Applies <c>filter</c>, <c>exclude-filter</c> and <c>exclude-type</c>.</summary>
    public static IReadOnlyList<ProxyConfigEntry> ApplyFilters(
        IReadOnlyList<ProxyConfigEntry> entries,
        ProxyProviderConfig config,
        string providerName)
    {
        IEnumerable<ProxyConfigEntry> result = entries;

        if (!string.IsNullOrWhiteSpace(config.Filter))
        {
            var filter = CompileFilter(config.Filter!, providerName, "filter");
            result = result.Where(e => filter.IsMatch(e.Name));
        }

        if (!string.IsNullOrWhiteSpace(config.ExcludeFilter))
        {
            var exclude = CompileFilter(config.ExcludeFilter!, providerName, "exclude-filter");
            result = result.Where(e => !exclude.IsMatch(e.Name));
        }

        if (!string.IsNullOrWhiteSpace(config.ExcludeType))
        {
            var types = config.ExcludeType!
                .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            result = result.Where(e => !types.Contains(e.Type));
        }

        return result.ToList();
    }

    private static Regex CompileFilter(string pattern, string providerName, string field)
    {
        try
        {
            return new Regex(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200));
        }
        catch (ArgumentException ex)
        {
            throw new ProviderException($"provider [{providerName}] has an invalid {field} regex: {ex.Message}", ex);
        }
    }

    /// <summary>Merges the provider's <c>override</c> map into each entry.</summary>
    public static ProxyConfigEntry ApplyOverride(ProxyConfigEntry entry, YamlMap overrides)
    {
        if (overrides.Count == 0) return entry;

        var merged = new Dictionary<string, object?>(entry.Map.Raw, StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in overrides.Raw)
        {
            // `override` must never rename a node, or provider references break.
            if (string.Equals(key, "name", StringComparison.OrdinalIgnoreCase)) continue;
            merged[key] = value;
        }

        return new ProxyConfigEntry(new YamlMap(merged));
    }

    // ── Step 3: create the group shells ──────────────────────────────────────

    private void CreateGroups(ClashConfig config, ProxyManager manager)
    {
        foreach (var groupConfig in config.ProxyGroups)
        {
            try
            {
                var group = CreateGroup(groupConfig);
                if (group is SelectorGroup selector)
                {
                    selector.UseStore(_selectionStore, groupConfig.Name);
                }
                manager.Add(group);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("skipping proxy group [{Name}]: {Message}", groupConfig.Name, ex.Message);
                _context.Log?.Invoke("warning", $"skipping proxy group [{groupConfig.Name}]: {ex.Message}");
            }
        }
    }

    private ProxyGroupBase CreateGroup(ProxyGroupConfig config)
    {
        var logger = _context.LoggerFactory.CreateLogger<ProxyGroupBase>();
        return config.Type switch
        {
            "select" => new SelectorGroup(config, _context.Tunnel, logger),
            "url-test" => new UrlTestGroup(config, _context.Tunnel, logger),
            "fallback" => new FallbackGroup(config, _context.Tunnel, logger),
            "load-balance" => new LoadBalanceGroup(config, _context.Tunnel, logger),
            "relay" => new RelayGroup(config, _context.Tunnel, logger),
            "smart" => new SmartGroup(config, _context.Tunnel, logger),
            _ => throw new ProxyCreationException($"unsupported proxy group type [{config.Type}]"),
        };
    }

    // ── Step 4: resolve membership (second pass, so groups may reference each other) ──

    private void ResolveGroupMembership(ClashConfig config, ProxyManager manager)
    {
        foreach (var groupConfig in config.ProxyGroups)
        {
            if (manager.Get(groupConfig.Name) is not ProxyGroupBase group) continue;

            var members = new List<IProxy>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            void AddMember(IProxy? proxy)
            {
                if (proxy is null) return;
                if (ReferenceEquals(proxy, group)) return; // a group may not contain itself
                if (seen.Add(proxy.Name)) members.Add(proxy);
            }

            // `include-all*` first, so explicit entries keep their priority order.
            if (groupConfig.IncludeAll || groupConfig.IncludeAllProxies)
            {
                foreach (var entry in config.Proxies) AddMember(manager.Get(entry.Name));
            }

            if (groupConfig.IncludeAll || groupConfig.IncludeAllProviders)
            {
                foreach (var list in manager.ProviderProxies.Values)
                {
                    foreach (var proxy in list) AddMember(proxy);
                }
            }

            foreach (var name in groupConfig.Proxies)
            {
                var proxy = manager.Get(name);
                if (proxy is null)
                {
                    _logger.LogWarning("group [{Group}] references unknown proxy [{Proxy}]", groupConfig.Name, name);
                    continue;
                }
                AddMember(proxy);
            }

            foreach (var providerName in groupConfig.Use)
            {
                if (!manager.ProviderProxies.TryGetValue(providerName, out var providerProxies))
                {
                    _logger.LogWarning("group [{Group}] references unknown provider [{Provider}]", groupConfig.Name, providerName);
                    continue;
                }
                foreach (var proxy in providerProxies) AddMember(proxy);
            }

            members = ApplyGroupFilters(members, groupConfig).ToList();
            group.SetMembers(members);
        }
    }

    private static IEnumerable<IProxy> ApplyGroupFilters(IEnumerable<IProxy> members, ProxyGroupConfig config)
    {
        var result = members;

        if (!string.IsNullOrWhiteSpace(config.Filter))
        {
            var filter = new Regex(config.Filter!, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200));
            result = result.Where(m => filter.IsMatch(m.Name));
        }

        if (!string.IsNullOrWhiteSpace(config.ExcludeFilter))
        {
            var exclude = new Regex(config.ExcludeFilter!, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200));
            result = result.Where(m => !exclude.IsMatch(m.Name));
        }

        if (!string.IsNullOrWhiteSpace(config.ExcludeType))
        {
            var types = config.ExcludeType!
                .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            result = result.Where(m => !types.Contains(m.TypeName));
        }

        return result;
    }

    private void StartHealthChecks(ProxyManager manager)
    {
        foreach (var proxy in manager.All)
        {
            if (proxy is ProxyGroupBase group) group.StartHealthCheck();
        }
    }
}
