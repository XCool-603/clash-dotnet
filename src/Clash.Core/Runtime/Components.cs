using Clash.Core.Adapter;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Providers;
using Clash.Core.Rules;
using Clash.Core.Transport;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Runtime;

/// <summary>
/// The single place where concrete implementations are named. Everything else in
/// the runtime talks to interfaces, so swapping an implementation (or a test
/// double) means editing only this file.
/// </summary>
public static class Components
{
    /// <summary>Creates the DNS resolver for a configuration.</summary>
    public static IDnsResolver CreateDns(ClashConfig config, ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        return new DnsResolver(config.Dns, config.Hosts, loggerFactory.CreateLogger<DnsResolver>());
    }

    /// <summary>Creates the GeoIP/GeoSite/ASN provider. Call <c>LoadAsync</c> before matching.</summary>
    public static IGeoData CreateGeo(ClashConfig config, ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        try
        {
            var dataDirectory = Path.Combine(AppContext.BaseDirectory, "data");
            return new GeoData(config, dataDirectory);
        }
        catch (Exception ex)
        {
            // Geo data is optional: rules that need it simply never match.
            loggerFactory.CreateLogger(nameof(Components))
                .LogWarning("geo data unavailable, GEOIP/GEOSITE rules will not match: {Message}", ex.Message);
            return GeoData.Empty;
        }
    }

    /// <summary>Builds the rule engine with the configuration's ordered rule list.</summary>
    public static IRuleEngine CreateRules(
        ClashConfig config,
        IDnsResolver dns,
        IGeoData geo,
        IReadOnlyDictionary<string, IRuleSet> ruleSets,
        ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(dns);
        ArgumentNullException.ThrowIfNull(geo);
        ArgumentNullException.ThrowIfNull(ruleSets);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        var rules = RuleEngine.BuildFromConfig(config, ruleSets);
        return new RuleEngine(dns, geo, rules, ruleSets);
    }

    /// <summary>Creates the transport composer shared by every outbound.</summary>
    public static ITransportComposer CreateTransports(ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        return new TransportComposer();
    }

    /// <summary>Builds a rule set from an inline provider payload.</summary>
    public static IRuleSet CreateRuleSet(string name, string behavior, IReadOnlyList<string> payload)
        => RuleSet.FromPayload(name, behavior, payload);

    /// <summary>Selection persistence honouring <c>profile.store-selected</c>.</summary>
    public static ISelectionStore CreateSelectionStore(string homeDir, ClashConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (!config.Profile.StoreSelected) return new MemorySelectionStore();

        try
        {
            return new FileSelectionStore(Path.Combine(homeDir, "cache", "selections.json"));
        }
        catch (Exception)
        {
            return new MemorySelectionStore();
        }
    }
}

/// <summary>
/// Persists group selections to a small JSON file so a restart restores the
/// user's choice, which is what <c>profile.store-selected</c> promises.
/// </summary>
public sealed class FileSelectionStore : ISelectionStore
{
    private readonly string _path;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly Lock _writeLock = new();

    public FileSelectionStore(string path)
    {
        _path = path;
        Load();
    }

    public string? Get(string group) => _values.TryGetValue(group, out var value) ? value : null;

    public void Set(string group, string proxy)
    {
        _values[group] = proxy;
        Persist();
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var json = File.ReadAllText(_path);
            var parsed = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            if (parsed is null) return;
            foreach (var (key, value) in parsed) _values[key] = value;
        }
        catch (Exception)
        {
            // A corrupt cache is not fatal; selections simply start empty.
        }
    }

    private void Persist()
    {
        lock (_writeLock)
        {
            try
            {
                var directory = Path.GetDirectoryName(_path);
                if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

                var snapshot = _values.ToDictionary(kv => kv.Key, kv => kv.Value);
                File.WriteAllText(_path, System.Text.Json.JsonSerializer.Serialize(snapshot));
            }
            catch (Exception)
            {
                // Persistence is best effort.
            }
        }
    }
}

/// <summary>The starter configuration written on first run.</summary>
public static class DefaultConfiguration
{
    /// <summary>A minimal but genuinely usable configuration.</summary>
    public const string Yaml = """
        # Clash for .NET — starter configuration
        # Documentation: https://wiki.metacubex.one/

        mixed-port: 7890
        allow-lan: false
        bind-address: '*'
        mode: rule
        log-level: info
        ipv6: false
        external-controller: 127.0.0.1:9090
        secret: ''
        unified-delay: true
        tcp-concurrent: true
        find-process-mode: strict
        global-client-fingerprint: chrome

        profile:
          store-selected: true
          store-fake-ip: true

        dns:
          enable: true
          listen: 0.0.0.0:1053
          ipv6: false
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          fake-ip-filter:
            - '*.lan'
            - '*.local'
            - '+.msftconnecttest.com'
            - '+.msftncsi.com'
            - localhost.ptlogin2.qq.com
          default-nameserver:
            - 223.5.5.5
            - 119.29.29.29
          nameserver:
            - https://doh.pub/dns-query
            - https://dns.alidns.com/dns-query
          fallback:
            - https://dns.google/dns-query
            - https://1.1.1.1/dns-query
          fallback-filter:
            geoip: true
            geoip-code: CN
            ipcidr:
              - 240.0.0.0/4

        # Add your nodes here, or import a subscription from the Profiles page.
        proxies: []

        proxy-groups:
          - name: PROXY
            type: select
            proxies:
              - DIRECT
          - name: AUTO
            type: url-test
            proxies:
              - DIRECT
            url: https://www.gstatic.com/generate_204
            interval: 300
            tolerance: 50

        rules:
          - DOMAIN-SUFFIX,local,DIRECT
          - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
          - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
          - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
          - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
          - GEOIP,CN,DIRECT
          - MATCH,PROXY
        """;
}
