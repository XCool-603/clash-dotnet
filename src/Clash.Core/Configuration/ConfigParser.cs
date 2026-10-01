using Clash.Core.Common;

namespace Clash.Core.Configuration;

/// <summary>Reads YAML text into the canonical <see cref="YamlMap"/> shape.</summary>
public static class YamlReader
{
    public static YamlMap Parse(string yaml)
    {
        if (string.IsNullOrWhiteSpace(yaml)) return YamlMap.Empty;

        var deserializer = new YamlDotNet.Serialization.DeserializerBuilder()
            .Build();

        object? raw;
        try
        {
            raw = deserializer.Deserialize<object?>(yaml);
        }
        catch (YamlDotNet.Core.YamlException ex)
        {
            throw new ClashConfigException($"invalid YAML: {ex.Message}", ex);
        }

        if (raw is null) return YamlMap.Empty;

        var normalized = YamlMap.Normalize(raw);
        if (normalized is not Dictionary<string, object?> map)
        {
            throw new ClashConfigException("configuration root must be a mapping");
        }

        return new YamlMap(map);
    }

    /// <summary>Serializes a canonical map back to YAML text.</summary>
    public static string Write(YamlMap map)
    {
        var serializer = new YamlDotNet.Serialization.SerializerBuilder()
            .WithIndentedSequences()
            .Build();
        return serializer.Serialize(ToPlain(map.Raw));
    }

    private static object? ToPlain(object? value) => value switch
    {
        null => null,
        Dictionary<string, object?> d => d.ToDictionary(kv => kv.Key, kv => ToPlain(kv.Value)),
        List<object?> l => l.Select(ToPlain).ToList(),
        _ => value,
    };
}

/// <summary>
/// Maps a raw configuration document onto <see cref="ClashConfig"/>. Unknown keys
/// are preserved in <see cref="ClashConfig.Raw"/> rather than rejected, which is
/// what lets a newer profile load in an older build.
/// </summary>
public static class ConfigParser
{
    public static ClashConfig Parse(YamlMap root)
    {
        var config = new ClashConfig { Raw = root };

        config.Port = root.GetInt("port");
        config.SocksPort = root.GetInt("socks-port");
        config.RedirPort = root.GetInt("redir-port");
        config.TProxyPort = root.GetInt("tproxy-port");
        config.MixedPort = root.GetInt("mixed-port");

        config.AllowLan = root.GetBool("allow-lan");
        config.BindAddress = root.GetString("bind-address") ?? "*";
        config.Mode = NetworkExtensions.ParseMode(root.GetString("mode"));
        config.LogLevel = (root.GetString("log-level") ?? "info").ToLowerInvariant();
        config.Ipv6 = root.GetBool("ipv6");
        config.InterfaceName = root.GetString("interface-name") ?? string.Empty;
        config.RoutingMark = root.GetInt("routing-mark");
        config.UnifiedDelay = root.GetBool("unified-delay");
        config.TcpConcurrent = root.GetBool("tcp-concurrent");
        config.FindProcessMode = (root.GetString("find-process-mode") ?? "strict").ToLowerInvariant();
        config.GlobalClientFingerprint = root.GetString("global-client-fingerprint") ?? string.Empty;
        config.KeepAliveInterval = root.GetInt("keep-alive-interval", 30);
        config.KeepAliveIdle = root.GetInt("keep-alive-idle", 15);
        config.DisableKeepAlive = root.GetBool("disable-keep-alive");

        config.ExternalController = root.GetString("external-controller") ?? string.Empty;
        var cors = root.GetMap("external-controller-cors");
        config.ExternalControllerCors = new ExternalControllerCorsConfig
        {
            AllowOrigins = cors.GetStringList("allow-origins"),
            AllowPrivateNetwork = cors.GetBool("allow-private-network"),
        };
        config.ExternalUi = root.GetString("external-ui") ?? string.Empty;
        config.ExternalUiName = root.GetString("external-ui-name") ?? string.Empty;
        config.ExternalUiUrl = root.GetString("external-ui-url") ?? string.Empty;
        config.Secret = root.GetString("secret") ?? string.Empty;

        config.GeoData = ParseGeoData(root.GetMap("geodata"));
        config.GeoxUrl = ParseGeoXUrl(root.GetMap("geox-url"));
        config.Tun = ParseTun(root.GetMap("tun"));
        config.Dns = ParseDns(root.GetMap("dns"));
        config.Sniffer = ParseSniffer(root.GetMap("sniffer"));
        config.Ntp = ParseNtp(root.GetMap("ntp"));
        config.Experimental = ParseExperimental(root.GetMap("experimental"));
        config.Profile = ParseProfile(root.GetMap("profile"));
        config.Script = ParseScript(root.GetMap("script"));
        config.Cluster = new ClusterConfig { Secret = root.GetMap("cluster").GetString("secret") ?? string.Empty };

        foreach (var entry in root.GetList("proxies"))
        {
            var map = YamlMap.From(entry);
            if (map.GetNonEmptyString("name") is null || map.GetNonEmptyString("type") is null) continue;
            config.Proxies.Add(new ProxyConfigEntry(map));
        }

        foreach (var entry in root.GetList("proxy-groups"))
        {
            var map = YamlMap.From(entry);
            if (map.GetNonEmptyString("name") is null || map.GetNonEmptyString("type") is null) continue;
            config.ProxyGroups.Add(ParseProxyGroup(map));
        }

        config.Rules.AddRange(root.GetStringList("rules"));

        foreach (var (key, value) in root.GetMap("sub-rules").Raw)
        {
            config.SubRules[key] = (value as List<object?> ?? [])
                .Select(x => Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty)
                .Where(s => s.Length > 0)
                .ToList();
        }

        foreach (var (key, value) in root.GetMap("rule-providers").Raw)
        {
            config.RuleProviders[key] = ParseRuleProvider(key, YamlMap.From(value));
        }

        foreach (var (key, value) in root.GetMap("proxy-providers").Raw)
        {
            config.ProxyProviders[key] = ParseProxyProvider(key, YamlMap.From(value));
        }

        foreach (var entry in root.GetList("listeners"))
        {
            var map = YamlMap.From(entry);
            var name = map.GetNonEmptyString("name");
            var type = map.GetNonEmptyString("type");
            if (name is null || type is null) continue;
            config.Listeners.Add(new ListenerConfig
            {
                Name = name,
                Type = type.ToLowerInvariant(),
                Port = map.GetInt("port"),
                Listen = map.GetString("listen") ?? string.Empty,
                Map = map,
                Proxy = map.GetStringList("proxy"),
            });
        }

        config.Hosts = new Dictionary<string, object?>(root.GetMap("hosts").Raw, StringComparer.OrdinalIgnoreCase);

        foreach (var entry in root.GetList("tunnels"))
        {
            var map = YamlMap.From(entry);
            if (map.Count > 0) config.Tunnels.Add(map);
        }

        config.Authentication = root.GetStringList("authentication");

        return config;
    }

    private static GeoDataConfig ParseGeoData(YamlMap map) => new()
    {
        GeodataMode = map.GetString("mode") ?? "memconservative",
        GeodataLoader = map.GetString("loader") ?? "standard",
        GeositeMatcher = map.GetString("matcher") ?? "succinct",
    };

    private static GeoXUrlConfig ParseGeoXUrl(YamlMap map) => new()
    {
        GeoIp = map.GetString("geoip") ?? string.Empty,
        GeoSite = map.GetString("geosite") ?? string.Empty,
        Mmdb = map.GetString("mmdb") ?? string.Empty,
        Asn = map.GetString("asn") ?? string.Empty,
    };

    private static TunConfig ParseTun(YamlMap map) => new()
    {
        Enable = map.GetBool("enable"),
        Stack = (map.GetString("stack") ?? "mixed").ToLowerInvariant(),
        Device = map.GetString("device") ?? string.Empty,
        AutoRoute = map.GetBool("auto-route"),
        AutoDetectInterface = map.GetBool("auto-detect-interface"),
        AutoRedirect = map.GetBool("auto-redirect"),
        DnsHijack = map.GetStringList("dns-hijack") is { Count: > 0 } hijack ? hijack : ["any:53"],
        Mtu = map.GetInt("mtu", 9000),
        Gso = map.GetBool("gso"),
        GsoMaxSize = map.GetInt("gso-max-size", 65536),
        StrictRoute = map.GetBool("strict-route"),
        EndpointIndependentNat = map.GetBool("endpoint-independent-nat"),
        Inet4Address = map.GetStringList("inet4-address"),
        Inet6Address = map.GetStringList("inet6-address"),
        UdpTimeout = map.GetString("udp-timeout") ?? "5m",
        RouteAddress = map.GetStringList("route-address"),
        RouteExcludeAddress = map.GetStringList("route-exclude-address"),
        IncludeInterface = map.GetStringList("include-interface"),
        ExcludeInterface = map.GetStringList("exclude-interface"),
        FileDescriptor = map.GetString("file-descriptor") ?? string.Empty,
        InterfaceName = map.GetString("interface-name") ?? string.Empty,
        RedirectToTun = map.GetBool("redirect-to-tun", true),
    };

    private static DnsConfig ParseDns(YamlMap map)
    {
        var fallbackFilter = map.GetMap("fallback-filter");
        return new DnsConfig
        {
            Enable = map.Has("enable") ? map.GetBool("enable") : true,
            Listen = map.GetString("listen") ?? "0.0.0.0:1053",
            Ipv6 = map.GetBool("ipv6"),
            EnhancedMode = (map.GetString("enhanced-mode") ?? "normal").ToLowerInvariant(),
            FakeIpRange = map.GetString("fake-ip-range") ?? "198.18.0.1/16",
            FakeIpRangeV6 = map.GetString("fake-ip-range-v6") ?? "fdfe:dcba:9876::1/96",
            FakeIpFilter = map.GetStringList("fake-ip-filter"),
            DefaultNameserver = map.GetStringList("default-nameserver") is { Count: > 0 } dns1 ? dns1 : ["114.114.114.114", "223.5.5.5"],
            Nameserver = map.GetStringList("nameserver"),
            Fallback = map.GetStringList("fallback"),
            FallbackFilter = new FallbackFilterConfig
            {
                GeoIp = fallbackFilter.GetBool("geoip", true),
                GeoIpCode = fallbackFilter.GetString("geoip-code") ?? "CN",
                IpCidr = fallbackFilter.GetStringList("ipcidr"),
                Domain = fallbackFilter.GetStringList("domain"),
                GeoIpFilter = fallbackFilter.GetBool("geoip-filter", true),
            },
            NameserverPolicy = new Dictionary<string, object?>(map.GetMap("nameserver-policy").Raw, StringComparer.OrdinalIgnoreCase),
            ProxyServerNameserver = map.GetStringList("proxy-server-nameserver"),
            DirectNameserver = map.GetStringList("direct-nameserver"),
            Hosts = new Dictionary<string, object?>(map.GetMap("hosts").Raw, StringComparer.OrdinalIgnoreCase),
            UseHosts = map.GetBool("use-hosts", true),
            UseSystemHosts = map.GetBool("use-system-hosts"),
            RespectRules = map.GetBool("respect-rules"),
            PreferH3 = map.GetBool("prefer-h3"),
            CacheAlgorithm = (map.GetString("cache-algorithm") ?? "arc").ToLowerInvariant(),
            CacheMaxSize = map.GetInt("cache-max-size", 8192),
        };
    }

    private static SnifferConfig ParseSniffer(YamlMap map)
    {
        var sniff = map.GetMap("sniff");
        return new SnifferConfig
        {
            Enable = map.GetBool("enable"),
            OverrideDestination = map.GetBool("override-destination"),
            ForceDomain = map.GetStringList("force-domain"),
            SkipDomain = map.GetStringList("skip-domain"),
            ForceDnsMapping = map.GetStringList("force-dns-mapping"),
            ParsePureIp = map.GetStringList("parse-pure-ip"),
            Sniff = new SniffProtocols
            {
                Http = ParseSniffProtocol(sniff.GetMap("http"), [80, "8080-8880"], true),
                Tls = ParseSniffProtocol(sniff.GetMap("tls"), [443, 8443], false),
                Quic = ParseSniffProtocol(sniff.GetMap("quic"), [443, 8443], false),
            },
        };
    }

    private static SniffProtocolConfig ParseSniffProtocol(YamlMap map, List<object?> defaultPorts, bool defaultOverride)
    {
        if (map.Count == 0) return new SniffProtocolConfig { Ports = defaultPorts, OverrideDestination = defaultOverride };
        var ports = map.GetList("ports");
        return new SniffProtocolConfig
        {
            Ports = ports.Count > 0 ? [.. ports] : defaultPorts,
            OverrideDestination = map.GetBool("override-destination", defaultOverride),
        };
    }

    private static NtpConfig ParseNtp(YamlMap map) => new()
    {
        Enable = map.GetBool("enable"),
        WriteToSystem = map.GetBool("write-to-system"),
        Server = map.GetString("server") ?? "time.apple.com",
        Port = map.GetInt("port", 123),
        Interval = map.GetString("interval") ?? "30m",
        DialerProxy = map.GetString("dialer-proxy") ?? string.Empty,
    };

    private static ExperimentalConfig ParseExperimental(YamlMap map)
    {
        var quicGo = map.GetMap("quic-go");
        return new ExperimentalConfig
        {
            Fingerprints = map.GetStringList("fingerprints"),
            QuicGo = new QuicGoConfig
            {
                MaxIdleTime = quicGo.GetNullableInt("max-idle-time"),
                KeepAlivePeriod = quicGo.GetNullableInt("keep-alive-period"),
                DisablePathMtuDiscovery = quicGo.GetNullableInt("disable-path-mtu-discovery"),
                InitialStreamReceiveWindow = quicGo.GetNullableInt("initial-stream-receive-window"),
                MaxStreamReceiveWindow = quicGo.GetNullableInt("max-stream-receive-window"),
                InitialConnectionReceiveWindow = quicGo.GetNullableInt("initial-connection-receive-window"),
                MaxConnectionReceiveWindow = quicGo.GetNullableInt("max-connection-receive-window"),
            },
        };
    }

    private static ProfileConfig ParseProfile(YamlMap map) => new()
    {
        StoreSelected = map.GetBool("store-selected", true),
        StoreFakeIp = map.GetBool("store-fake-ip", true),
        StoreRtt = map.GetString("store-rtt") ?? "30m",
    };

    private static ScriptConfig ParseScript(YamlMap map) => new()
    {
        Code = map.GetString("code") ?? string.Empty,
        Path = map.GetNonEmptyString("path"),
        Timeout = map.GetInt("timeout", 1000),
    };

    public static ProxyGroupConfig ParseProxyGroup(YamlMap map) => new()
    {
        Map = map,
        Name = map.GetString("name") ?? string.Empty,
        Type = (map.GetString("type") ?? string.Empty).ToLowerInvariant(),
        Proxies = map.GetStringList("proxies"),
        Use = map.GetStringList("use"),
        Url = map.GetString("url") ?? "https://www.gstatic.com/generate_204",
        Interval = map.GetInt("interval", 300),
        Tolerance = map.GetInt("tolerance", 50),
        Timeout = map.GetInt("timeout", 5000),
        MaxFailedTimes = map.GetInt("max-failed-times"),
        Lazy = map.GetBool("lazy"),
        DisableUdp = map.GetBool("disable-udp"),
        Filter = map.GetNonEmptyString("filter"),
        ExcludeFilter = map.GetNonEmptyString("exclude-filter"),
        ExcludeType = map.GetNonEmptyString("exclude-type"),
        ExpectedStatus = map.GetString("expected-status"),
        Strategy = map.GetNonEmptyString("strategy"),
        Hidden = map.GetBool("hidden"),
        Icon = map.GetNonEmptyString("icon"),
        IncludeAll = map.GetBool("include-all"),
        IncludeAllProxies = map.GetBool("include-all-proxies"),
        IncludeAllProviders = map.GetBool("include-all-providers"),
    };

    private static RuleProviderConfig ParseRuleProvider(string name, YamlMap map) => new()
    {
        Type = (map.GetString("type") ?? "http").ToLowerInvariant(),
        Behavior = (map.GetString("behavior") ?? "domain").ToLowerInvariant(),
        Format = (map.GetString("format") ?? "yaml").ToLowerInvariant(),
        Url = map.GetString("url") ?? string.Empty,
        Path = map.GetString("path") ?? string.Empty,
        Interval = map.GetInt("interval", 86400),
        Payload = map.Has("payload") ? map.GetStringList("payload") : null,
    };

    private static ProxyProviderConfig ParseProxyProvider(string name, YamlMap map)
    {
        var healthCheck = map.GetMap("health-check");
        var inline = new List<ProxyConfigEntry>();
        foreach (var entry in map.GetList("payload"))
        {
            var entryMap = YamlMap.From(entry);
            if (entryMap.GetNonEmptyString("name") is null) continue;
            inline.Add(new ProxyConfigEntry(entryMap));
        }

        return new ProxyProviderConfig
        {
            Type = (map.GetString("type") ?? "http").ToLowerInvariant(),
            Url = map.GetString("url") ?? string.Empty,
            Path = map.GetString("path") ?? string.Empty,
            Interval = map.GetInt("interval", 300),
            Filter = map.GetNonEmptyString("filter"),
            ExcludeFilter = map.GetNonEmptyString("exclude-filter"),
            ExcludeType = map.GetNonEmptyString("exclude-type"),
            HealthCheck = new HealthCheckConfig
            {
                Enable = healthCheck.Has("enable") ? healthCheck.GetBool("enable") : true,
                Url = healthCheck.GetString("url") ?? "https://www.gstatic.com/generate_204",
                Interval = healthCheck.GetInt("interval", 300),
                Timeout = healthCheck.GetInt("timeout", 5000),
                Lazy = healthCheck.GetInt("lazy"),
                ExpectedStatus = healthCheck.GetString("expected-status"),
            },
            Override = map.GetMap("override"),
            InlinePayload = inline.Count > 0 ? inline : null,
        };
    }
}
