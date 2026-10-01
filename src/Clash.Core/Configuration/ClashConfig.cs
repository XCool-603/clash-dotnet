using Clash.Core.Common;

namespace Clash.Core.Configuration;

/// <summary>
/// The strongly typed form of a Clash configuration document. Every property maps
/// to one kebab-case YAML key; <see cref="ConfigParser"/> performs the mapping and
/// <see cref="ConfigSerializer"/> the reverse.
/// </summary>
public sealed class ClashConfig
{
    // ── Inbound ports ────────────────────────────────────────────────────────
    public int Port { get; set; }
    public int SocksPort { get; set; }
    public int RedirPort { get; set; }
    public int TProxyPort { get; set; }
    public int MixedPort { get; set; }

    // ── General ──────────────────────────────────────────────────────────────
    public bool AllowLan { get; set; }
    public string BindAddress { get; set; } = "*";
    public Mode Mode { get; set; } = Mode.Rule;
    public string LogLevel { get; set; } = "info";
    public bool Ipv6 { get; set; }
    public string InterfaceName { get; set; } = string.Empty;
    public int RoutingMark { get; set; }
    public bool UnifiedDelay { get; set; }
    public bool TcpConcurrent { get; set; }
    public string FindProcessMode { get; set; } = "strict";
    public string GlobalClientFingerprint { get; set; } = string.Empty;
    public int KeepAliveInterval { get; set; } = 30;
    public int KeepAliveIdle { get; set; } = 15;
    public bool DisableKeepAlive { get; set; }

    // ── External controller ──────────────────────────────────────────────────
    public string ExternalController { get; set; } = string.Empty;
    public ExternalControllerCorsConfig ExternalControllerCors { get; set; } = new();
    public string ExternalUi { get; set; } = string.Empty;
    public string ExternalUiName { get; set; } = string.Empty;
    public string ExternalUiUrl { get; set; } = string.Empty;
    public string Secret { get; set; } = string.Empty;

    // ── Geo data ─────────────────────────────────────────────────────────────
    public GeoDataConfig GeoData { get; set; } = new();
    public GeoXUrlConfig GeoxUrl { get; set; } = new();

    // ── Subsystems ───────────────────────────────────────────────────────────
    public TunConfig Tun { get; set; } = new();
    public DnsConfig Dns { get; set; } = new();
    public SnifferConfig Sniffer { get; set; } = new();
    public NtpConfig Ntp { get; set; } = new();
    public ExperimentalConfig Experimental { get; set; } = new();
    public ProfileConfig Profile { get; set; } = new();
    public ScriptConfig Script { get; set; } = new();
    public ClusterConfig Cluster { get; set; } = new();

    // ── Routing data ─────────────────────────────────────────────────────────
    public List<ProxyConfigEntry> Proxies { get; set; } = [];
    public List<ProxyGroupConfig> ProxyGroups { get; set; } = [];
    public List<string> Rules { get; set; } = [];
    public Dictionary<string, List<string>> SubRules { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, RuleProviderConfig> RuleProviders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, ProxyProviderConfig> ProxyProviders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ListenerConfig> Listeners { get; set; } = [];
    public Dictionary<string, object?> Hosts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<YamlMap> Tunnels { get; set; } = [];
    public List<string> Authentication { get; set; } = [];

    /// <summary>
    /// The untyped document this instance was built from. Retained so
    /// <c>PATCH /configs</c> can merge a partial update and re-parse, exactly like
    /// Clash does, and so <c>GET /configs</c> can echo unknown keys back.
    /// </summary>
    public YamlMap Raw { get; set; } = YamlMap.Empty;
}

public sealed class ExternalControllerCorsConfig
{
    public List<string> AllowOrigins { get; set; } = [];
    public bool AllowPrivateNetwork { get; set; }
}

public sealed class GeoDataConfig
{
    public string GeodataMode { get; set; } = "memconservative";
    public string GeodataLoader { get; set; } = "standard";
    public string GeositeMatcher { get; set; } = "succinct";
}

public sealed class GeoXUrlConfig
{
    public string GeoIp { get; set; } = string.Empty;
    public string GeoSite { get; set; } = string.Empty;
    public string Mmdb { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
}

public sealed class TunConfig
{
    public bool Enable { get; set; }
    public string Stack { get; set; } = "mixed";
    public string Device { get; set; } = string.Empty;
    public bool AutoRoute { get; set; }
    public bool AutoDetectInterface { get; set; }
    public bool AutoRedirect { get; set; }
    public List<string> DnsHijack { get; set; } = ["any:53"];
    public int Mtu { get; set; } = 9000;
    public bool Gso { get; set; }
    public int GsoMaxSize { get; set; } = 65536;
    public bool StrictRoute { get; set; }
    public bool EndpointIndependentNat { get; set; }
    public List<string> Inet4Address { get; set; } = [];
    public List<string> Inet6Address { get; set; } = [];
    public string UdpTimeout { get; set; } = "5m";
    public List<string> RouteAddress { get; set; } = [];
    public List<string> RouteExcludeAddress { get; set; } = [];
    public List<string> IncludeInterface { get; set; } = [];
    public List<string> ExcludeInterface { get; set; } = [];
    public string FileDescriptor { get; set; } = string.Empty;
    public string InterfaceName { get; set; } = string.Empty;
    public bool RedirectToTun { get; set; } = true;
}

public sealed class DnsConfig
{
    public bool Enable { get; set; } = true;
    public string Listen { get; set; } = "0.0.0.0:1053";
    public bool Ipv6 { get; set; }
    public string EnhancedMode { get; set; } = "normal";
    public string FakeIpRange { get; set; } = "198.18.0.1/16";
    public string FakeIpRangeV6 { get; set; } = "fdfe:dcba:9876::1/96";
    public List<string> FakeIpFilter { get; set; } = [];
    public List<string> DefaultNameserver { get; set; } = ["114.114.114.114", "223.5.5.5"];
    public List<string> Nameserver { get; set; } = [];
    public List<string> Fallback { get; set; } = [];
    public FallbackFilterConfig FallbackFilter { get; set; } = new();
    public Dictionary<string, object?> NameserverPolicy { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> ProxyServerNameserver { get; set; } = [];
    public List<string> DirectNameserver { get; set; } = [];
    public Dictionary<string, object?> Hosts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool UseHosts { get; set; } = true;
    public bool UseSystemHosts { get; set; }
    public bool RespectRules { get; set; }
    public bool PreferH3 { get; set; }
    public string CacheAlgorithm { get; set; } = "arc";
    public int CacheMaxSize { get; set; } = 8192;
}

public sealed class FallbackFilterConfig
{
    public bool GeoIp { get; set; } = true;
    public string GeoIpCode { get; set; } = "CN";
    public List<string> IpCidr { get; set; } = [];
    public List<string> Domain { get; set; } = [];
    public bool GeoIpFilter { get; set; } = true;
}

public sealed class SnifferConfig
{
    public bool Enable { get; set; }
    public bool OverrideDestination { get; set; }
    public List<string> ForceDomain { get; set; } = [];
    public List<string> SkipDomain { get; set; } = [];
    public List<string> ForceDnsMapping { get; set; } = [];
    public List<string> ParsePureIp { get; set; } = [];
    public SniffProtocols Sniff { get; set; } = new();
}

public sealed class SniffProtocols
{
    public SniffProtocolConfig Http { get; set; } = new() { Ports = [80, "8080-8880"], OverrideDestination = true };
    public SniffProtocolConfig Tls { get; set; } = new() { Ports = [443, 8443] };
    public SniffProtocolConfig Quic { get; set; } = new() { Ports = [443, 8443] };
}

public sealed class SniffProtocolConfig
{
    public List<object?> Ports { get; set; } = [];
    public bool OverrideDestination { get; set; }
}

public sealed class NtpConfig
{
    public bool Enable { get; set; }
    public bool WriteToSystem { get; set; }
    public string Server { get; set; } = "time.apple.com";
    public int Port { get; set; } = 123;
    public string Interval { get; set; } = "30m";
    public string DialerProxy { get; set; } = string.Empty;
}

public sealed class ExperimentalConfig
{
    public List<string> Fingerprints { get; set; } = [];
    public QuicGoConfig QuicGo { get; set; } = new();
}

public sealed class QuicGoConfig
{
    public int? MaxIdleTime { get; set; }
    public int? KeepAlivePeriod { get; set; }
    public int? DisablePathMtuDiscovery { get; set; }
    public int? InitialStreamReceiveWindow { get; set; }
    public int? MaxStreamReceiveWindow { get; set; }
    public int? InitialConnectionReceiveWindow { get; set; }
    public int? MaxConnectionReceiveWindow { get; set; }
}

public sealed class ProfileConfig
{
    public bool StoreSelected { get; set; } = true;
    public bool StoreFakeIp { get; set; } = true;
    public string StoreRtt { get; set; } = "30m";
}

public sealed class ScriptConfig
{
    public string Code { get; set; } = string.Empty;
    public string? Path { get; set; }
    public int Timeout { get; set; } = 1000;
}

public sealed class ClusterConfig
{
    public string Secret { get; set; } = string.Empty;
}

/// <summary>One entry of the <c>proxies</c> list, kept in its raw YAML form.</summary>
public sealed class ProxyConfigEntry
{
    public ProxyConfigEntry(YamlMap map)
    {
        Map = map;
        Name = map.GetString("name") ?? string.Empty;
        Type = map.GetString("type") ?? string.Empty;
    }

    public YamlMap Map { get; }
    public string Name { get; }
    public string Type { get; }

    public override string ToString() => $"{Name} ({Type})";
}

/// <summary>One entry of the <c>proxy-groups</c> list.</summary>
public sealed class ProxyGroupConfig
{
    public YamlMap Map { get; init; } = YamlMap.Empty;
    public string Name { get; init; } = string.Empty;
    public string Type { get; init; } = string.Empty;
    public List<string> Proxies { get; init; } = [];
    public List<string> Use { get; init; } = [];
    public string Url { get; init; } = "https://www.gstatic.com/generate_204";
    public int Interval { get; init; } = 300;
    public int Tolerance { get; init; } = 50;
    public int Timeout { get; init; } = 5000;
    public int MaxFailedTimes { get; init; }
    public bool Lazy { get; init; }
    public bool DisableUdp { get; init; }
    public string? Filter { get; init; }
    public string? ExcludeFilter { get; init; }
    public string? ExcludeType { get; init; }
    public string? ExpectedStatus { get; init; }
    public string? Strategy { get; init; }
    public bool Hidden { get; init; }
    public string? Icon { get; init; }
    public bool IncludeAll { get; init; }
    public bool IncludeAllProxies { get; init; }
    public bool IncludeAllProviders { get; init; }

    public override string ToString() => $"{Name} ({Type}, {Proxies.Count} direct, {Use.Count} providers)";
}

public sealed class RuleProviderConfig
{
    public string Type { get; init; } = "http";
    public string Behavior { get; init; } = "domain";
    public string Format { get; init; } = "yaml";
    public string Url { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public int Interval { get; init; } = 86400;
    public List<string>? Payload { get; init; }
}

public sealed class ProxyProviderConfig
{
    public string Type { get; init; } = "http";
    public string Url { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public int Interval { get; init; } = 300;
    public string? Filter { get; init; }
    public string? ExcludeFilter { get; init; }
    public string? ExcludeType { get; init; }
    public HealthCheckConfig HealthCheck { get; init; } = new();
    public YamlMap Override { get; init; } = YamlMap.Empty;
    public List<ProxyConfigEntry>? InlinePayload { get; init; }
}

public sealed class HealthCheckConfig
{
    public bool Enable { get; init; } = true;
    public string Url { get; init; } = "https://www.gstatic.com/generate_204";
    public int Interval { get; init; } = 300;
    public int Timeout { get; init; } = 5000;
    public int Lazy { get; init; }
    public string? ExpectedStatus { get; init; }
}

public sealed class ListenerConfig
{
    public string Name { get; init; } = string.Empty;
    public string Type { get; init; } = string.Empty;
    public int Port { get; init; }
    public string Listen { get; init; } = string.Empty;
    public YamlMap Map { get; init; } = YamlMap.Empty;
    public List<string> Proxy { get; init; } = [];
}
