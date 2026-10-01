using System.Net;
using Clash.Core.Common;

namespace Clash.Core.Rules;

/// <summary>Every rule kind Clash/mihomo supports.</summary>
public enum RuleType
{
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    GeoSite,
    GeoIp,
    SrcGeoIp,
    IpCidr,
    IpCidr6,
    IpSuffix,
    IpAsn,
    SrcIpAsn,
    SrcIpCidr,
    SrcPort,
    DstPort,
    InPort,
    InType,
    InUser,
    InName,
    ProcessName,
    ProcessNameRegex,
    ProcessPath,
    ProcessPathRegex,
    Uid,
    Network,
    Dscp,
    RuleSet,
    SubRule,
    And,
    Or,
    Not,
    Match,
}

/// <summary>One routing rule. Matching is synchronous; IP resolution happens in the engine first.</summary>
public interface IRule
{
    RuleType Type { get; }

    /// <summary>Canonical upper-case name, e.g. <c>DOMAIN-SUFFIX</c>.</summary>
    string RuleTypeName { get; }

    /// <summary>The value being matched, e.g. <c>google.com</c>.</summary>
    string Payload { get; }

    /// <summary>Target adapter name, e.g. a proxy group.</summary>
    string Adapter { get; }

    /// <summary>True when the engine must resolve the destination before calling <see cref="Match"/>.</summary>
    bool ShouldResolveIp { get; }

    /// <summary>The <c>no-resolve</c> / <c>src</c> style modifier, when present.</summary>
    string? AdditionalPayload { get; }

    /// <summary>Evaluates this rule against a (possibly resolved) flow.</summary>
    bool Match(Metadata metadata);

    /// <summary>Human readable rendering used by <c>GET /rules</c>.</summary>
    string Description { get; }
}

/// <summary>A rule plus the adapter it resolved to.</summary>
public sealed record RuleMatch(IRule Rule, string AdapterName, int Index);

/// <summary>
/// GeoIP / GeoSite / ASN lookups. Implementations load the mmdb, <c>.dat</c> and
/// ASN databases and expose synchronous probes, since rule matching is hot.
/// </summary>
public interface IGeoData
{
    /// <summary>Loads (or reloads) all configured databases.</summary>
    Task LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>ISO country code for an address, e.g. <c>CN</c>. False when unknown.</summary>
    bool TryGetCountry(IPAddress address, out string countryCode);

    /// <summary>ASN for an address. False when unknown.</summary>
    bool TryGetAsn(IPAddress address, out uint asn);

    /// <summary>Domains belonging to a geosite code, or null when the code is absent.</summary>
    IReadOnlyCollection<string>? GetGeoSite(string code);

    /// <summary>GeoSite entries of the <c>IP</c> category, used to satisfy <c>GEOSITE,x,ipcidr</c>.</summary>
    IReadOnlyList<(IPAddress Network, int PrefixLength)>? GetGeoSiteCidrs(string code);

    /// <summary>True when a geosite code exists in the loaded data.</summary>
    bool HasGeoSite(string code);

    /// <summary>True when a geoip country code exists in the loaded data.</summary>
    bool HasCountry(string code);
}

/// <summary>
/// A named set of rules loaded from a <c>rule-providers</c> entry. Kept separate
/// from <see cref="IRule"/> so a single provider backs one <c>RULE-SET</c> rule.
/// </summary>
public interface IRuleSet
{
    string Name { get; }
    string Behavior { get; }
    int Count { get; }

    /// <summary>True when any entry matches. For <c>ipcidr</c> sets the caller resolves first.</summary>
    bool Match(Metadata metadata);

    /// <summary>True when this set needs the destination resolved to an address.</summary>
    bool ShouldResolveIp { get; }
}

/// <summary>Thrown when a rule line cannot be parsed.</summary>
public sealed class RuleParseException(string rule)
    : ClashException($"invalid rule: {rule}");
