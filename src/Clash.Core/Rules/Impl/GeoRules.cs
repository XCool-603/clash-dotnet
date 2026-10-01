using System.Globalization;
using System.Net;
using Clash.Core.Common;

namespace Clash.Core.Rules.Impl;

/// <summary><c>GEOIP</c> and <c>SRC-GEOIP</c>: matches the country of an address.</summary>
/// <remarks>
/// Besides ISO codes, the pseudo countries <c>LAN</c> and <c>PRIVATE</c> are recognised and
/// answered from the RFC1918 / loopback / link-local / ULA ranges, so they work even when
/// no mmdb has been loaded.
/// </remarks>
public sealed class GeoIpRule : IRule, ICanonicalRule, IGeoDataConsumer
{
    private readonly bool _source;

    /// <summary>Creates a geoip rule.</summary>
    /// <param name="type">Either <see cref="RuleType.GeoIp"/> or <see cref="RuleType.SrcGeoIp"/>.</param>
    /// <param name="code">ISO country code, or <c>LAN</c> / <c>PRIVATE</c>.</param>
    /// <param name="adapter">Target adapter name.</param>
    /// <param name="modifiers">Trailing modifiers.</param>
    /// <param name="source">True when the client address rather than the destination is matched.</param>
    public GeoIpRule(RuleType type, string code, string adapter, RuleModifiers? modifiers = null, bool source = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        Code = code.Trim().ToUpperInvariant();
        _source = source || type == RuleType.SrcGeoIp;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => Code;

    /// <summary>The upper-cased country code being matched.</summary>
    public string Code { get; }

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <summary>The geo databases consulted for country lookups.</summary>
    public IGeoData Geo { get; private set; } = GeoData.Empty;

    /// <inheritdoc />
    public bool ShouldResolveIp => !_source && !Modifiers.NoResolve;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        if (_source)
        {
            var source = RuleAddresses.Source(metadata);
            return source is not null && Test(source);
        }

        foreach (var address in RuleAddresses.Destination(metadata))
        {
            if (Test(address)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public void SetGeo(IGeoData geo) => Geo = geo ?? GeoData.Empty;

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    private bool Test(IPAddress address)
    {
        if (Code is "LAN" or "PRIVATE") return RuleAddresses.IsPrivate(address);
        return Geo.TryGetCountry(address, out var country)
            && string.Equals(country, Code, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// <c>GEOSITE</c>: matches the host against a geosite category.
/// <para>
/// A payload may carry an attribute list, e.g. <c>GEOSITE,cn@ipcidr</c>. The
/// <c>ipcidr</c> attribute switches matching to the address lists of the category
/// instead of its domain lists.
/// </para>
/// </summary>
public sealed class GeoSiteRule : IRule, ICanonicalRule, IGeoDataConsumer
{
    private readonly string _code;
    private readonly string? _attribute;

    /// <summary>Creates a geosite rule from a raw payload such as <c>cn</c> or <c>cn@ipcidr</c>.</summary>
    public GeoSiteRule(string payload, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = RuleType.GeoSite;
        RuleTypeName = "GEOSITE";
        Payload = payload.Trim();

        var at = Payload.IndexOf('@');
        if (at < 0)
        {
            _code = Payload.ToUpperInvariant();
            _attribute = null;
        }
        else
        {
            _code = Payload[..at].Trim().ToUpperInvariant();
            _attribute = Payload[(at + 1)..].Trim().ToLowerInvariant();
        }

        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload { get; }

    /// <summary>The category code, without any <c>@attribute</c> suffix.</summary>
    public string Code => _code;

    /// <summary>The <c>@attribute</c> suffix, when the payload carried one.</summary>
    public string? Attribute => _attribute;

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <summary>The geo databases consulted for geosite lookups.</summary>
    public IGeoData Geo { get; private set; } = GeoData.Empty;

    /// <inheritdoc />
    public bool ShouldResolveIp => _attribute == "ipcidr" && !Modifiers.NoResolve;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        if (Geo is IGeoSiteMatcherProvider provider)
        {
            if (_attribute == "ipcidr") return MatchCidrs(provider, metadata);

            var matcher = provider.GetGeoSiteMatcher(_code);
            return matcher is not null && matcher.Match(metadata.RuleHost) >= 0;
        }

        // Foreign IGeoData implementation: fall back to the plain domain list, using the
        // suffix semantics the text geosite format implies.
        if (_attribute == "ipcidr") return false;

        var domains = Geo.GetGeoSite(_code);
        if (domains is null || domains.Count == 0) return false;

        var host = DomainMatcher.Normalize(metadata.RuleHost);
        if (host.Length == 0) return false;

        foreach (var domain in domains)
        {
            var entry = DomainMatcher.Normalize(domain);
            if (entry.Length == 0) continue;
            if (string.Equals(host, entry, StringComparison.Ordinal)) return true;
            if (host.EndsWith("." + entry, StringComparison.Ordinal)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public void SetGeo(IGeoData geo) => Geo = geo ?? GeoData.Empty;

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    private bool MatchCidrs(IGeoSiteMatcherProvider provider, Metadata metadata)
    {
        var matcher = provider.GetGeoSiteCidrMatcher(_code);
        if (matcher is null) return false;

        foreach (var address in RuleAddresses.Destination(metadata))
        {
            if (matcher.Match(address) >= 0) return true;
        }

        return false;
    }
}
