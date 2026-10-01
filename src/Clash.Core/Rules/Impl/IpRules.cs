using System.Globalization;
using System.Net;
using Clash.Core.Common;

namespace Clash.Core.Rules.Impl;

/// <summary>
/// <c>IP-CIDR</c>, <c>IP-CIDR6</c> and <c>SRC-IP-CIDR</c>. The prefix is tested against
/// every address the engine resolved for the flow, or against the literal destination
/// address when nothing was resolved.
/// </summary>
public sealed class IpCidrRule : IRule, ICanonicalRule
{
    private readonly IpPrefix _prefix;
    private readonly bool _source;

    /// <summary>Creates a CIDR rule.</summary>
    /// <param name="type">The rule type this instance reports.</param>
    /// <param name="prefix">The parsed network prefix.</param>
    /// <param name="adapter">Target adapter name.</param>
    /// <param name="modifiers">Trailing modifiers.</param>
    /// <param name="source">True when the client address rather than the destination is matched.</param>
    public IpCidrRule(RuleType type, IpPrefix prefix, string adapter, RuleModifiers? modifiers = null, bool source = false)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _prefix = prefix;
        _source = source;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => _prefix.ToString();

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    /// <remarks>
    /// A rule that tests the client address needs no DNS lookup: the source is always an
    /// address literal. <c>no-resolve</c> suppresses resolution for the destination too.
    /// </remarks>
    public bool ShouldResolveIp => !_source && !Modifiers.NoResolve;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        if (_source)
        {
            var source = RuleAddresses.Source(metadata);
            return source is not null && _prefix.Contains(source);
        }

        foreach (var address in RuleAddresses.Destination(metadata))
        {
            if (_prefix.Contains(address)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;
}

/// <summary>
/// <c>IP-SUFFIX</c>: matches when the address ends with the payload's significant bits.
/// See <see cref="IpSuffix"/> for the exact interpretation.
/// </summary>
public sealed class IpSuffixRule : IRule, ICanonicalRule
{
    private readonly IpSuffix _suffix;
    private readonly string _payload;
    private readonly bool _source;

    /// <summary>Creates an <c>IP-SUFFIX</c> rule.</summary>
    public IpSuffixRule(string payload, IpSuffix suffix, string adapter, RuleModifiers? modifiers = null, bool source = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = RuleType.IpSuffix;
        RuleTypeName = "IP-SUFFIX";
        _payload = payload.Trim();
        _suffix = suffix;
        _source = source;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => _payload;

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => !_source && !Modifiers.NoResolve;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        if (_source)
        {
            var source = RuleAddresses.Source(metadata);
            return source is not null && _suffix.Matches(source);
        }

        foreach (var address in RuleAddresses.Destination(metadata))
        {
            if (_suffix.Matches(address)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, _payload, Adapter, AdditionalPayload, withAdapter);
}

/// <summary><c>IP-ASN</c> and <c>SRC-IP-ASN</c>: matches the autonomous system of an address.</summary>
public sealed class IpAsnRule : IRule, ICanonicalRule, IGeoDataConsumer
{
    private readonly uint _asn;
    private readonly bool _source;

    /// <summary>Creates an ASN rule.</summary>
    public IpAsnRule(RuleType type, uint asn, string adapter, RuleModifiers? modifiers = null, bool source = false)
    {
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _asn = asn;
        _source = source;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => _asn.ToString(CultureInfo.InvariantCulture);

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <summary>The geo databases consulted for ASN lookups.</summary>
    public IGeoData Geo { get; private set; } = GeoData.Empty;

    /// <inheritdoc />
    public bool ShouldResolveIp => !_source && !Modifiers.NoResolve;

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
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public void SetGeo(IGeoData geo) => Geo = geo ?? GeoData.Empty;

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    private bool Test(IPAddress address)
        => Geo.TryGetAsn(address, out var asn) && asn == _asn;
}
