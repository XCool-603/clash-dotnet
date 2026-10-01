using System.Text;

namespace Clash.Core.Rules;

/// <summary>Canonical upper-case names for every <see cref="RuleType"/>.</summary>
public static class RuleNames
{
    /// <summary>Returns the canonical Clash name of a rule type, e.g. <c>DOMAIN-SUFFIX</c>.</summary>
    public static string Of(RuleType type) => type switch
    {
        RuleType.Domain => "DOMAIN",
        RuleType.DomainSuffix => "DOMAIN-SUFFIX",
        RuleType.DomainKeyword => "DOMAIN-KEYWORD",
        RuleType.DomainRegex => "DOMAIN-REGEX",
        RuleType.GeoSite => "GEOSITE",
        RuleType.GeoIp => "GEOIP",
        RuleType.SrcGeoIp => "SRC-GEOIP",
        RuleType.IpCidr => "IP-CIDR",
        RuleType.IpCidr6 => "IP-CIDR6",
        RuleType.IpSuffix => "IP-SUFFIX",
        RuleType.IpAsn => "IP-ASN",
        RuleType.SrcIpAsn => "SRC-IP-ASN",
        RuleType.SrcIpCidr => "SRC-IP-CIDR",
        RuleType.SrcPort => "SRC-PORT",
        RuleType.DstPort => "DST-PORT",
        RuleType.InPort => "IN-PORT",
        RuleType.InType => "IN-TYPE",
        RuleType.InUser => "IN-USER",
        RuleType.InName => "IN-NAME",
        RuleType.ProcessName => "PROCESS-NAME",
        RuleType.ProcessNameRegex => "PROCESS-NAME-REGEX",
        RuleType.ProcessPath => "PROCESS-PATH",
        RuleType.ProcessPathRegex => "PROCESS-PATH-REGEX",
        RuleType.Uid => "UID",
        RuleType.Network => "NETWORK",
        RuleType.Dscp => "DSCP",
        RuleType.RuleSet => "RULE-SET",
        RuleType.SubRule => "SUB-RULE",
        RuleType.And => "AND",
        RuleType.Or => "OR",
        RuleType.Not => "NOT",
        RuleType.Match => "MATCH",
        _ => type.ToString().ToUpperInvariant(),
    };

    /// <summary>Parses a rule type name, case-insensitively.</summary>
    public static bool TryParse(string? name, out RuleType type)
    {
        type = RuleType.Match;
        if (string.IsNullOrWhiteSpace(name)) return false;
        var value = name.Trim();
        for (var candidate = RuleType.Domain; candidate <= RuleType.Match; candidate = (RuleType)((int)candidate + 1))
        {
            if (string.Equals(Of(candidate), value, StringComparison.OrdinalIgnoreCase))
            {
                type = candidate;
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// The trailing <c>no-resolve</c> / <c>src</c> modifiers of an IP-family rule.
/// Unknown tokens are preserved so that <see cref="RuleParser.Format"/> round-trips
/// lines this build does not understand.
/// </summary>
public sealed class RuleModifiers
{
    /// <summary>No modifiers at all.</summary>
    public static readonly RuleModifiers None = new([]);

    private readonly string[] _tokens;

    private RuleModifiers(string[] tokens) => _tokens = tokens;

    /// <summary>The modifiers exactly as they appeared, in order.</summary>
    public IReadOnlyList<string> Tokens => _tokens;

    /// <summary>The modifiers re-joined with commas; empty when there are none.</summary>
    public string Raw => _tokens.Length == 0 ? string.Empty : string.Join(',', _tokens);

    /// <summary>True when the rule is marked <c>no-resolve</c>.</summary>
    public bool NoResolve => Has("no-resolve");

    /// <summary>True when the rule is marked <c>src</c>, i.e. it matches the source address.</summary>
    public bool Src => Has("src");

    /// <summary>True when the given modifier token is present, ignoring case.</summary>
    public bool Has(string token)
    {
        foreach (var candidate in _tokens)
        {
            if (string.Equals(candidate, token, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    /// <summary>Builds a modifier set from raw trailing fields.</summary>
    public static RuleModifiers FromTokens(IEnumerable<string>? tokens)
    {
        if (tokens is null) return None;
        var list = new List<string>();
        foreach (var token in tokens)
        {
            var value = token.Trim();
            if (value.Length > 0) list.Add(value);
        }

        return list.Count == 0 ? None : new RuleModifiers([.. list]);
    }
}

/// <summary>Internal contract letting <see cref="RuleParser.Format"/> render a built-in rule.</summary>
internal interface ICanonicalRule
{
    /// <summary>
    /// Renders the rule as a Clash line. When <paramref name="withAdapter"/> is false the
    /// adapter field is omitted, which is how nested <c>AND</c>/<c>OR</c>/<c>NOT</c> members render.
    /// </summary>
    string FormatRule(bool withAdapter);
}

/// <summary>Internal contract for rules that consult the geo databases.</summary>
public interface IGeoDataConsumer
{
    /// <summary>Supplies the geo databases this rule must use. Called by <see cref="RuleEngine"/>.</summary>
    void SetGeo(IGeoData geo);
}

/// <summary>
/// Optional capability of an <see cref="IGeoData"/> implementation that can hand out
/// pre-built matchers for a geosite category. <see cref="GeoData"/> implements it, which
/// keeps <c>GEOSITE</c> matching O(labels) instead of a linear scan per connection.
/// </summary>
public interface IGeoSiteMatcherProvider
{
    /// <summary>A matcher over the domain entries of a geosite code, or null when the code is absent.</summary>
    DomainMatcher? GetGeoSiteMatcher(string code);

    /// <summary>A matcher over the <c>ipcidr</c> entries of a geosite code, or null when there are none.</summary>
    CidrMatcher? GetGeoSiteCidrMatcher(string code);
}

/// <summary>Composes canonical rule lines.</summary>
internal static class Canonical
{
    /// <summary>Joins the fields of a rule line, skipping the adapter and modifiers when absent.</summary>
    public static string Line(string typeName, string? payload, string adapter, string? modifiers, bool withAdapter)
    {
        var builder = new StringBuilder(typeName);
        if (payload is not null) builder.Append(',').Append(payload);
        if (withAdapter) builder.Append(',').Append(adapter);
        if (!string.IsNullOrEmpty(modifiers)) builder.Append(',').Append(modifiers);
        return builder.ToString();
    }
}

/// <summary>Splitting helpers shared by the parser, the rule sets and the config builder.</summary>
internal static class RuleLine
{
    /// <summary>
    /// Splits a rule line on commas, ignoring commas nested inside parentheses so that
    /// <c>AND,((DOMAIN-SUFFIX,a.com),(NETWORK,tcp)),PROXY</c> yields three fields.
    /// </summary>
    public static List<string> SplitFields(string line)
    {
        var fields = new List<string>();
        var builder = new StringBuilder();
        var depth = 0;

        foreach (var ch in line)
        {
            switch (ch)
            {
                case '(':
                    depth++;
                    break;
                case ')':
                    if (depth > 0) depth--;
                    break;
                case ',' when depth == 0:
                    fields.Add(builder.ToString().Trim());
                    builder.Clear();
                    continue;
            }

            builder.Append(ch);
        }

        fields.Add(builder.ToString().Trim());
        return fields;
    }

    /// <summary>Removes one layer of surrounding parentheses, when present.</summary>
    public static string Unwrap(string value)
    {
        var text = value.Trim();
        if (text.Length >= 2 && text[0] == '(' && text[^1] == ')') text = text[1..^1].Trim();
        return text;
    }

    /// <summary>
    /// Splits the parenthesised member list of a logical rule into its member expressions,
    /// e.g. <c>((A,a),(B,b))</c> becomes <c>(A,a)</c> and <c>(B,b)</c>.
    /// </summary>
    public static List<string> SplitMembers(string payload)
    {
        var inner = payload.Trim();
        if (inner.Length >= 2 && inner[0] == '(' && inner[^1] == ')') inner = inner[1..^1];

        var members = new List<string>();
        var builder = new StringBuilder();
        var depth = 0;

        foreach (var ch in inner)
        {
            switch (ch)
            {
                case '(':
                    depth++;
                    break;
                case ')':
                    if (depth > 0) depth--;
                    break;
                case ',' when depth == 0:
                    members.Add(builder.ToString().Trim());
                    builder.Clear();
                    continue;
            }

            builder.Append(ch);
        }

        var tail = builder.ToString().Trim();
        if (tail.Length > 0) members.Add(tail);
        return members.Where(m => m.Length > 0).ToList();
    }
}

/// <summary>Injects the geo databases into whatever rules need them.</summary>
internal static class RuleGeo
{
    /// <summary>Walks a rule (and its children) handing every geo consumer the same database.</summary>
    public static void Inject(IRule? rule, IGeoData geo)
    {
        if (rule is IGeoDataConsumer consumer) consumer.SetGeo(geo);
    }

    /// <summary>Injects the geo databases into a rule set, when it needs them.</summary>
    public static void Inject(IRuleSet? set, IGeoData geo)
    {
        if (set is IGeoDataConsumer consumer) consumer.SetGeo(geo);
    }
}
