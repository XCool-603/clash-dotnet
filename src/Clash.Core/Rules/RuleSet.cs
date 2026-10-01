using Clash.Core.Common;
using YamlDotNet.Core;

namespace Clash.Core.Rules;

/// <summary>
/// A named rule provider. Clash defines three behaviours:
/// <list type="bullet">
///   <item><description><c>domain</c> — domain entries, matched through a <see cref="DomainMatcher"/>.</description></item>
///   <item><description><c>ipcidr</c> — CIDR entries, matched through a <see cref="CidrMatcher"/>.</description></item>
///   <item><description><c>classical</c> — complete rule lines whose adapter is ignored.</description></item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// A <c>domain</c> entry follows the geosite conventions: <c>full:</c> is an exact match,
/// <c>domain:</c>, a leading <c>+.</c> and a plain entry are suffix matches, <c>keyword:</c>
/// is a substring and <c>regexp:</c> a regular expression. A plain entry being a suffix
/// match mirrors v2ray's <c>Plain</c> domain type.
/// </para>
/// <para>
/// An <c>ipcidr</c> entry may be a bare CIDR or a classical line such as
/// <c>IP-CIDR,1.2.3.0/24</c>; <c>IP-SUFFIX</c> lines are accepted too.
/// </para>
/// </remarks>
public sealed class RuleSet : IRuleSet, IGeoDataConsumer
{
    private readonly DomainMatcher? _domains;
    private readonly CidrMatcher? _cidrs;
    private readonly IRule[] _rules;

    private RuleSet(string name, string behavior, DomainMatcher? domains, CidrMatcher? cidrs, IRule[] rules, bool resolve, int count)
    {
        Name = name;
        Behavior = behavior;
        _domains = domains;
        _cidrs = cidrs;
        _rules = rules;
        ShouldResolveIp = resolve;
        Count = count;
    }

    /// <inheritdoc />
    public string Name { get; }

    /// <inheritdoc />
    public string Behavior { get; }

    /// <inheritdoc />
    public int Count { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp { get; }

    /// <summary>The classical rules of the set; empty for the other behaviours.</summary>
    public IReadOnlyList<IRule> Rules => _rules;

    /// <summary>Builds a set from an already-split payload.</summary>
    /// <param name="name">Provider name.</param>
    /// <param name="behavior"><c>domain</c>, <c>ipcidr</c> or <c>classical</c>.</param>
    /// <param name="payload">The payload entries.</param>
    public static IRuleSet FromPayload(string name, string behavior, IEnumerable<string> payload)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(payload);

        var entries = new List<string>();
        foreach (var line in payload)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var trimmed = line.Trim();
            if (trimmed.StartsWith('#')) continue;
            entries.Add(trimmed);
        }

        return behavior?.Trim().ToLowerInvariant() switch
        {
            "ipcidr" or "ip-cidr" => BuildCidr(name, entries),
            "classical" => BuildClassical(name, entries),
            _ => BuildDomain(name, entries),
        };
    }

    /// <summary>Builds a set from the YAML a rule provider serves, i.e. a <c>payload:</c> sequence.</summary>
    /// <param name="name">Provider name.</param>
    /// <param name="behavior"><c>domain</c>, <c>ipcidr</c> or <c>classical</c>.</param>
    /// <param name="yamlText">The provider document.</param>
    public static IRuleSet FromYaml(string name, string behavior, string yamlText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(yamlText);

        object? raw;
        try
        {
            raw = new YamlDotNet.Serialization.DeserializerBuilder().Build().Deserialize<object?>(yamlText);
        }
        catch (YamlException)
        {
            // Not YAML after all; fall back to the line-oriented form.
            return FromText(name, behavior, yamlText);
        }

        var entries = new List<string>();
        switch (YamlMap.Normalize(raw))
        {
            case Dictionary<string, object?> map when map.TryGetValue("payload", out var payload):
                Flatten(payload, entries);
                break;
            case List<object?> list:
                Flatten(list, entries);
                break;
        }

        // A document that yielded no payload was not a rule provider after all.
        if (entries.Count == 0 && !yamlText.Contains("payload:", StringComparison.OrdinalIgnoreCase))
        {
            return FromText(name, behavior, yamlText);
        }

        return FromPayload(name, behavior, entries);
    }

    /// <summary>
    /// Builds a set from plain text: one entry per line, or the YAML form when the text
    /// contains a <c>payload:</c> key.
    /// </summary>
    /// <param name="name">Provider name.</param>
    /// <param name="behavior"><c>domain</c>, <c>ipcidr</c> or <c>classical</c>.</param>
    /// <param name="text">The provider body.</param>
    public static IRuleSet FromText(string name, string behavior, string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(text);

        if (text.Contains("payload:", StringComparison.OrdinalIgnoreCase)) return FromYaml(name, behavior, text);

        var entries = new List<string>();
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim().TrimEnd('\r');
            if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
            entries.Add(trimmed.StartsWith("- ", StringComparison.Ordinal) ? trimmed[2..].Trim().Trim('"', '\'') : trimmed);
        }

        return FromPayload(name, behavior, entries);
    }

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        if (_domains is not null) return _domains.Match(metadata.RuleHost) >= 0;

        if (_cidrs is not null)
        {
            foreach (var address in RuleAddresses.Destination(metadata))
            {
                if (_cidrs.Match(address) >= 0) return true;
            }

            return false;
        }

        foreach (var rule in _rules)
        {
            if (rule.Match(metadata)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public void SetGeo(IGeoData geo)
    {
        foreach (var rule in _rules) RuleGeo.Inject(rule, geo);
    }

    private static IRuleSet BuildDomain(string name, List<string> entries)
    {
        var matcher = new DomainMatcher();
        var index = 0;
        var count = 0;

        foreach (var entry in entries)
        {
            if (!TryDomainEntry(entry, out var value, out var kind)) continue;
            try
            {
                matcher.Add(value, kind, index);
            }
            catch (ArgumentException)
            {
                continue;
            }

            index++;
            count++;
        }

        return new RuleSet(name, "domain", matcher, null, [], false, count);
    }

    private static IRuleSet BuildCidr(string name, List<string> entries)
    {
        var matcher = new CidrMatcher();
        var index = 0;
        var count = 0;

        foreach (var entry in entries)
        {
            if (!TryCidrEntry(entry, out var prefix, out var suffix, out var isSuffix)) continue;
            if (isSuffix) matcher.AddSuffix(suffix, index);
            else matcher.Add(prefix, index);
            index++;
            count++;
        }

        return new RuleSet(name, "ipcidr", null, matcher, [], count > 0, count);
    }

    private static IRuleSet BuildClassical(string name, List<string> entries)
    {
        var rules = new List<IRule>();
        var resolve = false;

        foreach (var entry in entries)
        {
            if (!RuleParser.TryParseClassical(entry, null, out var rule, out _) || rule is null) continue;
            rules.Add(rule);
            resolve |= rule.ShouldResolveIp;
        }

        return new RuleSet(name, "classical", null, null, [.. rules], resolve, rules.Count);
    }

    private static bool TryDomainEntry(string entry, out string value, out DomainMatchKind kind)
    {
        var text = entry.Trim();
        kind = DomainMatchKind.Suffix;

        if (text.StartsWith("full:", StringComparison.OrdinalIgnoreCase))
        {
            kind = DomainMatchKind.Full;
            text = text[5..];
        }
        else if (text.StartsWith("domain:", StringComparison.OrdinalIgnoreCase))
        {
            text = text[7..];
        }
        else if (text.StartsWith("keyword:", StringComparison.OrdinalIgnoreCase))
        {
            kind = DomainMatchKind.Keyword;
            text = text[8..];
        }
        else if (text.StartsWith("regexp:", StringComparison.OrdinalIgnoreCase))
        {
            kind = DomainMatchKind.Regex;
            text = text[7..];
        }
        else if (text.StartsWith("+.", StringComparison.Ordinal))
        {
            text = text[2..];
        }
        else if (text.StartsWith('.'))
        {
            text = text[1..];
        }

        value = text.Trim();
        return value.Length > 0;
    }

    private static bool TryCidrEntry(string entry, out IpPrefix prefix, out IpSuffix suffix, out bool isSuffix)
    {
        prefix = default;
        suffix = default;
        isSuffix = false;

        var text = entry.Trim();
        var comma = text.IndexOf(',');
        if (comma >= 0)
        {
            var typeName = text[..comma].Trim().ToUpperInvariant();
            var fields = RuleLine.SplitFields(text);
            if (fields.Count < 2) return false;

            text = fields[1];
            switch (typeName)
            {
                case "IP-CIDR":
                case "IP-CIDR6":
                case "SRC-IP-CIDR":
                    break;
                case "IP-SUFFIX":
                    isSuffix = true;
                    break;
                default:
                    return false;
            }
        }

        if (isSuffix) return IpSuffix.TryParse(text, out suffix);
        return IpPrefix.TryParse(text, out prefix);
    }

    private static void Flatten(object? node, List<string> into)
    {
        switch (node)
        {
            case null:
                return;
            case string text:
                if (!string.IsNullOrWhiteSpace(text)) into.Add(text.Trim());
                return;
            case IEnumerable<object?> list:
                foreach (var item in list) Flatten(item, into);
                return;
            case Dictionary<string, object?> map:
                foreach (var key in new[] { "domain", "ip", "value", "payload" })
                {
                    if (map.TryGetValue(key, out var inner) && inner is not null)
                    {
                        Flatten(inner, into);
                        return;
                    }
                }

                return;
            default:
                var rendered = Convert.ToString(node, System.Globalization.CultureInfo.InvariantCulture);
                if (!string.IsNullOrWhiteSpace(rendered)) into.Add(rendered.Trim());
                return;
        }
    }
}
