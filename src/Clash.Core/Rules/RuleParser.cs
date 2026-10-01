using System.Globalization;
using Clash.Core.Rules.Impl;

namespace Clash.Core.Rules;

/// <summary>
/// Turns a Clash rule line into an <see cref="IRule"/>, and back again.
/// <para>
/// The grammar is <c>TYPE,PAYLOAD,ADAPTER[,MODIFIER...]</c>. <c>MATCH</c> carries no
/// payload; <c>AND</c>/<c>OR</c>/<c>NOT</c> carry a parenthesised list of nested rules,
/// so field splitting is parenthesis-aware.
/// </para>
/// </summary>
public static class RuleParser
{
    /// <summary>Parses a rule line, throwing <see cref="RuleParseException"/> when it is malformed.</summary>
    /// <param name="line">The rule line.</param>
    /// <param name="ruleSetLookup">Resolves <c>RULE-SET</c> and <c>SUB-RULE</c> names.</param>
    public static IRule Parse(string line, Func<string, IRuleSet?>? ruleSetLookup = null)
    {
        if (!TryParse(line, out var rule, ruleSetLookup, out var error) || rule is null)
        {
            throw new RuleParseException($"{line?.Trim()} ({error ?? "invalid rule"})");
        }

        return rule;
    }

    /// <summary>Parses a rule line without throwing.</summary>
    /// <param name="line">The rule line.</param>
    /// <param name="rule">The parsed rule, or null.</param>
    /// <param name="error">Why parsing failed, when it did.</param>
    public static bool TryParse(string line, out IRule? rule, out string? error)
        => TryParse(line, out rule, null, out error);

    /// <summary>Parses a rule line without throwing.</summary>
    /// <param name="line">The rule line.</param>
    /// <param name="rule">The parsed rule, or null.</param>
    /// <param name="ruleSetLookup">Resolves <c>RULE-SET</c> and <c>SUB-RULE</c> names.</param>
    /// <param name="error">Why parsing failed, when it did.</param>
    /// <remarks>
    /// <paramref name="ruleSetLookup"/> is required here rather than optional: C# does not
    /// allow a required <c>out</c> parameter to follow an optional one, so the two-parameter
    /// convenience overload above carries the "no lookup" case instead.
    /// </remarks>
    public static bool TryParse(string line, out IRule? rule, Func<string, IRuleSet?>? ruleSetLookup, out string? error)
    {
        rule = null;
        error = null;

        if (string.IsNullOrWhiteSpace(line))
        {
            error = "empty rule line";
            return false;
        }

        return TryParseCore(line.Trim(), null, ruleSetLookup, out rule, out error);
    }

    /// <summary>Renders a rule as its canonical Clash line, which is what <c>GET /rules</c> returns.</summary>
    public static string Format(IRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule is ICanonicalRule canonical) return canonical.FormatRule(true);

        var builder = new System.Text.StringBuilder(rule.RuleTypeName);
        if (rule.Type != RuleType.Match) builder.Append(',').Append(rule.Payload);
        builder.Append(',').Append(rule.Adapter);
        if (!string.IsNullOrEmpty(rule.AdditionalPayload)) builder.Append(',').Append(rule.AdditionalPayload);
        return builder.ToString();
    }

    /// <summary>Renders a nested rule, i.e. without the adapter field.</summary>
    internal static string FormatNested(IRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        if (rule is ICanonicalRule canonical) return canonical.FormatRule(false);

        var builder = new System.Text.StringBuilder(rule.RuleTypeName);
        if (rule.Type != RuleType.Match) builder.Append(',').Append(rule.Payload);
        if (!string.IsNullOrEmpty(rule.AdditionalPayload)) builder.Append(',').Append(rule.AdditionalPayload);
        return builder.ToString();
    }

    /// <summary>
    /// Parses a rule-provider line, where the adapter is optional and ignored. Falls back to
    /// treating every trailing field as a modifier when the normal form does not parse.
    /// </summary>
    internal static bool TryParseClassical(string line, Func<string, IRuleSet?>? ruleSetLookup, out IRule? rule, out string? error)
    {
        rule = null;
        error = null;

        if (string.IsNullOrWhiteSpace(line))
        {
            error = "empty rule line";
            return false;
        }

        var text = line.Trim();
        if (TryParseCore(text, null, ruleSetLookup, out rule, out error) && rule is not null) return true;
        return TryParseCore(text, string.Empty, ruleSetLookup, out rule, out error) && rule is not null;
    }

    /// <summary>
    /// Parses a sub-rule member: its own adapter wins, otherwise the adapter of the
    /// <c>SUB-RULE</c> reference that pulled it in is used.
    /// </summary>
    internal static IRule ParseWithAdapter(string line, string? inheritedAdapter, Func<string, IRuleSet?>? ruleSetLookup)
    {
        ArgumentNullException.ThrowIfNull(line);

        var text = line.Trim();
        if (TryParseCore(text, null, ruleSetLookup, out var rule, out _) && rule is not null) return rule;

        if (inheritedAdapter is not null
            && TryParseCore(text, inheritedAdapter, ruleSetLookup, out rule, out var error)
            && rule is not null)
        {
            return rule;
        }

        // Re-run the strict form so the exception carries the real reason.
        return Parse(text, ruleSetLookup);
    }

    private static bool TryParseCore(string text, string? forcedAdapter, Func<string, IRuleSet?>? ruleSetLookup, out IRule? rule, out string? error)
    {
        rule = null;
        error = null;

        var fields = RuleLine.SplitFields(text);
        if (fields.Count == 0 || fields[0].Length == 0)
        {
            error = "missing rule type";
            return false;
        }

        var typeName = fields[0].ToUpperInvariant();

        if (typeName == "MATCH")
        {
            var matchAdapter = forcedAdapter ?? (fields.Count > 1 ? fields[1] : null);
            if (string.IsNullOrEmpty(matchAdapter))
            {
                error = "MATCH requires an adapter";
                return false;
            }

            rule = new MatchRule(matchAdapter, RuleModifiers.FromTokens(fields.Skip(forcedAdapter is null ? 2 : 1)));
            return true;
        }

        if (fields.Count < 2)
        {
            error = $"{typeName} requires a payload";
            return false;
        }

        var payload = fields[1];
        if (payload.Length == 0)
        {
            error = $"{typeName} requires a non-empty payload";
            return false;
        }

        string adapter;
        IEnumerable<string> modifierFields;
        if (forcedAdapter is not null)
        {
            adapter = forcedAdapter;
            modifierFields = fields.Skip(2);
        }
        else
        {
            if (fields.Count < 3 || fields[2].Length == 0)
            {
                error = $"{typeName} requires an adapter";
                return false;
            }

            adapter = fields[2];
            modifierFields = fields.Skip(3);
        }

        var modifiers = RuleModifiers.FromTokens(modifierFields);

        switch (typeName)
        {
            case "DOMAIN":
                rule = new DomainRule(RuleType.Domain, DomainMatchKind.Full, payload, adapter, modifiers);
                return true;

            case "DOMAIN-SUFFIX":
                rule = new DomainRule(RuleType.DomainSuffix, DomainMatchKind.Suffix, payload, adapter, modifiers);
                return true;

            case "DOMAIN-KEYWORD":
                rule = new DomainRule(RuleType.DomainKeyword, DomainMatchKind.Keyword, payload, adapter, modifiers);
                return true;

            case "DOMAIN-REGEX":
                if (!DomainRule.TryValidateRegex(payload, out error)) return false;
                rule = new DomainRule(RuleType.DomainRegex, DomainMatchKind.Regex, payload, adapter, modifiers);
                return true;

            case "GEOSITE":
                rule = new GeoSiteRule(payload, adapter, modifiers);
                return true;

            case "GEOIP":
                rule = new GeoIpRule(RuleType.GeoIp, payload, adapter, modifiers);
                return true;

            case "SRC-GEOIP":
                rule = new GeoIpRule(RuleType.SrcGeoIp, payload, adapter, modifiers);
                return true;

            case "IP-CIDR":
            case "IP-CIDR6":
            case "SRC-IP-CIDR":
            {
                if (!IpPrefix.TryParse(payload, out var prefix))
                {
                    error = $"{typeName} payload '{payload}' is not a valid CIDR";
                    return false;
                }

                var source = typeName == "SRC-IP-CIDR" || modifiers.Src;
                var type = typeName switch
                {
                    "SRC-IP-CIDR" => RuleType.SrcIpCidr,
                    "IP-CIDR6" => RuleType.IpCidr6,
                    _ => RuleType.IpCidr,
                };

                rule = new IpCidrRule(type, prefix, adapter, modifiers, source);
                return true;
            }

            case "IP-SUFFIX":
            {
                if (!IpSuffix.TryParse(payload, out var suffix))
                {
                    error = $"IP-SUFFIX payload '{payload}' is not a valid address";
                    return false;
                }

                rule = new IpSuffixRule(payload, suffix, adapter, modifiers, modifiers.Src);
                return true;
            }

            case "IP-ASN":
            case "SRC-IP-ASN":
            {
                if (!uint.TryParse(payload, NumberStyles.Integer, CultureInfo.InvariantCulture, out var asn))
                {
                    error = $"{typeName} payload '{payload}' is not a valid ASN";
                    return false;
                }

                var source = typeName == "SRC-IP-ASN" || modifiers.Src;
                var type = typeName == "SRC-IP-ASN" ? RuleType.SrcIpAsn : RuleType.IpAsn;
                rule = new IpAsnRule(type, asn, adapter, modifiers, source);
                return true;
            }

            case "SRC-PORT":
            case "DST-PORT":
            case "IN-PORT":
            {
                if (!PortSelector.TryParse(payload, out var selector))
                {
                    error = $"{typeName} payload '{payload}' is not a valid port or port range";
                    return false;
                }

                var type = typeName switch
                {
                    "SRC-PORT" => RuleType.SrcPort,
                    "DST-PORT" => RuleType.DstPort,
                    _ => RuleType.InPort,
                };

                rule = new PortRule(type, selector, adapter, modifiers);
                return true;
            }

            case "IN-TYPE":
                rule = new TextFieldRule(RuleType.InType, MetadataTextField.InboundType, payload, adapter, modifiers);
                return true;

            case "IN-USER":
                rule = new TextFieldRule(RuleType.InUser, MetadataTextField.InboundUser, payload, adapter, modifiers);
                return true;

            case "IN-NAME":
                rule = new TextFieldRule(RuleType.InName, MetadataTextField.InboundName, payload, adapter, modifiers);
                return true;

            case "PROCESS-NAME":
                rule = new TextFieldRule(RuleType.ProcessName, MetadataTextField.ProcessName, payload, adapter, modifiers, allowList: false);
                return true;

            case "PROCESS-PATH":
                rule = new TextFieldRule(RuleType.ProcessPath, MetadataTextField.ProcessPath, payload, adapter, modifiers, allowList: false);
                return true;

            case "PROCESS-NAME-REGEX":
                if (!TryValidateRegex(payload, out error)) return false;
                rule = new RegexFieldRule(RuleType.ProcessNameRegex, MetadataTextField.ProcessName, payload, adapter, modifiers);
                return true;

            case "PROCESS-PATH-REGEX":
                if (!TryValidateRegex(payload, out error)) return false;
                rule = new RegexFieldRule(RuleType.ProcessPathRegex, MetadataTextField.ProcessPath, payload, adapter, modifiers);
                return true;

            case "UID":
                rule = new UidRule(payload, adapter, modifiers);
                return true;

            case "NETWORK":
                rule = new NetworkRule(payload, adapter, modifiers);
                return true;

            case "DSCP":
                rule = new DscpRule(payload, adapter, modifiers);
                return true;

            case "RULE-SET":
            {
                var set = Resolve(ruleSetLookup, payload, "RULE-SET", out error);
                if (set is null) return false;
                rule = new RuleSetRule(set, adapter, modifiers);
                return true;
            }

            case "SUB-RULE":
            {
                var name = RuleLine.Unwrap(payload);
                var set = Resolve(ruleSetLookup, name, "SUB-RULE", out error);
                if (set is null) return false;
                rule = new SubRuleRule(name, set, adapter, modifiers);
                return true;
            }

            case "AND":
            case "OR":
            case "NOT":
                return TryParseLogical(typeName, payload, adapter, modifiers, ruleSetLookup, out rule, out error);

            default:
                error = $"unknown rule type '{typeName}'";
                return false;
        }
    }

    private static bool TryParseLogical(
        string typeName,
        string payload,
        string adapter,
        RuleModifiers modifiers,
        Func<string, IRuleSet?>? ruleSetLookup,
        out IRule? rule,
        out string? error)
    {
        rule = null;
        error = null;

        var members = RuleLine.SplitMembers(payload);
        if (members.Count == 0)
        {
            error = $"{typeName} requires at least one nested rule";
            return false;
        }

        if (typeName == "NOT" && members.Count != 1)
        {
            error = "NOT requires exactly one nested rule";
            return false;
        }

        var parsed = new List<IRule>(members.Count);
        foreach (var member in members)
        {
            var text = RuleLine.Unwrap(member);
            if (text.Length == 0)
            {
                error = $"{typeName} contains an empty nested rule";
                return false;
            }

            if (!TryParseCore(text, string.Empty, ruleSetLookup, out var nested, out var nestedError) || nested is null)
            {
                error = $"{typeName} nested rule '{text}' is invalid: {nestedError}";
                return false;
            }

            parsed.Add(nested);
        }

        var type = typeName switch
        {
            "AND" => RuleType.And,
            "OR" => RuleType.Or,
            _ => RuleType.Not,
        };

        rule = new LogicalRule(type, parsed, adapter, modifiers);
        return true;
    }

    private static IRuleSet? Resolve(Func<string, IRuleSet?>? lookup, string name, string typeName, out string? error)
    {
        error = null;
        if (lookup is null)
        {
            error = $"{typeName} '{name}' cannot be resolved: no rule-set lookup was supplied";
            return null;
        }

        IRuleSet? set;
        try
        {
            set = lookup(name);
        }
        catch (Exception ex)
        {
            error = $"{typeName} '{name}' lookup failed: {ex.Message}";
            return null;
        }

        if (set is null)
        {
            error = $"{typeName} '{name}' is not defined";
            return null;
        }

        return set;
    }

    private static bool TryValidateRegex(string pattern, out string? error)
    {
        error = null;
        try
        {
            _ = DomainMatcher.CompileRegex(pattern);
            return true;
        }
        catch (ArgumentException ex)
        {
            error = $"invalid regular expression '{pattern}': {ex.Message}";
            return false;
        }
    }
}
