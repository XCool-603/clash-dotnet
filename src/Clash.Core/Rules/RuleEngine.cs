using System.Collections.Concurrent;
using System.Net;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules.Impl;
using Clash.Core.Tunnel;

namespace Clash.Core.Rules;

/// <summary>
/// The ordered rule list plus the rule-set registry, with first-match-wins evaluation.
/// <para>
/// IP rules ask for the destination to be resolved on demand: the first such rule in a
/// walk triggers one lookup, the addresses are cached on the flow, and every later IP rule
/// reuses them. A failed lookup is not an error, it simply means IP rules cannot match.
/// </para>
/// </summary>
public sealed class RuleEngine : IRuleEngine
{
    private static readonly IReadOnlyDictionary<string, IRuleSet> NoRuleSets =
        new Dictionary<string, IRuleSet>(StringComparer.OrdinalIgnoreCase);

    private static readonly IRule DirectFallback = new MatchRule(WellKnown.Direct);

    /// <summary>
    /// Rules disabled through <c>PATCH /rules</c>. Clash keeps this state for the lifetime of
    /// the process, so it lives outside the engine instance.
    /// </summary>
    private static readonly ConcurrentDictionary<string, byte> DisabledRules = new(StringComparer.OrdinalIgnoreCase);

    private readonly IDnsResolver _dns;
    private readonly IGeoData _geo;

    private volatile IReadOnlyList<IRule> _rules = [];
    private volatile IReadOnlyDictionary<string, IRuleSet> _ruleSets = NoRuleSets;

    /// <summary>Creates an engine with no rules; call <see cref="SetRules"/> before matching.</summary>
    /// <param name="dns">Resolver used when a rule needs the destination resolved.</param>
    /// <param name="geo">Geo databases handed to <c>GEOIP</c>, <c>IP-ASN</c> and <c>GEOSITE</c> rules.</param>
    public RuleEngine(IDnsResolver dns, IGeoData geo)
        : this(dns, geo, null, null)
    {
    }

    /// <summary>Creates an engine and installs a rule list and rule-set registry.</summary>
    /// <param name="dns">Resolver used when a rule needs the destination resolved.</param>
    /// <param name="geo">Geo databases handed to the geo-aware rules.</param>
    /// <param name="rules">The ordered rules, when already built.</param>
    /// <param name="ruleSets">The rule providers backing <c>RULE-SET</c> rules.</param>
    public RuleEngine(
        IDnsResolver dns,
        IGeoData geo,
        IReadOnlyList<IRule>? rules,
        IReadOnlyDictionary<string, IRuleSet>? ruleSets)
    {
        ArgumentNullException.ThrowIfNull(dns);
        ArgumentNullException.ThrowIfNull(geo);

        _dns = dns;
        _geo = geo;

        if (ruleSets is not null) SetRuleSets(ruleSets);
        if (rules is not null) SetRules(rules);
    }

    /// <inheritdoc />
    public IReadOnlyList<IRule> Rules => _rules;

    /// <inheritdoc />
    public IReadOnlyDictionary<string, IRuleSet> RuleSets => _ruleSets;

    /// <summary>The geo databases handed to the geo-aware rules.</summary>
    public IGeoData Geo => _geo;

    /// <inheritdoc />
    public void SetRules(IReadOnlyList<IRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        foreach (var rule in rules) RuleGeo.Inject(rule, _geo);
        _rules = [.. rules];
    }

    /// <summary>Installs the rule providers backing <c>RULE-SET</c> rules.</summary>
    public void SetRuleSets(IReadOnlyDictionary<string, IRuleSet> ruleSets)
    {
        ArgumentNullException.ThrowIfNull(ruleSets);

        foreach (var set in ruleSets.Values) RuleGeo.Inject(set, _geo);
        _ruleSets = new Dictionary<string, IRuleSet>(ruleSets, StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc />
    public async Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        // A special proxy forces the outbound; rules are not consulted at all.
        if (!string.IsNullOrEmpty(metadata.SpecialProxy))
        {
            return new RuleMatch(new MatchRule(metadata.SpecialProxy), metadata.SpecialProxy, -1);
        }

        // SpecialRules may carry pre-parsed rule lines; the first one that matches wins.
        foreach (var special in metadata.SpecialRules)
        {
            if (special.IndexOf(',') < 0) continue;
            if (!RuleParser.TryParse(special, out var specialRule, LookupRuleSet, out _) || specialRule is null) continue;

            if (specialRule.ShouldResolveIp && !metadata.Resolved) await ResolveAsync(metadata, cancellationToken).ConfigureAwait(false);
            if (specialRule.Match(metadata)) return new RuleMatch(specialRule, specialRule.Adapter, -1);
        }

        var rules = _rules;
        for (var i = 0; i < rules.Count; i++)
        {
            var rule = rules[i];
            if (IsDisabled(rule.RuleTypeName, rule.Payload)) continue;

            if (rule.ShouldResolveIp && !metadata.Resolved) await ResolveAsync(metadata, cancellationToken).ConfigureAwait(false);
            if (rule.Match(metadata)) return new RuleMatch(rule, rule.Adapter, i);
        }

        // Built-in fallback: the configured MATCH rule, else DIRECT.
        for (var i = 0; i < rules.Count; i++)
        {
            var rule = rules[i];
            if (rule.Type != RuleType.Match) continue;
            if (IsDisabled(rule.RuleTypeName, rule.Payload)) continue;
            return new RuleMatch(rule, rule.Adapter, i);
        }

        return new RuleMatch(DirectFallback, WellKnown.Direct, -1);
    }

    /// <inheritdoc />
    public bool Disable(string ruleType, string payload) => DisabledRules.TryAdd(Key(ruleType, payload), 0);

    /// <inheritdoc />
    public bool Enable(string ruleType, string payload) => DisabledRules.TryRemove(Key(ruleType, payload), out _);

    /// <inheritdoc />
    public bool IsDisabled(string ruleType, string payload) => DisabledRules.ContainsKey(Key(ruleType, payload));

    /// <summary>
    /// Turns the <c>rules</c> and <c>sub-rules</c> sections of a configuration into the
    /// ordered rule list, expanding <c>SUB-RULE</c> references inline.
    /// </summary>
    /// <param name="config">The configuration to read.</param>
    /// <param name="sets">The rule providers backing <c>RULE-SET</c> rules.</param>
    /// <exception cref="RuleParseException">A rule line is malformed, or names an unknown provider.</exception>
    public static IReadOnlyList<IRule> BuildFromConfig(ClashConfig config, IReadOnlyDictionary<string, IRuleSet> sets)
    {
        ArgumentNullException.ThrowIfNull(config);

        var lookup = BuildLookup(sets);
        var result = new List<IRule>();
        Expand(config.Rules, config.SubRules, lookup, result, 0, null);
        return result;
    }

    /// <summary>Builds the rule-set lookup used by <c>RULE-SET</c> and <c>SUB-RULE</c> parsing.</summary>
    /// <param name="sets">The providers, may be null.</param>
    public static Func<string, IRuleSet?> BuildLookup(IReadOnlyDictionary<string, IRuleSet>? sets)
    {
        if (sets is null || sets.Count == 0) return _ => null;
        return name => sets.TryGetValue(name, out var set) ? set : null;
    }

    private static void Expand(
        IEnumerable<string> lines,
        IReadOnlyDictionary<string, List<string>> subRules,
        Func<string, IRuleSet?> lookup,
        List<IRule> result,
        int depth,
        string? inheritedAdapter)
    {
        if (depth > 16) throw new RuleParseException("sub-rule nesting is too deep (a cycle?)");

        foreach (var raw in lines)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var line = raw.Trim();
            if (line.StartsWith('#')) continue;

            var name = SubRuleName(line);
            if (name is not null && subRules.TryGetValue(name, out var members) && members is not null)
            {
                Expand(members, subRules, lookup, result, depth + 1, SubRuleAdapter(line) ?? inheritedAdapter);
                continue;
            }

            result.Add(RuleParser.ParseWithAdapter(line, inheritedAdapter, lookup));
        }
    }

    private static string? SubRuleName(string line)
    {
        if (!line.StartsWith("SUB-RULE,", StringComparison.OrdinalIgnoreCase)) return null;
        var fields = RuleLine.SplitFields(line);
        if (fields.Count < 2) return null;
        var name = RuleLine.Unwrap(fields[1]);
        return name.Length == 0 ? null : name;
    }

    private static string? SubRuleAdapter(string line)
    {
        var fields = RuleLine.SplitFields(line);
        return fields.Count >= 3 && fields[2].Length > 0 ? fields[2] : null;
    }

    private static string Key(string ruleType, string payload)
        => $"{ruleType}\u0000{payload}";

    private IRuleSet? LookupRuleSet(string name)
        => _ruleSets.TryGetValue(name, out var set) ? set : null;

    private async ValueTask ResolveAsync(Metadata metadata, CancellationToken cancellationToken)
    {
        if (metadata.Resolved) return;

        IPAddress[] addresses = [];
        var host = metadata.RuleHost;

        if (!string.IsNullOrEmpty(host))
        {
            if (IPAddress.TryParse(host, out var literal))
            {
                addresses = [literal];
            }
            else
            {
                try
                {
                    var resolved = await _dns.ResolveAsync(host, true, cancellationToken).ConfigureAwait(false);
                    if (resolved is { Length: > 0 }) addresses = resolved;
                }
                catch (Exception) when (!cancellationToken.IsCancellationRequested)
                {
                    // Resolution failure is not fatal: the IP rules simply cannot match.
                    addresses = [];
                }
            }
        }

        ResolvedAddresses.Set(metadata, addresses);
        metadata.Resolved = true;
    }
}
