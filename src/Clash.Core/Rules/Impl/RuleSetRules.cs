using Clash.Core.Common;

namespace Clash.Core.Rules.Impl;

/// <summary>
/// <c>RULE-SET,name,ADAPTER</c>: delegates to a named <see cref="IRuleSet"/> resolved at
/// parse time. The set's own <see cref="IRuleSet.ShouldResolveIp"/> drives resolution,
/// unless the rule carries <c>no-resolve</c>.
/// </summary>
public sealed class RuleSetRule : IRule, ICanonicalRule, IGeoDataConsumer
{
    /// <summary>Creates a rule-set rule.</summary>
    public RuleSetRule(IRuleSet ruleSet, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentNullException.ThrowIfNull(ruleSet);
        ArgumentNullException.ThrowIfNull(adapter);

        RuleSet = ruleSet;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type => RuleType.RuleSet;

    /// <inheritdoc />
    public string RuleTypeName => "RULE-SET";

    /// <inheritdoc />
    public string Payload => RuleSet.Name;

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>The provider this rule delegates to.</summary>
    public IRuleSet RuleSet { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => !Modifiers.NoResolve && RuleSet.ShouldResolveIp;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata) => RuleSet.Match(metadata);

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <summary>Forwards the geo databases to the backing set.</summary>
    public void SetGeo(IGeoData geo) => RuleGeo.Inject(RuleSet, geo);

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line("RULE-SET", RuleSet.Name, Adapter, AdditionalPayload, withAdapter);
}

/// <summary>
/// <c>SUB-RULE,(name),ADAPTER</c>: delegates to a named sub-rule list. The list is either
/// expanded inline by <see cref="RuleEngine.BuildFromConfig"/> or supplied through the
/// same lookup used by <c>RULE-SET</c>.
/// </summary>
public sealed class SubRuleRule : IRule, ICanonicalRule, IGeoDataConsumer
{
    /// <summary>Creates a sub-rule.</summary>
    public SubRuleRule(string name, IRuleSet ruleSet, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(ruleSet);
        ArgumentNullException.ThrowIfNull(adapter);

        Name = name.Trim();
        RuleSet = ruleSet;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type => RuleType.SubRule;

    /// <inheritdoc />
    public string RuleTypeName => "SUB-RULE";

    /// <inheritdoc />
    public string Payload => Name;

    /// <summary>The sub-rule list name, without the parentheses Clash writes.</summary>
    public string Name { get; }

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>The set backing this sub-rule.</summary>
    public IRuleSet RuleSet { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => !Modifiers.NoResolve && RuleSet.ShouldResolveIp;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata) => RuleSet.Match(metadata);

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <summary>Forwards the geo databases to the backing set.</summary>
    public void SetGeo(IGeoData geo) => RuleGeo.Inject(RuleSet, geo);

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line("SUB-RULE", $"({Name})", Adapter, AdditionalPayload, withAdapter);
}
