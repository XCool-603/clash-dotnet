using Clash.Core.Common;

namespace Clash.Core.Rules.Impl;

/// <summary>
/// <c>DOMAIN</c>, <c>DOMAIN-SUFFIX</c>, <c>DOMAIN-KEYWORD</c> and <c>DOMAIN-REGEX</c>.
/// All four share the same reverse-label trie so that the per-connection cost is
/// proportional to the number of labels in the host, not to the number of rules.
/// </summary>
public sealed class DomainRule : IRule, ICanonicalRule
{
    private readonly DomainMatcher _matcher;
    private readonly string _payload;

    /// <summary>Creates a domain rule.</summary>
    /// <param name="type">One of the four domain rule types.</param>
    /// <param name="kind">How the payload compares against the host.</param>
    /// <param name="payload">The domain, keyword or regular expression.</param>
    /// <param name="adapter">Target adapter name.</param>
    /// <param name="modifiers">Trailing modifiers, if any.</param>
    public DomainRule(RuleType type, DomainMatchKind kind, string payload, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _payload = kind == DomainMatchKind.Regex ? payload.Trim() : DomainMatcher.Normalize(payload);
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;

        _matcher = new DomainMatcher();
        _matcher.Add(payload, kind, 0);
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => _payload;

    /// <inheritdoc />
    public string Adapter { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool Match(Metadata metadata) => _matcher.Match(metadata.RuleHost) >= 0;

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <summary>Checks that a <c>DOMAIN-REGEX</c> payload compiles.</summary>
    public static bool TryValidateRegex(string pattern, out string? error)
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

    /// <inheritdoc />
    string ICanonicalRule.FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, _payload, Adapter, AdditionalPayload, withAdapter);
}
