using Clash.Core.Common;

namespace Clash.Core.Rules.Impl;

/// <summary>
/// <c>AND</c>, <c>OR</c> and <c>NOT</c>. Members are ordinary rules parsed from the
/// parenthesised list, e.g. <c>AND,((DOMAIN-SUFFIX,a.com),(NETWORK,tcp)),PROXY</c>.
/// A composite rule needs the destination resolved as soon as any member does.
/// </summary>
public sealed class LogicalRule : IRule, ICanonicalRule, IGeoDataConsumer
{
    private readonly IReadOnlyList<IRule> _members;

    /// <summary>Creates a logical rule.</summary>
    /// <param name="type">One of <see cref="RuleType.And"/>, <see cref="RuleType.Or"/> or <see cref="RuleType.Not"/>.</param>
    /// <param name="members">The nested rules.</param>
    /// <param name="adapter">Target adapter name.</param>
    /// <param name="modifiers">Trailing modifiers.</param>
    public LogicalRule(RuleType type, IReadOnlyList<IRule> members, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentNullException.ThrowIfNull(members);
        ArgumentNullException.ThrowIfNull(adapter);
        if (members.Count == 0) throw new ArgumentException("a logical rule needs at least one member", nameof(members));

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _members = [.. members];
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <summary>The nested rules, in source order.</summary>
    public IReadOnlyList<IRule> Members => _members;

    /// <inheritdoc />
    public string Payload => $"({string.Join(',', _members.Select(m => $"({RuleParser.FormatNested(m)})"))})";

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp
    {
        get
        {
            foreach (var member in _members)
            {
                if (member.ShouldResolveIp) return true;
            }

            return false;
        }
    }

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata) => Type switch
    {
        RuleType.And => MatchAll(metadata),
        RuleType.Or => MatchAny(metadata),
        RuleType.Not => !_members[0].Match(metadata),
        _ => false,
    };

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public void SetGeo(IGeoData geo)
    {
        foreach (var member in _members) RuleGeo.Inject(member, geo);
    }

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    private bool MatchAll(Metadata metadata)
    {
        foreach (var member in _members)
        {
            if (!member.Match(metadata)) return false;
        }

        return true;
    }

    private bool MatchAny(Metadata metadata)
    {
        foreach (var member in _members)
        {
            if (member.Match(metadata)) return true;
        }

        return false;
    }
}
