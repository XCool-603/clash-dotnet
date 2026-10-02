using System.Globalization;
using System.Text.RegularExpressions;
using Clash.Core.Common;

namespace Clash.Core.Rules.Impl;

/// <summary>A set of port values and inclusive ranges, e.g. <c>80</c>, <c>1000-2000</c> or <c>80/443</c>.</summary>
public sealed class PortSelector
{
    private readonly (int Start, int End)[] _ranges;

    private PortSelector((int Start, int End)[] ranges) => _ranges = ranges;

    /// <summary>Number of distinct ranges the selector holds.</summary>
    public int Count => _ranges.Length;

    /// <summary>Parses a port payload. Entries are separated by <c>/</c>; each is a port or an <c>a-b</c> range.</summary>
    public static bool TryParse(string? payload, out PortSelector selector)
    {
        selector = null!;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        var ranges = new List<(int Start, int End)>();
        foreach (var part in payload.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = part.IndexOf('-');
            if (dash < 0)
            {
                if (!TryPort(part, out var port)) return false;
                ranges.Add((port, port));
                continue;
            }

            if (!TryPort(part[..dash], out var start) || !TryPort(part[(dash + 1)..], out var end)) return false;
            if (end < start) (start, end) = (end, start);
            ranges.Add((start, end));
        }

        if (ranges.Count == 0) return false;
        selector = new PortSelector([.. ranges]);
        return true;
    }

    /// <summary>True when the port falls in any of the ranges.</summary>
    public bool Contains(int port)
    {
        foreach (var (start, end) in _ranges)
        {
            if (port >= start && port <= end) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public override string ToString()
        => string.Join('/', _ranges.Select(r => r.Start == r.End ? r.Start.ToString(CultureInfo.InvariantCulture) : $"{r.Start}-{r.End}"));

    private static bool TryPort(string text, out int port)
        => int.TryParse(text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out port) && port is >= 0 and <= 65535;
}

/// <summary><c>SRC-PORT</c>, <c>DST-PORT</c> and <c>IN-PORT</c>.</summary>
public sealed class PortRule : IRule, ICanonicalRule
{
    private readonly PortSelector _selector;

    /// <summary>Creates a port rule.</summary>
    public PortRule(RuleType type, PortSelector selector, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _selector = selector;
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => _selector.ToString();

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata) => Type switch
    {
        RuleType.SrcPort => _selector.Contains(metadata.SourcePort),
        RuleType.DstPort => _selector.Contains(metadata.DestinationPort),
        _ => _selector.Contains(metadata.InboundPort),
    };

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);
}

/// <summary>The flow field a <see cref="TextFieldRule"/> or <see cref="RegexFieldRule"/> inspects.</summary>
public enum MetadataTextField
{
    /// <summary><see cref="Metadata.InboundType"/>.</summary>
    InboundType,

    /// <summary><see cref="Metadata.InboundUser"/>.</summary>
    InboundUser,

    /// <summary><see cref="Metadata.InboundName"/>.</summary>
    InboundName,

    /// <summary><see cref="Metadata.ProcessName"/>.</summary>
    ProcessName,

    /// <summary><see cref="Metadata.ProcessPath"/>.</summary>
    ProcessPath,
}

/// <summary>
/// Exact-match rules over a string field of the flow: <c>IN-TYPE</c>, <c>IN-USER</c>,
/// <c>IN-NAME</c>, <c>PROCESS-NAME</c> and <c>PROCESS-PATH</c>. Comparison ignores case,
/// which matches Clash's behaviour on Windows and is the more forgiving choice elsewhere.
/// </summary>
public sealed class TextFieldRule : IRule, ICanonicalRule
{
    private readonly MetadataTextField _field;
    private readonly string[] _expected;

    /// <summary>Creates a text field rule.</summary>
    /// <param name="type">The rule type this instance reports.</param>
    /// <param name="field">Which flow field to inspect.</param>
    /// <param name="payload">The expected value; <c>/</c>-separated alternatives when <paramref name="allowList"/> is true.</param>
    /// <param name="adapter">Target adapter name.</param>
    /// <param name="modifiers">Trailing modifiers.</param>
    /// <param name="allowList">True for the inbound rules, where Clash accepts a <c>/</c>-separated list.</param>
    public TextFieldRule(RuleType type, MetadataTextField field, string payload, string adapter, RuleModifiers? modifiers = null, bool allowList = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _field = field;
        _expected = allowList
            ? payload.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [payload.Trim()];
        if (_expected.Length == 0) _expected = [payload.Trim()];

        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => string.Join('/', _expected);

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        var actual = FieldOf(metadata, _field);
        if (string.IsNullOrEmpty(actual)) return false;

        foreach (var expected in _expected)
        {
            if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    internal static string? FieldOf(Metadata metadata, MetadataTextField field) => field switch
    {
        MetadataTextField.InboundType => metadata.InboundType,
        MetadataTextField.InboundUser => metadata.InboundUser,
        MetadataTextField.InboundName => metadata.InboundName,
        MetadataTextField.ProcessName => metadata.ProcessName,
        MetadataTextField.ProcessPath => metadata.ProcessPath,
        _ => null,
    };
}

/// <summary><c>PROCESS-NAME-REGEX</c> and <c>PROCESS-PATH-REGEX</c>.</summary>
public sealed class RegexFieldRule : IRule, ICanonicalRule
{
    private readonly MetadataTextField _field;
    private readonly Regex _regex;

    /// <summary>Creates a regex field rule.</summary>
    public RegexFieldRule(RuleType type, MetadataTextField field, string payload, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = type;
        RuleTypeName = RuleNames.Of(type);
        _field = field;
        Payload = payload.Trim();
        _regex = DomainMatcher.CompileRegex(Payload);
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload { get; }

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        var actual = TextFieldRule.FieldOf(metadata, _field);
        if (string.IsNullOrEmpty(actual)) return false;

        try
        {
            return _regex.IsMatch(actual);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);
}

/// <summary><c>UID</c>: matches the owning user id, as a literal or as an inclusive numeric range.</summary>
public sealed class UidRule : IRule, ICanonicalRule
{
    private readonly string[] _values;
    private readonly (long Start, long End)[] _ranges;

    /// <summary>Creates a UID rule from a payload such as <c>1000</c>, <c>1000-2000</c> or <c>0/1000</c>.</summary>
    public UidRule(string payload, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = RuleType.Uid;
        RuleTypeName = "UID";
        Payload = payload.Trim();
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;

        var values = new List<string>();
        var ranges = new List<(long, long)>();
        foreach (var part in Payload.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            values.Add(part);
            if (TryRange(part, out var range)) ranges.Add(range);
        }

        if (values.Count == 0) values.Add(Payload);
        _values = [.. values];
        _ranges = [.. ranges];
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload { get; }

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        var uid = metadata.Uid;
        if (string.IsNullOrEmpty(uid)) return false;

        foreach (var value in _values)
        {
            if (string.Equals(uid, value, StringComparison.OrdinalIgnoreCase)) return true;
        }

        if (_ranges.Length == 0) return false;
        if (!long.TryParse(uid, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric)) return false;

        foreach (var (start, end) in _ranges)
        {
            if (numeric >= start && numeric <= end) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);

    private static bool TryRange(string text, out (long Start, long End) range)
    {
        range = default;
        var dash = text.IndexOf('-');
        if (dash <= 0) return false;
        if (!long.TryParse(text[..dash].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var start)) return false;
        if (!long.TryParse(text[(dash + 1)..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var end)) return false;
        if (end < start) (start, end) = (end, start);
        range = (start, end);
        return true;
    }
}

/// <summary><c>NETWORK</c>: <c>tcp</c>, <c>udp</c> or a <c>/</c>-separated list of both.</summary>
public sealed class NetworkRule : IRule, ICanonicalRule
{
    private readonly string[] _networks;

    /// <summary>Creates a network rule.</summary>
    public NetworkRule(string payload, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = RuleType.Network;
        RuleTypeName = "NETWORK";
        _networks = payload.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (_networks.Length == 0) _networks = [payload.Trim()];

        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload => string.Join('/', _networks);

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata)
    {
        var actual = metadata.Network.ToApiString();
        foreach (var network in _networks)
        {
            if (string.Equals(network, actual, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);
}

/// <summary><c>DSCP</c>: matches the DSCP mark of the inbound, as a value or an inclusive range.</summary>
public sealed class DscpRule : IRule, ICanonicalRule
{
    private readonly int _start;
    private readonly int _end;

    /// <summary>Creates a DSCP rule.</summary>
    public DscpRule(string payload, string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        ArgumentNullException.ThrowIfNull(adapter);

        Type = RuleType.Dscp;
        RuleTypeName = "DSCP";
        Payload = payload.Trim();
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;

        var dash = Payload.IndexOf('-');
        if (dash > 0
            && int.TryParse(Payload[..dash].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var start)
            && int.TryParse(Payload[(dash + 1)..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var end))
        {
            _start = Math.Min(start, end);
            _end = Math.Max(start, end);
            return;
        }

        _start = int.TryParse(Payload, NumberStyles.Integer, CultureInfo.InvariantCulture, out var single) ? single : int.MinValue;
        _end = _start;
    }

    /// <inheritdoc />
    public RuleType Type { get; }

    /// <inheritdoc />
    public string RuleTypeName { get; }

    /// <inheritdoc />
    public string Payload { get; }

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata) => metadata.Dscp >= _start && metadata.Dscp <= _end;

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line(RuleTypeName, Payload, Adapter, AdditionalPayload, withAdapter);
}

/// <summary>
/// <c>MATCH</c>: the catch-all rule. It carries no payload and always matches, which is
/// why the engine also synthesises a <c>DIRECT</c> one when a config has no <c>MATCH</c>.
/// </summary>
public sealed class MatchRule : IRule, ICanonicalRule
{
    /// <summary>Creates a match rule targeting the given adapter.</summary>
    public MatchRule(string adapter, RuleModifiers? modifiers = null)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        Adapter = adapter;
        Modifiers = modifiers ?? RuleModifiers.None;
    }

    /// <inheritdoc />
    public RuleType Type => RuleType.Match;

    /// <inheritdoc />
    public string RuleTypeName => "MATCH";

    /// <inheritdoc />
    public string Payload => string.Empty;

    /// <inheritdoc />
    public string Adapter { get; }

    /// <summary>Trailing modifiers of this rule.</summary>
    public RuleModifiers Modifiers { get; }

    /// <inheritdoc />
    public bool ShouldResolveIp => false;

    /// <inheritdoc />
    public string? AdditionalPayload => Modifiers.Raw.Length == 0 ? null : Modifiers.Raw;

    /// <inheritdoc />
    public bool Match(Metadata metadata) => true;

    /// <inheritdoc />
    public string Description => FormatRule(true);

    /// <inheritdoc />
    public string FormatRule(bool withAdapter)
        => Canonical.Line("MATCH", null, Adapter, AdditionalPayload, withAdapter);
}
