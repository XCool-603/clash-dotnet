using System.Text.RegularExpressions;

namespace Clash.Core.Rules;

/// <summary>How a <see cref="DomainMatcher"/> entry compares a host name.</summary>
public enum DomainMatchKind
{
    /// <summary>The host must equal the entry exactly.</summary>
    Full,

    /// <summary>The host must equal the entry, or end with <c>.</c> + the entry.</summary>
    Suffix,

    /// <summary>The host must contain the entry somewhere.</summary>
    Keyword,

    /// <summary>The entry is a regular expression matched against the host.</summary>
    Regex,
}

/// <summary>
/// A reverse-label trie over domain entries. Hosts are split on <c>.</c> and walked
/// from the top-level label down, so a lookup costs one dictionary probe per label
/// rather than one comparison per rule. Backs both single domain rules and the
/// <c>domain</c> behaviour of <see cref="RuleSet"/>.
/// </summary>
/// <remarks>
/// Construction is not thread-safe; <see cref="Match"/> is, once construction has
/// finished. All builders in this assembly publish a fully built matcher.
/// </remarks>
public sealed class DomainMatcher
{
    /// <summary>The match timeout applied to every <see cref="DomainMatchKind.Regex"/> entry.</summary>
    public static readonly TimeSpan DefaultRegexTimeout = TimeSpan.FromSeconds(1);

    private sealed class Node
    {
        public Dictionary<string, Node>? Children;
        public int FullIndex = -1;
        public int SuffixIndex = -1;
    }

    private readonly Node _root = new();
    private readonly List<KeyValuePair<string, int>> _keywords = [];
    private readonly List<KeyValuePair<Regex, int>> _regexes = [];
    private int _count;

    /// <summary>Number of entries added.</summary>
    public int Count => _count;

    /// <summary>True when no entry has been added.</summary>
    public bool IsEmpty => _count == 0;

    /// <summary>
    /// Compiles a rule regular expression with the options Clash expects. The timeout
    /// keeps a pathological pattern from stalling a connection forever.
    /// </summary>
    public static Regex CompileRegex(string pattern)
        => new(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, DefaultRegexTimeout);

    /// <summary>
    /// Lower-cases a host or domain entry and drops a leading dot and any trailing dots,
    /// so <c>.Example.COM.</c> and <c>example.com</c> compare equal.
    /// </summary>
    public static string Normalize(string? host)
    {
        if (string.IsNullOrEmpty(host)) return string.Empty;
        var span = host.AsSpan().Trim();
        if (span.Length > 1 && span[0] == '.') span = span[1..];
        while (span.Length > 0 && span[^1] == '.') span = span[..^1];
        return span.Length == 0 ? string.Empty : span.ToString().ToLowerInvariant();
    }

    /// <summary>Adds one entry. Blank entries are ignored.</summary>
    /// <param name="value">The domain, keyword or regular expression.</param>
    /// <param name="kind">How <paramref name="value"/> compares against a host.</param>
    /// <param name="index">Value returned by <see cref="Match"/> when this entry wins.</param>
    public void Add(string? value, DomainMatchKind kind, int index)
    {
        if (string.IsNullOrWhiteSpace(value)) return;

        if (kind == DomainMatchKind.Regex)
        {
            var pattern = value.Trim();
            _regexes.Add(new KeyValuePair<Regex, int>(CompileRegex(pattern), index));
            _count++;
            return;
        }

        var normalized = Normalize(value);
        if (normalized.Length == 0) return;

        switch (kind)
        {
            case DomainMatchKind.Full:
                var full = NodeFor(normalized);
                if (full.FullIndex < 0 || index < full.FullIndex) full.FullIndex = index;
                break;

            case DomainMatchKind.Keyword:
                _keywords.Add(new KeyValuePair<string, int>(normalized, index));
                break;

            default:
                var suffix = NodeFor(normalized);
                if (suffix.SuffixIndex < 0 || index < suffix.SuffixIndex) suffix.SuffixIndex = index;
                break;
        }

        _count++;
    }

    /// <summary>
    /// Returns the index of the best matching entry, or -1. Exact entries win over the
    /// longest suffix, which wins over keywords, which win over regular expressions.
    /// </summary>
    public int Match(string? host)
    {
        if (string.IsNullOrEmpty(host)) return -1;
        var normalized = Normalize(host);
        if (normalized.Length == 0) return -1;

        var span = normalized.AsSpan();
        var node = _root;
        var suffixIndex = -1;
        var end = span.Length;
        var consumedWholeHost = false;

        while (true)
        {
            var start = span[..end].LastIndexOf('.') + 1;
            var label = span[start..end];

            if (node.Children is null) break;
            var lookup = node.Children.GetAlternateLookup<ReadOnlySpan<char>>();
            if (!lookup.TryGetValue(label, out var next)) break;

            node = next;
            if (node.SuffixIndex >= 0) suffixIndex = node.SuffixIndex;
            if (start == 0)
            {
                consumedWholeHost = true;
                break;
            }

            end = start - 1;
        }

        if (consumedWholeHost && node.FullIndex >= 0) return node.FullIndex;
        if (suffixIndex >= 0) return suffixIndex;

        foreach (var keyword in _keywords)
        {
            if (normalized.Contains(keyword.Key, StringComparison.Ordinal)) return keyword.Value;
        }

        foreach (var regex in _regexes)
        {
            try
            {
                if (regex.Key.IsMatch(normalized)) return regex.Value;
            }
            catch (RegexMatchTimeoutException)
            {
                // A pattern that cannot finish in time simply does not match.
            }
        }

        return -1;
    }

    private Node NodeFor(string domain)
    {
        var node = _root;
        var labels = domain.Split('.');

        for (var i = labels.Length - 1; i >= 0; i--)
        {
            node.Children ??= new Dictionary<string, Node>(StringComparer.Ordinal);
            if (!node.Children.TryGetValue(labels[i], out var next))
            {
                next = new Node();
                node.Children[labels[i]] = next;
            }

            node = next;
        }

        return node;
    }
}
