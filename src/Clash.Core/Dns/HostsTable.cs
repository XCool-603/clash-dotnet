using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Clash.Core.Dns;

/// <summary>
/// The <c>hosts</c> override table: exact names plus <c>*.example.com</c> /
/// <c>+.example.com</c> wildcards, optionally merged with the operating system's
/// hosts file.
/// </summary>
/// <remarks>
/// <para>
/// Lookup precedence is: exact key first, then the wildcard whose suffix has the
/// most labels. Wildcard matching is suffix-based on label boundaries, so
/// <c>*.example.com</c> matches <c>a.example.com</c> and <c>a.b.example.com</c>
/// but never <c>example.com</c> or <c>notexample.com</c>; <c>+.example.com</c>
/// additionally matches the apex.
/// </para>
/// <para>
/// Values are IP literals; a value that is not an address is treated as an alias
/// for another entry and followed up to a small depth, which is how
/// <c>hosts: {'a.example.com': 'b.example.com'}</c> behaves in Clash.
/// </para>
/// <para>
/// Nothing here ever touches the network.
/// </para>
/// </remarks>
public sealed class HostsTable
{
    private const int MaxAliasDepth = 8;

    private readonly Dictionary<string, string[]> _exact;
    private readonly List<WildcardEntry> _wildcards;

    /// <summary>Builds a table from one hosts mapping.</summary>
    /// <param name="hosts">Mapping of name to an IP literal, an alias, or a list of either.</param>
    /// <param name="useSystemHosts">When true the OS hosts file is merged in at the lowest priority.</param>
    public HostsTable(IReadOnlyDictionary<string, object?>? hosts = null, bool useSystemHosts = false)
        : this(
            hosts is null
                ? Array.Empty<IReadOnlyDictionary<string, object?>>()
                : new IReadOnlyDictionary<string, object?>[] { hosts },
            useSystemHosts)
    {
    }

    /// <summary>
    /// Builds a table from several hosts mappings. Sources are applied in order,
    /// so a later source overrides an earlier one with the same key.
    /// </summary>
    public HostsTable(IEnumerable<IReadOnlyDictionary<string, object?>?>? sources, bool useSystemHosts)
    {
        var merged = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        foreach (var source in sources ?? [])
        {
            if (source is null) continue;
            foreach (var pair in source)
            {
                var key = Normalize(pair.Key);
                if (key.Length == 0) continue;
                var values = ToValues(pair.Value);
                if (values.Length == 0) continue;
                merged[key] = values;
            }
        }

        if (useSystemHosts)
        {
            foreach (var pair in ParseSystemHosts())
            {
                // Explicit configuration always wins over the OS file.
                merged.TryAdd(pair.Key, pair.Value);
            }
        }

        _exact = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        _wildcards = [];

        foreach (var pair in merged)
        {
            if (TrySplitWildcard(pair.Key, out var suffix, out var includeApex))
            {
                _wildcards.Add(new WildcardEntry(suffix, includeApex, pair.Value));
            }
            else
            {
                _exact[pair.Key] = pair.Value;
            }
        }

        _wildcards.Sort(static (a, b) => b.Suffix.Length.CompareTo(a.Suffix.Length));
    }

    /// <summary>Number of distinct keys, wildcards included.</summary>
    public int Count => _exact.Count + _wildcards.Count;

    /// <summary>Path of the OS hosts file this platform uses.</summary>
    public static string SystemHostsPath => OperatingSystem.IsWindows()
        ? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers",
            "etc",
            "hosts")
        : "/etc/hosts";

    /// <summary>True when the key denotes a wildcard (<c>*.</c>, <c>+.</c> or a leading dot).</summary>
    public static bool IsWildcardKey(string key)
        => key.StartsWith("*.", StringComparison.Ordinal)
            || key.StartsWith("+.", StringComparison.Ordinal)
            || key.StartsWith(".", StringComparison.Ordinal);

    /// <summary>
    /// Resolves <paramref name="host"/> from the table only. Exact keys beat
    /// wildcards; the longest wildcard suffix beats a shorter one.
    /// </summary>
    public bool TryResolve(string host, out IPAddress[] addresses)
    {
        addresses = [];
        var key = Normalize(host);
        if (key.Length == 0) return false;

        var values = LookupValues(key, depth: 0);
        if (values is null || values.Length == 0) return false;

        var resolved = new List<IPAddress>(values.Length);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { key };
        CollectAddresses(values, resolved, visited, depth: 0);

        if (resolved.Count == 0) return false;
        addresses = [.. resolved.Distinct()];
        return addresses.Length > 0;
    }

    /// <summary>True when the table has an entry (exact or wildcard) for <paramref name="host"/>.</summary>
    public bool Contains(string host)
    {
        var key = Normalize(host);
        if (key.Length == 0) return false;
        return LookupValues(key, depth: 0) is { Length: > 0 };
    }

    /// <summary>
    /// Reads the platform hosts file. Missing or unreadable files yield an empty
    /// table rather than an error, exactly like Clash.
    /// </summary>
    public static IReadOnlyDictionary<string, string[]> ParseSystemHosts()
    {
        var result = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var path = SystemHostsPath;
            if (!File.Exists(path)) return result;

            foreach (var rawLine in File.ReadLines(path))
            {
                var line = rawLine;
                var comment = line.IndexOf('#');
                if (comment >= 0) line = line[..comment];
                line = line.Trim();
                if (line.Length == 0) continue;

                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                if (!IPAddress.TryParse(parts[0], out var address)) continue;

                for (var i = 1; i < parts.Length; i++)
                {
                    var name = Normalize(parts[i]);
                    if (name.Length == 0) continue;

                    if (result.TryGetValue(name, out var existing))
                    {
                        var text = address.ToString();
                        if (!existing.Contains(text, StringComparer.OrdinalIgnoreCase))
                        {
                            result[name] = [.. existing, text];
                        }
                    }
                    else
                    {
                        result[name] = [address.ToString()];
                    }
                }
            }
        }
        catch (IOException)
        {
            // An unreadable hosts file must never break resolution.
        }
        catch (UnauthorizedAccessException)
        {
        }

        return result;
    }

    // ── Internals ───────────────────────────────────────────────────────────

    private string[]? LookupValues(string key, int depth)
    {
        if (_exact.TryGetValue(key, out var exact)) return exact;
        if (depth > MaxAliasDepth) return null;

        foreach (var wildcard in _wildcards)
        {
            if (wildcard.Matches(key)) return wildcard.Values;
        }

        return null;
    }

    private void CollectAddresses(string[] values, List<IPAddress> into, HashSet<string> visited, int depth)
    {
        if (depth > MaxAliasDepth) return;

        foreach (var value in values)
        {
            if (IPAddress.TryParse(value, out var address))
            {
                into.Add(address);
                continue;
            }

            var alias = Normalize(value);
            if (alias.Length == 0 || !visited.Add(alias)) continue;

            var nested = LookupValues(alias, depth + 1);
            if (nested is not null) CollectAddresses(nested, into, visited, depth + 1);
        }
    }

    private static bool TrySplitWildcard(string key, out string suffix, out bool includeApex)
    {
        suffix = string.Empty;
        includeApex = false;

        if (key.StartsWith("*.", StringComparison.Ordinal))
        {
            suffix = key[2..];
            return suffix.Length > 0;
        }

        if (key.StartsWith("+.", StringComparison.Ordinal))
        {
            suffix = key[2..];
            includeApex = true;
            return suffix.Length > 0;
        }

        if (key.StartsWith(".", StringComparison.Ordinal))
        {
            suffix = key[1..];
            includeApex = true;
            return suffix.Length > 0;
        }

        return false;
    }

    private static string[] ToValues(object? value)
    {
        switch (value)
        {
            case null:
                return [];

            case string text:
                return text
                    .Split(new[] { ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            case System.Collections.IEnumerable sequence:
            {
                var values = new List<string>();
                foreach (var item in sequence)
                {
                    var text = Convert.ToString(item, CultureInfo.InvariantCulture);
                    if (!string.IsNullOrWhiteSpace(text)) values.Add(text.Trim());
                }

                return [.. values];
            }

            default:
            {
                var text = Convert.ToString(value, CultureInfo.InvariantCulture);
                return string.IsNullOrWhiteSpace(text) ? [] : [text.Trim()];
            }
        }
    }

    private static string Normalize(string? host)
        => host is null ? string.Empty : host.Trim().TrimEnd('.').ToLowerInvariant();

    private sealed record WildcardEntry(string Suffix, bool IncludeApex, string[] Values)
    {
        /// <summary>
        /// Label-boundary suffix match: <c>a.example.com</c> ends with
        /// <c>.example.com</c>; the apex only matches when <see cref="IncludeApex"/>.
        /// </summary>
        public bool Matches(string host)
        {
            if (host.Length <= Suffix.Length) return IncludeApex && string.Equals(host, Suffix, StringComparison.OrdinalIgnoreCase);
            if (!host.EndsWith(Suffix, StringComparison.OrdinalIgnoreCase)) return false;
            return host[^(Suffix.Length + 1)] == '.';
        }
    }
}
