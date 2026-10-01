using System.Globalization;
using System.Text;
using Clash.Core.Configuration;

namespace Clash.Core.Providers;

/// <summary>
/// Renders parsed proxy entries as a complete, loadable Clash document: the
/// <c>proxies:</c> block, a <c>PROXY</c> <c>select</c> group listing every node,
/// and a <c>MATCH,PROXY</c> rule.
/// </summary>
/// <remarks>
/// <para>
/// This is the shared implementation of the conversion
/// <see cref="Configuration.ProfileManager"/> performs privately in
/// <c>NormalizeToYaml</c>; the two are deliberately kept in step and a caller
/// importing a share-link subscription should prefer this type.
/// </para>
/// <para>
/// Scalars are quoted whenever YAML would otherwise reinterpret them: names
/// containing <c>:</c>, <c>#</c>, quotes, whitespace or a leading indicator
/// character, values that look numeric or boolean, and the empty string.
/// </para>
/// </remarks>
public static class SubscriptionConverter
{
    /// <summary>The name of the <c>select</c> group every converted document gets.</summary>
    public const string DefaultGroupName = "PROXY";

    /// <summary>Renders proxies as a Clash document with a <c>PROXY</c> group.</summary>
    /// <param name="proxies">The nodes to include, in order.</param>
    public static string ToYaml(IReadOnlyList<ProxyConfigEntry> proxies) => ToYaml(proxies, DefaultGroupName);

    /// <summary>Renders proxies as a Clash document with a named select group.</summary>
    /// <param name="proxies">The nodes to include, in order.</param>
    /// <param name="groupName">Name of the <c>select</c> group and the <c>MATCH</c> target.</param>
    public static string ToYaml(IReadOnlyList<ProxyConfigEntry> proxies, string groupName)
    {
        ArgumentNullException.ThrowIfNull(proxies);
        if (string.IsNullOrWhiteSpace(groupName)) groupName = DefaultGroupName;

        var names = UniqueNames(proxies);
        var builder = new StringBuilder();

        builder.Append("proxies:");
        if (proxies.Count == 0)
        {
            builder.Append(" []\n");
        }
        else
        {
            builder.Append('\n');
            for (var i = 0; i < proxies.Count; i++) WriteListEntry(builder, "  ", proxies[i], names[i]);
        }

        builder.Append('\n');
        builder.Append("proxy-groups:\n");
        builder.Append("  - name: ").Append(QuoteIfNeeded(groupName)).Append('\n');
        builder.Append("    type: select\n");
        builder.Append("    proxies:\n");
        foreach (var name in names)
        {
            builder.Append("      - ").Append(QuoteIfNeeded(name)).Append('\n');
        }

        if (!names.Contains("DIRECT", StringComparer.Ordinal)) builder.Append("      - DIRECT\n");

        builder.Append('\n');
        builder.Append("rules:\n");
        builder.Append("  - MATCH,").Append(groupName).Append('\n');

        return builder.ToString();
    }

    /// <summary>
    /// Quotes a scalar when a plain rendering would be reinterpreted, and returns
    /// it unchanged otherwise.
    /// </summary>
    /// <param name="value">The scalar text.</param>
    public static string QuoteIfNeeded(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return NeedsQuoting(value) ? Quote(value) : value;
    }

    /// <summary>Always-quoted, escaped YAML double-quoted scalar.</summary>
    /// <param name="value">The scalar text.</param>
    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');

        foreach (var c in value)
        {
            switch (c)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (c < ' ') builder.Append("\\x").Append(((int)c).ToString("x2", CultureInfo.InvariantCulture));
                    else builder.Append(c);
                    break;
            }
        }

        builder.Append('"');
        return builder.ToString();
    }

    /// <summary>Renders one YAML scalar (or flow scalar) for a mapping value.</summary>
    /// <param name="value">The value to render.</param>
    public static string FormatScalar(object? value) => value switch
    {
        null => "''",
        bool b => b ? "true" : "false",
        string s => QuoteIfNeeded(s),
        _ when IsNumeric(value) => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "''",
        _ => QuoteIfNeeded(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty),
    };

    /// <summary>
    /// Names in document order, with collisions renamed to <c>name 2</c>,
    /// <c>name 3</c>, … because a Clash document may not declare two proxies with
    /// the same name.
    /// </summary>
    private static List<string> UniqueNames(IReadOnlyList<ProxyConfigEntry> proxies)
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        var names = new List<string>(proxies.Count);

        foreach (var entry in proxies)
        {
            var name = entry.Name;
            if (name.Length == 0) name = $"proxy-{names.Count + 1}";

            if (used.Add(name))
            {
                names.Add(name);
                continue;
            }

            var suffix = 2;
            string candidate;
            do
            {
                candidate = $"{name} {suffix++}";
            }
            while (!used.Add(candidate));

            names.Add(candidate);
        }

        return names;
    }

    private static void WriteListEntry(StringBuilder builder, string indent, ProxyConfigEntry entry, string name)
    {
        var map = entry.Map;
        var pairs = new List<(string Key, object? Value)>
        {
            ("name", name),
        };

        if (map.Has("type")) pairs.Add(("type", map["type"]));

        foreach (var (key, value) in map.Raw)
        {
            if (string.Equals(key, "name", StringComparison.OrdinalIgnoreCase)) continue;
            if (string.Equals(key, "type", StringComparison.OrdinalIgnoreCase)) continue;
            pairs.Add((key, value));
        }

        var first = true;
        foreach (var (key, value) in pairs)
        {
            builder.Append(indent).Append(first ? "- " : "  ");
            builder.Append(key).Append(':');
            WriteInline(builder, value, indent + "  ");
            builder.Append('\n');
            first = false;
        }
    }

    private static void WriteInline(StringBuilder builder, object? value, string childIndent)
    {
        switch (value)
        {
            case null:
                builder.Append(" ''");
                return;

            case Dictionary<string, object?> map when map.Count > 0:
                foreach (var (key, item) in map)
                {
                    builder.Append('\n').Append(childIndent).Append(key).Append(':');
                    WriteInline(builder, item, childIndent + "  ");
                }

                return;

            case Dictionary<string, object?>:
                builder.Append(" {}");
                return;

            case List<object?> list when list.Count > 0:
                foreach (var item in list)
                {
                    builder.Append('\n').Append(childIndent).Append("- ");
                    WriteInline(builder, item, childIndent + "  ");
                }

                return;

            case List<object?>:
                builder.Append(" []");
                return;

            default:
                builder.Append(' ').Append(FormatScalar(value));
                return;
        }
    }

    private static bool NeedsQuoting(string value)
    {
        if (value.Length == 0) return true;

        foreach (var c in value)
        {
            if (c is ':' or '#' or '"' or '\'' || char.IsWhiteSpace(c) || c < ' ') return true;
        }

        if ("-?:,[]{}#&*!|>'\"%@`~".IndexOf(value[0]) >= 0) return true;
        if (LooksNumeric(value)) return true;
        return IsYamlKeyword(value);
    }

    private static bool LooksNumeric(string value)
        => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)
           || double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _);

    private static bool IsYamlKeyword(string value)
        => value.ToLowerInvariant() is "true" or "false" or "yes" or "no" or "on" or "off" or "null" or "~" or "y" or "n";

    private static bool IsNumeric(object value)
        => value is byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal;
}
