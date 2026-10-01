using System.Collections;
using System.Globalization;

namespace Clash.Core.Common;

/// <summary>
/// A read-only, typed view over one YAML mapping node.
/// <para>
/// Heterogeneous YAML — <c>proxies</c>, <c>proxy-groups</c>, <c>listeners</c>,
/// <c>rule-providers</c> overrides — is decoded into plain CLR containers
/// (<see cref="string"/>, <see cref="bool"/>, <see cref="long"/>,
/// <see cref="double"/>, <see cref="List{T}"/> of <see cref="object"/>,
/// <see cref="Dictionary{TKey,TValue}"/> of string to object) and then read
/// through this wrapper. That keeps every protocol parser uniform and tolerant
/// of the loose typing real-world subscriptions contain (numbers quoted as
/// strings, <c>"true"</c> instead of <c>true</c>, and so on).
/// </para>
/// </summary>
public sealed class YamlMap
{
    private readonly Dictionary<string, object?> _values;

    public YamlMap(Dictionary<string, object?> values) => _values = values;

    public static readonly YamlMap Empty = new(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase));

    public int Count => _values.Count;

    public IReadOnlyDictionary<string, object?> Raw => _values;

    public bool Has(string key) => _values.ContainsKey(key);

    public IEnumerable<string> Keys => _values.Keys;

    /// <summary>Case-insensitive lookup returning the raw node.</summary>
    public object? this[string key]
        => _values.TryGetValue(key, out var v) ? v : null;

    /// <summary>Builds a map from an arbitrary YAML node, or returns empty when the node is not a mapping.</summary>
    public static YamlMap From(object? node)
    {
        if (node is YamlMap m) return m;
        if (node is Dictionary<string, object?> d) return new YamlMap(d);
        if (node is IDictionary<object, object?> od)
        {
            var res = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in od) res[Convert.ToString(kv.Key, CultureInfo.InvariantCulture) ?? ""] = Normalize(kv.Value);
            return new YamlMap(res);
        }
        if (node is IDictionary plain)
        {
            var res = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry kv in plain) res[Convert.ToString(kv.Key, CultureInfo.InvariantCulture) ?? ""] = Normalize(kv.Value);
            return new YamlMap(res);
        }
        return Empty;
    }

    /// <summary>Converts a raw YAML scalar/sequence/mapping into the canonical CLR shapes.</summary>
    public static object? Normalize(object? value) => value switch
    {
        null => null,
        string s => s,
        bool b => b,
        byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal
            => Convert.ToInt64(value, CultureInfo.InvariantCulture) is var l && value is float or double or decimal
                ? Convert.ToDouble(value, CultureInfo.InvariantCulture)
                : l,
        IDictionary<object, object?> od => od.ToDictionary(
            kv => Convert.ToString(kv.Key, CultureInfo.InvariantCulture) ?? "",
            kv => Normalize(kv.Value),
            StringComparer.OrdinalIgnoreCase),
        IDictionary d => d.Cast<DictionaryEntry>().ToDictionary(
            kv => Convert.ToString(kv.Key, CultureInfo.InvariantCulture) ?? "",
            kv => Normalize(kv.Value),
            StringComparer.OrdinalIgnoreCase),
        IEnumerable e and not string => e.Cast<object?>().Select(Normalize).ToList(),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture),
    };

    public string? GetString(string key, string? fallback = null)
    {
        var v = this[key];
        return v switch
        {
            null => fallback,
            string s => s,
            bool b => b ? "true" : "false",
            double d => d.ToString(CultureInfo.InvariantCulture),
            _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? fallback,
        };
    }

    public string? GetNonEmptyString(string key)
    {
        var s = GetString(key);
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    public int GetInt(string key, int fallback = 0)
    {
        var v = this[key];
        return v switch
        {
            null => fallback,
            int i => i,
            long l => (int)l,
            double d => (int)d,
            bool b => b ? 1 : 0,
            string s => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var r) ? r : fallback,
            _ => fallback,
        };
    }

    public int? GetNullableInt(string key) => Has(key) ? GetInt(key) : null;

    public long GetLong(string key, long fallback = 0)
    {
        var v = this[key];
        return v switch
        {
            null => fallback,
            long l => l,
            int i => i,
            double d => (long)d,
            string s => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var r) ? r : fallback,
            _ => fallback,
        };
    }

    public double GetDouble(string key, double fallback = 0)
    {
        var v = this[key];
        return v switch
        {
            null => fallback,
            double d => d,
            long l => l,
            int i => i,
            string s => double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? r : fallback,
            _ => fallback,
        };
    }

    public bool GetBool(string key, bool fallback = false)
    {
        var v = this[key];
        return v switch
        {
            null => fallback,
            bool b => b,
            long l => l != 0,
            int i => i != 0,
            double d => d != 0,
            string s => s.Trim().ToLowerInvariant() switch
            {
                "true" or "yes" or "on" or "1" => true,
                "false" or "no" or "off" or "0" or "" => false,
                _ => fallback,
            },
            _ => fallback,
        };
    }

    public bool? GetNullableBool(string key) => Has(key) ? GetBool(key) : null;

    public YamlMap GetMap(string key) => From(this[key]);

    public IReadOnlyList<object?> GetList(string key)
        => this[key] as IReadOnlyList<object?> ?? (this[key] as List<object?>) ?? [];

    public List<string> GetStringList(string key)
        => GetList(key).Select(x => Convert.ToString(x, CultureInfo.InvariantCulture) ?? "").Where(s => s.Length > 0).ToList();

    /// <summary>Returns the value as a map, treating a bare scalar as the single "name" field.</summary>
    public YamlMap GetMapOrScalar(string key)
    {
        var v = this[key];
        return v is string s
            ? new YamlMap(new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["name"] = s })
            : From(v);
    }

    public YamlMap With(string key, object? value)
    {
        var copy = new Dictionary<string, object?>(_values, StringComparer.OrdinalIgnoreCase) { [key] = value };
        return new YamlMap(copy);
    }

    public override string ToString() => string.Join(", ", _values.Select(kv => $"{kv.Key}={kv.Value}"));
}
