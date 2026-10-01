using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using Clash.Core.Configuration;
using MaxMind.Db;

namespace Clash.Core.Rules;

/// <summary>
/// A no-op <see cref="IGeoData"/>. Used when the tunnel starts without any data files so
/// that <c>GEOIP</c>, <c>IP-ASN</c> and <c>GEOSITE</c> rules simply never match instead of
/// failing the whole configuration.
/// </summary>
public sealed class EmptyGeoData : IGeoData
{
    /// <inheritdoc />
    public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    /// <inheritdoc />
    public bool TryGetCountry(IPAddress address, out string countryCode)
    {
        countryCode = string.Empty;
        return false;
    }

    /// <inheritdoc />
    public bool TryGetAsn(IPAddress address, out uint asn)
    {
        asn = 0;
        return false;
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string>? GetGeoSite(string code) => null;

    /// <inheritdoc />
    public IReadOnlyList<(IPAddress Network, int PrefixLength)>? GetGeoSiteCidrs(string code) => null;

    /// <inheritdoc />
    public bool HasGeoSite(string code) => false;

    /// <inheritdoc />
    public bool HasCountry(string code) => false;
}

/// <summary>
/// Loads and queries the geo databases used by the <c>GEOIP</c>, <c>SRC-GEOIP</c>,
/// <c>IP-ASN</c>, <c>SRC-IP-ASN</c> and <c>GEOSITE</c> rules.
/// </summary>
/// <remarks>
/// <para>Supported inputs, discovered in the configured data directory and in a
/// <c>data/</c> folder next to the executable:</para>
/// <list type="bullet">
///   <item><description>MaxMind mmdb for countries (<c>Country.mmdb</c>, <c>GeoLite2-Country.mmdb</c>, <c>GeoLite2-City.mmdb</c>, …).</description></item>
///   <item><description>MaxMind mmdb for ASNs (<c>ASN.mmdb</c>, <c>GeoLite2-ASN.mmdb</c>).</description></item>
///   <item><description>v2ray <c>geosite.dat</c>, decoded from its protobuf wire format.</description></item>
///   <item><description>v2ray <c>geoip.dat</c>, likewise.</description></item>
///   <item><description>A <c>geosite/</c> directory of text or YAML category files, one entry per line, with optional <c>full:</c>, <c>domain:</c>, <c>keyword:</c> and <c>regexp:</c> prefixes.</description></item>
///   <item><description>A <c>geoip/</c> directory of text category files holding CIDRs.</description></item>
/// </list>
/// <para>
/// mihomo's <c>.metadb</c> and the v2ray <c>.dat</c> files carrying attribute metadata beyond
/// <c>ipcidr</c> are not decoded; such categories still load, minus the attributes.
/// Downloads happen only when a URL is configured in <c>geox-url</c>, the file is missing,
/// and downloading was opted into through the constructor.
/// </para>
/// </remarks>
public sealed class GeoData : IGeoData, IGeoSiteMatcherProvider, IDisposable
{
    private static readonly string[] CountryMmdbNames =
        ["Country.mmdb", "GeoLite2-Country.mmdb", "GeoLite2-City.mmdb", "geoip.mmdb", "dbip-country-lite.mmdb", "Country.metadb"];

    private static readonly string[] AsnMmdbNames =
        ["ASN.mmdb", "GeoLite2-ASN.mmdb", "asn.mmdb", "GeoLite2-ASN.metadb"];

    private static readonly string[] GeoSiteNames = ["geosite.dat", "GeoSite.dat", "geosite.db"];

    private static readonly string[] GeoIpNames = ["geoip.dat", "GeoIP.dat", "geoip.db"];

    private readonly ClashConfig _config;
    private readonly string[] _roots;
    private readonly string _downloadDirectory;
    private readonly bool _allowDownload;
    private readonly HttpClient? _http;
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private readonly ConcurrentDictionary<string, DomainMatcher?> _geoMatchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CidrMatcher?> _geoCidrMatchers = new(StringComparer.OrdinalIgnoreCase);

    private Reader? _country;
    private Reader? _asn;
    private volatile Dictionary<string, GeoSiteCategory> _geo = new(StringComparer.OrdinalIgnoreCase);
    private volatile CidrMatcher? _countryCidrs;
    private volatile string[] _countryCodes = [];
    private volatile bool _useConcreteRecord;

    /// <summary>Creates a geo database holder.</summary>
    /// <param name="config">The configuration supplying <c>geodata</c> and <c>geox-url</c>; may be null.</param>
    /// <param name="dataDirectory">Explicit data directory. Defaults to <c>data/</c> next to the executable.</param>
    /// <param name="allowDownload">When true, a missing file with a configured URL is fetched over HTTP.</param>
    /// <param name="handler">Optional HTTP handler, for tests.</param>
    public GeoData(ClashConfig? config = null, string? dataDirectory = null, bool allowDownload = false, HttpMessageHandler? handler = null)
    {
        _config = config ?? new ClashConfig();
        _allowDownload = allowDownload;
        _http = handler is null && !allowDownload ? null : new HttpClient(handler ?? new HttpClientHandler());

        if (!string.IsNullOrWhiteSpace(dataDirectory))
        {
            _roots = [dataDirectory];
            _downloadDirectory = dataDirectory;
        }
        else
        {
            _roots = DefaultRoots();
            _downloadDirectory = _roots.Length > 0 ? _roots[0] : AppContext.BaseDirectory;
        }
    }

    /// <summary>A no-op instance, so the tunnel can start without any data files.</summary>
    public static IGeoData Empty { get; } = new EmptyGeoData();

    /// <summary>The directories searched for data files, in order.</summary>
    public IReadOnlyList<string> SearchRoots => _roots;

    /// <inheritdoc />
    public async Task LoadAsync(CancellationToken cancellationToken = default)
    {
        await _loadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await Task.Run(() => LoadCore(cancellationToken), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _loadGate.Release();
        }
    }

    /// <inheritdoc />
    public bool TryGetCountry(IPAddress address, out string countryCode)
    {
        countryCode = string.Empty;
        if (address is null) return false;

        var reader = _country;
        if (reader is not null)
        {
            var record = FindRecord(reader, address);
            if (record is not null)
            {
                var code = ReadString(record, "country", "iso_code")
                    ?? ReadString(record, "registered_country", "iso_code")
                    ?? ReadString(record, "represented_country", "iso_code");
                if (!string.IsNullOrEmpty(code))
                {
                    countryCode = code.ToUpperInvariant();
                    return true;
                }
            }
        }

        var matcher = _countryCidrs;
        if (matcher is not null)
        {
            var index = matcher.Match(address);
            var codes = _countryCodes;
            if (index >= 0 && index < codes.Length)
            {
                countryCode = codes[index];
                return true;
            }
        }

        return false;
    }

    /// <inheritdoc />
    public bool TryGetAsn(IPAddress address, out uint asn)
    {
        asn = 0;
        var reader = _asn;
        if (reader is null || address is null) return false;

        var record = FindRecord(reader, address);
        if (record is null) return false;
        if (!record.TryGetValue("autonomous_system_number", out var value) || value is null) return false;

        try
        {
            asn = Convert.ToUInt32(value, CultureInfo.InvariantCulture);
            return true;
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public IReadOnlyCollection<string>? GetGeoSite(string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        return _geo.TryGetValue(code.Trim(), out var category) ? category.PlainDomains : null;
    }

    /// <inheritdoc />
    public IReadOnlyList<(IPAddress Network, int PrefixLength)>? GetGeoSiteCidrs(string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        if (!_geo.TryGetValue(code.Trim(), out var category) || category.Cidrs.Count == 0) return null;
        return category.Cidrs.Select(c => (c.Network, c.PrefixLength)).ToList();
    }

    /// <inheritdoc />
    public bool HasGeoSite(string code) => !string.IsNullOrWhiteSpace(code) && _geo.ContainsKey(code.Trim());

    /// <inheritdoc />
    public bool HasCountry(string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        var value = code.Trim();
        if (_country is not null) return true;
        return Array.Exists(_countryCodes, c => string.Equals(c, value, StringComparison.OrdinalIgnoreCase));
    }

    /// <inheritdoc />
    public DomainMatcher? GetGeoSiteMatcher(string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        return _geoMatchers.GetOrAdd(code.Trim(), BuildDomainMatcher);
    }

    /// <inheritdoc />
    public CidrMatcher? GetGeoSiteCidrMatcher(string code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        return _geoCidrMatchers.GetOrAdd(code.Trim(), BuildCidrMatcher);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _country?.Dispose();
        _asn?.Dispose();
        _country = null;
        _asn = null;
        _http?.Dispose();
        _loadGate.Dispose();
    }

    private static string[] DefaultRoots()
    {
        var roots = new List<string>();
        var baseDirectory = AppContext.BaseDirectory;
        if (!string.IsNullOrEmpty(baseDirectory))
        {
            roots.Add(Path.Combine(baseDirectory, "data"));
            roots.Add(baseDirectory);
        }

        var current = Directory.GetCurrentDirectory();
        if (!string.IsNullOrEmpty(current))
        {
            var candidate = Path.Combine(current, "data");
            if (!roots.Contains(candidate, StringComparer.OrdinalIgnoreCase)) roots.Add(candidate);
        }

        return [.. roots];
    }

    private void LoadCore(CancellationToken cancellationToken)
    {
        var geoSite = new Dictionary<string, GeoSiteCategory>(StringComparer.OrdinalIgnoreCase);
        var geoIp = new Dictionary<string, List<IpPrefix>>(StringComparer.OrdinalIgnoreCase);

        var countryPath = Locate(CountryMmdbNames) ?? Download("mmdb", "Country.mmdb", cancellationToken);
        if (countryPath is not null) ReplaceReader(ref _country, countryPath);

        var asnPath = Locate(AsnMmdbNames) ?? Download("asn", "ASN.mmdb", cancellationToken);
        if (asnPath is not null) ReplaceReader(ref _asn, asnPath);

        var geoSitePath = Locate(GeoSiteNames) ?? Download("geosite", "geosite.dat", cancellationToken);
        if (geoSitePath is not null)
        {
            try
            {
                foreach (var pair in GeoDataFiles.ParseGeoSite(File.ReadAllBytes(geoSitePath)))
                {
                    if (geoSite.TryGetValue(pair.Key, out var existing)) existing.Merge(pair.Value);
                    else geoSite[pair.Key] = pair.Value;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // A corrupt data file must not stop the tunnel from starting.
            }
        }

        LoadGeoSiteDirectory(geoSite);

        var geoIpPath = Locate(GeoIpNames) ?? Download("geoip", "geoip.dat", cancellationToken);
        if (geoIpPath is not null)
        {
            try
            {
                foreach (var pair in GeoDataFiles.ParseGeoIp(File.ReadAllBytes(geoIpPath)))
                {
                    if (geoIp.TryGetValue(pair.Key, out var existing)) existing.AddRange(pair.Value);
                    else geoIp[pair.Key] = pair.Value;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // As above: degrade to "unknown country" rather than failing.
            }
        }

        LoadGeoIpDirectory(geoIp);

        var codes = new List<string>();
        var matcher = new CidrMatcher();
        foreach (var pair in geoIp)
        {
            var index = codes.Count;
            codes.Add(pair.Key.ToUpperInvariant());
            foreach (var prefix in pair.Value) matcher.Add(prefix, index);
        }

        _countryCodes = [.. codes];
        _countryCidrs = matcher.IsEmpty ? null : matcher;
        _geo = geoSite;
        _geoMatchers.Clear();
        _geoCidrMatchers.Clear();
    }

    private void LoadGeoSiteDirectory(Dictionary<string, GeoSiteCategory> target)
    {
        foreach (var root in _roots)
        {
            var directory = Path.Combine(root, "geosite");
            if (!Directory.Exists(directory)) continue;

            foreach (var file in Directory.EnumerateFiles(directory))
            {
                var code = Path.GetFileNameWithoutExtension(file);
                if (string.IsNullOrWhiteSpace(code)) continue;

                var entries = ReadEntries(file);
                if (entries.Count == 0) continue;

                if (!target.TryGetValue(code, out var category))
                {
                    category = new GeoSiteCategory();
                    target[code] = category;
                }

                foreach (var entry in entries)
                {
                    if (TryCidrEntry(entry, out var prefix))
                    {
                        category.Cidrs.Add(prefix);
                        continue;
                    }

                    if (TryDomainEntry(entry, out var value, out var kind)) category.Domains.Add((kind, value));
                }
            }
        }
    }

    private void LoadGeoIpDirectory(Dictionary<string, List<IpPrefix>> target)
    {
        foreach (var root in _roots)
        {
            var directory = Path.Combine(root, "geoip");
            if (!Directory.Exists(directory)) continue;

            foreach (var file in Directory.EnumerateFiles(directory))
            {
                var code = Path.GetFileNameWithoutExtension(file);
                if (string.IsNullOrWhiteSpace(code)) continue;

                var entries = ReadEntries(file);
                if (entries.Count == 0) continue;

                if (!target.TryGetValue(code, out var prefixes))
                {
                    prefixes = [];
                    target[code] = prefixes;
                }

                foreach (var entry in entries)
                {
                    if (IpPrefix.TryParse(entry, out var prefix)) prefixes.Add(prefix);
                }
            }
        }
    }

    private static List<string> ReadEntries(string path)
    {
        var entries = new List<string>();
        try
        {
            var text = File.ReadAllText(path);
            if (text.Contains("payload:", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var entry in ExtractYamlPayload(text))
                {
                    var trimmed = entry.Trim();
                    if (trimmed.Length > 0) entries.Add(trimmed);
                }

                return entries;
            }

            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.Trim().TrimEnd('\r').Trim('"', '\'');
                if (trimmed.Length == 0 || trimmed.StartsWith('#')) continue;
                entries.Add(trimmed.StartsWith("- ", StringComparison.Ordinal) ? trimmed[2..].Trim() : trimmed);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Unreadable category file: skip it.
        }

        return entries;
    }

    private static List<string> ExtractYamlPayload(string text)
    {
        var entries = new List<string>();
        try
        {
            var raw = new YamlDotNet.Serialization.DeserializerBuilder().Build().Deserialize<object?>(text);
            if (Clash.Core.Common.YamlMap.Normalize(raw) is Dictionary<string, object?> map
                && map.TryGetValue("payload", out var payload)
                && payload is IEnumerable<object?> list)
            {
                foreach (var item in list)
                {
                    var rendered = Convert.ToString(item, CultureInfo.InvariantCulture);
                    if (!string.IsNullOrWhiteSpace(rendered)) entries.Add(rendered);
                }
            }
        }
        catch (YamlDotNet.Core.YamlException)
        {
            // Not YAML; the caller already handled the plain-text form.
        }

        return entries;
    }

    private static bool TryCidrEntry(string entry, out IpPrefix prefix)
    {
        prefix = default;

        var text = entry.Trim();
        foreach (var marker in (string[])["ipcidr:", "cidr:"])
        {
            if (!text.StartsWith(marker, StringComparison.OrdinalIgnoreCase)) continue;
            text = text[marker.Length..].Trim();
            return IpPrefix.TryParse(text, out prefix);
        }

        return false;
    }

    private static bool TryDomainEntry(string entry, out string value, out DomainMatchKind kind)
    {
        var text = entry.Trim();
        kind = DomainMatchKind.Suffix;

        if (text.StartsWith("full:", StringComparison.OrdinalIgnoreCase))
        {
            kind = DomainMatchKind.Full;
            text = text[5..];
        }
        else if (text.StartsWith("domain:", StringComparison.OrdinalIgnoreCase))
        {
            text = text[7..];
        }
        else if (text.StartsWith("keyword:", StringComparison.OrdinalIgnoreCase))
        {
            kind = DomainMatchKind.Keyword;
            text = text[8..];
        }
        else if (text.StartsWith("regexp:", StringComparison.OrdinalIgnoreCase))
        {
            kind = DomainMatchKind.Regex;
            text = text[7..];
        }
        else if (text.StartsWith("+.", StringComparison.Ordinal))
        {
            text = text[2..];
        }
        else if (text.StartsWith('.'))
        {
            text = text[1..];
        }

        value = text.Trim();
        return value.Length > 0;
    }

    private DomainMatcher? BuildDomainMatcher(string code)
    {
        if (!_geo.TryGetValue(code, out var category)) return null;

        var matcher = new DomainMatcher();
        var index = 0;
        foreach (var (kind, value) in category.Domains)
        {
            try
            {
                matcher.Add(value, kind, index);
            }
            catch (ArgumentException)
            {
                continue;
            }

            index++;
        }

        return matcher.IsEmpty ? null : matcher;
    }

    private CidrMatcher? BuildCidrMatcher(string code)
    {
        if (!_geo.TryGetValue(code, out var category) || category.Cidrs.Count == 0) return null;

        var matcher = new CidrMatcher();
        for (var i = 0; i < category.Cidrs.Count; i++) matcher.Add(category.Cidrs[i], i);
        return matcher;
    }

    private string? Locate(string[] names)
    {
        foreach (var root in _roots)
        {
            if (string.IsNullOrWhiteSpace(root)) continue;
            foreach (var name in names)
            {
                var candidate = Path.Combine(root, name);
                if (File.Exists(candidate)) return candidate;
            }
        }

        return null;
    }

    private string? Download(string key, string fileName, CancellationToken cancellationToken)
    {
        if (!_allowDownload) return null;

        var url = key switch
        {
            "mmdb" => _config.GeoxUrl.Mmdb,
            "asn" => _config.GeoxUrl.Asn,
            "geosite" => _config.GeoxUrl.GeoSite,
            "geoip" => _config.GeoxUrl.GeoIp,
            _ => string.Empty,
        };

        if (string.IsNullOrWhiteSpace(url)) return null;

        var target = Path.Combine(_downloadDirectory, fileName);
        if (File.Exists(target)) return target;

        try
        {
            Directory.CreateDirectory(_downloadDirectory);
            using var client = _http ?? new HttpClient();
            var bytes = client.GetByteArrayAsync(url, cancellationToken).GetAwaiter().GetResult();
            if (bytes.Length == 0) return null;

            var temporary = target + ".tmp";
            File.WriteAllBytes(temporary, bytes);
            File.Move(temporary, target, true);
            return target;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or TaskCanceledException or InvalidOperationException)
        {
            return null;
        }
    }

    private void ReplaceReader(ref Reader? field, string path)
    {
        try
        {
            var replacement = new Reader(path);
            field?.Dispose();
            field = replacement;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
        {
            // A malformed mmdb leaves the previous reader (or none) in place.
        }
    }

    private IDictionary<string, object>? FindRecord(Reader reader, IPAddress address)
    {
        if (!_useConcreteRecord)
        {
            try
            {
                return reader.Find<IDictionary<string, object>>(address);
            }
            catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException or InvalidCastException)
            {
                _useConcreteRecord = true;
            }
        }

        try
        {
            return reader.Find<Dictionary<string, object>>(address);
        }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException or InvalidCastException or IOException)
        {
            return null;
        }
    }

    private static string? ReadString(IDictionary<string, object> record, params string[] path)
    {
        object? current = record;
        foreach (var key in path)
        {
            switch (current)
            {
                case IDictionary<string, object> map when map.TryGetValue(key, out var next):
                    current = next;
                    break;
                case IDictionary<string, string> strings when strings.TryGetValue(key, out var text):
                    current = text;
                    break;
                default:
                    return null;
            }
        }

        return current as string;
    }
}
