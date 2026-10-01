using System.Text.Json;
using System.Text.Json.Serialization;
using Clash.Core.Common;
using Clash.Core.Providers;
using Clash.Core.Runtime;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Configuration;

/// <summary>One stored profile: a local document, a remote subscription, or a merge overlay.</summary>
public sealed class Profile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("n");

    public string Name { get; set; } = string.Empty;

    /// <summary><c>local</c>, <c>remote</c> or <c>merge</c>.</summary>
    public string Type { get; set; } = "local";

    /// <summary>Subscription URL for <c>remote</c> profiles.</summary>
    public string? Url { get; set; }

    /// <summary>Absolute path of the stored YAML document.</summary>
    public string Path { get; set; } = string.Empty;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public bool Selected { get; set; }

    public string? Description { get; set; }

    /// <summary>Traffic and expiry reported by the subscription server, when known.</summary>
    public SubscriptionInfo? SubscriptionInfo { get; set; }

    /// <summary>Populated only for the currently selected profile.</summary>
    [JsonIgnore]
    public string? RawContent { get; set; }
}

/// <summary>
/// Stores, imports and activates profiles under <c>&lt;home&gt;/profiles</c>,
/// and composes the effective configuration from the selected profile plus the
/// merge overlays.
/// </summary>
public sealed class ProfileManager
{
    private const string MetadataFile = "profiles.json";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly ILogger<ProfileManager> _logger;
    private readonly Lock _gate = new();
    private List<Profile> _profiles = [];

    public ProfileManager(string homeDir, ILogger<ProfileManager> logger)
    {
        HomeDir = homeDir;
        _logger = logger;
        ProfilesDir = System.IO.Path.Combine(homeDir, "profiles");
        Directory.CreateDirectory(ProfilesDir);
        Load();
    }

    public string HomeDir { get; }

    public string ProfilesDir { get; }

    private string MetadataPath => System.IO.Path.Combine(HomeDir, MetadataFile);

    /// <summary>Every profile, selected first, then by most recently updated.</summary>
    public IReadOnlyList<Profile> List()
    {
        lock (_gate)
        {
            return _profiles
                .OrderByDescending(p => p.Selected)
                .ThenByDescending(p => p.UpdatedAt)
                .ToList();
        }
    }

    public Profile? Get(string id)
    {
        lock (_gate) return _profiles.FirstOrDefault(p => p.Id == id);
    }

    /// <summary>The active profile, or null when none has been selected.</summary>
    public Profile? Selected
    {
        get
        {
            lock (_gate) return _profiles.FirstOrDefault(p => p.Selected);
        }
    }

    /// <summary>Creates a profile. When <paramref name="content"/> is null an empty document is stored.</summary>
    public Profile Create(string name, string type, string? url = null, string? content = null)
    {
        var profile = new Profile
        {
            Name = string.IsNullOrWhiteSpace(name) ? $"profile-{DateTime.Now:yyyyMMdd-HHmmss}" : name,
            Type = type,
            Url = url,
            UpdatedAt = DateTimeOffset.UtcNow,
        };

        profile.Path = System.IO.Path.Combine(ProfilesDir, $"{profile.Id}.yaml");
        File.WriteAllText(profile.Path, content ?? string.Empty);

        lock (_gate)
        {
            // The first profile becomes the active one automatically.
            if (_profiles.Count == 0) profile.Selected = true;
            _profiles.Add(profile);
            Save();
        }

        _logger.LogInformation("created {Type} profile {Name} ({Id})", type, profile.Name, profile.Id);
        return profile;
    }

    /// <summary>Renames a profile or changes its subscription URL.</summary>
    public bool Update(string id, string? name, string? url, string? description)
    {
        lock (_gate)
        {
            var profile = _profiles.FirstOrDefault(p => p.Id == id);
            if (profile is null) return false;

            if (!string.IsNullOrWhiteSpace(name)) profile.Name = name!;
            if (url is not null) profile.Url = url;
            if (description is not null) profile.Description = description;
            profile.UpdatedAt = DateTimeOffset.UtcNow;
            Save();
            return true;
        }
    }

    public bool Delete(string id)
    {
        lock (_gate)
        {
            var profile = _profiles.FirstOrDefault(p => p.Id == id);
            if (profile is null) return false;

            _profiles.Remove(profile);
            try
            {
                if (File.Exists(profile.Path)) File.Delete(profile.Path);
            }
            catch (Exception ex)
            {
                _logger.LogWarning("could not delete {Path}: {Message}", profile.Path, ex.Message);
            }

            // Never leave the instance without an active profile.
            if (profile.Selected && _profiles.Count > 0) _profiles[0].Selected = true;

            Save();
            return true;
        }
    }

    /// <summary>Marks a profile active and clears the flag on the others.</summary>
    public bool Select(string id)
    {
        lock (_gate)
        {
            var target = _profiles.FirstOrDefault(p => p.Id == id);
            if (target is null) return false;

            foreach (var profile in _profiles) profile.Selected = ReferenceEquals(profile, target);
            Save();
            _logger.LogInformation("profile {Name} selected", target.Name);
            return true;
        }
    }

    public string ReadContent(string id)
    {
        var profile = Get(id) ?? throw new ClashException($"profile [{id}] not found");
        return File.Exists(profile.Path) ? File.ReadAllText(profile.Path) : string.Empty;
    }

    public void WriteContent(string id, string content)
    {
        var profile = Get(id) ?? throw new ClashException($"profile [{id}] not found");
        File.WriteAllText(profile.Path, content);
        lock (_gate)
        {
            profile.UpdatedAt = DateTimeOffset.UtcNow;
            Save();
        }
    }

    /// <summary>Downloads a remote profile and stores it, recording subscription metadata.</summary>
    public async Task<Profile> UpdateRemoteAsync(string id, CancellationToken cancellationToken = default)
    {
        var profile = Get(id) ?? throw new ClashException($"profile [{id}] not found");
        if (string.IsNullOrWhiteSpace(profile.Url))
        {
            throw new ClashException($"profile [{profile.Name}] has no subscription url");
        }

        var (content, info) = await DownloadAsync(profile.Url!, cancellationToken).ConfigureAwait(false);

        // A subscription may be a share-link list rather than a Clash document;
        // convert it so the profile is always loadable.
        var yaml = NormalizeToYaml(content);

        File.WriteAllText(profile.Path, yaml);

        lock (_gate)
        {
            profile.UpdatedAt = DateTimeOffset.UtcNow;
            profile.SubscriptionInfo = info?.Info;
            Save();
        }

        _logger.LogInformation("updated remote profile {Name} ({Bytes} bytes)", profile.Name, yaml.Length);
        return profile;
    }

    /// <summary>Imports a subscription URL as a new remote profile.</summary>
    public async Task<Profile> ImportUrlAsync(string url, string? name, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ClashException($"invalid subscription url: {url}");
        }

        var (content, info) = await DownloadAsync(url, cancellationToken).ConfigureAwait(false);
        var yaml = NormalizeToYaml(content);

        // Prefer the name the subscription advertises via Content-Disposition.
        var profile = Create(name ?? info?.Name ?? uri.Host, "remote", url, yaml);

        lock (_gate)
        {
            var stored = _profiles.First(p => p.Id == profile.Id);
            stored.SubscriptionInfo = info?.Info;
            stored.Description = info?.Description;
            Save();
        }

        return profile;
    }

    /// <summary>
    /// Builds the effective configuration: the selected profile's document with
    /// every <c>merge</c> profile applied on top, in list order.
    /// </summary>
    public ClashConfig BuildActiveConfig()
    {
        var selected = Selected;
        var root = selected is not null && File.Exists(selected.Path)
            ? YamlReader.Parse(File.ReadAllText(selected.Path))
            : YamlReader.Parse(DefaultConfiguration.Yaml);

        List<Profile> merges;
        lock (_gate) merges = _profiles.Where(p => p.Type == "merge" && File.Exists(p.Path)).ToList();

        foreach (var merge in merges)
        {
            try
            {
                root = Merge(root, YamlReader.Parse(File.ReadAllText(merge.Path)));
            }
            catch (Exception ex)
            {
                _logger.LogWarning("merge profile {Name} failed: {Message}", merge.Name, ex.Message);
            }
        }

        return ConfigParser.Parse(root);
    }

    /// <summary>
    /// Deep-merges <paramref name="overlay"/> onto <paramref name="base"/>.
    /// Mappings merge key by key, sequences concatenate (so merge profiles can
    /// append proxies and rules), and scalars are replaced.
    /// </summary>
    public static YamlMap Merge(YamlMap @base, YamlMap overlay)
    {
        var result = new Dictionary<string, object?>(@base.Raw, StringComparer.OrdinalIgnoreCase);

        foreach (var (key, value) in overlay.Raw)
        {
            if (result.TryGetValue(key, out var existing) &&
                existing is Dictionary<string, object?> existingMap &&
                value is Dictionary<string, object?> overlayMap)
            {
                result[key] = Merge(new YamlMap(existingMap), new YamlMap(overlayMap)).Raw;
                continue;
            }

            if (result.TryGetValue(key, out existing) &&
                existing is List<object?> existingList &&
                value is List<object?> overlayList)
            {
                var merged = new List<object?>(existingList);
                merged.AddRange(overlayList);
                result[key] = merged;
                continue;
            }

            result[key] = value;
        }

        return new YamlMap(result);
    }

    private void Load()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(MetadataPath))
                {
                    _profiles = [];
                    return;
                }

                var json = File.ReadAllText(MetadataPath);
                _profiles = JsonSerializer.Deserialize<List<Profile>>(json, Json) ?? [];

                // Drop entries whose document vanished.
                _profiles.RemoveAll(p => !File.Exists(p.Path));
                if (_profiles.Count > 0 && _profiles.All(p => !p.Selected)) _profiles[0].Selected = true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("profiles.json could not be read ({Message}); starting empty", ex.Message);
                _profiles = [];
            }
        }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(HomeDir);
            File.WriteAllText(MetadataPath, JsonSerializer.Serialize(_profiles, Json));
        }
        catch (Exception ex)
        {
            _logger.LogWarning("profiles.json could not be written: {Message}", ex.Message);
        }
    }

    private static async Task<(string Content, SubscriptionHeader? Header)> DownloadAsync(string url, CancellationToken cancellationToken)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("clash-verge/v1.0.0");

        using var response = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        var header = new SubscriptionHeader
        {
            Info = SubscriptionInfoParser.FromHeaders(response.Headers),
            Name = SubscriptionInfoParser.ProfileNameFromHeaders(response.Headers, response.Content.Headers),
            Description = response.Headers.TryGetValues("profile-description", out var d) ? string.Join(" ", d) : null,
        };

        return (content, header);
    }

    /// <summary>
    /// Ensures a downloaded body is a Clash document. A share-link subscription is
    /// converted into a <c>proxies</c> list so it can be loaded directly.
    /// </summary>
    private string NormalizeToYaml(string content)
    {
        var trimmed = content.TrimStart();

        // Already YAML: a Clash document starts with a key or a comment.
        if (trimmed.Contains("proxies:", StringComparison.Ordinal) ||
            trimmed.Contains("mixed-port:", StringComparison.Ordinal) ||
            trimmed.Contains("port:", StringComparison.Ordinal) ||
            trimmed.Contains("proxy-groups:", StringComparison.Ordinal))
        {
            return content;
        }

        if (!ShareLinks.IsAvailable) return content;

        try
        {
            var entries = ShareLinks.Parser.ParseSubscription(content);
            if (entries.Count == 0) return content;

            var builder = new System.Text.StringBuilder();
            builder.AppendLine("proxies:");
            foreach (var entry in entries)
            {
                builder.AppendLine($"  - name: {Quote(entry.Name)}");
                builder.AppendLine($"    type: {entry.Type}");
                foreach (var (key, value) in entry.Map.Raw)
                {
                    if (key is "name" or "type") continue;
                    builder.AppendLine($"    {key}: {FormatScalar(value)}");
                }
            }

            builder.AppendLine("proxy-groups:");
            builder.AppendLine("  - name: PROXY");
            builder.AppendLine("    type: select");
            builder.AppendLine("    proxies:");
            foreach (var entry in entries) builder.AppendLine($"      - {Quote(entry.Name)}");
            builder.AppendLine("rules:");
            builder.AppendLine("  - MATCH,PROXY");

            _logger.LogInformation("converted {Count} share links into a Clash document", entries.Count);
            return builder.ToString();
        }
        catch (Exception ex)
        {
            _logger.LogWarning("share-link conversion failed, storing the body verbatim: {Message}", ex.Message);
            return content;
        }
    }

    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";

    private static string FormatScalar(object? value) => value switch
    {
        null => "''",
        bool b => b ? "true" : "false",
        string s when s.Length == 0 => "''",
        string s => s.Contains(':') || s.Contains('#') || s.Contains(' ') || s.Contains('"') || s.Contains('\'')
            ? Quote(s)
            : s,
        Dictionary<string, object?> map => FormatMap(map),
        List<object?> list => FormatList(list),
        _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "''",
    };

    private static string FormatList(List<object?> list)
        => "[" + string.Join(", ", list.Select(FormatScalar)) + "]";

    private static string FormatMap(Dictionary<string, object?> map)
    {
        var inner = string.Join(", ", map.Select(kv => $"{kv.Key}: {FormatScalar(kv.Value)}"));
        return "{" + inner + "}";
    }

    private sealed record SubscriptionHeader
    {
        public SubscriptionInfo? Info { get; init; }
        public string? Name { get; init; }
        public string? Description { get; init; }
    }
}
