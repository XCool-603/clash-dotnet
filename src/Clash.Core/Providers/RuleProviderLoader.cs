using System.Globalization;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;
using YamlDotNet.Core;
using YamlDotNet.Serialization;

namespace Clash.Core.Providers;

/// <summary>
/// Fetches <c>rule-providers</c> entries over the <c>inline</c>, <c>file</c> and
/// <c>http</c> vehicles, caching downloaded bodies on disk, and turns their
/// payloads into matchable rule sets.
/// </summary>
/// <remarks>
/// <para>
/// The <c>yaml</c> (a document with a <c>payload:</c> sequence), <c>text</c> (one
/// entry per line) and <c>mrs</c> formats are recognised. The <c>mrs</c> binary
/// format mihomo introduced is <b>not decoded</b> by this build: the <c>MRS</c>
/// magic is detected, a warning is logged and an empty payload is returned, so a
/// profile referencing an <c>mrs</c> provider still loads and simply matches
/// nothing for that set instead of failing outright.
/// </para>
/// <para>
/// Caching mirrors <see cref="ProxyProviderLoader"/>: a body cached at <c>path</c>
/// younger than <c>interval</c> seconds (86400 by default, 0 meaning "never
/// re-download on a cache hit") is served without touching the network, and a
/// failed download falls back to the cached copy.
/// </para>
/// </remarks>
public sealed class RuleProviderLoader : IRuleProviderLoader, IDisposable
{
    private const string UserAgent = "clash-verge/v1.0.0";

    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(60);

    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _homeDir;
    private readonly ILogger<RuleProviderLoader>? _logger;

    /// <summary>Creates a loader that downloads with its own <see cref="HttpClient"/>.</summary>
    /// <param name="homeDir">Directory relative cache and provider paths resolve against.</param>
    /// <param name="logger">Optional logger.</param>
    public RuleProviderLoader(string homeDir, ILogger<RuleProviderLoader>? logger = null)
        : this(homeDir, new HttpClient { Timeout = DownloadTimeout }, logger, ownsClient: true)
    {
    }

    /// <summary>Creates a loader over a caller supplied message handler, for tests and custom transports.</summary>
    /// <param name="homeDir">Directory relative cache and provider paths resolve against.</param>
    /// <param name="handler">The handler the internal <see cref="HttpClient"/> uses.</param>
    /// <param name="logger">Optional logger.</param>
    public RuleProviderLoader(string homeDir, HttpMessageHandler handler, ILogger<RuleProviderLoader>? logger = null)
        : this(homeDir, new HttpClient(handler, disposeHandler: false) { Timeout = DownloadTimeout }, logger, ownsClient: true)
    {
    }

    /// <summary>Creates a loader over a caller supplied client.</summary>
    /// <param name="homeDir">Directory relative cache and provider paths resolve against.</param>
    /// <param name="httpClient">The client to download with; it is not disposed by this loader.</param>
    /// <param name="logger">Optional logger.</param>
    public RuleProviderLoader(string homeDir, HttpClient httpClient, ILogger<RuleProviderLoader>? logger = null)
        : this(homeDir, httpClient, logger, ownsClient: false)
    {
    }

    private RuleProviderLoader(string homeDir, HttpClient httpClient, ILogger<RuleProviderLoader>? logger, bool ownsClient)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(homeDir);
        ArgumentNullException.ThrowIfNull(httpClient);

        _homeDir = homeDir;
        _http = httpClient;
        _ownsClient = ownsClient;
        _logger = logger;
    }

    /// <summary>Directory relative provider paths resolve against.</summary>
    public string HomeDir => _homeDir;

    /// <summary>Disposes the internally created <see cref="HttpClient"/>, if any.</summary>
    public void Dispose()
    {
        if (_ownsClient) _http.Dispose();
    }

    /// <inheritdoc />
    public Task<RuleProviderResult> LoadAsync(string name, RuleProviderConfig config, CancellationToken cancellationToken = default)
        => LoadCoreAsync(name, config, forceRefresh: false, cancellationToken);

    /// <inheritdoc />
    public Task<RuleProviderResult> RefreshAsync(string name, RuleProviderConfig config, CancellationToken cancellationToken = default)
        => LoadCoreAsync(name, config, forceRefresh: true, cancellationToken);

    /// <inheritdoc />
    public Rules.IRuleSet ToRuleSet(string name, RuleProviderResult result)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(result);

        return CreateRuleSet(name, result);
    }

    /// <summary>
    /// The single call site into the <c>Clash.Core.Rules</c> factory, kept alone so
    /// a change to that API only has to be tracked down in one place.
    /// </summary>
    private static Rules.IRuleSet CreateRuleSet(string name, RuleProviderResult result)
        => Rules.RuleSet.FromPayload(name, result.Behavior, result.Payload);

    private Task<RuleProviderResult> LoadCoreAsync(string name, RuleProviderConfig config, bool forceRefresh, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(config);

        return (config.Type ?? "http").Trim().ToLowerInvariant() switch
        {
            "inline" => Task.FromResult(LoadInline(name, config)),
            "file" => Task.FromResult(LoadFile(name, config)),
            "http" => LoadHttpAsync(name, config, forceRefresh, cancellationToken),
            _ => throw new ProviderException($"rule provider [{name}] has an unsupported type [{config.Type}]"),
        };
    }

    private static RuleProviderResult LoadInline(string name, RuleProviderConfig config)
    {
        var payload = config.Payload ?? [];
        if (payload.Count == 0)
        {
            throw new ProviderException($"inline rule provider [{name}] declares no payload");
        }

        return new RuleProviderResult(config.Behavior, payload, DateTimeOffset.UtcNow);
    }

    private RuleProviderResult LoadFile(string name, RuleProviderConfig config)
    {
        var path = ResolvePath(name, config.Path);
        if (!File.Exists(path))
        {
            throw new ProviderException($"rule provider [{name}] file not found: {path}");
        }

        string body;
        try
        {
            body = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ProviderException($"rule provider [{name}] could not be read from {path}: {ex.Message}", ex);
        }

        return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, body), LastWrite(path));
    }

    private async Task<RuleProviderResult> LoadHttpAsync(
        string name,
        RuleProviderConfig config,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        var cachePath = ResolvePath(name, config.Path);
        var cached = ReadCache(cachePath);
        var interval = TimeSpan.FromSeconds(Math.Max(0, config.Interval));

        if (!forceRefresh && cached is { } fresh && (interval <= TimeSpan.Zero || DateTimeOffset.UtcNow - fresh.UpdatedAt < interval))
        {
            return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, fresh.Body), fresh.UpdatedAt);
        }

        RuleProviderResult? FromCache(string reason)
        {
            if (cached is not { } fallback) return null;

            _logger?.LogWarning(
                "rule provider [{Name}] {Reason}; serving the cached copy from {UpdatedAt:u}",
                name,
                reason,
                fallback.UpdatedAt);

            return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, fallback.Body), fallback.UpdatedAt);
        }

        if (string.IsNullOrWhiteSpace(config.Url))
        {
            return FromCache("has no url") ?? throw new ProviderException($"rule provider [{name}] has no url");
        }

        string body;
        try
        {
            body = await DownloadAsync(config.Url!, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return FromCache($"download failed: {ex.Message}")
                ?? throw new ProviderException($"rule provider [{name}] download failed: {ex.Message}", ex);
        }

        WriteCache(cachePath, body);
        return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, body), DateTimeOffset.UtcNow);
    }

    private async Task<string> DownloadAsync(string url, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(DownloadTimeout);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        using var response = await _http
            .SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
    }

    // ── payload parsing ──────────────────────────────────────────────────────

    private List<string> ParsePayload(string name, string? format, string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return [];

        return (format ?? "yaml").Trim().ToLowerInvariant() switch
        {
            "yaml" or "yml" => ReadYamlPayload(body),
            "text" => ReadTextPayload(body),
            "mrs" => ReadMrsPayload(name, body),
            _ => ReadTextPayload(body),
        };
    }

    private static List<string> ReadYamlPayload(string body)
    {
        var result = new List<string>();

        object? raw;
        try
        {
            raw = new DeserializerBuilder().Build().Deserialize<object?>(body);
        }
        catch (YamlException)
        {
            // Not YAML at all; a provider that mislabels its format still works.
            return ReadTextPayload(body);
        }

        switch (YamlMap.Normalize(raw))
        {
            case Dictionary<string, object?> map:
                if (map.TryGetValue("payload", out var payload)) Flatten(payload, result);
                break;
            case List<object?> list:
                Flatten(list, result);
                break;
            case string text:
                return ReadTextPayload(text);
            default:
                return ReadTextPayload(body);
        }

        return result;
    }

    private static List<string> ReadTextPayload(string body)
    {
        var result = new List<string>();

        foreach (var raw in body.Split('\n'))
        {
            var line = raw.Trim().TrimEnd('\r').Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            if (line.StartsWith("- ", StringComparison.Ordinal)) line = line[2..].Trim().Trim('"', '\'');

            if (line.Length > 0) result.Add(line);
        }

        return result;
    }

    private List<string> ReadMrsPayload(string name, string body)
    {
        if (body.StartsWith("MRS", StringComparison.Ordinal))
        {
            _logger?.LogWarning(
                "rule provider [{Name}] serves mihomo's binary mrs format, which this build cannot decode; " +
                "the rule set is empty. Convert it to yaml or text to use it.",
                name);
        }
        else
        {
            _logger?.LogWarning(
                "rule provider [{Name}] declares format mrs but the body carries no MRS magic; the rule set is empty.",
                name);
        }

        return [];
    }

    private static void Flatten(object? node, List<string> into)
    {
        switch (node)
        {
            case null:
                return;
            case string text:
                var trimmed = text.Trim();
                if (trimmed.Length > 0) into.Add(trimmed);
                return;
            case IEnumerable<object?> list:
                foreach (var item in list) Flatten(item, into);
                return;
            case Dictionary<string, object?> map:
                foreach (var key in new[] { "domain", "ip", "value", "payload" })
                {
                    if (map.TryGetValue(key, out var inner) && inner is not null)
                    {
                        Flatten(inner, into);
                        return;
                    }
                }

                return;
            default:
                var rendered = Convert.ToString(node, CultureInfo.InvariantCulture);
                if (!string.IsNullOrWhiteSpace(rendered)) into.Add(rendered.Trim());
                return;
        }
    }

    // ── cache ────────────────────────────────────────────────────────────────

    private string ResolvePath(string name, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            var value = path!.Trim();
            return Path.IsPathRooted(value) ? value : Path.Combine(_homeDir, value);
        }

        return Path.Combine(_homeDir, "providers", "rules", Sanitize(name) + ".yaml");
    }

    private static string Sanitize(string name)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(name.Length);
        foreach (var c in name) builder.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        return builder.Length == 0 ? "provider" : builder.ToString();
    }

    private static DateTimeOffset LastWrite(string path)
    {
        try
        {
            return new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return DateTimeOffset.UtcNow;
        }
    }

    private static (string Body, DateTimeOffset UpdatedAt)? ReadCache(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;

            var body = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(body)) return null;

            return (body, new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void WriteCache(string path, string body)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            File.WriteAllText(path, body);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("rule provider cache could not be written to {Path}: {Message}", path, ex.Message);
        }
    }
}
