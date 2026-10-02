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
/// entry per line) and <c>mrs</c> formats are recognised. An <c>mrs</c> body is decoded
/// by <see cref="MrsDecoder"/> into the same entries the other two formats produce; a body
/// that cannot be decoded — wrong magic, truncated, a behaviour the provider does not
/// declare — logs a warning and yields an empty payload, so a profile referencing a broken
/// <c>mrs</c> provider still loads and simply matches nothing for that set.
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

        byte[] body;
        try
        {
            body = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ProviderException($"rule provider [{name}] could not be read from {path}: {ex.Message}", ex);
        }

        return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, config.Behavior, body), LastWrite(path));
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
            return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, config.Behavior, fresh.Body), fresh.UpdatedAt);
        }

        RuleProviderResult? FromCache(string reason)
        {
            if (cached is not { } fallback) return null;

            _logger?.LogWarning(
                "rule provider [{Name}] {Reason}; serving the cached copy from {UpdatedAt:u}",
                name,
                reason,
                fallback.UpdatedAt);

            return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, config.Behavior, fallback.Body), fallback.UpdatedAt);
        }

        if (string.IsNullOrWhiteSpace(config.Url))
        {
            return FromCache("has no url") ?? throw new ProviderException($"rule provider [{name}] has no url");
        }

        byte[] body;
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
        return new RuleProviderResult(config.Behavior, ParsePayload(name, config.Format, config.Behavior, body), DateTimeOffset.UtcNow);
    }

    private async Task<byte[]> DownloadAsync(string url, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(DownloadTimeout);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        using var response = await _http
            .SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsByteArrayAsync(timeout.Token).ConfigureAwait(false);
    }

    // ── payload parsing ──────────────────────────────────────────────────────

    /// <summary>
    /// Turns a fetched body into entries. The body stays bytes until a text format is known,
    /// because an <c>mrs</c> provider is a zstd stream and decoding it as UTF-8 text would
    /// destroy it.
    /// </summary>
    private List<string> ParsePayload(string name, string? format, string? behavior, byte[] body)
    {
        if (body.Length == 0) return [];

        return (format ?? "yaml").Trim().ToLowerInvariant() switch
        {
            "yaml" or "yml" => ReadYamlPayload(ReadText(body)),
            "text" => ReadTextPayload(ReadText(body)),
            "mrs" => ReadMrsPayload(name, behavior, body),
            _ => ReadTextPayload(ReadText(body)),
        };
    }

    /// <summary>Decodes a body as UTF-8 text, dropping the byte-order mark a reader would skip.</summary>
    private static string ReadText(byte[] body)
    {
        var span = body.AsSpan();
        if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF) span = span[3..];
        return Encoding.UTF8.GetString(span);
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
                // A body of bare lines is folded into a single YAML scalar; its
                // whitespace still separates the entries.
                foreach (var part in text.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!part.StartsWith('#')) result.Add(part);
                }

                break;
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

    private List<string> ReadMrsPayload(string name, string? behavior, byte[] body)
    {
        try
        {
            return MrsDecoder.Decode(body, behavior);
        }
        catch (ProviderException ex)
        {
            // A file the decoder cannot make sense of must leave an empty set that matches
            // nothing, never take the core (or a reload) down.
            _logger?.LogWarning(
                "rule provider [{Name}] serves an mrs payload that could not be decoded; the rule set is empty: {Message}",
                name,
                ex.Message);

            return [];
        }
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

    private static (byte[] Body, DateTimeOffset UpdatedAt)? ReadCache(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;

            var body = File.ReadAllBytes(path);
            if (body.Length == 0) return null;

            return (body, new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void WriteCache(string path, byte[] body)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            File.WriteAllBytes(path, body);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("rule provider cache could not be written to {Path}: {Message}", path, ex.Message);
        }
    }
}
