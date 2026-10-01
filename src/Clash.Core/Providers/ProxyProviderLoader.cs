using System.Text;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Providers;

/// <summary>
/// Fetches <c>proxy-providers</c> entries over the <c>inline</c>, <c>file</c> and
/// <c>http</c> vehicles, caching downloaded bodies on disk.
/// </summary>
/// <remarks>
/// <para>
/// <b>Filtering is deliberately not done here.</b> <c>filter</c>,
/// <c>exclude-filter</c>, <c>exclude-type</c> and <c>override</c> are applied by
/// <see cref="Adapter.ProxyFactory"/>, which already owns that behaviour; doing it
/// twice would make the provider's raw contents and the registered adapters
/// disagree. This loader returns the raw node list exactly as the subscription
/// declared it.
/// </para>
/// <para>
/// An <c>http</c> provider caches the response body at <c>path</c> (relative paths
/// resolve against the home directory given to the constructor; when <c>path</c> is
/// empty a name derived one under <c>providers/proxies</c> is used). A cached body
/// younger than <c>interval</c> seconds is served without touching the network — an
/// <c>interval</c> of 0 means the cache is always considered fresh, matching
/// mihomo's "no automatic update" — and a failed download falls back to a stale
/// cache rather than failing the whole configuration. The
/// <c>subscription-userinfo</c> header is preserved next to the cache as a
/// <c>.info</c> sidecar so a cache hit still reports traffic and expiry.
/// </para>
/// </remarks>
public sealed class ProxyProviderLoader : IProxyProviderLoader, IDisposable
{
    private const string UserAgent = "clash-verge/v1.0.0";

    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(60);

    private readonly HttpClient _http;
    private readonly bool _ownsClient;
    private readonly string _homeDir;
    private readonly ILogger<ProxyProviderLoader>? _logger;

    /// <summary>Creates a loader that downloads with its own <see cref="HttpClient"/>.</summary>
    /// <param name="homeDir">Directory relative cache and provider paths resolve against.</param>
    /// <param name="logger">Optional logger.</param>
    public ProxyProviderLoader(string homeDir, ILogger<ProxyProviderLoader>? logger = null)
        : this(homeDir, new HttpClient { Timeout = DownloadTimeout }, logger, ownsClient: true)
    {
    }

    /// <summary>Creates a loader over a caller supplied message handler, for tests and custom transports.</summary>
    /// <param name="homeDir">Directory relative cache and provider paths resolve against.</param>
    /// <param name="handler">The handler the internal <see cref="HttpClient"/> uses.</param>
    /// <param name="logger">Optional logger.</param>
    public ProxyProviderLoader(string homeDir, HttpMessageHandler handler, ILogger<ProxyProviderLoader>? logger = null)
        : this(homeDir, new HttpClient(handler, disposeHandler: false) { Timeout = DownloadTimeout }, logger, ownsClient: true)
    {
    }

    /// <summary>Creates a loader over a caller supplied client.</summary>
    /// <param name="homeDir">Directory relative cache and provider paths resolve against.</param>
    /// <param name="httpClient">The client to download with; it is not disposed by this loader.</param>
    /// <param name="logger">Optional logger.</param>
    public ProxyProviderLoader(string homeDir, HttpClient httpClient, ILogger<ProxyProviderLoader>? logger = null)
        : this(homeDir, httpClient, logger, ownsClient: false)
    {
    }

    private ProxyProviderLoader(string homeDir, HttpClient httpClient, ILogger<ProxyProviderLoader>? logger, bool ownsClient)
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
    public Task<ProxyProviderResult> LoadAsync(string name, ProxyProviderConfig config, CancellationToken cancellationToken = default)
        => LoadCoreAsync(name, config, forceRefresh: false, cancellationToken);

    /// <inheritdoc />
    public Task<ProxyProviderResult> RefreshAsync(string name, ProxyProviderConfig config, CancellationToken cancellationToken = default)
        => LoadCoreAsync(name, config, forceRefresh: true, cancellationToken);

    private Task<ProxyProviderResult> LoadCoreAsync(string name, ProxyProviderConfig config, bool forceRefresh, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(config);

        return (config.Type ?? "http").Trim().ToLowerInvariant() switch
        {
            "inline" => Task.FromResult(LoadInline(name, config)),
            "file" => Task.FromResult(LoadFile(name, config)),
            "http" => LoadHttpAsync(name, config, forceRefresh, cancellationToken),
            _ => throw new ProviderException($"proxy provider [{name}] has an unsupported type [{config.Type}]"),
        };
    }

    private static ProxyProviderResult LoadInline(string name, ProxyProviderConfig config)
    {
        var entries = config.InlinePayload ?? [];
        if (entries.Count == 0)
        {
            throw new ProviderException($"inline proxy provider [{name}] declares no payload");
        }

        return new ProxyProviderResult(entries, null, DateTimeOffset.UtcNow);
    }

    private ProxyProviderResult LoadFile(string name, ProxyProviderConfig config)
    {
        var path = ResolvePath(name, config.Path);
        if (!File.Exists(path))
        {
            throw new ProviderException($"proxy provider [{name}] file not found: {path}");
        }

        string body;
        try
        {
            body = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ProviderException($"proxy provider [{name}] could not be read from {path}: {ex.Message}", ex);
        }

        var entries = ParseProxyBody(body);
        if (entries.Count == 0)
        {
            throw new ProviderException($"proxy provider [{name}] declared no usable proxies in {path}");
        }

        return new ProxyProviderResult(entries, null, LastWrite(path));
    }

    private async Task<ProxyProviderResult> LoadHttpAsync(
        string name,
        ProxyProviderConfig config,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        var cachePath = ResolvePath(name, config.Path);
        var cached = ReadCache(cachePath);
        var interval = TimeSpan.FromSeconds(Math.Max(0, config.Interval));

        if (!forceRefresh && cached is { } fresh && (interval <= TimeSpan.Zero || DateTimeOffset.UtcNow - fresh.UpdatedAt < interval))
        {
            var cachedEntries = ParseProxyBody(fresh.Body);
            if (cachedEntries.Count > 0)
            {
                return new ProxyProviderResult(cachedEntries, ReadCachedInfo(cachePath), fresh.UpdatedAt);
            }
        }

        ProxyProviderResult? FromCache(string reason)
        {
            if (cached is not { } fallback) return null;

            var entries = ParseProxyBody(fallback.Body);
            if (entries.Count == 0) return null;

            _logger?.LogWarning(
                "proxy provider [{Name}] {Reason}; serving the cached copy from {UpdatedAt:u}",
                name,
                reason,
                fallback.UpdatedAt);

            return new ProxyProviderResult(entries, ReadCachedInfo(cachePath), fallback.UpdatedAt);
        }

        if (string.IsNullOrWhiteSpace(config.Url))
        {
            return FromCache("has no url") ?? throw new ProviderException($"proxy provider [{name}] has no url");
        }

        string body;
        SubscriptionInfo? info;
        try
        {
            (body, info) = await DownloadAsync(config.Url!, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return FromCache($"download failed: {ex.Message}")
                ?? throw new ProviderException($"proxy provider [{name}] download failed: {ex.Message}", ex);
        }

        var entries = ParseProxyBody(body);
        if (entries.Count == 0)
        {
            return FromCache("returned no usable proxies")
                ?? throw new ProviderException($"proxy provider [{name}] returned no usable proxies from {config.Url}");
        }

        WriteCache(cachePath, body, info);
        return new ProxyProviderResult(entries, info, DateTimeOffset.UtcNow);
    }

    private async Task<(string Body, SubscriptionInfo? Info)> DownloadAsync(string url, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(DownloadTimeout);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);

        using var response = await _http
            .SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
        return (body, SubscriptionInfoParser.FromHeaders(response.Headers));
    }

    /// <summary>
    /// Reads a provider body: a Clash document contributes its <c>proxies:</c> list
    /// directly, anything else is converted through <see cref="ShareLinks"/>.
    /// </summary>
    private static IReadOnlyList<ProxyConfigEntry> ParseProxyBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return [];

        if (ShareLinkParser.LooksLikeClashDocument(body)) return ShareLinkParser.ReadClashProxies(body);
        if (!ShareLinks.IsAvailable) return [];

        return ShareLinks.Parser.ParseSubscription(body);
    }

    private string ResolvePath(string name, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            var value = path!.Trim();
            return Path.IsPathRooted(value) ? value : Path.Combine(_homeDir, value);
        }

        return Path.Combine(_homeDir, "providers", "proxies", Sanitize(name) + ".yaml");
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

    private void WriteCache(string path, string body, SubscriptionInfo? info)
    {
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            File.WriteAllText(path, body);

            var infoPath = path + ".info";
            if (info is null)
            {
                if (File.Exists(infoPath)) File.Delete(infoPath);
            }
            else
            {
                File.WriteAllText(
                    infoPath,
                    $"upload={info.Upload}; download={info.Download}; total={info.Total}; expire={info.Expire?.ToUnixTimeSeconds() ?? 0}");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning("proxy provider cache could not be written to {Path}: {Message}", path, ex.Message);
        }
    }

    private static SubscriptionInfo? ReadCachedInfo(string cachePath)
    {
        try
        {
            var infoPath = cachePath + ".info";
            return File.Exists(infoPath) ? SubscriptionInfoParser.ParseUserInfo(File.ReadAllText(infoPath)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
