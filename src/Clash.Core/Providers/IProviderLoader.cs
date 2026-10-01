using Clash.Core.Configuration;

namespace Clash.Core.Providers;

/// <summary>Parses proxy share links (<c>ss://</c>, <c>vmess://</c>, ...) and whole subscriptions.</summary>
public interface IShareLinkParser
{
    /// <summary>Parses one share link into a configuration entry, or null when the scheme is unknown.</summary>
    ProxyConfigEntry? Parse(string link);

    /// <summary>
    /// Parses a subscription body: a base64-encoded newline-separated link list, a
    /// plain link list, a Clash YAML document, or a SIP008 JSON document.
    /// </summary>
    IReadOnlyList<ProxyConfigEntry> ParseSubscription(string content);
}

/// <summary>
/// Registration point for <see cref="IShareLinkParser"/>. The implementation lives
/// beside the protocol parsers and installs itself from a module initializer.
/// </summary>
public static class ShareLinks
{
    private static IShareLinkParser? _parser;

    public static void Use(IShareLinkParser parser) => Volatile.Write(ref _parser, parser);

    public static bool IsAvailable => Volatile.Read(ref _parser) is not null;

    public static IShareLinkParser Parser =>
        Volatile.Read(ref _parser) ?? throw new InvalidOperationException("no share-link parser has been registered");
}

/// <summary>Traffic and expiry metadata carried by a subscription response header.</summary>
public sealed record SubscriptionInfo(long Upload, long Download, long Total, DateTimeOffset? Expire)
{
    public long Used => Upload + Download;
}

/// <summary>What a proxy provider produced.</summary>
public sealed record ProxyProviderResult(
    IReadOnlyList<ProxyConfigEntry> Proxies,
    SubscriptionInfo? SubscriptionInfo,
    DateTimeOffset UpdatedAt);

/// <summary>What a rule provider produced.</summary>
public sealed record RuleProviderResult(
    string Behavior,
    IReadOnlyList<string> Payload,
    DateTimeOffset UpdatedAt);

/// <summary>
/// Fetches and caches <c>proxy-providers</c> entries. Implementations handle the
/// <c>http</c>, <c>file</c> and <c>inline</c> vehicles, on-disk caching under
/// <c>path</c>, the refresh <c>interval</c> and the provider filters.
/// </summary>
public interface IProxyProviderLoader
{
    /// <summary>Loads one provider, using the on-disk cache when it is still fresh.</summary>
    Task<ProxyProviderResult> LoadAsync(string name, ProxyProviderConfig config, CancellationToken cancellationToken = default);

    /// <summary>Forces a re-fetch, ignoring the cache. Backs <c>PUT /providers/proxies/:name</c>.</summary>
    Task<ProxyProviderResult> RefreshAsync(string name, ProxyProviderConfig config, CancellationToken cancellationToken = default);
}

/// <summary>
/// Fetches and caches <c>rule-providers</c> entries and turns their payloads into
/// matchable rule sets.
/// </summary>
public interface IRuleProviderLoader
{
    Task<RuleProviderResult> LoadAsync(string name, RuleProviderConfig config, CancellationToken cancellationToken = default);

    Task<RuleProviderResult> RefreshAsync(string name, RuleProviderConfig config, CancellationToken cancellationToken = default);

    /// <summary>Builds the matchable set from a fetched payload.</summary>
    Rules.IRuleSet ToRuleSet(string name, RuleProviderResult result);
}

/// <summary>Raised when a provider cannot be fetched or parsed.</summary>
public sealed class ProviderException : Common.ClashException
{
    public ProviderException(string message) : base(message) { }

    public ProviderException(string message, Exception inner) : base(message, inner) { }
}
