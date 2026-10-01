using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Dns;

/// <summary>
/// Builds the upstream transport for one <c>nameserver</c> entry. Supplied by
/// tests to keep resolution off the network; production uses
/// <see cref="DnsUpstreams.Create"/>.
/// </summary>
/// <param name="nameserver">The raw nameserver entry.</param>
/// <param name="bootstrap"><c>default-nameserver</c> entries used to resolve a domain-valued host.</param>
/// <param name="ipv6">Whether AAAA results are wanted while bootstrapping.</param>
/// <param name="bootstrapResolver">Fallback resolver for domain-valued hosts.</param>
public delegate IDnsUpstream DnsUpstreamFactory(
    string nameserver,
    IReadOnlyList<string> bootstrap,
    bool ipv6,
    Func<string, CancellationToken, Task<IPAddress[]>>? bootstrapResolver);

/// <summary>
/// The real resolver: hosts overrides, fake-IP allocation, nameserver policy,
/// the <c>fallback</c> pollution filter, a TTL-aware answer cache and the
/// upstream chain that the DNS listener and <c>GET /dns/query</c> use.
/// </summary>
/// <remarks>
/// <para>
/// Resolution order for <see cref="ResolveAsync"/> is hosts → fake-IP → cache →
/// upstream. Hosts and fake-IP answers never touch the network, and every
/// failure is swallowed into an empty result (logged through the injected
/// <see cref="ILogger{T}"/>) so a dead nameserver can never break the tunnel.
/// </para>
/// <para>
/// <c>nameserver-policy</c> keys are domain suffixes (<c>example.com</c>,
/// <c>+.example.com</c>, <c>*.example.com</c>). The <c>geosite:…</c>,
/// <c>geoip:…</c> and <c>rule-set:…</c> key forms need geodata that this class
/// does not own, so they are ignored with a warning instead of silently
/// misrouting; inject a predicate through <see cref="GeoIpLookup"/> for the
/// <c>fallback-filter</c> GeoIP check.
/// </para>
/// </remarks>
public sealed class DnsResolver : IDnsResolver, IDisposable
{
    /// <summary>Lower bound applied to every cached TTL.</summary>
    public const int MinimumTtlSeconds = 1;

    /// <summary>Upper bound applied to every cached TTL.</summary>
    public const int MaximumTtlSeconds = 3600;

    /// <summary>TTL handed out for fake-IP answers.</summary>
    public const uint FakeIpTtl = 1;

    private static readonly TimeSpan NegativeTtl = TimeSpan.FromSeconds(10);

    private readonly DnsConfig _config;
    private readonly ILogger<DnsResolver> _logger;
    private readonly DnsUpstreamFactory? _upstreamFactory;
    private readonly HostsTable _hosts;
    private readonly FakeIpPool _fakeIp;
    private readonly ConcurrentDictionary<CacheKey, CacheEntry> _positive = new();
    private readonly ConcurrentDictionary<CacheKey, DateTimeOffset> _negative = new();
    private readonly ConcurrentDictionary<string, NameserverChain> _chains = new(StringComparer.Ordinal);
    private readonly List<PolicyEntry> _policies = [];
    private readonly List<(IPAddress Network, int Prefix)> _fallbackCidrs = [];
    private readonly List<string> _fakeIpFilter = [];
    private readonly AsyncLocal<bool> _bootstrapping = new();

    private readonly NameserverChain _defaultChain;
    private readonly int _cacheMaxSize;
    private readonly int _negativeMaxSize;

    /// <summary>Creates a resolver from the <c>dns</c> section of a config.</summary>
    /// <param name="config">The DNS configuration.</param>
    /// <param name="topLevelHosts">The document's top-level <c>hosts</c> mapping; <c>dns.hosts</c> wins on conflicts.</param>
    /// <param name="logger">Logger for upstream failures and unsupported keys.</param>
    /// <param name="upstreamFactory">Optional transport factory; tests inject a fake here.</param>
    public DnsResolver(
        DnsConfig config,
        IReadOnlyDictionary<string, object?> topLevelHosts,
        ILogger<DnsResolver> logger,
        DnsUpstreamFactory? upstreamFactory = null)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _upstreamFactory = upstreamFactory;

        _cacheMaxSize = config.CacheMaxSize > 0 ? config.CacheMaxSize : 8192;
        _negativeMaxSize = Math.Clamp(_cacheMaxSize / 8, 64, 1024);

        _hosts = new HostsTable(
            [
                topLevelHosts ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase),
                config.Hosts ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase),
            ],
            config.UseSystemHosts);

        _fakeIp = new FakeIpPool(config.FakeIpRange, config.FakeIpRangeV6, _cacheMaxSize);

        foreach (var pattern in config.FakeIpFilter ?? [])
        {
            if (string.IsNullOrWhiteSpace(pattern)) continue;
            if (DomainPattern.IsUnsupportedKey(pattern))
            {
                _logger.LogDebug("dns.fake-ip-filter entry '{Pattern}' needs geodata and is ignored", pattern);
                continue;
            }

            _fakeIpFilter.Add(pattern);
        }

        ParseFallbackCidrs(config.FallbackFilter);
        ParsePolicies(config.NameserverPolicy);

        // The default nameservers are bootstrap-only: their hosts must already be
        // literals (or fall back to the system resolver) so they can never
        // recurse into the chain they are supposed to bootstrap.
        _defaultChain = BuildChain(config.DefaultNameserver ?? [], allowBootstrapFallback: false);
    }

    /// <inheritdoc />
    public DnsConfig Config => _config;

    /// <summary>
    /// Optional GeoIP predicate used by <c>fallback-filter.geoip-filter</c>.
    /// Returns an ISO country code such as <c>CN</c>, or null when unknown.
    /// </summary>
    public Func<IPAddress, string?>? GeoIpLookup { get; set; }

    /// <summary>Upstreams created for <c>default-nameserver</c>.</summary>
    public IReadOnlyList<IDnsUpstream> DefaultUpstreams => _defaultChain.Upstreams;

    /// <summary>Nameserver strings this resolver would use for <paramref name="host"/>.</summary>
    public IReadOnlyList<string> SelectNameservers(string host)
    {
        var name = Normalize(host);
        var policy = MatchPolicy(name);
        if (policy is not null) return policy.Servers;

        return _config.Nameserver is { Count: > 0 } ? _config.Nameserver : _config.DefaultNameserver ?? [];
    }

    /// <inheritdoc />
    public async ValueTask<IPAddress[]> ResolveAsync(
        string host,
        bool ipv6 = true,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var name = Normalize(host);
            if (name.Length == 0) return [];

            if (IPAddress.TryParse(name, out var literal)) return [literal];

            var wantV6 = ipv6 && _config.Ipv6;

            var hosts = ResolveHosts(name);
            if (hosts.Length > 0)
            {
                return wantV6
                    ? hosts
                    : [.. hosts.Where(a => a.AddressFamily == AddressFamily.InterNetwork)];
            }

            if (IsFakeIpMode && ShouldFakeIp(name))
            {
                var fake = _fakeIp.Allocate(name, wantV6);
                if (fake is not null) return [fake];
            }

            return await ResolveThroughUpstreamsAsync(name, wantV6, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            _logger.LogWarning(error, "dns: resolving {Host} failed", host);
            return [];
        }
    }

    /// <inheritdoc />
    public IPAddress[] ResolveHosts(string host)
    {
        if (!_config.UseHosts) return [];

        var name = Normalize(host);
        if (name.Length == 0) return [];

        return _hosts.TryResolve(name, out var addresses) ? addresses : [];
    }

    /// <inheritdoc />
    public bool IsFakeIp(IPAddress address) => _fakeIp.Contains(address);

    /// <inheritdoc />
    public string? ReverseFakeIp(IPAddress address) => _fakeIp.Lookup(address);

    /// <inheritdoc />
    public IPAddress? FakeIpFor(string host)
    {
        var name = Normalize(host);
        if (name.Length == 0) return null;

        var existing = _fakeIp.LookupHost(name);
        if (existing is not null) return existing;

        if (!ShouldFakeIp(name)) return null;
        return _fakeIp.Allocate(name, ipv6: false);
    }

    /// <inheritdoc />
    public bool ShouldFakeIp(string host)
    {
        var name = Normalize(host);
        if (name.Length == 0) return false;
        if (IPAddress.TryParse(name, out _)) return false;

        if (!name.Contains('.'))
        {
            // A bare single-label name is a local/NetBIOS style name; only
            // "localhost" is still eligible for a fake address.
            if (!string.Equals(name, "localhost", StringComparison.OrdinalIgnoreCase)) return false;
        }

        foreach (var pattern in _fakeIpFilter)
        {
            if (DomainPattern.Matches(pattern, name, bareIsSuffix: true)) return false;
        }

        return true;
    }

    /// <inheritdoc />
    public async Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (query.IsResponse || query.Questions.Count == 0)
        {
            return DnsCodec.CreateResponse(query, DnsResponseCode.FormatError);
        }

        var question = query.Questions[0];
        var name = Normalize(question.Name);
        if (name.Length == 0) return DnsCodec.CreateResponse(query, DnsResponseCode.FormatError);

        try
        {
            if (question.Type is DnsQueryType.A or DnsQueryType.Aaaa)
            {
                // IPv6 disabled: answer AAAA with an empty NOERROR, exactly like
                // Clash, instead of leaking the query upstream.
                if (question.Type == DnsQueryType.Aaaa && !_config.Ipv6)
                {
                    return DnsCodec.CreateResponse(query, DnsResponseCode.NoError);
                }

                var local = ResolveLocally(query, name, question.Type);
                if (local is not null) return local;
            }

            return await ForwardAsync(query, name, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error)
        {
            _logger.LogWarning(error, "dns: query for {Name} failed", name);
            return DnsCodec.CreateResponse(query, DnsResponseCode.ServerFailure);
        }
    }

    /// <inheritdoc />
    public void FlushFakeIp() => _fakeIp.Flush();

    /// <inheritdoc />
    public void FlushCache()
    {
        _positive.Clear();
        _negative.Clear();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var chain in _chains.Values) chain.Dispose();
        _chains.Clear();
        _defaultChain.Dispose();
    }

    // ── Local answers ───────────────────────────────────────────────────────

    private DnsMessage? ResolveLocally(DnsMessage query, string name, DnsQueryType type)
    {
        var family = type == DnsQueryType.A ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;

        var hosts = ResolveHosts(name);
        if (hosts.Length > 0)
        {
            // A hosts entry is authoritative: answer with whatever family it
            // has, even when that is nothing, rather than leaking to the network.
            var answers = hosts
                .Where(a => a.AddressFamily == family)
                .Select(a => DnsCodec.CreateAddressRecord(name, a, FakeIpTtl))
                .ToList();

            return DnsCodec.WithAnswers(query, answers, FakeIpTtl);
        }

        if (IsFakeIpMode && ShouldFakeIp(name))
        {
            var fake = _fakeIp.Allocate(name, type == DnsQueryType.Aaaa);
            if (fake is not null)
            {
                var record = DnsCodec.CreateAddressRecord(name, fake, FakeIpTtl);
                return DnsCodec.WithAnswers(query, [record], FakeIpTtl);
            }
        }

        if (TryGetCached(new CacheKey(name, type), out var cached) && cached.Length > 0)
        {
            var answers = cached
                .Where(a => a.AddressFamily == family)
                .Select(a => DnsCodec.CreateAddressRecord(name, a, MinimumTtlSeconds))
                .ToList();

            return DnsCodec.WithAnswers(query, answers, MinimumTtlSeconds);
        }

        return null;
    }

    // ── Upstream path ───────────────────────────────────────────────────────

    private async Task<IPAddress[]> ResolveThroughUpstreamsAsync(string name, bool wantV6, CancellationToken cancellationToken)
    {
        var results = new List<IPAddress>();
        var needV4 = true;
        var needV6 = wantV6;

        if (TryGetCached(new CacheKey(name, DnsQueryType.A), out var cachedV4))
        {
            results.AddRange(cachedV4);
            needV4 = false;
        }

        if (wantV6 && TryGetCached(new CacheKey(name, DnsQueryType.Aaaa), out var cachedV6))
        {
            results.AddRange(cachedV6);
            needV6 = false;
        }

        if (!needV4 && !needV6) return [.. results.Distinct()];

        var (primary, fallback) = SelectChains(name);
        var host = MatchFallbackDomain(name);

        var v4 = needV4 ? QueryTypeAsync(primary, fallback, name, DnsQueryType.A, host, cancellationToken) : null;
        var v6 = needV6 ? QueryTypeAsync(primary, fallback, name, DnsQueryType.Aaaa, host, cancellationToken) : null;

        if (v4 is not null) results.AddRange(await v4.ConfigureAwait(false));
        if (v6 is not null) results.AddRange(await v6.ConfigureAwait(false));

        return [.. results.Distinct()];
    }

    private async Task<IPAddress[]> QueryTypeAsync(
        NameserverChain primary,
        NameserverChain? fallback,
        string name,
        DnsQueryType type,
        bool forceFallback,
        CancellationToken cancellationToken)
    {
        var primaryTask = QueryChainAsync(primary, name, type, cancellationToken);

        if (fallback is null)
        {
            var only = await primaryTask.ConfigureAwait(false);
            Store(type, name, only);
            return only.Addresses;
        }

        var fallbackTask = QueryChainAsync(fallback, name, type, cancellationToken);
        var primaryAnswer = await primaryTask.ConfigureAwait(false);
        var fallbackAnswer = await fallbackTask.ConfigureAwait(false);

        var chosen = ChooseAnswer(name, forceFallback, primaryAnswer, fallbackAnswer);
        Store(type, name, chosen);
        return chosen.Addresses;
    }

    private UpstreamAnswer ChooseAnswer(string name, bool forceFallback, UpstreamAnswer primary, UpstreamAnswer fallback)
    {
        if (primary.Addresses.Length == 0) return fallback.Addresses.Length > 0 ? fallback : primary;

        if (forceFallback || IsPolluted(primary.Addresses))
        {
            if (fallback.Addresses.Length > 0) return fallback;
        }

        return primary;
    }

    private async Task<UpstreamAnswer> QueryChainAsync(
        NameserverChain chain,
        string name,
        DnsQueryType type,
        CancellationToken cancellationToken)
    {
        foreach (var upstream in chain.Upstreams)
        {
            try
            {
                var query = DnsMessage.CreateQuery(name, type, (ushort)Random.Shared.Next(1, ushort.MaxValue));
                var response = await upstream.ExchangeAsync(query, cancellationToken).ConfigureAwait(false);

                if (response.ResponseCode is DnsResponseCode.ServerFailure or DnsResponseCode.Refused)
                {
                    _logger.LogDebug("dns: {Upstream} answered {Code} for {Name}", upstream.Name, response.ResponseCode, name);
                    continue;
                }

                var addresses = new List<IPAddress>();
                var ttl = uint.MaxValue;
                foreach (var answer in response.Answers)
                {
                    if (answer.Type != type || answer.Address is null) continue;
                    addresses.Add(answer.Address);
                    ttl = Math.Min(ttl, answer.Ttl);
                }

                var seconds = ttl == uint.MaxValue ? MinimumTtlSeconds : ClampTtl(ttl);
                return new UpstreamAnswer([.. addresses], TimeSpan.FromSeconds(seconds), response.ResponseCode);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                _logger.LogDebug(error, "dns: upstream {Upstream} failed for {Name}", upstream.Name, name);
            }
        }

        return new UpstreamAnswer([], TimeSpan.FromSeconds(MinimumTtlSeconds), DnsResponseCode.ServerFailure);
    }

    private void Store(DnsQueryType type, string name, UpstreamAnswer answer)
    {
        var key = new CacheKey(name, type);

        if (answer.Addresses.Length == 0)
        {
            // Only cache a real "no such record" answer; a transport failure is
            // not evidence that the name does not exist.
            if (answer.Code is DnsResponseCode.NoError or DnsResponseCode.NameError) StoreNegative(key);
            return;
        }

        if (_cacheMaxSize <= 0) return;

        if (_positive.Count >= _cacheMaxSize) PrunePositive();

        var seconds = Math.Clamp(answer.Ttl.TotalSeconds, MinimumTtlSeconds, MaximumTtlSeconds);
        _positive[key] = new CacheEntry(answer.Addresses, DateTimeOffset.UtcNow.AddSeconds(seconds));
    }

    private void StoreNegative(CacheKey key)
    {
        if (_negative.Count >= _negativeMaxSize) PruneNegative();
        _negative[key] = DateTimeOffset.UtcNow + NegativeTtl;
    }

    private bool TryGetCached(CacheKey key, out IPAddress[] addresses)
    {
        addresses = [];

        if (_negative.TryGetValue(key, out var negativeExpiry))
        {
            if (negativeExpiry > DateTimeOffset.UtcNow) return true;
            _negative.TryRemove(key, out _);
        }

        if (!_positive.TryGetValue(key, out var entry)) return false;

        if (entry.Expires <= DateTimeOffset.UtcNow)
        {
            _positive.TryRemove(key, out _);
            return false;
        }

        addresses = entry.Addresses;
        return true;
    }

    private void PrunePositive()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in _positive)
        {
            if (pair.Value.Expires <= now) _positive.TryRemove(pair.Key, out _);
        }

        if (_positive.Count < _cacheMaxSize) return;

        var victims = _positive
            .OrderBy(pair => pair.Value.Expires)
            .Take(Math.Max(1, _cacheMaxSize / 10))
            .Select(pair => pair.Key)
            .ToList();

        foreach (var victim in victims) _positive.TryRemove(victim, out _);
    }

    private void PruneNegative()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in _negative)
        {
            if (pair.Value <= now) _negative.TryRemove(pair.Key, out _);
        }

        if (_negative.Count < _negativeMaxSize) return;

        foreach (var victim in _negative.OrderBy(pair => pair.Value).Take(Math.Max(1, _negativeMaxSize / 10)).Select(p => p.Key).ToList())
        {
            _negative.TryRemove(victim, out _);
        }
    }

    // ── Raw forwarding ──────────────────────────────────────────────────────

    private async Task<DnsMessage> ForwardAsync(DnsMessage query, string name, CancellationToken cancellationToken)
    {
        var (primary, fallback) = SelectChains(name);
        var forceFallback = MatchFallbackDomain(name);

        var primaryTask = QueryRawAsync(primary, query, cancellationToken);

        if (fallback is null)
        {
            var only = await primaryTask.ConfigureAwait(false);
            return Finish(query, only);
        }

        var fallbackTask = QueryRawAsync(fallback, query, cancellationToken);
        var primaryResponse = await primaryTask.ConfigureAwait(false);
        var fallbackResponse = await fallbackTask.ConfigureAwait(false);

        var chosen = primaryResponse;

        if (query.Questions[0].Type is DnsQueryType.A or DnsQueryType.Aaaa)
        {
            var primaryAddresses = ExtractAddresses(primaryResponse, query.Questions[0].Type);
            if ((primaryAddresses.Length == 0 || forceFallback || IsPolluted(primaryAddresses))
                && ExtractAddresses(fallbackResponse, query.Questions[0].Type).Length > 0)
            {
                chosen = fallbackResponse;
            }
        }
        else if (primaryResponse is null)
        {
            chosen = fallbackResponse;
        }

        if (chosen is not null && query.Questions[0].Type is DnsQueryType.A or DnsQueryType.Aaaa)
        {
            var addresses = ExtractAddresses(chosen, query.Questions[0].Type);
            var ttl = chosen.Answers.Count > 0 ? ClampTtl(chosen.Answers.Min(a => a.Ttl)) : MinimumTtlSeconds;
            Store(query.Questions[0].Type, name, new UpstreamAnswer(addresses, TimeSpan.FromSeconds(ttl), chosen.ResponseCode));
        }

        return Finish(query, chosen);
    }

    private static DnsMessage Finish(DnsMessage query, DnsMessage? response)
    {
        if (response is null) return DnsCodec.CreateResponse(query, DnsResponseCode.ServerFailure);

        // Preserve the caller's id; the upstream exchange used its own.
        response.Id = query.Id;
        if (response.Questions.Count == 0) response.Questions = [.. query.Questions];
        return response;
    }

    private async Task<DnsMessage?> QueryRawAsync(NameserverChain chain, DnsMessage query, CancellationToken cancellationToken)
    {
        foreach (var upstream in chain.Upstreams)
        {
            try
            {
                var copy = new DnsMessage
                {
                    Id = (ushort)Random.Shared.Next(1, ushort.MaxValue),
                    IsResponse = false,
                    OpCode = query.OpCode,
                    RecursionDesired = query.RecursionDesired,
                    Questions = [.. query.Questions],
                };

                var response = await upstream.ExchangeAsync(copy, cancellationToken).ConfigureAwait(false);
                if (response.ResponseCode is DnsResponseCode.ServerFailure or DnsResponseCode.Refused) continue;
                return response;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception error)
            {
                _logger.LogDebug(error, "dns: upstream {Upstream} failed for {Name}", upstream.Name, query.Questions[0].Name);
            }
        }

        return null;
    }

    private static IPAddress[] ExtractAddresses(DnsMessage? response, DnsQueryType type)
    {
        if (response is null || response.ResponseCode != DnsResponseCode.NoError) return [];

        var addresses = new List<IPAddress>();
        foreach (var answer in response.Answers)
        {
            if (answer.Type != type || answer.Address is null) continue;
            addresses.Add(answer.Address);
        }

        return [.. addresses];
    }

    // ── Selection helpers ───────────────────────────────────────────────────

    private (NameserverChain Primary, NameserverChain? Fallback) SelectChains(string name)
    {
        var policy = MatchPolicy(name);
        if (policy is not null)
        {
            return (GetChain(policy.Servers), null);
        }

        var primaryRaw = _config.Nameserver is { Count: > 0 } ? _config.Nameserver : _config.DefaultNameserver ?? [];
        var primary = GetChain(primaryRaw);
        var fallback = _config.Fallback is { Count: > 0 } ? GetChain(_config.Fallback) : null;
        return (primary, fallback);
    }

    private NameserverChain GetChain(IReadOnlyList<string> raw)
        => _chains.GetOrAdd(string.Join('\u0001', raw), _ => BuildChain(raw, allowBootstrapFallback: true));

    private NameserverChain BuildChain(IReadOnlyList<string> raw, bool allowBootstrapFallback)
    {
        var upstreams = new List<IDnsUpstream>();
        var bootstrap = _config.DefaultNameserver ?? [];
        Func<string, CancellationToken, Task<IPAddress[]>>? bootstrapResolver =
            allowBootstrapFallback ? BootstrapResolveAsync : null;

        foreach (var entry in raw)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;

            try
            {
                var upstream = _upstreamFactory is not null
                    ? _upstreamFactory(entry, bootstrap, _config.Ipv6, bootstrapResolver)
                    : DnsUpstreams.Create(entry, bootstrap, _config.Ipv6, bootstrapResolver);

                upstreams.Add(upstream);
            }
            catch (DnsException error)
            {
                _logger.LogWarning("dns: ignoring nameserver '{Entry}': {Message}", entry, error.Message);
            }
        }

        return new NameserverChain(raw, upstreams);
    }

    /// <summary>
    /// Resolves a domain-valued nameserver host through <c>default-nameserver</c>.
    /// Re-entry is refused so a bootstrap server that itself needs bootstrapping
    /// fails loudly instead of recursing.
    /// </summary>
    private async Task<IPAddress[]> BootstrapResolveAsync(string host, CancellationToken cancellationToken)
    {
        if (_bootstrapping.Value)
        {
            throw new DnsException($"dns: refusing to bootstrap '{host}' recursively");
        }

        _bootstrapping.Value = true;
        try
        {
            foreach (var upstream in _defaultChain.Upstreams)
            {
                try
                {
                    var addresses = await DnsUpstreams
                        .QueryAsync(upstream, host, _config.Ipv6, cancellationToken)
                        .ConfigureAwait(false);

                    if (addresses.Length > 0) return addresses;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception error)
                {
                    _logger.LogDebug(error, "dns: bootstrap via {Upstream} failed for {Host}", upstream.Name, host);
                }
            }

            _logger.LogDebug("dns: falling back to the system resolver to bootstrap {Host}", host);
            return await System.Net.Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _bootstrapping.Value = false;
        }
    }

    private bool IsFakeIpMode => string.Equals(_config.EnhancedMode, "fake-ip", StringComparison.OrdinalIgnoreCase);

    private bool IsPolluted(IPAddress[] addresses)
    {
        var filter = _config.FallbackFilter;

        foreach (var address in addresses)
        {
            foreach (var (network, prefix) in _fallbackCidrs)
            {
                if (InCidr(address, network, prefix)) return true;
            }
        }

        if (!filter.GeoIpFilter || !filter.GeoIp) return false;

        var lookup = GeoIpLookup;
        if (lookup is null) return false;

        foreach (var address in addresses)
        {
            string? code;
            try
            {
                code = lookup(address);
            }
            catch (Exception)
            {
                continue;
            }

            if (code is null) continue;

            // A nameserver answer outside the trusted country is the classic
            // DNS-poisoning signature, so the fallback answer wins.
            if (!string.Equals(code, filter.GeoIpCode, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private bool MatchFallbackDomain(string name)
    {
        foreach (var pattern in _config.FallbackFilter.Domain ?? [])
        {
            if (string.IsNullOrWhiteSpace(pattern)) continue;
            if (DomainPattern.Matches(pattern, name, bareIsSuffix: false)) return true;
        }

        return false;
    }

    private PolicyEntry? MatchPolicy(string name)
    {
        PolicyEntry? best = null;

        foreach (var policy in _policies)
        {
            if (!policy.Matches(name)) continue;
            if (best is null || policy.Specificity > best.Specificity) best = policy;
        }

        return best;
    }

    private void ParsePolicies(Dictionary<string, object?>? policies)
    {
        if (policies is null) return;

        foreach (var pair in policies)
        {
            var key = pair.Key?.Trim();
            if (string.IsNullOrEmpty(key)) continue;

            if (DomainPattern.IsUnsupportedKey(key))
            {
                _logger.LogWarning(
                    "dns: nameserver-policy key '{Key}' needs geodata that is not available; the entry is ignored",
                    key);
                continue;
            }

            var servers = ToStringList(pair.Value);
            if (servers.Count == 0) continue;

            _policies.Add(new PolicyEntry(key, servers));
        }
    }

    private void ParseFallbackCidrs(FallbackFilterConfig? filter)
    {
        if (filter?.IpCidr is null) return;

        foreach (var entry in filter.IpCidr)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            if (TryParseCidr(entry, out var network, out var prefix)) _fallbackCidrs.Add((network, prefix));
            else _logger.LogWarning("dns: fallback-filter.ipcidr entry '{Entry}' is not a CIDR and is ignored", entry);
        }
    }

    private static bool TryParseCidr(string text, out IPAddress network, out int prefix)
    {
        network = IPAddress.None;
        prefix = 0;

        var trimmed = text.Trim();
        var slash = trimmed.IndexOf('/');
        var addressPart = slash >= 0 ? trimmed[..slash] : trimmed;
        var prefixPart = slash >= 0 ? trimmed[(slash + 1)..] : null;

        if (!IPAddress.TryParse(addressPart, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();

        var bits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        prefix = bits;
        if (prefixPart is not null && !int.TryParse(prefixPart, out prefix)) return false;
        if (prefix < 0 || prefix > bits) return false;

        network = address;
        return true;
    }

    private static bool InCidr(IPAddress address, IPAddress network, int prefix)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != network.AddressFamily) return false;

        var bytes = address.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        if (bytes.Length != networkBytes.Length) return false;

        var fullBytes = prefix / 8;
        var remaining = prefix % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            if (bytes[i] != networkBytes[i]) return false;
        }

        if (remaining == 0) return true;

        var mask = (byte)(0xFF << (8 - remaining));
        return (bytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    /// <summary>Clamps an upstream TTL into the range the cache will honour.</summary>
    public static uint ClampTtl(uint ttl)
        => Math.Clamp(ttl, MinimumTtlSeconds, MaximumTtlSeconds);

    private static List<string> ToStringList(object? value)
    {
        var result = new List<string>();

        switch (value)
        {
            case null:
                break;

            case string text:
                foreach (var part in text.Split([',', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    result.Add(part);
                }

                break;

            case System.Collections.IEnumerable sequence:
                foreach (var item in sequence)
                {
                    var text = Convert.ToString(item, System.Globalization.CultureInfo.InvariantCulture);
                    if (!string.IsNullOrWhiteSpace(text)) result.Add(text.Trim());
                }

                break;

            default:
            {
                var text = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
                if (!string.IsNullOrWhiteSpace(text)) result.Add(text.Trim());
                break;
            }
        }

        return result;
    }

    private static string Normalize(string? host)
        => host is null ? string.Empty : host.Trim().TrimEnd('.').ToLowerInvariant();

    // ── Nested types ────────────────────────────────────────────────────────

    private readonly record struct CacheKey(string Name, DnsQueryType Type);

    private sealed class CacheEntry(IPAddress[] addresses, DateTimeOffset expires)
    {
        public IPAddress[] Addresses { get; } = addresses;

        public DateTimeOffset Expires { get; } = expires;
    }

    private readonly record struct UpstreamAnswer(IPAddress[] Addresses, TimeSpan Ttl, DnsResponseCode Code);

    private sealed class NameserverChain(IReadOnlyList<string> raw, IReadOnlyList<IDnsUpstream> upstreams) : IDisposable
    {
        public IReadOnlyList<string> Raw { get; } = raw;

        public IReadOnlyList<IDnsUpstream> Upstreams { get; } = upstreams;

        public void Dispose()
        {
            foreach (var upstream in Upstreams) upstream.Dispose();
        }
    }

    private sealed class PolicyEntry
    {
        public PolicyEntry(string key, IReadOnlyList<string> servers)
        {
            Key = key;
            Servers = servers;

            var bare = key.Trim().TrimEnd('.').ToLowerInvariant();
            var offset = bare.StartsWith('.', StringComparison.Ordinal) ? 1 : 2;

            if (bare.StartsWith("+.", StringComparison.Ordinal)
                || bare.StartsWith("*.", StringComparison.Ordinal)
                || bare.StartsWith('.', StringComparison.Ordinal))
            {
                Suffix = bare[offset..];
                IncludeApex = !bare.StartsWith("*.", StringComparison.Ordinal);
            }
            else
            {
                Suffix = bare;
                IncludeApex = true;
            }
        }

        public string Key { get; }

        public IReadOnlyList<string> Servers { get; }

        public string Suffix { get; }

        public bool IncludeApex { get; }

        /// <summary>Longer suffixes are more specific and win.</summary>
        public int Specificity => Suffix.Length;

        public bool Matches(string host) => DomainPattern.MatchesSuffix(Suffix, host, IncludeApex);
    }
}

/// <summary>
/// Domain-pattern matching shared by <c>fake-ip-filter</c>,
/// <c>fallback-filter.domain</c> and <c>nameserver-policy</c> keys.
/// </summary>
internal static class DomainPattern
{
    /// <summary>True for key forms that need geodata this subsystem does not own.</summary>
    public static bool IsUnsupportedKey(string key)
        => key.StartsWith("geosite:", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("geoip:", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("rule-set:", StringComparison.OrdinalIgnoreCase)
            || key.StartsWith("ruleset:", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Matches <paramref name="host"/> against a Clash domain pattern.
    /// <c>*.example.com</c> matches subdomains only, <c>+.example.com</c> and a
    /// leading dot match the apex too, and a bare pattern is exact unless
    /// <paramref name="bareIsSuffix"/> is set.
    /// </summary>
    public static bool Matches(string pattern, string host, bool bareIsSuffix)
    {
        if (string.IsNullOrWhiteSpace(pattern)) return false;

        var value = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        if (value.Length == 0) return false;
        if (value == "*") return true;

        if (value.StartsWith("*.", StringComparison.Ordinal)) return MatchesSuffix(value[2..], host, includeApex: false);
        if (value.StartsWith("+.", StringComparison.Ordinal)) return MatchesSuffix(value[2..], host, includeApex: true);
        if (value.StartsWith('.', StringComparison.Ordinal)) return MatchesSuffix(value[1..], host, includeApex: true);

        if (bareIsSuffix) return MatchesSuffix(value, host, includeApex: true);
        return string.Equals(value, host, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Label-boundary suffix match.</summary>
    public static bool MatchesSuffix(string suffix, string host, bool includeApex)
    {
        if (suffix.Length == 0) return false;
        if (host.Length < suffix.Length) return false;

        if (string.Equals(host, suffix, StringComparison.OrdinalIgnoreCase)) return includeApex;
        if (host.Length == suffix.Length) return false;
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return false;

        return host[^(suffix.Length + 1)] == '.';
    }
}
