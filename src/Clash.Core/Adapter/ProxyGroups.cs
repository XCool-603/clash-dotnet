using System.Collections.Concurrent;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Adapter;

/// <summary>
/// Shared machinery for the proxy groups: membership, the periodic health check,
/// delay history propagation and the API-visible group metadata.
/// </summary>
public abstract class ProxyGroupBase : ProxyAdapter, IProxyGroup, IAsyncDisposable
{
    private readonly ITunnelAccessor _tunnel;
    private readonly ILogger _logger;
    private readonly Lock _memberLock = new();
    private readonly List<IProxy> _members = [];
    private readonly string _testUrl;
    private readonly int _interval;
    private readonly int _timeout;
    private readonly bool _lazy;
    private readonly bool _disableUdp;
    private readonly string? _icon;
    private readonly bool _hidden;
    private readonly string? _expectedStatus;

    private CancellationTokenSource? _healthCheckCts;
    private Task? _healthCheckTask;

    protected ProxyGroupBase(
        ProxyGroupConfig config,
        ITunnelAccessor tunnel,
        ILogger logger)
        : base(config.Name, ParseGroupType(config.Type))
    {
        _tunnel = tunnel;
        _logger = logger;
        _testUrl = config.Url;
        _interval = Math.Max(1, config.Interval);
        _timeout = Math.Max(100, config.Timeout);
        _lazy = config.Lazy;
        _disableUdp = config.DisableUdp;
        _icon = config.Icon;
        _hidden = config.Hidden;
        _expectedStatus = config.ExpectedStatus;
    }

    public override bool IsGroup => true;

    /// <summary>
    /// Resolved membership, in configuration order. Virtual so the built-in
    /// <c>GLOBAL</c> group can expose the live registry instead of a fixed list.
    /// </summary>
    public virtual IReadOnlyList<IProxy> Members
    {
        get
        {
            lock (_memberLock) return _members.ToArray();
        }
    }

    public virtual string? SelectedName => null;

    public string TestUrl => _testUrl;

    public int IntervalSeconds => _interval;

    public int TimeoutMs => _timeout;

    public bool Lazy => _lazy;

    public string? ExpectedStatus => _expectedStatus;

    public virtual bool Hidden => _hidden;

    public virtual string? Icon => _icon;

    /// <summary>True when at least one member can carry datagrams.</summary>
    public override bool SupportUdp => !_disableUdp && Members.Any(m => m.SupportUdp);

    /// <summary>Replaces the membership, preserving order.</summary>
    public void SetMembers(IEnumerable<IProxy> members)
    {
        lock (_memberLock)
        {
            _members.Clear();
            _members.AddRange(members);
        }
    }

    /// <summary>Selection is only meaningful for <c>select</c>; other groups refuse it.</summary>
    public virtual Task<bool> SelectAsync(string proxyName) => Task.FromResult(false);

    public override Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        var member = SelectMember(metadata)
            ?? throw new ProxyNotFoundException($"{Name}: no usable member");

        metadata.Chain.Add(member.Name);
        return member.DialTcpAsync(metadata, upstream, cancellationToken);
    }

    public override Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        var member = SelectMember(metadata)
            ?? throw new ProxyNotFoundException($"{Name}: no usable member");

        metadata.Chain.Add(member.Name);
        return member.DialUdpAsync(metadata, cancellationToken);
    }

    /// <summary>Chooses the member that carries a flow. Must be cheap and thread-safe.</summary>
    protected abstract IProxy? SelectMember(Metadata metadata);

    /// <summary>Runs a delay probe over every member and records the results.</summary>
    public virtual async Task<IReadOnlyDictionary<string, int>> UrlTestAsync(CancellationToken cancellationToken = default)
    {
        var results = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);
        var members = Members;
        if (members.Count == 0) return results;

        var tester = _tunnel.IsReady ? _tunnel.Tunnel.DelayTester : null;
        if (tester is null) return results;

        using var gate = new SemaphoreSlim(8);
        var tasks = members.Select(async member =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var probe = await tester.TestAsync(member, _testUrl, _timeout, cancellationToken).ConfigureAwait(false);
                results[member.Name] = probe.DelayMs;
                if (member is ProxyAdapter adapter) adapter.PushHistory(probe.DelayMs);
                if (!probe.Success && probe.Error is not null)
                {
                    _logger.LogDebug("url-test {Group}/{Member} failed: {Error}", Name, member.Name, probe.Error);
                }
            }
            catch (OperationCanceledException)
            {
                results[member.Name] = 0;
            }
            catch (Exception ex)
            {
                results[member.Name] = 0;
                _logger.LogDebug("url-test {Group}/{Member} threw: {Message}", Name, member.Name, ex.Message);
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        OnHealthCheckCompleted(results);
        return results;
    }

    /// <summary>Hook for groups that track the winner of a health check.</summary>
    protected virtual void OnHealthCheckCompleted(IReadOnlyDictionary<string, int> results) { }

    /// <summary>Starts the periodic health check. Lazy groups only test on demand.</summary>
    public void StartHealthCheck()
    {
        if (_lazy || _healthCheckTask is not null) return;

        _healthCheckCts = new CancellationTokenSource();
        var token = _healthCheckCts.Token;
        _healthCheckTask = Task.Run(async () =>
        {
            // Small initial delay so startup is not blocked by a burst of probes.
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        await UrlTestAsync(token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug("health check for {Group} failed: {Message}", Name, ex.Message);
                    }

                    await Task.Delay(TimeSpan.FromSeconds(_interval), token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                // Shutting down.
            }
        }, token);
    }

    public override void CloseConnections()
    {
        foreach (var member in Members) member.CloseConnections();
        base.CloseConnections();
    }

    public async ValueTask DisposeAsync()
    {
        if (_healthCheckCts is not null)
        {
            await _healthCheckCts.CancelAsync().ConfigureAwait(false);
            if (_healthCheckTask is not null)
            {
                try { await _healthCheckTask.ConfigureAwait(false); } catch { /* cancelled */ }
            }
            _healthCheckCts.Dispose();
            _healthCheckCts = null;
            _healthCheckTask = null;
        }
        GC.SuppressFinalize(this);
    }

    private static ProxyType ParseGroupType(string type) => type.ToLowerInvariant() switch
    {
        "select" => ProxyType.Selector,
        "url-test" => ProxyType.UrlTest,
        "fallback" => ProxyType.Fallback,
        "load-balance" => ProxyType.LoadBalance,
        "relay" => ProxyType.Relay,
        "smart" => ProxyType.Smart,
        _ => throw new ProxyCreationException($"unsupported proxy group type [{type}]"),
    };
}

/// <summary><c>select</c>: the user (or the API) picks the member.</summary>
public class SelectorGroup : ProxyGroupBase
{
    private readonly Lock _selectionLock = new();
    private string? _selected;
    private ISelectionStore? _store;

    public SelectorGroup(ProxyGroupConfig config, ITunnelAccessor tunnel, ILogger logger)
        : base(config, tunnel, logger)
    {
    }

    public override string? SelectedName
    {
        get
        {
            lock (_selectionLock) return _selected;
        }
    }

    /// <summary>Attaches the persistence store and restores the previous selection.</summary>
    public void UseStore(ISelectionStore store, string groupKey)
    {
        _store = store;
        var saved = store.Get(groupKey);
        if (!string.IsNullOrEmpty(saved)) SelectAsync(saved).GetAwaiter().GetResult();
    }

    public override Task<bool> SelectAsync(string proxyName)
    {
        var match = Members.FirstOrDefault(m => string.Equals(m.Name, proxyName, StringComparison.Ordinal));
        if (match is null) return Task.FromResult(false);

        lock (_selectionLock) _selected = match.Name;
        _store?.Set(Name, match.Name);
        return Task.FromResult(true);
    }

    protected override IProxy? SelectMember(Metadata metadata)
    {
        var members = Members;
        if (members.Count == 0) return null;

        lock (_selectionLock)
        {
            if (_selected is not null)
            {
                var chosen = members.FirstOrDefault(m => string.Equals(m.Name, _selected, StringComparison.Ordinal));
                if (chosen is not null) return chosen;
            }

            // The saved selection is gone (provider refresh); fall back to the
            // first member that is not known to be dead.
            var fallback = members.FirstOrDefault(m => m.Alive) ?? members[0];
            _selected = fallback.Name;
            _store?.Set(Name, fallback.Name);
            return fallback;
        }
    }
}

/// <summary><c>url-test</c>: the fastest member wins.</summary>
public class UrlTestGroup : ProxyGroupBase
{
    private readonly int _tolerance;
    private volatile IProxy? _best;

    public UrlTestGroup(ProxyGroupConfig config, ITunnelAccessor tunnel, ILogger logger)
        : base(config, tunnel, logger)
    {
        _tolerance = Math.Max(0, config.Tolerance);
    }

    public override string? SelectedName => _best?.Name;

    protected override IProxy? SelectMember(Metadata metadata)
    {
        var members = Members;
        if (members.Count == 0) return null;

        var best = _best;
        if (best is not null && members.Contains(best)) return best;

        // Nothing measured yet: use the first member and let the health check
        // correct it shortly.
        return members.FirstOrDefault(m => m.Alive) ?? members[0];
    }

    protected override void OnHealthCheckCompleted(IReadOnlyDictionary<string, int> results)
    {
        var members = Members;
        IProxy? winner = null;
        var winnerDelay = int.MaxValue;

        foreach (var member in members)
        {
            if (!results.TryGetValue(member.Name, out var delay) || delay <= 0) continue;
            if (delay < winnerDelay)
            {
                winnerDelay = delay;
                winner = member;
            }
        }

        if (winner is null)
        {
            Alive = false;
            return;
        }

        Alive = true;

        // The incumbent is the current best, or — before anything has been
        // measured — the first member that answered. A challenger must be faster
        // by more than `tolerance` to take the group over, which is what stops a
        // noisy probe from flapping the selection.
        var incumbent = _best is not null && members.Contains(_best)
            ? _best
            : members.FirstOrDefault(m => results.TryGetValue(m.Name, out var d) && d > 0);

        if (incumbent is not null &&
            results.TryGetValue(incumbent.Name, out var incumbentDelay) &&
            incumbentDelay > 0 &&
            winnerDelay + _tolerance >= incumbentDelay)
        {
            _best = incumbent;
            return;
        }

        _best = winner;
    }
}

/// <summary><c>fallback</c>: the first member that is alive.</summary>
public sealed class FallbackGroup : ProxyGroupBase
{
    private volatile IProxy? _current;

    public FallbackGroup(ProxyGroupConfig config, ITunnelAccessor tunnel, ILogger logger)
        : base(config, tunnel, logger)
    {
    }

    public override string? SelectedName => _current?.Name;

    protected override IProxy? SelectMember(Metadata metadata)
    {
        var members = Members;
        if (members.Count == 0) return null;

        var current = _current;
        if (current is not null && current.Alive && members.Contains(current)) return current;

        var next = members.FirstOrDefault(m => m.Alive) ?? members[0];
        _current = next;
        return next;
    }

    protected override void OnHealthCheckCompleted(IReadOnlyDictionary<string, int> results)
    {
        // Fallback order is configuration order: the first member that answered
        // wins, and a recovered primary takes the group back.
        var members = Members;
        _current = members.FirstOrDefault(m => results.TryGetValue(m.Name, out var delay) && delay > 0);
        Alive = _current is not null;
    }
}

/// <summary><c>load-balance</c>: spreads flows across members.</summary>
public sealed class LoadBalanceGroup : ProxyGroupBase
{
    private readonly string _strategy;
    private int _roundRobin;

    public LoadBalanceGroup(ProxyGroupConfig config, ITunnelAccessor tunnel, ILogger logger)
        : base(config, tunnel, logger)
    {
        _strategy = (config.Strategy ?? "consistent-hashing").ToLowerInvariant();
    }

    public string Strategy => _strategy;

    protected override IProxy? SelectMember(Metadata metadata)
    {
        var members = Members;
        if (members.Count == 0) return null;
        if (members.Count == 1) return members[0];

        if (_strategy == "round-robin")
        {
            var index = (int)((uint)Interlocked.Increment(ref _roundRobin) % (uint)members.Count);
            return members[index];
        }

        // consistent-hashing: stable per destination host, so a given site keeps
        // landing on the same node (important for session-bound sites).
        var key = metadata.RuleHost;
        var hash = StableHash(key);
        return members[(int)(hash % (uint)members.Count)];
    }

    private static uint StableHash(string value)
    {
        // FNV-1a: stable across runs, unlike string.GetHashCode.
        unchecked
        {
            var hash = 2166136261u;
            foreach (var c in value)
            {
                hash ^= c;
                hash *= 16777619u;
            }
            return hash;
        }
    }
}

/// <summary>
/// <c>relay</c>: chains every member, so traffic traverses them in order.
/// <para>
/// The chain is built outside-in: member[0] connects to member[1]'s server,
/// member[1] tunnels over that to member[2]'s server, and the last member
/// tunnels to the real destination.
/// </para>
/// </summary>
public sealed class RelayGroup : ProxyGroupBase
{
    public RelayGroup(ProxyGroupConfig config, ITunnelAccessor tunnel, ILogger logger)
        : base(config, tunnel, logger)
    {
    }

    public override string? SelectedName => null;

    protected override IProxy? SelectMember(Metadata metadata) => Members.FirstOrDefault();

    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        var members = Members;
        if (members.Count == 0) throw new ProxyNotFoundException($"{Name}: relay group has no members");

        foreach (var member in members) metadata.Chain.Add(member.Name);

        if (upstream is not null)
        {
            // Already inside a chain: the last member carries it to the target.
            return await members[^1].DialTcpAsync(metadata, upstream, cancellationToken).ConfigureAwait(false);
        }

        // Build the chain from the first hop inwards.
        return await DialHopAsync(members, 0, metadata, null, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ProxyStream> DialHopAsync(
        IReadOnlyList<IProxy> members,
        int index,
        Metadata metadata,
        ProxyStream? upstream,
        CancellationToken cancellationToken)
    {
        var member = members[index];

        // The final hop dials the real destination, carried over the stream the
        // previous hop established.
        if (index == members.Count - 1)
        {
            return await member.DialTcpAsync(metadata, upstream, cancellationToken).ConfigureAwait(false);
        }

        var next = members[index + 1] as IOutboundProxy
            ?? throw new ProxyCreationException(
                $"relay group member [{members[index + 1].Name}] does not expose a server address");

        if (string.IsNullOrEmpty(next.ServerHost))
        {
            throw new ProxyCreationException(
                $"relay group member [{next.Name}] has no server address and cannot be chained");
        }

        // This hop is dialed to the *next* member's server address.
        var hopMetadata = metadata.Clone();
        hopMetadata.DestinationAddress = next.ServerHost!;
        hopMetadata.DestinationPort = (ushort)next.ServerPort;
        hopMetadata.Host = next.ServerHost;

        var stream = await member.DialTcpAsync(hopMetadata, upstream, cancellationToken).ConfigureAwait(false);
        try
        {
            return await DialHopAsync(members, index + 1, metadata, stream, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}

/// <summary>
/// <c>smart</c>: mihomo's adaptive group. Approximated by url-test ordering plus
/// per-domain stickiness, which captures the behaviour users rely on.
/// </summary>
public sealed class SmartGroup : UrlTestGroup
{
    private readonly ConcurrentDictionary<string, string> _sticky = new(StringComparer.OrdinalIgnoreCase);

    public SmartGroup(ProxyGroupConfig config, ITunnelAccessor tunnel, ILogger logger)
        : base(config, tunnel, logger)
    {
    }

    protected override IProxy? SelectMember(Metadata metadata)
    {
        var members = Members;
        if (members.Count == 0) return null;

        var host = metadata.RuleHost;
        if (_sticky.TryGetValue(host, out var stickyName))
        {
            var sticky = members.FirstOrDefault(m => string.Equals(m.Name, stickyName, StringComparison.Ordinal));
            if (sticky is not null && sticky.Alive) return sticky;
            _sticky.TryRemove(host, out _);
        }

        var chosen = base.SelectMember(metadata);
        if (chosen is not null && _sticky.Count < 4096) _sticky[host] = chosen.Name;
        return chosen;
    }
}

/// <summary>
/// Persists group selections across restarts, backing <c>profile.store-selected</c>.
/// </summary>
public interface ISelectionStore
{
    string? Get(string group);

    void Set(string group, string proxy);
}

/// <summary>An in-memory selection store, used when persistence is disabled.</summary>
public sealed class MemorySelectionStore : ISelectionStore
{
    private readonly ConcurrentDictionary<string, string> _values = new(StringComparer.Ordinal);

    public string? Get(string group) => _values.TryGetValue(group, out var v) ? v : null;

    public void Set(string group, string proxy) => _values[group] = proxy;
}
