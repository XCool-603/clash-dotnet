using System.Net;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;
using Clash.Core.Tunnel;

namespace Clash.Tests.Support;

/// <summary>An <see cref="IProxy"/> double that records what it was asked to do.</summary>
public sealed class FakeProxy : ProxyAdapter, IOutboundProxy
{
    public FakeProxy(string name, ProxyType type = ProxyType.Shadowsocks, string? serverHost = null, int serverPort = 0)
        : base(name, type)
    {
        ServerHost = serverHost;
        ServerPort = serverPort;
    }

    public string? ServerHost { get; }

    public int ServerPort { get; }

    public string? DialerProxy => null;

    public override bool SupportUdp => true;

    /// <summary>Flows this adapter was asked to dial, in order.</summary>
    public List<Metadata> Dialled { get; } = [];

    /// <summary>Streams handed to <see cref="DialTcpAsync"/> as the upstream hop.</summary>
    public List<Stream?> Upstreams { get; } = [];

    public Func<Metadata, Stream?, Task<ProxyStream>>? OnDial { get; set; }

    public Exception? FailWith { get; set; }

    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        Dialled.Add(metadata.Clone());
        Upstreams.Add(upstream);

        if (FailWith is not null) throw FailWith;
        if (OnDial is not null) return await OnDial(metadata, upstream);

        return new ProxyStream(NullStream.Instance);
    }

    public override Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult<IPacketConnection>(new FakePacketConnection());
}

/// <summary>A packet association that never yields data.</summary>
public sealed class FakePacketConnection : IPacketConnection
{
    public bool SupportsMultipleDestinations => true;

    public EndPoint? LocalEndPoint => null;

    public List<(byte[] Payload, EndPoint Destination)> Sent { get; } = [];

    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
    {
        Sent.Add((payload.ToArray(), destination));
        return ValueTask.FromResult(payload.Length);
    }

    public async ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Block until cancelled, mirroring a real association with no traffic.
        await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        return new PacketResult(0, null);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

/// <summary>A delay tester whose results are scripted per proxy name.</summary>
public sealed class FakeDelayTester : IDelayTester
{
    public Dictionary<string, int> Delays { get; } = new(StringComparer.Ordinal);

    public int DefaultDelay { get; set; } = 100;

    public List<string> Probed { get; } = [];

    public Task<DelayProbeResult> TestAsync(IProxy proxy, string url, int timeoutMs, CancellationToken cancellationToken = default)
    {
        Probed.Add(proxy.Name);
        var delay = Delays.TryGetValue(proxy.Name, out var value) ? value : DefaultDelay;
        return Task.FromResult(new DelayProbeResult(proxy.Name, delay, delay > 0 ? null : "timeout"));
    }
}

/// <summary>A DNS resolver double with a scripted hosts table.</summary>
public sealed class FakeDnsResolver : IDnsResolver
{
    public Dictionary<string, IPAddress[]> Answers { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> FakeIps { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, string> FakeReverse { get; } = new(StringComparer.Ordinal);

    public DnsConfig Config { get; } = new();

    public int ResolveCalls { get; private set; }

    public ValueTask<IPAddress[]> ResolveAsync(string host, bool ipv6 = true, CancellationToken cancellationToken = default)
    {
        ResolveCalls++;
        return ValueTask.FromResult(Answers.TryGetValue(host, out var addresses) ? addresses : []);
    }

    public IPAddress[] ResolveHosts(string host) => Answers.TryGetValue(host, out var a) ? a : [];

    public bool IsFakeIp(IPAddress address) => FakeIps.Contains(address.ToString());

    public string? ReverseFakeIp(IPAddress address)
        => FakeReverse.TryGetValue(address.ToString(), out var host) ? host : null;

    public IPAddress? FakeIpFor(string host) => null;

    public bool ShouldFakeIp(string host) => false;

    public Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken = default)
        => Task.FromResult(DnsMessage.CreateQuery(query.Questions[0].Name, query.Questions[0].Type, query.Id));

    public void FlushFakeIp() { }

    public void FlushCache() { }
}

/// <summary>A geo provider that answers nothing.</summary>
public sealed class FakeGeoData : IGeoData
{
    public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    public bool TryGetCountry(IPAddress address, out string countryCode)
    {
        countryCode = string.Empty;
        return false;
    }

    public bool TryGetAsn(IPAddress address, out uint asn)
    {
        asn = 0;
        return false;
    }

    public IReadOnlyCollection<string>? GetGeoSite(string code) => null;

    public IReadOnlyList<(IPAddress Network, int PrefixLength)>? GetGeoSiteCidrs(string code) => null;

    public bool HasGeoSite(string code) => false;

    public bool HasCountry(string code) => false;
}

/// <summary>A rule engine double that returns a scripted match.</summary>
public sealed class FakeRuleEngine : IRuleEngine
{
    public List<IRule> RuleList { get; } = [];

    public Dictionary<string, IRuleSet> RuleSetMap { get; } = new(StringComparer.OrdinalIgnoreCase);

    public RuleMatch? Next { get; set; }

    public List<Metadata> Matched { get; } = [];

    public IReadOnlyList<IRule> Rules => RuleList;

    public IReadOnlyDictionary<string, IRuleSet> RuleSets => RuleSetMap;

    public Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        Matched.Add(metadata);
        if (Next is not null)
        {
            metadata.Rule = Next.Rule.RuleTypeName;
            metadata.RulePayload = Next.Rule.Payload;
        }
        return Task.FromResult(Next);
    }

    public void SetRules(IReadOnlyList<IRule> rules)
    {
        RuleList.Clear();
        RuleList.AddRange(rules);
    }

    public bool Disable(string ruleType, string payload) => true;

    public bool Enable(string ruleType, string payload) => true;

    public bool IsDisabled(string ruleType, string payload) => false;
}

/// <summary>A tunnel accessor that is ready immediately.</summary>
public sealed class FakeTunnelAccessor : ITunnelAccessor
{
    public FakeTunnelAccessor(ITunnel tunnel) => Tunnel = tunnel;

    public ITunnel Tunnel { get; }

    public bool IsReady => true;
}

/// <summary>A minimal <see cref="ITunnel"/> for exercising adapters and groups.</summary>
public sealed class FakeTunnel : ITunnel
{
    public FakeTunnel(ClashConfig? config = null)
    {
        Config = config ?? new ClashConfig();
        Dns = new FakeDnsResolver();
        Geo = new FakeGeoData();
        Rules = new FakeRuleEngine();
        Proxies = new ProxyManager(new FakeTunnelAccessor(this), new Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory());
        Traffic = new TrafficTracker();
        Connections = new ConnectionManager(Traffic);
        DelayTester = new FakeDelayTester();
    }

    public ClashConfig Config { get; set; }

    public IDnsResolver Dns { get; }

    public IGeoData Geo { get; }

    public IProxyManager Proxies { get; }

    public ConnectionManager Connections { get; }

    public IRuleEngine Rules { get; }

    public TrafficTracker Traffic { get; }

    public IDelayTester DelayTester { get; set; }

    public Mode Mode { get; set; } = Mode.Rule;

    public List<(string Level, string Message)> Logs { get; } = [];

    public event Action<string, string>? LogEmitted;

    public Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Rules.MatchAsync(metadata, cancellationToken);

    public Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult(new ProxyStream(NullStream.Instance));

    public Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult<IPacketConnection>(new FakePacketConnection());

    public Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public void Log(string level, string message)
    {
        Logs.Add((level, message));
        LogEmitted?.Invoke(level, message);
    }
}
