using System.Net;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Rules;
using Clash.Core.Tunnel;
using Clash.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Tunnel;

public class TunnelTests
{
    private sealed class StubRule(string typeName, string payload, string adapter, bool resolveIp = false) : IRule
    {
        public RuleType Type => RuleType.DomainSuffix;
        public string RuleTypeName => typeName;
        public string Payload => payload;
        public string Adapter => adapter;
        public bool ShouldResolveIp => resolveIp;
        public string? AdditionalPayload => null;
        public bool Match(Metadata metadata) => true;
        public string Description => $"{typeName},{payload},{adapter}";
    }

    private static (Core.Tunnel.Tunnel Tunnel, ProxyManager Proxies, FakeRuleEngine Rules, FakeDnsResolver Dns, FakeTunnelAccessor Accessor) Build(
        Mode mode = Mode.Rule,
        Action<ClashConfig>? configure = null)
    {
        var config = new ClashConfig { Mode = mode };
        configure?.Invoke(config);

        var accessor = new TunnelAccessor();
        var loggerFactory = NullLoggerFactory.Instance;
        var proxies = new ProxyManager(accessor, loggerFactory);
        var dns = new FakeDnsResolver();
        var geo = new FakeGeoData();
        var rules = new FakeRuleEngine();

        var tunnel = new Core.Tunnel.Tunnel(config, dns, geo, proxies, rules, NullLogger<Core.Tunnel.Tunnel>.Instance);
        accessor.Attach(tunnel);

        return (tunnel, proxies, rules, dns, new FakeTunnelAccessor(tunnel));
    }

    private static Metadata Flow(string destination = "example.com", ushort port = 443) => new()
    {
        Network = Network.Tcp,
        DestinationAddress = destination,
        DestinationPort = port,
        InboundType = "mixed",
    };

    // ── mode resolution ──────────────────────────────────────────────────────

    [Fact]
    public async Task RuleModeUsesTheMatchedAdapter()
    {
        var (tunnel, proxies, rules, _, _) = Build(Mode.Rule);
        var target = new FakeProxy("node1");
        proxies.Add(target);
        rules.Next = new RuleMatch(new StubRule("DOMAIN-SUFFIX", "example.com", "node1"), "node1", 0);

        var metadata = Flow();
        await tunnel.DialTcpAsync(metadata);

        Assert.Single(target.Dialled);
        Assert.Equal(["node1"], metadata.Chain);
        Assert.Equal("DOMAIN-SUFFIX", metadata.Rule);
        Assert.Equal("example.com", metadata.RulePayload);
    }

    [Fact]
    public async Task DirectModeBypassesTheRules()
    {
        var (tunnel, proxies, rules, _, _) = Build(Mode.Direct);
        var target = new FakeProxy("node1");
        proxies.Add(target);
        rules.Next = new RuleMatch(new StubRule("DOMAIN-SUFFIX", "example.com", "node1"), "node1", 0);

        var metadata = Flow();
        await tunnel.DialTcpAsync(metadata);

        Assert.Empty(target.Dialled);
        Assert.Empty(rules.Matched);
        Assert.Equal(["DIRECT"], metadata.Chain);
        Assert.Equal("Match", metadata.Rule);
    }

    [Fact]
    public async Task GlobalModeUsesTheGlobalSelection()
    {
        var (tunnel, proxies, rules, _, _) = Build(Mode.Global);
        var a = new FakeProxy("a");
        var b = new FakeProxy("b");
        proxies.Add(a);
        proxies.Add(b);

        // GLOBAL excludes the built-ins and defaults to the first real proxy.
        await tunnel.DialTcpAsync(Flow());
        Assert.Single(a.Dialled);
        Assert.Empty(rules.Matched);

        Assert.True(await ((IProxyGroup)proxies.Global).SelectAsync("b"));
        await tunnel.DialTcpAsync(Flow());
        Assert.Single(b.Dialled);
    }

    [Fact]
    public async Task RuleModeWithoutAMatchFallsBackToDirect()
    {
        var (tunnel, _, _, _, _) = Build(Mode.Rule);
        var metadata = Flow();

        await tunnel.DialTcpAsync(metadata);

        Assert.Equal(["DIRECT"], metadata.Chain);
        Assert.Equal("Match", metadata.Rule);
    }

    [Fact]
    public async Task SpecialProxyShortCircuitsRuleEvaluation()
    {
        var (tunnel, proxies, rules, _, _) = Build(Mode.Rule);
        var forced = new FakeProxy("forced");
        proxies.Add(forced);

        var metadata = Flow();
        metadata.SpecialProxy = "forced";

        await tunnel.DialTcpAsync(metadata);

        Assert.Single(forced.Dialled);
        Assert.Empty(rules.Matched);
        Assert.Equal(["forced"], metadata.Chain);
    }

    [Fact]
    public async Task UnknownRuleTargetThrows()
    {
        var (tunnel, _, rules, _, _) = Build(Mode.Rule);
        rules.Next = new RuleMatch(new StubRule("DOMAIN-SUFFIX", "example.com", "ghost"), "ghost", 0);

        await Assert.ThrowsAsync<ProxyNotFoundException>(() => tunnel.DialTcpAsync(Flow()));
    }

    // ── fake-IP handling ─────────────────────────────────────────────────────

    [Fact]
    public async Task FakeIpDestinationIsReversedToTheRealHost()
    {
        var (tunnel, proxies, _, dns, _) = Build(Mode.Rule);
        var direct = (DirectAdapter)proxies.Direct;
        Assert.NotNull(direct);

        var fake = IPAddress.Parse("198.18.0.5");
        dns.FakeIps.Add(fake.ToString());
        dns.FakeReverse[fake.ToString()] = "real.example.com";

        var metadata = Flow(fake.ToString());
        await tunnel.MatchAsync(metadata);

        Assert.Equal("real.example.com", metadata.Host);
        Assert.Equal(DnsMode.FakeIp, metadata.DnsMode);
        Assert.Equal("real.example.com", metadata.RuleHost);
        Assert.Equal("real.example.com", metadata.ApiHost);
    }

    [Fact]
    public async Task NonFakeAddressLeavesTheHostEmptySoIpRulesCanMatch()
    {
        var (tunnel, _, _, _, _) = Build(Mode.Rule);
        var metadata = Flow("93.184.216.34");
        await tunnel.MatchAsync(metadata);

        Assert.Null(metadata.Host);
        Assert.Equal("93.184.216.34", metadata.RuleHost);
        Assert.Equal(DnsMode.Normal, metadata.DnsMode);
    }

    [Fact]
    public async Task DomainDestinationIsMirroredIntoHost()
    {
        var (tunnel, _, _, _, _) = Build(Mode.Rule);
        var metadata = Flow("www.example.com");
        await tunnel.MatchAsync(metadata);

        Assert.Equal("www.example.com", metadata.Host);
        Assert.False(metadata.DestinationIsIp);
    }

    // ── mode switching ───────────────────────────────────────────────────────

    [Fact]
    public void ModeChangesAreAppliedImmediately()
    {
        var (tunnel, _, _, _, _) = Build(Mode.Rule);
        var logged = new List<string>();
        tunnel.LogEmitted += (_, message) => logged.Add(message);

        Assert.Equal(Mode.Rule, tunnel.Mode);

        tunnel.Mode = Mode.Global;
        Assert.Equal(Mode.Global, tunnel.Mode);
        Assert.Contains("mode changed to global", logged);

        // Setting the same mode again must not emit a second event.
        tunnel.Mode = Mode.Global;
        Assert.Single(logged);
    }

    [Fact]
    public void LogsAreForwardedToSubscribers()
    {
        var (tunnel, _, _, _, _) = Build();
        var received = new List<(string Level, string Message)>();
        tunnel.LogEmitted += (level, message) => received.Add((level, message));

        tunnel.Log("warning", "something happened");

        Assert.Single(received);
        Assert.Equal("warning", received[0].Level);
        Assert.Equal("something happened", received[0].Message);
    }

    // ── connection tracking ──────────────────────────────────────────────────

    [Fact]
    public async Task HandleTcpRelaysBothDirectionsAndAccountsBytes()
    {
        var (tunnel, _, _, _, _) = Build(Mode.Direct);

        // The outbound side is an echo server on loopback.
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            var buffer = new byte[1024];
            var read = await stream.ReadAsync(buffer);
            await stream.WriteAsync(buffer.AsMemory(0, read));
        });

        var inbound = new MemoryStream();
        var payload = "hello-through-the-tunnel"u8.ToArray();
        await inbound.WriteAsync(payload);
        inbound.Position = 0;

        var metadata = Flow("127.0.0.1", (ushort)port);
        metadata.Host = "127.0.0.1";

        // DIRECT dials the real address, so point the metadata at the listener.
        await tunnel.HandleTcpAsync(inbound, metadata);

        await serverTask;

        Assert.True(tunnel.Connections.Traffic.UploadTotal > 0, "no bytes were counted on the upload path");
        Assert.True(tunnel.Connections.Traffic.DownloadTotal > 0, "no bytes were counted on the download path");
        Assert.Equal(0, tunnel.Connections.ActiveCount);

        listener.Stop();
    }

    [Fact]
    public void ConnectionsSnapshotIsEmptyAtStart()
    {
        var (tunnel, _, _, _, _) = Build();
        Assert.Empty(tunnel.Connections.Snapshot());
        Assert.Equal(0, tunnel.Connections.ActiveCount);
    }

    [Fact]
    public void TrafficTrackerTakeDeltaResetsTheWindow()
    {
        var tracker = new TrafficTracker();
        tracker.AddUpload(100);
        tracker.AddDownload(250);

        var first = tracker.TakeDelta();
        Assert.Equal(100, first.Upload);
        Assert.Equal(250, first.Download);

        var second = tracker.TakeDelta();
        Assert.Equal(0, second.Upload);
        Assert.Equal(0, second.Download);

        // Totals are cumulative and unaffected by the window reset.
        Assert.Equal(100, tracker.UploadTotal);
        Assert.Equal(250, tracker.DownloadTotal);
    }

    [Fact]
    public async Task ReplaceProxiesSwapsTheRegistry()
    {
        var (tunnel, _, rules, _, _) = Build(Mode.Rule);

        var accessor = new TunnelAccessor();
        accessor.Attach(tunnel);
        var replacement = new ProxyManager(accessor, NullLoggerFactory.Instance);
        var newRules = new FakeRuleEngine();

        tunnel.ReplaceProxies(replacement, newRules);

        Assert.Same(replacement, tunnel.Proxies);
        Assert.Same(newRules, tunnel.Rules);
        await Task.CompletedTask;
    }
}
