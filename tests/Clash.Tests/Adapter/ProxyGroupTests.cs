using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Adapter;

public class ProxyGroupTests
{
    private static ProxyGroupConfig Config(
        string type,
        string name = "G",
        int tolerance = 50,
        int interval = 300,
        bool lazy = true) => new()
        {
            Name = name,
            Type = type,
            Tolerance = tolerance,
            Interval = interval,
            Lazy = lazy,
            Url = "https://www.gstatic.com/generate_204",
        };

    private static (FakeTunnel Tunnel, FakeTunnelAccessor Accessor) Harness()
    {
        var tunnel = new FakeTunnel();
        return (tunnel, new FakeTunnelAccessor(tunnel));
    }

    private static Metadata Flow(string host = "example.com", ushort port = 443) => new()
    {
        Network = Network.Tcp,
        DestinationAddress = host,
        DestinationPort = port,
        Host = host,
    };

    // ── select ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task SelectorUsesTheChosenMember()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(Config("select"), accessor, NullLogger.Instance);
        var a = new FakeProxy("a");
        var b = new FakeProxy("b");
        group.SetMembers([a, b]);

        // Without an explicit choice the first member wins.
        await group.DialTcpAsync(Flow());
        Assert.Single(a.Dialled);
        Assert.Empty(b.Dialled);

        Assert.True(await group.SelectAsync("b"));
        Assert.Equal("b", group.SelectedName);

        await group.DialTcpAsync(Flow());
        Assert.Single(b.Dialled);
    }

    [Fact]
    public async Task SelectorRejectsAnUnknownMember()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(Config("select"), accessor, NullLogger.Instance);
        group.SetMembers([new FakeProxy("a")]);

        Assert.False(await group.SelectAsync("nope"));
        Assert.Null(group.SelectedName);
    }

    [Fact]
    public async Task SelectorFallsBackWhenTheSelectedMemberDisappears()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(Config("select"), accessor, NullLogger.Instance);
        var a = new FakeProxy("a");
        var b = new FakeProxy("b");
        group.SetMembers([a, b]);
        await group.SelectAsync("b");

        // A provider refresh removed the selected node.
        group.SetMembers([a]);

        await group.DialTcpAsync(Flow());
        Assert.Single(a.Dialled);
        Assert.Equal("a", group.SelectedName);
    }

    [Fact]
    public async Task SelectorRecordsTheChain()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(Config("select", "PROXY"), accessor, NullLogger.Instance);
        group.SetMembers([new FakeProxy("node1")]);

        var metadata = Flow();
        await group.DialTcpAsync(metadata);

        Assert.Equal(["node1"], metadata.Chain);
    }

    // ── url-test ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task UrlTestPicksTheFastestMember()
    {
        var (tunnel, accessor) = Harness();
        var tester = (FakeDelayTester)tunnel.DelayTester;
        tester.Delays["slow"] = 800;
        tester.Delays["fast"] = 120;
        tester.Delays["dead"] = 0;

        var group = new UrlTestGroup(Config("url-test"), accessor, NullLogger.Instance);
        var slow = new FakeProxy("slow");
        var fast = new FakeProxy("fast");
        var dead = new FakeProxy("dead");
        group.SetMembers([slow, fast, dead]);

        var results = await group.UrlTestAsync();

        Assert.Equal(800, results["slow"]);
        Assert.Equal(120, results["fast"]);
        Assert.Equal(0, results["dead"]);
        Assert.Equal("fast", group.SelectedName);

        await group.DialTcpAsync(Flow());
        Assert.Single(fast.Dialled);
        Assert.Empty(slow.Dialled);
    }

    [Fact]
    public async Task UrlTestHonoursToleranceToAvoidFlapping()
    {
        var (tunnel, accessor) = Harness();
        var tester = (FakeDelayTester)tunnel.DelayTester;
        tester.Delays["incumbent"] = 200;
        tester.Delays["challenger"] = 180;

        var group = new UrlTestGroup(Config("url-test", tolerance: 50), accessor, NullLogger.Instance);
        group.SetMembers([new FakeProxy("incumbent"), new FakeProxy("challenger")]);

        await group.UrlTestAsync();
        Assert.Equal("incumbent", group.SelectedName);

        // 180 is within the 50ms tolerance of 200, so the incumbent is kept.
        tester.Delays["challenger"] = 100;
        await group.UrlTestAsync();
        Assert.Equal("challenger", group.SelectedName);
    }

    [Fact]
    public async Task UrlTestMarksTheGroupDeadWhenEveryMemberFails()
    {
        var (tunnel, accessor) = Harness();
        ((FakeDelayTester)tunnel.DelayTester).DefaultDelay = 0;

        var group = new UrlTestGroup(Config("url-test"), accessor, NullLogger.Instance);
        group.SetMembers([new FakeProxy("a"), new FakeProxy("b")]);

        await group.UrlTestAsync();

        Assert.False(group.Alive);
        Assert.Null(group.SelectedName);
    }

    [Fact]
    public async Task UrlTestPushesHistoryOntoMembers()
    {
        var (tunnel, accessor) = Harness();
        ((FakeDelayTester)tunnel.DelayTester).Delays["a"] = 42;

        var group = new UrlTestGroup(Config("url-test"), accessor, NullLogger.Instance);
        var a = new FakeProxy("a");
        group.SetMembers([a]);

        await group.UrlTestAsync();

        Assert.Single(a.History);
        Assert.Equal(42, a.History[0].Delay);
        Assert.True(a.Alive);
    }

    [Fact]
    public async Task UrlTestDoesNotStartABackgroundLoopWhenLazy()
    {
        var (_, accessor) = Harness();
        var group = new UrlTestGroup(Config("url-test", lazy: true), accessor, NullLogger.Instance);
        group.SetMembers([new FakeProxy("a")]);

        group.StartHealthCheck();
        await Task.Delay(50);

        // A lazy group must not have probed on its own.
        Assert.Empty(((FakeDelayTester)((FakeTunnel)accessor.Tunnel).DelayTester).Probed);
    }

    // ── fallback ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task FallbackUsesTheFirstAliveMember()
    {
        var (tunnel, accessor) = Harness();
        var tester = (FakeDelayTester)tunnel.DelayTester;
        tester.Delays["primary"] = 0;
        tester.Delays["secondary"] = 100;

        var group = new FallbackGroup(Config("fallback"), accessor, NullLogger.Instance);
        var primary = new FakeProxy("primary");
        var secondary = new FakeProxy("secondary");
        group.SetMembers([primary, secondary]);

        await group.UrlTestAsync();
        Assert.Equal("secondary", group.SelectedName);

        await group.DialTcpAsync(Flow());
        Assert.Empty(primary.Dialled);
        Assert.Single(secondary.Dialled);
    }

    [Fact]
    public async Task FallbackReturnsToThePrimaryOnceItRecovers()
    {
        var (tunnel, accessor) = Harness();
        var tester = (FakeDelayTester)tunnel.DelayTester;
        tester.Delays["primary"] = 0;
        tester.Delays["secondary"] = 100;

        var group = new FallbackGroup(Config("fallback"), accessor, NullLogger.Instance);
        var primary = new FakeProxy("primary");
        group.SetMembers([primary, new FakeProxy("secondary")]);
        await group.UrlTestAsync();

        tester.Delays["primary"] = 50;
        await group.UrlTestAsync();

        Assert.Equal("primary", group.SelectedName);
    }

    // ── load-balance ─────────────────────────────────────────────────────────

    [Fact]
    public async Task LoadBalanceIsStablePerHostByDefault()
    {
        var (_, accessor) = Harness();
        var group = new LoadBalanceGroup(Config("load-balance"), accessor, NullLogger.Instance);
        var members = Enumerable.Range(0, 4).Select(i => new FakeProxy($"n{i}")).ToArray();
        group.SetMembers(members);

        for (var i = 0; i < 10; i++) await group.DialTcpAsync(Flow("stable.example.com"));

        // Every flow for the same host lands on exactly one node.
        Assert.Single(members, m => m.Dialled.Count > 0);
        Assert.Equal(10, members.Sum(m => m.Dialled.Count));
    }

    [Fact]
    public async Task LoadBalanceRoundRobinCyclesThroughMembers()
    {
        var (_, accessor) = Harness();
        var group = new LoadBalanceGroup(
            new ProxyGroupConfig { Name = "G", Type = "load-balance", Strategy = "round-robin", Lazy = true },
            accessor,
            NullLogger.Instance);
        var members = Enumerable.Range(0, 3).Select(i => new FakeProxy($"n{i}")).ToArray();
        group.SetMembers(members);

        for (var i = 0; i < 9; i++) await group.DialTcpAsync(Flow($"host{i}.example.com"));

        Assert.All(members, m => Assert.Equal(3, m.Dialled.Count));
    }

    // ── relay ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task RelayChainsMembersOutsideIn()
    {
        var (_, accessor) = Harness();
        var group = new RelayGroup(Config("relay"), accessor, NullLogger.Instance);

        var a = new FakeProxy("A", serverHost: "a.example.com", serverPort: 1001);
        var b = new FakeProxy("B", serverHost: "b.example.com", serverPort: 1002);
        var c = new FakeProxy("C", serverHost: "c.example.com", serverPort: 1003);
        group.SetMembers([a, b, c]);

        var metadata = Flow("target.example.com", 443);
        await group.DialTcpAsync(metadata);

        // A dials B's server with no upstream.
        Assert.Single(a.Dialled);
        Assert.Equal("b.example.com", a.Dialled[0].DestinationAddress);
        Assert.Equal(1002, a.Dialled[0].DestinationPort);
        Assert.Null(a.Upstreams[0]);

        // B dials C's server over A's stream.
        Assert.Single(b.Dialled);
        Assert.Equal("c.example.com", b.Dialled[0].DestinationAddress);
        Assert.Equal(1003, b.Dialled[0].DestinationPort);
        Assert.NotNull(b.Upstreams[0]);

        // C dials the real target over B's stream.
        Assert.Single(c.Dialled);
        Assert.Equal("target.example.com", c.Dialled[0].DestinationAddress);
        Assert.Equal(443, c.Dialled[0].DestinationPort);
        Assert.NotNull(c.Upstreams[0]);

        Assert.Equal(["A", "B", "C"], metadata.Chain);
    }

    [Fact]
    public async Task RelayWithOneMemberBehavesLikeThatMember()
    {
        var (_, accessor) = Harness();
        var group = new RelayGroup(Config("relay"), accessor, NullLogger.Instance);
        var a = new FakeProxy("A", serverHost: "a.example.com", serverPort: 1001);
        group.SetMembers([a]);

        await group.DialTcpAsync(Flow("target.example.com", 443));

        Assert.Single(a.Dialled);
        Assert.Equal("target.example.com", a.Dialled[0].DestinationAddress);
        Assert.Null(a.Upstreams[0]);
    }

    [Fact]
    public async Task RelayRejectsAMemberWithoutAServerAddress()
    {
        var (_, accessor) = Harness();
        var group = new RelayGroup(Config("relay"), accessor, NullLogger.Instance);
        var a = new FakeProxy("A", serverHost: "a.example.com", serverPort: 1001);
        var noServer = new FakeProxy("NOSERVER", serverHost: null);
        group.SetMembers([a, noServer]);

        await Assert.ThrowsAsync<ProxyCreationException>(() => group.DialTcpAsync(Flow()));
    }

    [Fact]
    public async Task EmptyGroupFailsWithAProxyNotFound()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(Config("select"), accessor, NullLogger.Instance);

        await Assert.ThrowsAsync<ProxyNotFoundException>(() => group.DialTcpAsync(Flow()));
    }

    // ── shared behaviour ─────────────────────────────────────────────────────

    [Fact]
    public async Task GroupsReportTheirTypeAndMetadata()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(
            new ProxyGroupConfig { Name = "PICK", Type = "select", Icon = "https://x/i.png", Hidden = true, Lazy = true },
            accessor,
            NullLogger.Instance);

        Assert.True(group.IsGroup);
        Assert.Equal("Selector", group.TypeName);
        Assert.Equal("PICK", group.Name);
        Assert.Equal("https://x/i.png", group.Icon);
        Assert.True(group.Hidden);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task GroupUdpSupportFollowsItsMembers()
    {
        var (_, accessor) = Harness();
        var group = new SelectorGroup(Config("select"), accessor, NullLogger.Instance);
        Assert.False(group.SupportUdp);

        group.SetMembers([new FakeProxy("udp-capable")]);
        Assert.True(group.SupportUdp);

        var noUdp = new SelectorGroup(
            new ProxyGroupConfig { Name = "G2", Type = "select", DisableUdp = true, Lazy = true },
            accessor,
            NullLogger.Instance);
        noUdp.SetMembers([new FakeProxy("udp-capable")]);
        Assert.False(noUdp.SupportUdp);
        await Task.CompletedTask;
    }

    [Fact]
    public void UnsupportedGroupTypeIsRejected()
    {
        var (_, accessor) = Harness();
        Assert.Throws<ProxyCreationException>(() => new UrlTestGroup(Config("nonsense"), accessor, NullLogger.Instance));
    }
}
