using System.Net;
using Clash.Core.Common;
using Clash.Core.Dns;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class DnsUpstreamsTests
{
    [Theory]
    [InlineData("1.1.1.1", typeof(UdpDnsUpstream))]
    [InlineData("tcp://1.1.1.1", typeof(TcpDnsUpstream))]
    [InlineData("tcp://1.1.1.1:5353", typeof(TcpDnsUpstream))]
    [InlineData("tls://1.1.1.1", typeof(TlsDnsUpstream))]
    [InlineData("https://1.1.1.1/dns-query", typeof(HttpsDnsUpstream))]
    [InlineData("h3://1.1.1.1/dns-query", typeof(HttpsDnsUpstream))]
    [InlineData("quic://1.1.1.1", typeof(TlsDnsUpstream))]
    [InlineData("dhcp://en0", typeof(DhcpDnsUpstream))]
    [InlineData("hosts://", typeof(SystemHostsDnsUpstream))]
    public void CreatePicksTheTransportForEachScheme(string nameserver, Type expected)
    {
        using var upstream = DnsUpstreams.Create(nameserver);

        Assert.IsType(expected, upstream);
    }

    [Fact]
    public void DomainNameserversAreWrappedInABootstrapUpstream()
    {
        using var upstream = DnsUpstreams.Create("tls://dns.google");

        var bootstrap = Assert.IsType<BootstrapDnsUpstream>(upstream);
        Assert.Equal("dns.google", bootstrap.Host);
        Assert.False(bootstrap.IsReady);
    }

    [Fact]
    public void H3PathsAreNormalisedOffTheHost()
    {
        using var upstream = DnsUpstreams.Create("h3://1.1.1.1/dns-query");

        var doh = Assert.IsType<HttpsDnsUpstream>(upstream);
        Assert.Equal("1.1.1.1", doh.Hostname);
        Assert.Equal("/dns-query", doh.Uri.AbsolutePath);
    }

    [Fact]
    public void HttpsKeepsItsConfiguredPath()
    {
        using var upstream = DnsUpstreams.Create("https://1.1.1.1/custom-query");

        var doh = Assert.IsType<HttpsDnsUpstream>(upstream);
        Assert.Equal("/custom-query", doh.Uri.AbsolutePath);
    }

    [Fact]
    public void HttpsWithoutAPathUsesTheDefault()
    {
        using var upstream = DnsUpstreams.Create("https://1.1.1.1");

        var doh = Assert.IsType<HttpsDnsUpstream>(upstream);
        Assert.Equal(DnsUpstreams.DefaultDohPath, doh.Uri.AbsolutePath);
    }

    [Fact]
    public void EmptyNameserverIsRejected()
    {
        Assert.Throws<DnsException>(() => DnsUpstreams.Create("   "));
    }

    [Fact]
    public void NameserverWithoutAHostIsRejected()
    {
        Assert.Throws<DnsException>(() => DnsUpstreams.Create("tls://"));
    }

    [Fact]
    public void BootstrapListDoesNotChangeAnIpLiteralNameserver()
    {
        using var upstream = DnsUpstreams.Create("1.1.1.1", ["8.8.8.8", "1.0.0.1"], ipv6: false, bootstrapResolver: null);

        Assert.IsType<UdpDnsUpstream>(upstream);
    }

    [Fact]
    public void BootstrapListIgnoresDomainValuedEntries()
    {
        // "dns.google" cannot bootstrap itself, so it is skipped and the
        // upstream stays lazy until it is first used.
        using var upstream = DnsUpstreams.Create("tls://example.invalid", ["dns.google"], ipv6: false, bootstrapResolver: null);

        Assert.IsType<BootstrapDnsUpstream>(upstream);
    }

    [Fact]
    public async Task QueryAsyncCollectsAddressAnswers()
    {
        var upstream = new FakeDnsUpstream(query => query.Questions[0].Type == DnsQueryType.A
            ? DnsAnswers.Addresses(query, "1.2.3.4", "5.6.7.8")
            : DnsAnswers.Addresses(query, "2606:4700::1"));

        var addresses = await DnsUpstreams.QueryAsync(upstream, "example.com", ipv6: true, CancellationToken.None);

        Assert.Equal(3, addresses.Length);
        Assert.Contains(IPAddress.Parse("1.2.3.4"), addresses);
        Assert.Contains(IPAddress.Parse("2606:4700::1"), addresses);
        Assert.Equal(new List<DnsQueryType> { DnsQueryType.A, DnsQueryType.Aaaa }, upstream.QueryTypes);
    }

    [Fact]
    public async Task QueryAsyncSkipsAaaaWhenIpv6IsOff()
    {
        var upstream = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.2.3.4"));

        var addresses = await DnsUpstreams.QueryAsync(upstream, "example.com", ipv6: false, CancellationToken.None);

        Assert.Equal(new[] { IPAddress.Parse("1.2.3.4") }, addresses);
        Assert.Equal(new List<DnsQueryType> { DnsQueryType.A }, upstream.QueryTypes);
    }

    [Fact]
    public async Task BootstrapUpstreamResolvesTheHostOnceAndDelegates()
    {
        IPAddress? dialled = null;
        var inner = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "9.9.9.9"));
        var resolutions = 0;

        using var upstream = new BootstrapDnsUpstream(
            "dns.example",
            address =>
            {
                dialled = address;
                return inner;
            },
            (_, _) =>
            {
                resolutions++;
                return Task.FromResult(new[] { IPAddress.Parse("8.8.8.8") });
            });

        var query = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 0x1234);
        var first = await upstream.ExchangeAsync(query, CancellationToken.None);
        var second = await upstream.ExchangeAsync(query, CancellationToken.None);

        Assert.Equal(IPAddress.Parse("8.8.8.8"), dialled);
        Assert.True(upstream.IsReady);
        Assert.Equal(1, resolutions);
        Assert.Equal(0x1234, first.Id);
        Assert.Equal(2, inner.Calls);
        Assert.Equal(IPAddress.Parse("9.9.9.9"), Assert.Single(second.Answers).Address);
    }

    [Fact]
    public async Task BootstrapUpstreamFailsWhenNothingResolves()
    {
        using var upstream = new BootstrapDnsUpstream(
            "dns.example",
            _ => new FakeDnsUpstream(query => DnsAnswers.Empty(query)),
            (_, _) => Task.FromResult(Array.Empty<IPAddress>()));

        var error = await Assert.ThrowsAsync<DnsException>(
            () => upstream.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1), CancellationToken.None));

        Assert.Contains("bootstrap", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BootstrapUpstreamWrapsResolverFailures()
    {
        using var upstream = new BootstrapDnsUpstream(
            "dns.example",
            _ => new FakeDnsUpstream(query => DnsAnswers.Empty(query)),
            (_, _) => throw new DnsException("no bootstrap servers"));

        var error = await Assert.ThrowsAsync<DnsException>(
            () => upstream.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1), CancellationToken.None));

        Assert.Contains("no bootstrap servers", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HostsUpstreamAnswersFromTheHostsTable()
    {
        using var upstream = new SystemHostsDnsUpstream(useSystemHosts: false);

        Assert.Equal("hosts://", upstream.Name);
    }

    [Fact]
    public void SystemDnsServersAreReadable()
    {
        // Reading adapter configuration is not network I/O and must never throw.
        var servers = DhcpDnsUpstream.GetSystemDnsServers(ipv6: false);

        Assert.NotNull(servers);
    }

    [Fact]
    public void UpstreamNamesDescribeTheEndpoint()
    {
        using var udp = DnsUpstreams.Create("1.1.1.1");
        using var tcp = DnsUpstreams.Create("tcp://1.1.1.1:5353");
        using var tls = DnsUpstreams.Create("tls://[2606:4700:4700::1111]:853");

        Assert.Equal("udp://1.1.1.1:53", udp.Name);
        Assert.Equal("tcp://1.1.1.1:5353", tcp.Name);
        Assert.Equal("tls://[2606:4700:4700::1111]:853", tls.Name);
    }
}
