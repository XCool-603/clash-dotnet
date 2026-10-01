using System.Net;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class DnsResolverTests
{
    private static DnsResolver CreateResolver(
        DnsConfig config,
        IReadOnlyDictionary<string, object?>? hosts = null,
        Dictionary<string, FakeDnsUpstream>? upstreams = null)
    {
        var map = upstreams ?? [];
        return new DnsResolver(
            config,
            hosts ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase),
            NullLogger<DnsResolver>.Instance,
            (nameserver, _, _, _) => map.TryGetValue(nameserver, out var upstream)
                ? upstream
                : new FakeDnsUpstream(query => DnsAnswers.Failure(query), $"unused://{nameserver}"));
    }

    private static Dictionary<string, object?> Hosts(params (string Key, object? Value)[] entries)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in entries) map[key] = value;
        return map;
    }

    // ── Hosts ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task HostsWinOverUpstreams()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.Hosts["example.com"] = "10.1.2.3";

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("10.1.2.3") }, addresses);
        Assert.Equal(0, primary.Calls);
    }

    [Fact]
    public async Task TopLevelHostsAreConsulted()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, Hosts(("example.com", "10.9.9.9")), new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("10.9.9.9") }, addresses);
        Assert.Equal(0, primary.Calls);
    }

    [Fact]
    public async Task DnsHostsOverrideTopLevelHosts()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.Hosts["example.com"] = "10.1.1.1";

        using var resolver = CreateResolver(config, Hosts(("example.com", "10.2.2.2")));

        Assert.Equal(new[] { IPAddress.Parse("10.1.1.1") }, resolver.ResolveHosts("example.com"));
    }

    [Fact]
    public async Task ResolveHostsNeverTouchesTheNetwork()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.Hosts["example.com"] = "10.1.2.3";

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = resolver.ResolveHosts("example.com");
        var missing = resolver.ResolveHosts("other.example.com");

        Assert.Equal(new[] { IPAddress.Parse("10.1.2.3") }, addresses);
        Assert.Empty(missing);
        Assert.Equal(0, primary.Calls);
    }

    [Fact]
    public async Task UseHostsFalseDisablesTheHostsTable()
    {
        var config = new DnsConfig { Nameserver = ["primary"], UseHosts = false };
        config.Hosts["example.com"] = "10.1.2.3";

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        Assert.Empty(resolver.ResolveHosts("example.com"));

        var addresses = await resolver.ResolveAsync("example.com");
        Assert.Equal(new[] { IPAddress.Parse("1.1.1.1") }, addresses);
    }

    [Fact]
    public async Task IpLiteralsResolveToThemselves()
    {
        using var resolver = CreateResolver(new DnsConfig());

        Assert.Equal(new[] { IPAddress.Parse("9.9.9.9") }, await resolver.ResolveAsync("9.9.9.9"));
        Assert.Equal(new[] { IPAddress.Parse("2606:4700::1") }, await resolver.ResolveAsync("2606:4700::1"));
    }

    // ── Fake IP ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task FakeIpModeAnswersWithoutTouchingTheNetwork()
    {
        var config = new DnsConfig
        {
            Nameserver = ["primary"],
            EnhancedMode = "fake-ip",
            FakeIpRange = "198.18.0.1/16",
        };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com");

        var address = Assert.Single(addresses);
        Assert.True(resolver.IsFakeIp(address));
        Assert.Equal(0, primary.Calls);
        Assert.Equal("example.com", resolver.ReverseFakeIp(address));
        Assert.Equal(address, resolver.FakeIpFor("example.com"));
    }

    [Fact]
    public async Task FlushFakeIpDropsTheMapping()
    {
        var config = new DnsConfig { EnhancedMode = "fake-ip" };
        using var resolver = CreateResolver(config);

        var address = await resolver.ResolveAsync("example.com");
        Assert.NotNull(resolver.ReverseFakeIp(address[0]));

        resolver.FlushFakeIp();

        Assert.Null(resolver.ReverseFakeIp(address[0]));
        Assert.True(resolver.IsFakeIp(address[0]));
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("localhost", true)]
    [InlineData("router", false)]
    [InlineData("1.2.3.4", false)]
    [InlineData("2606:4700::1", false)]
    [InlineData("", false)]
    public void ShouldFakeIpFollowsTheDocumentedRules(string host, bool expected)
    {
        var config = new DnsConfig { EnhancedMode = "fake-ip" };
        using var resolver = CreateResolver(config);

        Assert.Equal(expected, resolver.ShouldFakeIp(host));
    }

    [Theory]
    [InlineData("*.example.com", "a.example.com", false)]
    [InlineData("*.example.com", "example.com", true)]
    [InlineData("+.example.com", "a.example.com", false)]
    [InlineData("+.example.com", "example.com", false)]
    [InlineData("localhost.ptlogin2.qq.com", "localhost.ptlogin2.qq.com", false)]
    public void FakeIpFilterExcludesMatchingHosts(string pattern, string host, bool expected)
    {
        var config = new DnsConfig { EnhancedMode = "fake-ip", FakeIpFilter = [pattern] };
        using var resolver = CreateResolver(config);

        Assert.Equal(expected, resolver.ShouldFakeIp(host));
    }

    [Fact]
    public void GeoFilterEntriesAreIgnoredWithoutGeodata()
    {
        var config = new DnsConfig { EnhancedMode = "fake-ip", FakeIpFilter = ["geosite:cn"] };
        using var resolver = CreateResolver(config);

        Assert.True(resolver.ShouldFakeIp("example.com"));
    }

    [Fact]
    public async Task FakeIpIsOnlyUsedInFakeIpMode()
    {
        var config = new DnsConfig { Nameserver = ["primary"], EnhancedMode = "normal" };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("1.1.1.1") }, addresses);
        Assert.Equal(1, primary.Calls);
    }

    // ── Caching ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task RepeatedQueriesAreServedFromTheCache()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, 60, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        await resolver.ResolveAsync("example.com");
        await resolver.ResolveAsync("example.com");

        Assert.Equal(1, primary.Calls);
    }

    [Fact]
    public async Task FlushCacheForcesARefresh()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, 60, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        await resolver.ResolveAsync("example.com");
        resolver.FlushCache();
        await resolver.ResolveAsync("example.com");

        Assert.Equal(2, primary.Calls);
    }

    [Fact]
    public async Task ZeroTtlIsClampedUpToOneSecond()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, 0, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        await resolver.ResolveAsync("example.com");
        await resolver.ResolveAsync("example.com");

        Assert.Equal(1, primary.Calls);
    }

    [Fact]
    public async Task EmptyAnswersPopulateTheNegativeCache()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(DnsAnswers.NameError);
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        Assert.Empty(await resolver.ResolveAsync("missing.example.com"));
        Assert.Empty(await resolver.ResolveAsync("missing.example.com"));

        Assert.Equal(1, primary.Calls);
    }

    [Theory]
    [InlineData(0u, 1u)]
    [InlineData(1u, 1u)]
    [InlineData(300u, 300u)]
    [InlineData(7200u, 3600u)]
    [InlineData(uint.MaxValue, 3600u)]
    public void TtlIsClamped(uint input, uint expected)
    {
        Assert.Equal(expected, DnsResolver.ClampTtl(input));
    }

    // ── Nameserver policy ───────────────────────────────────────────────────

    [Fact]
    public void NameserverPolicyMatchesSuffixes()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.NameserverPolicy["+.corp.example"] = new List<object?> { "policy-server" };

        using var resolver = CreateResolver(config);

        Assert.Equal(new[] { "policy-server" }, resolver.SelectNameservers("corp.example").ToArray());
        Assert.Equal(new[] { "policy-server" }, resolver.SelectNameservers("a.corp.example").ToArray());
        Assert.Equal(new[] { "primary" }, resolver.SelectNameservers("example.com").ToArray());
    }

    [Fact]
    public void NameserverPolicySupportsWildcardKeysAndScalarValues()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.NameserverPolicy["*.corp.example"] = "policy-server";

        using var resolver = CreateResolver(config);

        Assert.Equal(new[] { "policy-server" }, resolver.SelectNameservers("a.corp.example").ToArray());
        Assert.Equal(new[] { "primary" }, resolver.SelectNameservers("corp.example").ToArray());
    }

    [Fact]
    public void NameserverPolicyFallsBackToDefaultNameserversWhenNameserverIsEmpty()
    {
        var config = new DnsConfig { DefaultNameserver = ["114.114.114.114"] };
        using var resolver = CreateResolver(config);

        Assert.Equal(new[] { "114.114.114.114" }, resolver.SelectNameservers("example.com").ToArray());
    }

    [Fact]
    public void GeoPolicyKeysAreIgnored()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.NameserverPolicy["geosite:cn"] = new List<object?> { "policy-server" };

        using var resolver = CreateResolver(config);

        Assert.Equal(new[] { "primary" }, resolver.SelectNameservers("example.com").ToArray());
    }

    [Fact]
    public async Task NameserverPolicyRoutesTheQuery()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.NameserverPolicy["corp.example"] = new List<object?> { "policy-server" };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        var policy = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "10.0.0.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["policy-server"] = policy });

        var addresses = await resolver.ResolveAsync("host.corp.example");

        Assert.Equal(new[] { IPAddress.Parse("10.0.0.1") }, addresses);
        Assert.Equal(0, primary.Calls);
        Assert.Equal(1, policy.Calls);
    }

    // ── fallback-filter ─────────────────────────────────────────────────────

    [Fact]
    public async Task FallbackWinsWhenThePrimaryAnswerIsInIpCidr()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Fallback = ["fallback"] };
        config.FallbackFilter = new FallbackFilterConfig { IpCidr = ["240.0.0.0/4"], GeoIpFilter = false };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "240.0.0.1"));
        var fallback = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.2.3.4"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["fallback"] = fallback });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("1.2.3.4") }, addresses);
        Assert.Equal(1, fallback.Calls);
    }

    [Fact]
    public async Task PrimaryWinsWhenItsAnswerIsClean()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Fallback = ["fallback"] };
        config.FallbackFilter = new FallbackFilterConfig { IpCidr = ["240.0.0.0/4"], GeoIpFilter = false };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        var fallback = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "9.9.9.9"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["fallback"] = fallback });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("1.1.1.1") }, addresses);
        Assert.Equal(1, fallback.Calls);
    }

    [Fact]
    public async Task FallbackCoversAPrimaryFailure()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Fallback = ["fallback"] };
        var primary = new FakeDnsUpstream(DnsAnswers.Failure);
        var fallback = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "9.9.9.9"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["fallback"] = fallback });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("9.9.9.9") }, addresses);
    }

    [Fact]
    public async Task GeoIpLookupMarksForeignAnswersAsPolluted()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Fallback = ["fallback"] };
        config.FallbackFilter = new FallbackFilterConfig { GeoIp = true, GeoIpFilter = true, GeoIpCode = "CN" };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.2.3.4"));
        var fallback = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "10.10.10.10"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["fallback"] = fallback });

        resolver.GeoIpLookup = address => address.ToString() == "1.2.3.4" ? "US" : "CN";

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("10.10.10.10") }, addresses);
    }

    [Fact]
    public async Task GeoIpLookupKeepsDomesticAnswers()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Fallback = ["fallback"] };
        config.FallbackFilter = new FallbackFilterConfig { GeoIp = true, GeoIpFilter = true, GeoIpCode = "CN" };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.2.3.4"));
        var fallback = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "10.10.10.10"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["fallback"] = fallback });

        resolver.GeoIpLookup = _ => "CN";

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Equal(new[] { IPAddress.Parse("1.2.3.4") }, addresses);
    }

    [Fact]
    public async Task FallbackFilterDomainForcesTheFallbackAnswer()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Fallback = ["fallback"] };
        config.FallbackFilter = new FallbackFilterConfig { GeoIpFilter = false, Domain = ["+.blocked.example"] };

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        var fallback = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "2.2.2.2"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary, ["fallback"] = fallback });

        var addresses = await resolver.ResolveAsync("www.blocked.example");

        Assert.Equal(new[] { IPAddress.Parse("2.2.2.2") }, addresses);
    }

    // ── IPv6 and resilience ─────────────────────────────────────────────────

    [Fact]
    public async Task Ipv6DisabledKeepsAaaaOutOfResolveAsync()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Ipv6 = false };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1", "2606:4700::1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com", ipv6: true);

        Assert.Equal(new[] { IPAddress.Parse("1.1.1.1") }, addresses);
        Assert.DoesNotContain(DnsQueryType.Aaaa, primary.QueryTypes);
    }

    [Fact]
    public async Task Ipv6EnabledQueriesBothFamilies()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Ipv6 = true };
        var primary = new FakeDnsUpstream(query => query.Questions[0].Type == DnsQueryType.A
            ? DnsAnswers.Addresses(query, "1.1.1.1")
            : DnsAnswers.Addresses(query, "2606:4700::1"));

        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com", ipv6: true);

        Assert.Contains(IPAddress.Parse("1.1.1.1"), addresses);
        Assert.Contains(IPAddress.Parse("2606:4700::1"), addresses);
    }

    [Fact]
    public async Task UpstreamFailuresNeverThrow()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(DnsAnswers.Explode);
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var addresses = await resolver.ResolveAsync("example.com");

        Assert.Empty(addresses);
    }

    [Fact]
    public async Task ResolveAsyncWithoutAnyNameserverReturnsEmpty()
    {
        var config = new DnsConfig { DefaultNameserver = [] };
        using var resolver = CreateResolver(config);

        Assert.Empty(await resolver.ResolveAsync("example.com"));
    }

    // ── ExchangeAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task ExchangeAsyncPreservesTheQueryId()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var query = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 0xABCD);
        var response = await resolver.ExchangeAsync(query);

        Assert.Equal(0xABCD, response.Id);
        Assert.True(response.IsResponse);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), Assert.Single(response.Answers).Address);
    }

    [Fact]
    public async Task ExchangeAsyncAnswersFakeIpLocally()
    {
        var config = new DnsConfig { Nameserver = ["primary"], EnhancedMode = "fake-ip" };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var response = await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 7));

        var answer = Assert.Single(response.Answers);
        Assert.True(resolver.IsFakeIp(answer.Address!));
        Assert.Equal(0, primary.Calls);
        Assert.Equal(7, response.Id);
    }

    [Fact]
    public async Task ExchangeAsyncAnswersFromHosts()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        config.Hosts["example.com"] = "10.0.0.7";

        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var response = await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 7));

        Assert.Equal(IPAddress.Parse("10.0.0.7"), Assert.Single(response.Answers).Address);
        Assert.Equal(0, primary.Calls);
    }

    [Fact]
    public async Task ExchangeAsyncDropsAaaaWhenIpv6IsDisabled()
    {
        var config = new DnsConfig { Nameserver = ["primary"], Ipv6 = false };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "2606:4700::1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var response = await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.Aaaa, 9));

        Assert.Equal(DnsResponseCode.NoError, response.ResponseCode);
        Assert.Empty(response.Answers);
        Assert.Equal(0, primary.Calls);
    }

    [Fact]
    public async Task ExchangeAsyncForwardsOtherRecordTypes()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query =>
        {
            var response = DnsCodec.CreateResponse(query, DnsResponseCode.NoError);
            response.Answers.Add(new DnsResourceRecord
            {
                Name = query.Questions[0].Name,
                Type = DnsQueryType.Txt,
                Ttl = 30,
                Data = [0x02, (byte)'h', (byte)'i'],
            });

            return response;
        });

        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var response = await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.Txt, 3));

        Assert.Equal(3, response.Id);
        Assert.Equal(DnsQueryType.Txt, Assert.Single(response.Answers).Type);
        Assert.Equal(1, primary.Calls);
    }

    [Fact]
    public async Task ExchangeAsyncReturnsServerFailureWhenEverythingFails()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(DnsAnswers.Explode);
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        var response = await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 5));

        Assert.Equal(DnsResponseCode.ServerFailure, response.ResponseCode);
        Assert.Equal(5, response.Id);
    }

    [Fact]
    public async Task ExchangeAsyncRejectsResponsesAndEmptyQuestions()
    {
        using var resolver = CreateResolver(new DnsConfig());

        var response = DnsCodec.CreateResponse(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1), DnsResponseCode.NoError);
        Assert.Equal(DnsResponseCode.FormatError, (await resolver.ExchangeAsync(response)).ResponseCode);
        Assert.Equal(DnsResponseCode.FormatError, (await resolver.ExchangeAsync(new DnsMessage { Id = 1 })).ResponseCode);
    }

    [Fact]
    public async Task ExchangeAsyncPopulatesTheCache()
    {
        var config = new DnsConfig { Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, 60, "1.1.1.1"));
        using var resolver = CreateResolver(config, null, new() { ["primary"] = primary });

        await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1));
        await resolver.ExchangeAsync(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 2));

        Assert.Equal(1, primary.Calls);
    }
}
