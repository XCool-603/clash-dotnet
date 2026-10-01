using System.Net;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Rules;
using Xunit;

namespace Clash.Tests.Rules;

public class RuleEngineTests
{
    private static RuleEngine Engine(
        IEnumerable<string> lines,
        FakeDnsResolver? dns = null,
        IGeoData? geo = null,
        IReadOnlyDictionary<string, IRuleSet>? sets = null)
    {
        var lookup = RuleEngine.BuildLookup(sets);
        var rules = lines.Select(l => RuleParser.Parse(l, lookup)).ToList();
        return new RuleEngine(dns ?? new FakeDnsResolver(), geo ?? GeoData.Empty, rules, sets);
    }

    [Fact]
    public async Task FirstMatchWins()
    {
        var engine = Engine(["DOMAIN-SUFFIX,a.com,DIRECT", "DOMAIN-SUFFIX,a.com,PROXY", "MATCH,REJECT"]);

        var match = await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "www.a.com"));

        Assert.NotNull(match);
        Assert.Equal("DIRECT", match!.AdapterName);
        Assert.Equal(0, match.Index);
        Assert.Equal("DOMAIN-SUFFIX", match.Rule.RuleTypeName);
    }

    [Fact]
    public async Task FallsBackToTheMatchRule()
    {
        var engine = Engine(["DOMAIN-SUFFIX,a.com,DIRECT", "MATCH,PROXY"]);

        var match = await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "b.com"));

        Assert.NotNull(match);
        Assert.Equal("PROXY", match!.AdapterName);
        Assert.Equal(RuleType.Match, match.Rule.Type);
        Assert.Equal(1, match.Index);
    }

    [Fact]
    public async Task FallsBackToDirectWhenNoMatchRuleExists()
    {
        var engine = Engine(["DOMAIN-SUFFIX,a.com,DIRECT"]);

        var match = await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "b.com"));

        Assert.NotNull(match);
        Assert.Equal(WellKnown.Direct, match!.AdapterName);
        Assert.Equal(-1, match.Index);
    }

    [Fact]
    public async Task SpecialProxyShortCircuitsEverything()
    {
        var dns = new FakeDnsResolver();
        var engine = Engine(["MATCH,PROXY"], dns);

        var metadata = TestMetadata.Flow("1.1.1.1", host: "b.com");
        metadata.SpecialProxy = "SPECIAL";

        var match = await engine.MatchAsync(metadata);

        Assert.NotNull(match);
        Assert.Equal("SPECIAL", match!.AdapterName);
        Assert.Equal(-1, match.Index);
        Assert.Equal(0, dns.Calls);
    }

    [Fact]
    public async Task SpecialRulesAreEvaluatedBeforeTheConfiguredList()
    {
        var engine = Engine(["MATCH,PROXY"]);

        var metadata = TestMetadata.Flow("1.1.1.1", host: "b.com");
        metadata.SpecialRules.Add("DOMAIN-SUFFIX,b.com,SPECIAL");
        metadata.SpecialRules.Add("not-a-rule");

        var match = await engine.MatchAsync(metadata);

        Assert.NotNull(match);
        Assert.Equal("SPECIAL", match!.AdapterName);
    }

    [Fact]
    public async Task DisabledRulesAreSkippedAndCanBeReEnabled()
    {
        var engine = Engine(["DOMAIN-SUFFIX,disabled-probe.example,DIRECT", "MATCH,PROXY"]);

        try
        {
            Assert.True(engine.Disable("DOMAIN-SUFFIX", "disabled-probe.example"));
            Assert.True(engine.IsDisabled("DOMAIN-SUFFIX", "disabled-probe.example"));
            Assert.True(engine.IsDisabled("domain-suffix", "DISABLED-PROBE.EXAMPLE"));

            var skipped = await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "a.disabled-probe.example"));
            Assert.NotNull(skipped);
            Assert.Equal("PROXY", skipped!.AdapterName);
        }
        finally
        {
            Assert.True(engine.Enable("DOMAIN-SUFFIX", "disabled-probe.example"));
        }

        Assert.False(engine.IsDisabled("DOMAIN-SUFFIX", "disabled-probe.example"));

        var matched = await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "a.disabled-probe.example"));
        Assert.NotNull(matched);
        Assert.Equal("DIRECT", matched!.AdapterName);
    }

    [Fact]
    public async Task NoResolveSkipsTheLookup()
    {
        var dns = new FakeDnsResolver().Answer("example.com", "1.1.1.1");
        var engine = Engine(["IP-CIDR,1.1.1.1/32,PROXY,no-resolve", "MATCH,DIRECT"], dns);

        var match = await engine.MatchAsync(TestMetadata.Flow("example.com"));

        Assert.NotNull(match);
        Assert.Equal("DIRECT", match!.AdapterName);
        Assert.Equal(0, dns.Calls);
    }

    [Fact]
    public async Task ResolvedAddressesAreCachedAcrossRules()
    {
        var dns = new FakeDnsResolver().Answer("example.com", "2.2.2.2");
        var engine = Engine(["IP-CIDR,1.1.1.1/32,DIRECT", "IP-CIDR,2.2.2.2/32,PROXY", "MATCH,REJECT"], dns);

        var match = await engine.MatchAsync(TestMetadata.Flow("example.com"));

        Assert.NotNull(match);
        Assert.Equal("PROXY", match!.AdapterName);
        Assert.Equal(1, dns.Calls);
    }

    [Fact]
    public async Task ResolutionHappensOncePerFlowEvenWithSeveralIpRules()
    {
        var dns = new FakeDnsResolver().Answer("example.com", "9.9.9.9");
        var engine = Engine(["IP-CIDR,1.1.1.1/32,DIRECT", "IP-CIDR,2.2.2.2/32,DIRECT", "MATCH,REJECT"], dns);

        var match = await engine.MatchAsync(TestMetadata.Flow("example.com"));

        Assert.Equal("REJECT", match!.AdapterName);
        Assert.Equal(1, dns.Calls);
    }

    [Fact]
    public async Task ResolutionFailureIsNotFatal()
    {
        var dns = new FakeDnsResolver { Fail = true };
        var engine = Engine(["IP-CIDR,1.1.1.1/32,PROXY", "MATCH,DIRECT"], dns);

        var match = await engine.MatchAsync(TestMetadata.Flow("example.com"));

        Assert.NotNull(match);
        Assert.Equal("DIRECT", match!.AdapterName);
    }

    [Fact]
    public async Task EmptyResolutionIsNotFatal()
    {
        var engine = Engine(["GEOIP,CN,PROXY", "MATCH,DIRECT"], new FakeDnsResolver());

        var match = await engine.MatchAsync(TestMetadata.Flow("unknown.example"));

        Assert.Equal("DIRECT", match!.AdapterName);
    }

    [Fact]
    public async Task LiteralDestinationsNeedNoLookup()
    {
        var dns = new FakeDnsResolver();
        var engine = Engine(["IP-CIDR,10.0.0.0/8,PROXY", "MATCH,DIRECT"], dns);

        var match = await engine.MatchAsync(TestMetadata.Flow("10.1.2.3"));

        Assert.Equal("PROXY", match!.AdapterName);
        Assert.Equal(0, dns.Calls);
    }

    [Fact]
    public async Task SourceRulesUseTheClientAddress()
    {
        var dns = new FakeDnsResolver();
        var engine = Engine(["SRC-IP-CIDR,192.168.1.0/24,PROXY", "MATCH,DIRECT"], dns);

        var metadata = TestMetadata.Flow("example.com");
        var match = await engine.MatchAsync(metadata);

        Assert.Equal("PROXY", match!.AdapterName);
        Assert.Equal(0, dns.Calls);

        var other = TestMetadata.Flow("example.com");
        other.SourceAddress = "8.8.8.8";
        Assert.Equal("DIRECT", (await engine.MatchAsync(other))!.AdapterName);
    }

    [Fact]
    public async Task SrcModifierSwitchesAnIpRuleToTheSource()
    {
        var dns = new FakeDnsResolver();
        var engine = Engine(["IP-CIDR,192.168.1.0/24,PROXY,src", "MATCH,DIRECT"], dns);

        var match = await engine.MatchAsync(TestMetadata.Flow("example.com"));

        Assert.Equal("PROXY", match!.AdapterName);
        Assert.Equal(0, dns.Calls);
    }

    [Fact]
    public async Task PortRulesUseTheRightField()
    {
        var engine = Engine(["SRC-PORT,51234,PROXY", "MATCH,DIRECT"]);
        Assert.Equal("PROXY", (await engine.MatchAsync(TestMetadata.Flow("1.1.1.1")))!.AdapterName);

        var destination = Engine(["DST-PORT,443,PROXY", "MATCH,DIRECT"]);
        Assert.Equal("PROXY", (await destination.MatchAsync(TestMetadata.Flow("1.1.1.1")))!.AdapterName);

        var inbound = Engine(["IN-PORT,7890,PROXY", "MATCH,DIRECT"]);
        Assert.Equal("PROXY", (await inbound.MatchAsync(TestMetadata.Flow("1.1.1.1")))!.AdapterName);
    }

    [Fact]
    public async Task LogicalRulesMatchThroughTheEngine()
    {
        var dns = new FakeDnsResolver().Answer("example.com", "1.1.1.1");

        var and = Engine(["AND,((DOMAIN-SUFFIX,example.com),(NETWORK,tcp)),PROXY", "MATCH,DIRECT"], dns);
        Assert.Equal("PROXY", (await and.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);

        var andFails = Engine(["AND,((DOMAIN-SUFFIX,example.com),(NETWORK,udp)),PROXY", "MATCH,DIRECT"], dns);
        Assert.Equal("DIRECT", (await andFails.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);

        var or = Engine(["OR,((DOMAIN-SUFFIX,other.com),(NETWORK,tcp)),PROXY", "MATCH,DIRECT"], dns);
        Assert.Equal("PROXY", (await or.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);

        var not = Engine(["NOT,((DOMAIN-SUFFIX,example.com)),PROXY", "MATCH,DIRECT"], dns);
        Assert.Equal("DIRECT", (await not.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);
        Assert.Equal("PROXY", (await not.MatchAsync(TestMetadata.Flow("other.com")))!.AdapterName);
    }

    [Fact]
    public async Task GeoRulesUseTheInjectedDatabase()
    {
        var dns = new FakeDnsResolver().Answer("example.com", "1.1.1.1");
        var geo = new FakeGeoData().Country("1.1.1.1", "CN").Asn("1.1.1.1", 13335);

        var country = Engine(["GEOIP,CN,PROXY", "MATCH,DIRECT"], dns, geo);
        Assert.Equal("PROXY", (await country.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);

        var asn = Engine(["IP-ASN,13335,PROXY", "MATCH,DIRECT"], dns, geo);
        Assert.Equal("PROXY", (await asn.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);

        var source = Engine(["SRC-GEOIP,CN,PROXY", "MATCH,DIRECT"], dns, geo);
        Assert.Equal("DIRECT", (await source.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);
    }

    [Fact]
    public async Task GeoSiteRulesUseTheInjectedDatabase()
    {
        var geo = new FakeGeoData().Site("CN", "google.com");
        var engine = Engine(["GEOSITE,CN,PROXY", "MATCH,DIRECT"], null, geo);

        Assert.Equal("PROXY", (await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "www.google.com")))!.AdapterName);
        Assert.Equal("DIRECT", (await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "example.com")))!.AdapterName);
    }

    [Fact]
    public async Task RuleSetRulesDelegateToTheProvider()
    {
        var sets = new Dictionary<string, IRuleSet>(StringComparer.OrdinalIgnoreCase)
        {
            ["domains"] = RuleSet.FromPayload("domains", "domain", ["a.com"]),
            ["nets"] = RuleSet.FromPayload("nets", "ipcidr", ["10.0.0.0/8"]),
        };

        var engine = Engine(["RULE-SET,domains,PROXY", "RULE-SET,nets,DIRECT", "MATCH,REJECT"], sets: sets);

        Assert.Equal("PROXY", (await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "x.a.com")))!.AdapterName);
        Assert.Equal("DIRECT", (await engine.MatchAsync(TestMetadata.Flow("10.1.1.1")))!.AdapterName);
        Assert.Equal("REJECT", (await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "b.com")))!.AdapterName);
    }

    [Fact]
    public async Task RuleSetHonoursNoResolve()
    {
        var dns = new FakeDnsResolver().Answer("example.com", "10.1.1.1");
        var sets = new Dictionary<string, IRuleSet>(StringComparer.OrdinalIgnoreCase)
        {
            ["nets"] = RuleSet.FromPayload("nets", "ipcidr", ["10.0.0.0/8"]),
        };

        var engine = Engine(["RULE-SET,nets,PROXY,no-resolve", "MATCH,DIRECT"], dns, sets: sets);

        Assert.Equal("DIRECT", (await engine.MatchAsync(TestMetadata.Flow("example.com")))!.AdapterName);
        Assert.Equal(0, dns.Calls);
    }

    [Fact]
    public async Task SetRulesCarryTheirIndex()
    {
        var engine = Engine(["DOMAIN-SUFFIX,zzz.example,DIRECT", "MATCH,PROXY"]);

        var match = await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "a.zzz.example"));

        Assert.Equal(0, match!.Index);
    }

    [Fact]
    public void SetRulesReplacesTheList()
    {
        var engine = Engine(["MATCH,DIRECT"]);
        Assert.Single(engine.Rules);

        engine.SetRules([RuleParser.Parse("MATCH,PROXY"), RuleParser.Parse("DOMAIN,a.com,DIRECT")]);
        Assert.Equal(2, engine.Rules.Count);
    }

    [Fact]
    public void BuildFromConfigExpandsSubRulesInline()
    {
        var config = new ClashConfig
        {
            Rules = ["SUB-RULE,(sub-a),PROXY", "MATCH,DIRECT"],
        };
        config.SubRules["sub-a"] = ["DOMAIN-SUFFIX,a.com", "DOMAIN-SUFFIX,b.com"];

        var rules = RuleEngine.BuildFromConfig(config, new Dictionary<string, IRuleSet>());

        Assert.Equal(3, rules.Count);
        Assert.Equal("DOMAIN-SUFFIX", rules[0].RuleTypeName);
        Assert.Equal("a.com", rules[0].Payload);
        Assert.Equal("PROXY", rules[0].Adapter);
        Assert.Equal("b.com", rules[1].Payload);
        Assert.Equal(RuleType.Match, rules[2].Type);
    }

    [Fact]
    public void BuildFromConfigExpandsNestedSubRules()
    {
        var config = new ClashConfig { Rules = ["SUB-RULE,(outer),PROXY"] };
        config.SubRules["outer"] = ["SUB-RULE,(inner),DIRECT"];
        config.SubRules["inner"] = ["DOMAIN,a.com"];

        var rules = RuleEngine.BuildFromConfig(config, new Dictionary<string, IRuleSet>());

        Assert.Single(rules);
        Assert.Equal("a.com", rules[0].Payload);
        Assert.Equal("DIRECT", rules[0].Adapter);
    }

    [Fact]
    public void BuildFromConfigResolvesRuleSets()
    {
        var sets = new Dictionary<string, IRuleSet>(StringComparer.OrdinalIgnoreCase)
        {
            ["domains"] = RuleSet.FromPayload("domains", "domain", ["a.com"]),
        };
        var config = new ClashConfig { Rules = ["RULE-SET,domains,PROXY", "MATCH,DIRECT"] };

        var rules = RuleEngine.BuildFromConfig(config, sets);

        Assert.Equal(2, rules.Count);
        Assert.Equal(RuleType.RuleSet, rules[0].Type);
    }

    [Fact]
    public void BuildFromConfigSkipsCommentsAndBlankLines()
    {
        var config = new ClashConfig { Rules = ["# a comment", "  ", "MATCH,DIRECT"] };

        var rules = RuleEngine.BuildFromConfig(config, new Dictionary<string, IRuleSet>());

        Assert.Single(rules);
    }

    [Fact]
    public void BuildFromConfigThrowsOnUnknownRuleSet()
    {
        var config = new ClashConfig { Rules = ["RULE-SET,missing,PROXY"] };

        Assert.Throws<RuleParseException>(() => RuleEngine.BuildFromConfig(config, new Dictionary<string, IRuleSet>()));
    }

    [Fact]
    public void BuildFromConfigThrowsOnMalformedRule()
    {
        var config = new ClashConfig { Rules = ["DOMAIN"] };

        Assert.Throws<RuleParseException>(() => RuleEngine.BuildFromConfig(config, new Dictionary<string, IRuleSet>()));
    }

    [Fact]
    public void BuildFromConfigGuardsAgainstCycles()
    {
        var config = new ClashConfig { Rules = ["SUB-RULE,(a),PROXY"] };
        config.SubRules["a"] = ["SUB-RULE,(b),PROXY"];
        config.SubRules["b"] = ["SUB-RULE,(a),PROXY"];

        Assert.Throws<RuleParseException>(() => RuleEngine.BuildFromConfig(config, new Dictionary<string, IRuleSet>()));
    }

    [Fact]
    public async Task EngineInjectsGeoIntoRuleSets()
    {
        var geo = new FakeGeoData().Site("CN", "google.com");
        var sets = new Dictionary<string, IRuleSet>(StringComparer.OrdinalIgnoreCase)
        {
            ["mixed"] = RuleSet.FromPayload("mixed", "classical", ["GEOSITE,CN,DIRECT"]),
        };

        var engine = Engine(["RULE-SET,mixed,PROXY", "MATCH,REJECT"], null, geo, sets);

        Assert.Equal("PROXY", (await engine.MatchAsync(TestMetadata.Flow("1.1.1.1", host: "www.google.com")))!.AdapterName);
    }

    [Fact]
    public async Task MatchAsyncRejectsNullMetadata()
    {
        var engine = Engine(["MATCH,DIRECT"]);
        await Assert.ThrowsAsync<ArgumentNullException>(() => engine.MatchAsync(null!));
    }

    [Fact]
    public void EngineRejectsNullDependencies()
    {
        Assert.Throws<ArgumentNullException>(() => new RuleEngine(null!, GeoData.Empty));
        Assert.Throws<ArgumentNullException>(() => new RuleEngine(new FakeDnsResolver(), null!));
    }
}
