using Clash.Core.Common;
using Clash.Core.Rules;
using Clash.Core.Rules.Impl;
using Xunit;

namespace Clash.Tests.Rules;

public class RuleParserTests
{
    private static readonly Func<string, IRuleSet?> NoSets = _ => null;

    [Theory]
    [InlineData("DOMAIN,example.com,PROXY", RuleType.Domain, "example.com", "PROXY")]
    [InlineData("DOMAIN-SUFFIX,example.com,PROXY", RuleType.DomainSuffix, "example.com", "PROXY")]
    [InlineData("DOMAIN-KEYWORD,google,PROXY", RuleType.DomainKeyword, "google", "PROXY")]
    [InlineData("DOMAIN-REGEX,^ads\\.example\\.com$,PROXY", RuleType.DomainRegex, "^ads\\.example\\.com$", "PROXY")]
    [InlineData("GEOSITE,cn,PROXY", RuleType.GeoSite, "cn", "PROXY")]
    [InlineData("GEOIP,CN,PROXY", RuleType.GeoIp, "CN", "PROXY")]
    [InlineData("SRC-GEOIP,CN,PROXY", RuleType.SrcGeoIp, "CN", "PROXY")]
    [InlineData("IP-CIDR,10.0.0.0/8,PROXY", RuleType.IpCidr, "10.0.0.0/8", "PROXY")]
    [InlineData("IP-CIDR6,2001:db8::/32,PROXY", RuleType.IpCidr6, "2001:db8::/32", "PROXY")]
    [InlineData("IP-SUFFIX,1.2.3.4,PROXY", RuleType.IpSuffix, "1.2.3.4", "PROXY")]
    [InlineData("IP-ASN,13335,PROXY", RuleType.IpAsn, "13335", "PROXY")]
    [InlineData("SRC-IP-ASN,13335,PROXY", RuleType.SrcIpAsn, "13335", "PROXY")]
    [InlineData("SRC-IP-CIDR,10.0.0.0/8,PROXY", RuleType.SrcIpCidr, "10.0.0.0/8", "PROXY")]
    [InlineData("SRC-PORT,80,PROXY", RuleType.SrcPort, "80", "PROXY")]
    [InlineData("DST-PORT,443,PROXY", RuleType.DstPort, "443", "PROXY")]
    [InlineData("IN-PORT,7890,PROXY", RuleType.InPort, "7890", "PROXY")]
    [InlineData("IN-TYPE,http,PROXY", RuleType.InType, "http", "PROXY")]
    [InlineData("IN-USER,alice,PROXY", RuleType.InUser, "alice", "PROXY")]
    [InlineData("IN-NAME,inbound-1,PROXY", RuleType.InName, "inbound-1", "PROXY")]
    [InlineData("PROCESS-NAME,chrome.exe,PROXY", RuleType.ProcessName, "chrome.exe", "PROXY")]
    [InlineData("PROCESS-NAME-REGEX,^chrome,PROXY", RuleType.ProcessNameRegex, "^chrome", "PROXY")]
    [InlineData("PROCESS-PATH,/usr/bin/curl,PROXY", RuleType.ProcessPath, "/usr/bin/curl", "PROXY")]
    [InlineData("PROCESS-PATH-REGEX,^/usr/bin/,PROXY", RuleType.ProcessPathRegex, "^/usr/bin/", "PROXY")]
    [InlineData("UID,1000,PROXY", RuleType.Uid, "1000", "PROXY")]
    [InlineData("NETWORK,tcp,PROXY", RuleType.Network, "tcp", "PROXY")]
    [InlineData("DSCP,4,PROXY", RuleType.Dscp, "4", "PROXY")]
    [InlineData("MATCH,PROXY", RuleType.Match, "", "PROXY")]
    public void ParsesEveryRuleType(string line, RuleType type, string payload, string adapter)
    {
        var rule = RuleParser.Parse(line);

        Assert.Equal(type, rule.Type);
        Assert.Equal(payload, rule.Payload);
        Assert.Equal(adapter, rule.Adapter);
        Assert.Equal(line, RuleParser.Format(rule));
        Assert.Equal(line, rule.Description);
    }

    [Fact]
    public void ParsesRuleSetThroughTheLookup()
    {
        var set = TestMetadata.Set("my-set", "domain", "example.com");
        var rule = RuleParser.Parse("RULE-SET,my-set,PROXY", name => name == "my-set" ? set : null);

        Assert.Equal(RuleType.RuleSet, rule.Type);
        Assert.Equal("my-set", rule.Payload);
        Assert.True(rule.ShouldResolveIp is false);
        Assert.Equal("RULE-SET,my-set,PROXY", RuleParser.Format(rule));
    }

    [Fact]
    public void ParsesSubRuleThroughTheLookup()
    {
        var set = TestMetadata.Set("sub-1", "classical", "DOMAIN-SUFFIX,a.com");
        var rule = RuleParser.Parse("SUB-RULE,(sub-1),PROXY", name => name == "sub-1" ? set : null);

        Assert.Equal(RuleType.SubRule, rule.Type);
        Assert.Equal("sub-1", rule.Payload);
        Assert.Equal("SUB-RULE,(sub-1),PROXY", RuleParser.Format(rule));
    }

    [Fact]
    public void RuleSetWithoutLookupThrows()
    {
        var exception = Assert.Throws<RuleParseException>(() => RuleParser.Parse("RULE-SET,my-set,PROXY"));
        Assert.Contains("RULE-SET", exception.Message);
        Assert.Contains("my-set", exception.Message);
    }

    [Fact]
    public void RuleSetWithUnknownNameThrows()
    {
        Assert.Throws<RuleParseException>(() => RuleParser.Parse("RULE-SET,missing,PROXY", NoSets));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("DOMAIN")]
    [InlineData("DOMAIN,example.com")]
    [InlineData("DOMAIN,,PROXY")]
    [InlineData("NOPE,example.com,PROXY")]
    [InlineData("IP-CIDR,not-a-cidr,PROXY")]
    [InlineData("IP-CIDR,10.0.0.0/33,PROXY")]
    [InlineData("IP-ASN,abc,PROXY")]
    [InlineData("SRC-PORT,99999,PROXY")]
    [InlineData("DOMAIN-REGEX,[unclosed,PROXY")]
    [InlineData("MATCH")]
    [InlineData("AND,,PROXY")]
    [InlineData("AND,((DOMAIN,a.com),PROXY")]
    [InlineData("NOT,((DOMAIN,a.com),(DOMAIN,b.com)),PROXY")]
    [InlineData("OR,(),PROXY")]
    public void MalformedLinesAreRejected(string line)
    {
        Assert.Throws<RuleParseException>(() => RuleParser.Parse(line));
        Assert.False(RuleParser.TryParse(line, out var rule, NoSets, out var error));
        Assert.Null(rule);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void TryParseNeverThrows()
    {
        foreach (var line in new[] { "", "   ", ",,,", "((((", "))))", "DOMAIN,,,", "NOT,((((,PROXY" })
        {
            var parsed = RuleParser.TryParse(line, out var rule, NoSets, out _);
            if (!parsed) Assert.Null(rule);
        }
    }

    [Fact]
    public void TwoArgumentTryParseOverloadWorks()
    {
        Assert.True(RuleParser.TryParse("DOMAIN,example.com,PROXY", out var rule, out var error));
        Assert.NotNull(rule);
        Assert.Null(error);
    }

    [Theory]
    [InlineData("IP-CIDR,10.0.0.0/8,PROXY", true)]
    [InlineData("IP-CIDR,10.0.0.0/8,PROXY,no-resolve", false)]
    [InlineData("IP-CIDR6,2001:db8::/32,PROXY", true)]
    [InlineData("GEOIP,CN,PROXY", true)]
    [InlineData("GEOIP,CN,PROXY,no-resolve", false)]
    [InlineData("IP-ASN,13335,PROXY", true)]
    [InlineData("IP-ASN,13335,PROXY,no-resolve", false)]
    [InlineData("IP-SUFFIX,1.2.3.4,PROXY", true)]
    [InlineData("SRC-IP-CIDR,10.0.0.0/8,PROXY", false)]
    [InlineData("SRC-GEOIP,CN,PROXY", false)]
    [InlineData("SRC-IP-ASN,13335,PROXY", false)]
    [InlineData("IP-CIDR,10.0.0.0/8,PROXY,src", false)]
    [InlineData("GEOIP,CN,PROXY,src", false)]
    [InlineData("DOMAIN,example.com,PROXY", false)]
    [InlineData("MATCH,PROXY", false)]
    public void ShouldResolveIpFollowsTheRuleFamilyAndModifiers(string line, bool expected)
        => Assert.Equal(expected, RuleParser.Parse(line).ShouldResolveIp);

    [Fact]
    public void NoResolveModifierIsExposedAndRoundTrips()
    {
        var rule = RuleParser.Parse("IP-CIDR,10.0.0.0/8,PROXY,no-resolve");
        Assert.Equal("no-resolve", rule.AdditionalPayload);
        Assert.False(rule.ShouldResolveIp);
        Assert.Equal("IP-CIDR,10.0.0.0/8,PROXY,no-resolve", RuleParser.Format(rule));
    }

    [Fact]
    public void SrcModifierRoundTrips()
    {
        var rule = RuleParser.Parse("IP-CIDR,10.0.0.0/8,PROXY,src");
        Assert.Equal("src", rule.AdditionalPayload);
        Assert.Equal("IP-CIDR,10.0.0.0/8,PROXY,src", RuleParser.Format(rule));
    }

    [Theory]
    [InlineData("DOMAIN,.Example.COM.,PROXY", "example.com")]
    [InlineData("DOMAIN-SUFFIX,.Example.COM.,PROXY", "example.com")]
    public void DomainPayloadsAreNormalised(string line, string expectedPayload)
        => Assert.Equal(expectedPayload, RuleParser.Parse(line).Payload);

    [Fact]
    public void LogicalRulesParseAndRoundTrip()
    {
        var and = RuleParser.Parse("AND,((DOMAIN-SUFFIX,a.com),(NETWORK,tcp)),PROXY");
        Assert.Equal(RuleType.And, and.Type);
        Assert.Equal("AND,((DOMAIN-SUFFIX,a.com),(NETWORK,tcp)),PROXY", RuleParser.Format(and));
        Assert.Equal(2, Assert.IsType<LogicalRule>(and).Members.Count);

        var or = RuleParser.Parse("OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-SUFFIX,b.com)),PROXY");
        Assert.Equal("OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-SUFFIX,b.com)),PROXY", RuleParser.Format(or));

        var not = RuleParser.Parse("NOT,((DOMAIN-SUFFIX,a.com)),PROXY");
        Assert.Equal("NOT,((DOMAIN-SUFFIX,a.com)),PROXY", RuleParser.Format(not));
    }

    [Fact]
    public void LogicalRulesNest()
    {
        const string line = "AND,((OR,((DOMAIN-SUFFIX,a.com),(DOMAIN-SUFFIX,b.com))),(NOT,((NETWORK,udp)))),PROXY";
        var rule = RuleParser.Parse(line);
        Assert.Equal(line, RuleParser.Format(rule));
    }

    [Fact]
    public void LogicalRuleResolvesWhenAnyMemberDoes()
    {
        Assert.True(RuleParser.Parse("AND,((IP-CIDR,1.1.1.1/32),(NETWORK,tcp)),PROXY").ShouldResolveIp);
        Assert.False(RuleParser.Parse("AND,((DOMAIN,a.com),(NETWORK,tcp)),PROXY").ShouldResolveIp);
        Assert.True(RuleParser.Parse("OR,((IP-CIDR,1.1.1.1/32),(NETWORK,tcp)),PROXY").ShouldResolveIp);
    }

    [Fact]
    public void NestedNoResolveModifierRoundTrips()
    {
        const string line = "AND,((IP-CIDR,1.1.1.1/32,no-resolve),(NETWORK,tcp)),PROXY";
        var rule = RuleParser.Parse(line);
        Assert.False(rule.ShouldResolveIp);
        Assert.Equal(line, RuleParser.Format(rule));
    }

    [Fact]
    public void MatchIsCaseInsensitiveForTheType()
    {
        Assert.Equal(RuleType.DomainSuffix, RuleParser.Parse("domain-suffix,example.com,PROXY").Type);
    }

    [Fact]
    public void MatchRuleHasNoPayload()
    {
        var rule = RuleParser.Parse("MATCH,DIRECT");
        Assert.Equal(string.Empty, rule.Payload);
        Assert.Equal("MATCH,DIRECT", RuleParser.Format(rule));
    }

    [Fact]
    public void GeoSiteAttributesAreKept()
    {
        var rule = Assert.IsType<GeoSiteRule>(RuleParser.Parse("GEOSITE,cn@ipcidr,PROXY"));
        Assert.Equal("CN", rule.Code);
        Assert.Equal("ipcidr", rule.Attribute);
        Assert.True(rule.ShouldResolveIp);
        Assert.Equal("GEOSITE,cn@ipcidr,PROXY", RuleParser.Format(rule));
    }

    [Fact]
    public void RuleSetNoResolveSuppressesResolution()
    {
        var set = TestMetadata.Set("ip-set", "ipcidr", "10.0.0.0/8");
        var rule = RuleParser.Parse("RULE-SET,ip-set,PROXY,no-resolve", name => name == "ip-set" ? set : null);
        Assert.False(rule.ShouldResolveIp);
    }

    [Fact]
    public void FormatFallsBackForForeignRules()
    {
        Assert.Equal("DOMAIN,example.com,PROXY", RuleParser.Format(new ForeignRule()));
    }

    private sealed class ForeignRule : IRule
    {
        public RuleType Type => RuleType.Domain;
        public string RuleTypeName => "DOMAIN";
        public string Payload => "example.com";
        public string Adapter => "PROXY";
        public bool ShouldResolveIp => false;
        public string? AdditionalPayload => null;
        public bool Match(Metadata metadata) => false;
        public string Description => "foreign";
    }
}
