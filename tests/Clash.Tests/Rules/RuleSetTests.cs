using Clash.Core.Rules;
using Xunit;

namespace Clash.Tests.Rules;

public class RuleSetTests
{
    [Theory]
    [InlineData("google.com", "google.com", true)]
    [InlineData("google.com", "www.google.com", true)]
    [InlineData("google.com", "notgoogle.com", false)]
    [InlineData("+.google.com", "www.google.com", true)]
    [InlineData(".google.com", "www.google.com", true)]
    [InlineData("full:google.com", "google.com", true)]
    [InlineData("full:google.com", "www.google.com", false)]
    [InlineData("domain:google.com", "www.google.com", true)]
    [InlineData("keyword:google", "www.google.com", true)]
    [InlineData("keyword:google", "example.com", false)]
    [InlineData(@"regexp:^ads\.", "ads.example.com", true)]
    [InlineData(@"regexp:^ads\.", "cdn.example.com", false)]
    public void DomainBehaviourFollowsGeositeConventions(string entry, string host, bool expected)
    {
        var set = RuleSet.FromPayload("s", "domain", [entry]);
        var metadata = TestMetadata.Flow("1.1.1.1", host: host);

        Assert.Equal(expected, set.Match(metadata));
        Assert.Equal("domain", set.Behavior);
        Assert.False(set.ShouldResolveIp);
    }

    [Fact]
    public void DomainBehaviourCountsItsEntries()
    {
        var set = RuleSet.FromPayload("s", "domain", ["a.com", "b.com", "  ", "# comment", "c.com"]);
        Assert.Equal(3, set.Count);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.1.2.3", true)]
    [InlineData("10.0.0.0/8", "11.1.2.3", false)]
    [InlineData("IP-CIDR,10.0.0.0/8", "10.1.2.3", true)]
    [InlineData("IP-CIDR,10.0.0.0/8,PROXY", "10.1.2.3", true)]
    [InlineData("IP-CIDR6,2001:db8::/32", "2001:db8::1", true)]
    [InlineData("IP-CIDR6,2001:db8::/32", "2001:db9::1", false)]
    [InlineData("IP-SUFFIX,0.0.3.4/16", "9.9.3.4", true)]
    [InlineData("IP-SUFFIX,0.0.3.4/16", "9.9.4.4", false)]
    public void IpcidrBehaviourAcceptsBareAndClassicalEntries(string entry, string address, bool expected)
    {
        var set = RuleSet.FromPayload("s", "ipcidr", [entry]);
        var metadata = TestMetadata.Flow(address);

        Assert.Equal(expected, set.Match(metadata));
        Assert.True(set.ShouldResolveIp);
    }

    [Fact]
    public void IpcidrBehaviourIgnoresUnrelatedClassicalLines()
    {
        var set = RuleSet.FromPayload("s", "ipcidr", ["DOMAIN-SUFFIX,a.com", "10.0.0.0/8", "garbage"]);
        Assert.Equal(1, set.Count);
        Assert.True(set.Match(TestMetadata.Flow("10.1.1.1")));
    }

    [Fact]
    public void ClassicalBehaviourHoldsFullRules()
    {
        var set = RuleSet.FromPayload("s", "classical", ["DOMAIN-SUFFIX,a.com,PROXY", "NETWORK,udp,DIRECT"]);

        Assert.Equal("classical", set.Behavior);
        Assert.Equal(2, set.Count);
        Assert.False(set.ShouldResolveIp);

        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "www.a.com")));
        Assert.False(set.Match(TestMetadata.Flow("1.1.1.1", host: "b.com")));
    }

    [Fact]
    public void ClassicalBehaviourReportsResolutionNeeds()
    {
        var set = RuleSet.FromPayload("s", "classical", ["IP-CIDR,10.0.0.0/8,PROXY"]);
        Assert.True(set.ShouldResolveIp);
    }

    [Fact]
    public void ClassicalBehaviourAcceptsRulesWithoutAnAdapter()
    {
        var set = RuleSet.FromPayload("s", "classical", ["DOMAIN-SUFFIX,a.com"]);
        Assert.Equal(1, set.Count);
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "a.com")));
    }

    [Fact]
    public void FromYamlReadsThePayloadList()
    {
        const string yaml = """
            payload:
              - '+.google.com'
              - 'full:exact.com'
              - 'keyword:ads'
            """;

        var set = RuleSet.FromYaml("s", "domain", yaml);
        Assert.Equal(3, set.Count);
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "www.google.com")));
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "exact.com")));
        Assert.False(set.Match(TestMetadata.Flow("1.1.1.1", host: "www.exact.com")));
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "cdn.ads.example")));
    }

    [Fact]
    public void FromYamlReadsIpcidrPayloads()
    {
        const string yaml = """
            payload:
              - '10.0.0.0/8'
              - 'IP-CIDR,192.168.0.0/16'
            """;

        var set = RuleSet.FromYaml("s", "ipcidr", yaml);
        Assert.Equal(2, set.Count);
        Assert.True(set.Match(TestMetadata.Flow("192.168.4.4")));
        Assert.False(set.Match(TestMetadata.Flow("172.16.4.4")));
    }

    [Fact]
    public void FromYamlFallsBackToPlainText()
    {
        var set = RuleSet.FromYaml("s", "domain", "a.com\nb.com\n");
        Assert.Equal(2, set.Count);
    }

    [Fact]
    public void FromTextReadsOneEntryPerLine()
    {
        var set = RuleSet.FromText("s", "domain", "# comment\na.com\n\n  b.com  \n");
        Assert.Equal(2, set.Count);
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "x.a.com")));
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "b.com")));
    }

    [Fact]
    public void FromTextDetectsYaml()
    {
        var set = RuleSet.FromText("s", "domain", "payload:\n  - a.com\n");
        Assert.Equal(1, set.Count);
        Assert.True(set.Match(TestMetadata.Flow("1.1.1.1", host: "a.com")));
    }

    [Fact]
    public void UnknownBehaviourDefaultsToDomain()
    {
        var set = RuleSet.FromPayload("s", "whatever", ["a.com"]);
        Assert.Equal("domain", set.Behavior);
    }

    [Fact]
    public void EmptySetsMatchNothing()
    {
        var set = RuleSet.FromPayload("s", "domain", []);
        Assert.Equal(0, set.Count);
        Assert.False(set.Match(TestMetadata.Flow("1.1.1.1", host: "a.com")));
    }
}
