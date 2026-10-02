using System.Net;
using Clash.Core.Rules;
using Xunit;

namespace Clash.Tests.Rules;

public class CidrMatcherTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.0", true)]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "10.1.2.3", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("10.0.0.0/8", "9.255.255.255", false)]
    [InlineData("192.168.1.0/24", "192.168.1.0", true)]
    [InlineData("192.168.1.0/24", "192.168.1.255", true)]
    [InlineData("192.168.1.0/24", "192.168.2.0", false)]
    [InlineData("192.168.1.0/24", "192.168.0.255", false)]
    [InlineData("192.168.1.5/32", "192.168.1.5", true)]
    [InlineData("192.168.1.5/32", "192.168.1.6", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("1.2.3.4/31", "1.2.3.5", true)]
    [InlineData("1.2.3.4/31", "1.2.3.6", false)]
    [InlineData("1.2.3.4/30", "1.2.3.7", true)]
    [InlineData("1.2.3.4/30", "1.2.3.8", false)]
    [InlineData("2001:db8::/32", "2001:db8::1", true)]
    [InlineData("2001:db8::/32", "2001:db8:ffff:ffff::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("::1/128", "::1", true)]
    [InlineData("::1/128", "::2", false)]
    [InlineData("fe80::/10", "fe80::1", true)]
    [InlineData("fe80::/10", "fec0::1", false)]
    public void PrefixesMatchTheirRange(string cidr, string address, bool expected)
    {
        Assert.True(IpPrefix.TryParse(cidr, out var prefix));
        Assert.Equal(expected, prefix.Contains(IPAddress.Parse(address)));
    }

    [Fact]
    public void HostBitsAreClearedOnParse()
    {
        Assert.True(IpPrefix.TryParse("192.168.1.5/24", out var prefix));
        Assert.Equal("192.168.1.0", prefix.Network.ToString());
        Assert.Equal(24, prefix.PrefixLength);
        Assert.True(prefix.Contains(IPAddress.Parse("192.168.1.200")));
    }

    [Fact]
    public void BareAddressBecomesAHostRoute()
    {
        Assert.True(IpPrefix.TryParse("1.2.3.4", out var v4));
        Assert.Equal(32, v4.PrefixLength);
        Assert.Equal("1.2.3.4", v4.Network.ToString());

        Assert.True(IpPrefix.TryParse("2001:db8::1", out var v6));
        Assert.Equal(128, v6.PrefixLength);
    }

    [Theory]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("2001:db8::/129")]
    [InlineData("not-an-address")]
    [InlineData("10.0.0.0/abc")]
    [InlineData("")]
    public void InvalidPrefixesAreRejected(string text)
        => Assert.False(IpPrefix.TryParse(text, out _));

    [Fact]
    public void FamiliesDoNotCrossMatch()
    {
        Assert.True(IpPrefix.TryParse("10.0.0.0/8", out var v4));
        Assert.False(v4.Contains(IPAddress.Parse("2001:db8::1")));

        // Sockets hand IPv4 peers back as IPv4-mapped IPv6, so those are normalised to IPv4.
        Assert.True(v4.Contains(IPAddress.Parse("::ffff:10.0.0.1")));

        Assert.True(IpPrefix.TryParse("::/0", out var v6));
        Assert.False(v6.Contains(IPAddress.Parse("10.0.0.1")));
    }

    [Fact]
    public void MatcherReturnsTheLongestPrefix()
    {
        var matcher = new CidrMatcher();
        Assert.True(IpPrefix.TryParse("10.0.0.0/8", out var wide));
        Assert.True(IpPrefix.TryParse("10.1.0.0/16", out var narrow));
        matcher.Add(wide, 1);
        matcher.Add(narrow, 2);

        Assert.Equal(2, matcher.Match(IPAddress.Parse("10.1.2.3")));
        Assert.Equal(1, matcher.Match(IPAddress.Parse("10.2.2.3")));
        Assert.Equal(-1, matcher.Match(IPAddress.Parse("11.2.2.3")));
    }

    [Fact]
    public void EmptyMatcherNeverMatches()
    {
        var matcher = new CidrMatcher();
        Assert.True(matcher.IsEmpty);
        Assert.Equal(-1, matcher.Match(IPAddress.Parse("10.0.0.1")));
    }

    [Fact]
    public void DefaultRouteMatchesEverything()
    {
        var matcher = new CidrMatcher();
        Assert.True(IpPrefix.TryParse("0.0.0.0/0", out var any));
        matcher.Add(any, 9);

        Assert.Equal(9, matcher.Match(IPAddress.Parse("1.2.3.4")));
        Assert.Equal(-1, matcher.Match(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void SuffixEntriesMatchTrailingBits()
    {
        var matcher = new CidrMatcher();
        Assert.True(IpSuffix.TryParse("1.2.3.4", out var full));
        Assert.True(IpSuffix.TryParse("0.0.3.4/16", out var tail));
        matcher.AddSuffix(full, 1);
        matcher.AddSuffix(tail, 2);

        Assert.Equal(1, matcher.Match(IPAddress.Parse("1.2.3.4")));
        Assert.Equal(2, matcher.Match(IPAddress.Parse("9.9.3.4")));
        Assert.Equal(-1, matcher.Match(IPAddress.Parse("9.9.3.5")));
    }

    [Fact]
    public void PrefixEntriesWinOverSuffixEntries()
    {
        var matcher = new CidrMatcher();
        Assert.True(IpPrefix.TryParse("1.2.3.0/24", out var prefix));
        Assert.True(IpSuffix.TryParse("0.0.3.4/16", out var suffix));
        matcher.Add(prefix, 1);
        matcher.AddSuffix(suffix, 2);

        Assert.Equal(1, matcher.Match(IPAddress.Parse("1.2.3.9")));
    }

    [Theory]
    [InlineData("1.2.3.4", "1.2.3.4", true)]
    [InlineData("1.2.3.4", "1.2.3.5", false)]
    [InlineData("0.0.3.4/16", "9.9.3.4", true)]
    [InlineData("0.0.3.4/16", "9.9.4.4", false)]
    public void SuffixMatchesLowBits(string pattern, string address, bool expected)
    {
        Assert.True(IpSuffix.TryParse(pattern, out var suffix));
        Assert.Equal(expected, suffix.Matches(IPAddress.Parse(address)));
    }

    [Fact]
    public void SuffixDoesNotCrossAddressFamilies()
    {
        Assert.True(IpSuffix.TryParse("1.2.3.4", out var suffix));
        Assert.False(suffix.Matches(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Ipv6SuffixMatchesLowBits()
    {
        Assert.True(IpSuffix.TryParse("::1/128", out var suffix));
        Assert.True(suffix.Matches(IPAddress.Parse("::1")));
        Assert.False(suffix.Matches(IPAddress.Parse("2001:db8::1")));
        Assert.False(suffix.Matches(IPAddress.Parse("::2")));

        Assert.True(IpSuffix.TryParse("::abcd/112", out var block));
        Assert.True(block.Matches(IPAddress.Parse("::abcd")));
        Assert.True(block.Matches(IPAddress.Parse("1::abcd")));
        Assert.False(block.Matches(IPAddress.Parse("2001:db8::abcd")));
        Assert.False(block.Matches(IPAddress.Parse("::1:abcd")));
    }
}
