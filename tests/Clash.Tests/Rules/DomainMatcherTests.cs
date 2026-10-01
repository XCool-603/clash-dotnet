using Clash.Core.Rules;
using Xunit;

namespace Clash.Tests.Rules;

public class DomainMatcherTests
{
    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("example.com", "www.example.com", false)]
    [InlineData("example.com", "EXAMPLE.COM", true)]
    [InlineData("example.com", "example.com.", true)]
    [InlineData("example.com", "example.org", false)]
    public void FullEntriesMatchExactly(string entry, string host, bool expected)
        => Assert.Equal(expected, Single(entry, DomainMatchKind.Full).Match(host) >= 0);

    [Theory]
    [InlineData("a.com", "a.com", true)]
    [InlineData("a.com", "b.a.com", true)]
    [InlineData("a.com", "b.c.a.com", true)]
    [InlineData("a.com", "xa.com", false)]
    [InlineData("a.com", "a.com.cn", false)]
    [InlineData("a.com", "A.COM", true)]
    [InlineData("a.com", "b.a.com.", true)]
    [InlineData("a.com", "com", false)]
    [InlineData("a.com", "nota.com", false)]
    [InlineData(".a.com", "b.a.com", true)]
    [InlineData(".a.com", "xa.com", false)]
    public void SuffixEntriesMatchTheDomainAndItsSubdomains(string entry, string host, bool expected)
        => Assert.Equal(expected, Single(entry, DomainMatchKind.Suffix).Match(host) >= 0);

    [Theory]
    [InlineData("google", "www.google.com", true)]
    [InlineData("google", "GOOGLE.com", true)]
    [InlineData("google", "example.com", false)]
    public void KeywordEntriesMatchAnywhere(string entry, string host, bool expected)
        => Assert.Equal(expected, Single(entry, DomainMatchKind.Keyword).Match(host) >= 0);

    [Theory]
    [InlineData(@"^ads\.", "ads.example.com", true)]
    [InlineData(@"^ads\.", "cdn.example.com", false)]
    [InlineData(@"\.ads\.", "cdn.ads.example.com", true)]
    public void RegexEntriesMatchThePattern(string entry, string host, bool expected)
        => Assert.Equal(expected, Single(entry, DomainMatchKind.Regex).Match(host) >= 0);

    [Fact]
    public void ExactMatchWinsOverSuffix()
    {
        var matcher = new DomainMatcher();
        matcher.Add("a.com", DomainMatchKind.Suffix, 7);
        matcher.Add("a.com", DomainMatchKind.Full, 3);

        Assert.Equal(3, matcher.Match("a.com"));
        Assert.Equal(7, matcher.Match("b.a.com"));
    }

    [Fact]
    public void LongestSuffixWins()
    {
        var matcher = new DomainMatcher();
        matcher.Add("com", DomainMatchKind.Suffix, 1);
        matcher.Add("a.com", DomainMatchKind.Suffix, 2);

        Assert.Equal(2, matcher.Match("x.a.com"));
        Assert.Equal(1, matcher.Match("x.b.com"));
    }

    [Fact]
    public void SuffixWinsOverKeywordAndRegex()
    {
        var matcher = new DomainMatcher();
        matcher.Add("example", DomainMatchKind.Keyword, 5);
        matcher.Add(@"\.com$", DomainMatchKind.Regex, 6);
        matcher.Add("example.com", DomainMatchKind.Suffix, 4);

        Assert.Equal(4, matcher.Match("www.example.com"));
        Assert.Equal(5, matcher.Match("example.org"));
        Assert.Equal(6, matcher.Match("other.com"));
        Assert.Equal(-1, matcher.Match("nothing.net"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("...")]
    public void DegenerateHostsDoNotMatch(string? host)
    {
        var matcher = new DomainMatcher();
        matcher.Add("a.com", DomainMatchKind.Suffix, 0);
        Assert.Equal(-1, matcher.Match(host));
    }

    [Fact]
    public void EmptyMatcherNeverMatches()
    {
        var matcher = new DomainMatcher();
        Assert.True(matcher.IsEmpty);
        Assert.Equal(-1, matcher.Match("a.com"));
    }

    [Theory]
    [InlineData(".Example.COM.", "example.com")]
    [InlineData("EXAMPLE.com", "example.com")]
    [InlineData("example.com.", "example.com")]
    [InlineData("  example.com  ", "example.com")]
    public void NormalizeStripsDotsAndCase(string input, string expected)
        => Assert.Equal(expected, DomainMatcher.Normalize(input));

    [Fact]
    public void CountsAddedEntries()
    {
        var matcher = new DomainMatcher();
        matcher.Add("a.com", DomainMatchKind.Full, 0);
        matcher.Add("b.com", DomainMatchKind.Suffix, 1);
        matcher.Add("c", DomainMatchKind.Keyword, 2);
        matcher.Add("d", DomainMatchKind.Regex, 3);
        matcher.Add("   ", DomainMatchKind.Full, 4);

        Assert.Equal(4, matcher.Count);
    }

    private static DomainMatcher Single(string entry, DomainMatchKind kind)
    {
        var matcher = new DomainMatcher();
        matcher.Add(entry, kind, 0);
        return matcher;
    }
}
