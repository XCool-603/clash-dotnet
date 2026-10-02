using Clash.Core.Providers;
using Xunit;

namespace Clash.Tests.Providers;

public sealed class SubscriptionInfoParserTests
{
    [Fact]
    public void ParsesTheStandardUserInfoHeader()
    {
        var info = SubscriptionInfoParser.ParseUserInfo("upload=100; download=200; total=1000; expire=1700000000");

        Assert.NotNull(info);
        Assert.Equal(100L, info!.Upload);
        Assert.Equal(200L, info.Download);
        Assert.Equal(1000L, info.Total);
        Assert.Equal(300L, info.Used);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), info.Expire);
    }

    [Fact]
    public void ParsesAPartialUserInfoHeader()
    {
        var info = SubscriptionInfoParser.ParseUserInfo("upload=5; download=7");

        Assert.NotNull(info);
        Assert.Equal(5L, info!.Upload);
        Assert.Equal(7L, info.Download);
        Assert.Equal(0L, info.Total);
        Assert.Null(info.Expire);
    }

    [Fact]
    public void ParsesAColonSeparatedUserInfoHeader()
    {
        var info = SubscriptionInfoParser.ParseUserInfo("upload=1,download=2,total=3");

        Assert.NotNull(info);
        Assert.Equal(1L, info!.Upload);
        Assert.Equal(2L, info.Download);
        Assert.Equal(3L, info.Total);
    }

    [Fact]
    public void IgnoresANonPositiveExpiry()
    {
        var info = SubscriptionInfoParser.ParseUserInfo("upload=1; total=3; expire=0");

        Assert.NotNull(info);
        Assert.Null(info!.Expire);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("no numbers here")]
    [InlineData("upload=;download=")]
    public void AMissingOrUnusableHeaderYieldsNull(string value)
        => Assert.Null(SubscriptionInfoParser.ParseUserInfo(value));

    [Fact]
    public void NullHeaderYieldsNull() => Assert.Null(SubscriptionInfoParser.ParseUserInfo(null!));
}
