using Clash.Core.Configuration;
using Clash.Core.Providers;
using Xunit;

namespace Clash.Tests.Providers;

public sealed class RuleProviderLoaderTests
{
    private const string YamlPayload = """
        payload:
          - example.com
          - +.example.org
          - full:only.example.net
        """;

    private const string TextPayload = """
        example.com
        # a comment
        +.example.org
        """;

    private static RuleProviderConfig Config(
        string type,
        string format = "yaml",
        string behavior = "domain",
        string url = "https://rules.example.com/set.yaml",
        string path = "cache/rules.yaml",
        int interval = 86400,
        List<string>? payload = null)
        => new()
        {
            Type = type,
            Format = format,
            Behavior = behavior,
            Url = url,
            Path = path,
            Interval = interval,
            Payload = payload,
        };

    // ── inline ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task InlineProviderReturnsItsPayload()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root, FakeHttpMessageHandler.Throws());

        var result = await loader.LoadAsync("inline", Config("inline", payload: ["example.com", "example.org"]));

        Assert.Equal("domain", result.Behavior);
        Assert.Equal(2, result.Payload.Count);

        var set = loader.ToRuleSet("inline", result);
        Assert.Equal(2, set.Count);
        Assert.True(set.Match(TestEntries.Flow("www.example.com")));
        Assert.False(set.Match(TestEntries.Flow("example.invalid")));
    }

    [Fact]
    public async Task InlineProviderWithoutAPayloadThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(() => loader.LoadAsync("inline", Config("inline")));
    }

    [Fact]
    public async Task AnUnsupportedVehicleThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(() => loader.LoadAsync("weird", Config("smoke-signal")));
    }

    // ── file ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FileProviderReadsAYamlPayload()
    {
        using var temp = new TempDirectory();
        temp.Write("rules/set.yaml", YamlPayload);

        using var loader = new RuleProviderLoader(temp.Root);
        var result = await loader.LoadAsync("file", Config("file", path: "rules/set.yaml"));

        Assert.Equal(3, result.Payload.Count);
        Assert.Contains("example.com", result.Payload);
        Assert.Contains("full:only.example.net", result.Payload);

        var set = loader.ToRuleSet("file", result);
        Assert.Equal(3, set.Count);
        Assert.True(set.Match(TestEntries.Flow("deep.sub.example.com")));
        Assert.True(set.Match(TestEntries.Flow("only.example.net")));
        Assert.False(set.Match(TestEntries.Flow("not.example.net")));
    }

    [Fact]
    public async Task FileProviderReadsATextPayload()
    {
        using var temp = new TempDirectory();
        temp.Write("rules/set.txt", TextPayload);

        using var loader = new RuleProviderLoader(temp.Root);
        var result = await loader.LoadAsync("file", Config("file", format: "text", path: "rules/set.txt"));

        Assert.Equal(new[] {"example.com", "+.example.org"}, result.Payload);
    }

    [Fact]
    public async Task FileProviderWithAMissingFileThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(
            () => loader.LoadAsync("file", Config("file", path: "rules/missing.yaml")));
    }

    [Fact]
    public async Task AYamlProviderServingPlainTextStillParses()
    {
        using var temp = new TempDirectory();
        temp.Write("rules/set.yaml", "example.com\nexample.org\n");

        using var loader = new RuleProviderLoader(temp.Root);
        var result = await loader.LoadAsync("file", Config("file", path: "rules/set.yaml"));

        Assert.Equal(new[] {"example.com", "example.org"}, result.Payload);
    }

    // ── http ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task HttpProviderDownloadsParsesAndCachesTheBody()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns(YamlPayload);

        using var loader = new RuleProviderLoader(temp.Root, handler);
        var result = await loader.LoadAsync("remote", Config("http"));

        Assert.Equal(3, result.Payload.Count);
        Assert.Equal(1, handler.Calls);
        Assert.Contains("clash-verge", handler.LastUserAgent);
        Assert.True(File.Exists(temp.PathOf("cache/rules.yaml")));
    }

    [Fact]
    public async Task AFreshRuleCacheIsServedWithoutTouchingTheNetwork()
    {
        using var temp = new TempDirectory();
        temp.Write("cache/rules.yaml", YamlPayload);

        var handler = FakeHttpMessageHandler.Throws();
        using var loader = new RuleProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", Config("http"));

        Assert.Equal(0, handler.Calls);
        Assert.Equal(3, result.Payload.Count);
    }

    [Fact]
    public async Task AStaleRuleCacheIsUsedWhenTheDownloadFails()
    {
        using var temp = new TempDirectory();
        var cachePath = temp.Write("cache/rules.yaml", YamlPayload);
        File.SetLastWriteTimeUtc(cachePath, DateTime.UtcNow.AddDays(-2));

        var handler = FakeHttpMessageHandler.Throws("offline");
        using var loader = new RuleProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", Config("http"));

        Assert.Equal(1, handler.Calls);
        Assert.Equal(3, result.Payload.Count);
    }

    [Fact]
    public async Task RefreshAsyncIgnoresAFreshRuleCache()
    {
        using var temp = new TempDirectory();
        temp.Write("cache/rules.yaml", YamlPayload);

        var handler = FakeHttpMessageHandler.Returns("payload:\n  - fresh.example.com\n");
        using var loader = new RuleProviderLoader(temp.Root, handler);

        var result = await loader.RefreshAsync("remote", Config("http"));

        Assert.Equal(1, handler.Calls);
        Assert.Equal(new[] {"fresh.example.com"}, result.Payload);
    }

    [Fact]
    public async Task AFailedDownloadWithoutACacheThrows()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Throws("offline");
        using var loader = new RuleProviderLoader(temp.Root, handler);

        await Assert.ThrowsAsync<ProviderException>(() => loader.LoadAsync("remote", Config("http")));
    }

    // ── mrs ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AnMrsBodyIsDetectedAndYieldsAnEmptyPayloadInsteadOfThrowing()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns("MRS\u0001\u0000\u0002binary-blob");

        using var loader = new RuleProviderLoader(temp.Root, handler);
        var result = await loader.LoadAsync("mrs", Config("http", format: "mrs"));

        Assert.Empty(result.Payload);

        var set = loader.ToRuleSet("mrs", result);
        Assert.Equal(0, set.Count);
        Assert.False(set.Match(TestEntries.Flow("example.com")));
    }

    [Fact]
    public async Task AnMrsFormatWithoutTheMagicYieldsAnEmptyPayload()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns("example.com\nexample.org\n");

        using var loader = new RuleProviderLoader(temp.Root, handler);
        var result = await loader.LoadAsync("mrs", Config("http", format: "mrs"));

        Assert.Empty(result.Payload);
    }

    // ── behaviours ───────────────────────────────────────────────────────────

    [Fact]
    public void ToRuleSetBuildsAnIpCidrSetThatResolvesFirst()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root);

        var result = new RuleProviderResult("ipcidr", ["10.0.0.0/8", "192.168.0.0/16"], DateTimeOffset.UtcNow);
        var set = loader.ToRuleSet("cidrs", result);

        Assert.Equal("ipcidr", set.Behavior);
        Assert.Equal(2, set.Count);
        Assert.True(set.ShouldResolveIp);
        Assert.True(set.Match(new Clash.Core.Common.Metadata { DestinationAddress = "10.1.2.3" }));
        Assert.False(set.Match(new Clash.Core.Common.Metadata { DestinationAddress = "8.8.8.8" }));
    }

    [Fact]
    public void ToRuleSetBuildsAClassicalSet()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root);

        var result = new RuleProviderResult("classical", ["DOMAIN-SUFFIX,example.com", "DOMAIN,exact.test"], DateTimeOffset.UtcNow);
        var set = loader.ToRuleSet("classical", result);

        Assert.Equal("classical", set.Behavior);
        Assert.Equal(2, set.Count);
        Assert.True(set.Match(TestEntries.Flow("www.example.com")));
        Assert.True(set.Match(TestEntries.Flow("exact.test")));
        Assert.False(set.Match(TestEntries.Flow("other.test")));
    }

    [Fact]
    public void ToRuleSetRejectsABlankName()
    {
        using var temp = new TempDirectory();
        using var loader = new RuleProviderLoader(temp.Root);
        var result = new RuleProviderResult("domain", ["example.com"], DateTimeOffset.UtcNow);

        Assert.Throws<ArgumentException>(() => loader.ToRuleSet("  ", result));
    }
}
