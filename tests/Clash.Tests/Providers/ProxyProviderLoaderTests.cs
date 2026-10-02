using Clash.Core.Configuration;
using Clash.Core.Providers;
using Xunit;

namespace Clash.Tests.Providers;

public sealed class ProxyProviderLoaderTests
{
    private const string LinkList = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#Node";

    private const string ClashBody = """
        proxies:
          - name: "from yaml"
            type: ss
            server: yaml.example.com
            port: 8388
            cipher: aes-128-gcm
            password: pw
        """;

    [Fact]
    public void TheShareLinkParserIsRegisteredByTheModuleInitializer()
        => Assert.True(ShareLinks.IsAvailable);

    // ── inline ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task InlineProviderReturnsItsPayloadWithoutIo()
    {
        using var temp = new TempDirectory();
        var payload = new[] { TestEntries.Proxy("inline node", "ss", ("server", "1.2.3.4"), ("port", 8388)) };
        var config = new ProxyProviderConfig { Type = "inline", InlinePayload = [.. payload] };

        using var loader = new ProxyProviderLoader(temp.Root, FakeHttpMessageHandler.Throws());
        var result = await loader.LoadAsync("inline-provider", config);

        Assert.Single(result.Proxies);
        Assert.Equal("inline node", result.Proxies[0].Name);
        Assert.Equal("1.2.3.4", result.Proxies[0].Map.GetString("server"));
        Assert.Null(result.SubscriptionInfo);
    }

    [Fact]
    public async Task InlineProviderWithoutAPayloadThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new ProxyProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(
            () => loader.LoadAsync("empty", new ProxyProviderConfig { Type = "inline" }));
    }

    // ── file ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task FileProviderReadsClashYamlRelativeToTheHomeDirectory()
    {
        using var temp = new TempDirectory();
        temp.Write("providers/file.yaml", ClashBody);

        var config = new ProxyProviderConfig { Type = "file", Path = "providers/file.yaml" };
        using var loader = new ProxyProviderLoader(temp.Root);

        var result = await loader.LoadAsync("file-provider", config);

        Assert.Single(result.Proxies);
        Assert.Equal("from yaml", result.Proxies[0].Name);
        Assert.Equal("ss", result.Proxies[0].Type);
        Assert.Equal(8388, result.Proxies[0].Map.GetInt("port"));
    }

    [Fact]
    public async Task FileProviderReadsAShareLinkFile()
    {
        using var temp = new TempDirectory();
        temp.Write("providers/links.txt", LinkList);

        var config = new ProxyProviderConfig { Type = "file", Path = "providers/links.txt" };
        using var loader = new ProxyProviderLoader(temp.Root);

        var result = await loader.LoadAsync("links", config);

        Assert.Single(result.Proxies);
        Assert.Equal("Node", result.Proxies[0].Name);
        Assert.Equal("ss", result.Proxies[0].Type);
    }

    [Fact]
    public async Task FileProviderWithAMissingFileThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new ProxyProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(
            () => loader.LoadAsync("missing", new ProxyProviderConfig { Type = "file", Path = "providers/nope.yaml" }));
    }

    [Fact]
    public async Task AnUnsupportedVehicleThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new ProxyProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(
            () => loader.LoadAsync("weird", new ProxyProviderConfig { Type = "carrier-pigeon" }));
    }

    // ── http ─────────────────────────────────────────────────────────────────

    private static ProxyProviderConfig HttpConfig(string url = "https://sub.example.com/all", string path = "cache/provider.yaml", int interval = 300)
        => new() { Type = "http", Url = url, Path = path, Interval = interval };

    [Fact]
    public async Task HttpProviderDownloadsParsesAndCachesTheBody()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns(
            LinkList,
            ("subscription-userinfo", "upload=100; download=200; total=1000; expire=1700000000"));

        using var loader = new ProxyProviderLoader(temp.Root, handler);
        var result = await loader.LoadAsync("remote", HttpConfig());

        Assert.Single(result.Proxies);
        Assert.Equal("Node", result.Proxies[0].Name);
        Assert.Equal(1, handler.Calls);
        Assert.Contains("clash-verge", handler.LastUserAgent);

        Assert.NotNull(result.SubscriptionInfo);
        Assert.Equal(100L, result.SubscriptionInfo!.Upload);
        Assert.Equal(200L, result.SubscriptionInfo.Download);
        Assert.Equal(1000L, result.SubscriptionInfo.Total);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000), result.SubscriptionInfo.Expire);

        Assert.True(File.Exists(temp.PathOf("cache/provider.yaml")));
        Assert.Equal(LinkList, File.ReadAllText(temp.PathOf("cache/provider.yaml")));
    }

    [Fact]
    public async Task HttpProviderConvertsAClashBody()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns(ClashBody);

        using var loader = new ProxyProviderLoader(temp.Root, handler);
        var result = await loader.LoadAsync("remote", HttpConfig());

        Assert.Single(result.Proxies);
        Assert.Equal("from yaml", result.Proxies[0].Name);
    }

    [Fact]
    public async Task AFreshCacheIsServedWithoutTouchingTheNetwork()
    {
        using var temp = new TempDirectory();
        temp.Write("cache/provider.yaml", LinkList);

        var handler = FakeHttpMessageHandler.Throws();
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", HttpConfig());

        Assert.Equal(0, handler.Calls);
        Assert.Single(result.Proxies);
        Assert.Equal("Node", result.Proxies[0].Name);
    }

    [Fact]
    public async Task ACachedSubscriptionInfoSidecarIsReportedOnACacheHit()
    {
        using var temp = new TempDirectory();
        temp.Write("cache/provider.yaml", LinkList);
        temp.Write("cache/provider.yaml.info", "upload=1; download=2; total=3; expire=1700000000");

        var handler = FakeHttpMessageHandler.Throws();
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", HttpConfig());

        Assert.Equal(0, handler.Calls);
        Assert.NotNull(result.SubscriptionInfo);
        Assert.Equal(1L, result.SubscriptionInfo!.Upload);
        Assert.Equal(3L, result.SubscriptionInfo.Total);
    }

    [Fact]
    public async Task RefreshAsyncIgnoresAFreshCache()
    {
        using var temp = new TempDirectory();
        temp.Write("cache/provider.yaml", LinkList);

        var handler = FakeHttpMessageHandler.Returns("trojan://pw@trojan.example.com:443#Fresh");
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        var result = await loader.RefreshAsync("remote", HttpConfig());

        Assert.Equal(1, handler.Calls);
        Assert.Single(result.Proxies);
        Assert.Equal("Fresh", result.Proxies[0].Name);
        Assert.Equal("trojan://pw@trojan.example.com:443#Fresh", File.ReadAllText(temp.PathOf("cache/provider.yaml")));
    }

    [Fact]
    public async Task AStaleCacheIsUsedWhenTheDownloadFails()
    {
        using var temp = new TempDirectory();
        var cachePath = temp.Write("cache/provider.yaml", LinkList);
        File.SetLastWriteTimeUtc(cachePath, DateTime.UtcNow.AddHours(-2));

        var handler = FakeHttpMessageHandler.Throws("connection refused");
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", HttpConfig(interval: 300));

        Assert.Equal(1, handler.Calls);
        Assert.Single(result.Proxies);
        Assert.Equal("Node", result.Proxies[0].Name);
    }

    [Fact]
    public async Task AStaleCacheIsUsedWhenTheServerErrors()
    {
        using var temp = new TempDirectory();
        var cachePath = temp.Write("cache/provider.yaml", LinkList);
        File.SetLastWriteTimeUtc(cachePath, DateTime.UtcNow.AddHours(-2));

        var handler = FakeHttpMessageHandler.Fails();
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", HttpConfig(interval: 300));

        Assert.Single(result.Proxies);
    }

    [Fact]
    public async Task AFailedDownloadWithoutACacheThrows()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Throws("offline");
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        await Assert.ThrowsAsync<ProviderException>(() => loader.LoadAsync("remote", HttpConfig()));
    }

    [Fact]
    public async Task AnEmptyDownloadWithoutACacheThrows()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns("nothing usable here");
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        await Assert.ThrowsAsync<ProviderException>(() => loader.LoadAsync("remote", HttpConfig()));
    }

    [Fact]
    public async Task AnEmptyDownloadFallsBackToAStaleCache()
    {
        using var temp = new TempDirectory();
        var cachePath = temp.Write("cache/provider.yaml", LinkList);
        File.SetLastWriteTimeUtc(cachePath, DateTime.UtcNow.AddHours(-2));

        var handler = FakeHttpMessageHandler.Returns("nothing usable here");
        using var loader = new ProxyProviderLoader(temp.Root, handler);

        var result = await loader.LoadAsync("remote", HttpConfig(interval: 300));

        Assert.Single(result.Proxies);
        Assert.Equal("Node", result.Proxies[0].Name);
    }

    [Fact]
    public async Task AnHttpProviderWithoutAUrlAndWithoutACacheThrows()
    {
        using var temp = new TempDirectory();
        using var loader = new ProxyProviderLoader(temp.Root);

        await Assert.ThrowsAsync<ProviderException>(
            () => loader.LoadAsync("remote", new ProxyProviderConfig { Type = "http", Path = "cache/provider.yaml" }));
    }

    [Fact]
    public async Task AnEmptyPathCachesUnderTheProviderDirectory()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns(LinkList);

        using var loader = new ProxyProviderLoader(temp.Root, handler);
        await loader.LoadAsync("my provider", HttpConfig(path: string.Empty));

        Assert.True(File.Exists(Path.Combine(temp.Root, "providers", "proxies", "my provider.yaml")));
    }

    [Fact]
    public async Task AProviderResultCarriesAnUpdateTimestamp()
    {
        using var temp = new TempDirectory();
        var handler = FakeHttpMessageHandler.Returns(LinkList);

        using var loader = new ProxyProviderLoader(temp.Root, handler);
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);
        var result = await loader.LoadAsync("remote", HttpConfig());

        Assert.True(result.UpdatedAt >= before);
        Assert.True(result.UpdatedAt <= DateTimeOffset.UtcNow.AddSeconds(1));
    }
}
