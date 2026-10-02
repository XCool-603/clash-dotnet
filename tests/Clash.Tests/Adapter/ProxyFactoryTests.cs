using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Transport;
using Clash.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Adapter;

public class ProxyFactoryTests
{
    private static ProxyFactory Factory(out TunnelAccessor accessor)
    {
        accessor = new TunnelAccessor();
        var context = new AdapterBuildContext
        {
            Config = new ClashConfig(),
            Tunnel = accessor,
            Transports = new TransportComposer(),
            LoggerFactory = NullLoggerFactory.Instance,
        };
        return new ProxyFactory(context, new MemorySelectionStore());
    }

    private static ProxyConfigEntry Entry(string name, string type, params (string Key, object? Value)[] extra)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = name,
            ["type"] = type,
        };
        foreach (var (key, value) in extra) map[key] = value;
        return new ProxyConfigEntry(new YamlMap(map));
    }

    private static ClashConfig ConfigWith(params ProxyGroupConfig[] groups)
    {
        var config = new ClashConfig();
        config.Proxies.Add(Entry("n1", "direct"));
        config.Proxies.Add(Entry("n2", "direct"));
        config.Proxies.Add(Entry("n3", "reject"));
        config.ProxyGroups.AddRange(groups);
        return config;
    }

    [Fact]
    public async Task BuildsProxiesAndGroups()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig
        {
            Name = "PROXY",
            Type = "select",
            Proxies = ["n1", "n2"],
        });

        var manager = await factory.BuildAsync(config);

        Assert.NotNull(manager.Get("n1"));
        Assert.NotNull(manager.Get("n2"));
        Assert.NotNull(manager.Get("n3"));

        var group = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("PROXY"));
        Assert.Equal(["n1", "n2"], group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task GroupsMayReferenceOtherGroups()
    {
        var factory = Factory(out _);
        var config = ConfigWith(
            new ProxyGroupConfig { Name = "OUTER", Type = "select", Proxies = ["INNER", "n1"] },
            new ProxyGroupConfig { Name = "INNER", Type = "select", Proxies = ["n2"] });

        var manager = await factory.BuildAsync(config);

        // Membership is resolved in a second pass, so forward references work.
        var outer = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("OUTER"));
        Assert.Equal(["INNER", "n1"], outer.Members.Select(m => m.Name));

        var inner = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("INNER"));
        Assert.Equal(["n2"], inner.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task AGroupCannotContainItself()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig { Name = "LOOP", Type = "select", Proxies = ["LOOP", "n1"] });

        var manager = await factory.BuildAsync(config);

        var group = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("LOOP"));
        Assert.Equal(["n1"], group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task UnknownMembersAreSkipped()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig { Name = "PROXY", Type = "select", Proxies = ["n1", "ghost"] });

        var manager = await factory.BuildAsync(config);

        var group = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("PROXY"));
        Assert.Equal(["n1"], group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task IncludeAllProxiesPullsInEveryConfiguredNode()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig
        {
            Name = "ALL",
            Type = "select",
            IncludeAllProxies = true,
        });

        var manager = await factory.BuildAsync(config);

        var group = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("ALL"));
        Assert.Equal(["n1", "n2", "n3"], group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task GroupFilterAndExcludeFilterAreApplied()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig
        {
            Name = "FILTERED",
            Type = "select",
            IncludeAllProxies = true,
            Filter = "^n[12]$",
            ExcludeFilter = "^n2$",
        });

        var manager = await factory.BuildAsync(config);

        var group = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("FILTERED"));
        Assert.Equal(["n1"], group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task GroupExcludeTypeRemovesMatchingAdapters()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig
        {
            Name = "NO_REJECT",
            Type = "select",
            IncludeAllProxies = true,
            ExcludeType = "Reject",
        });

        var manager = await factory.BuildAsync(config);

        var group = Assert.IsAssignableFrom<IProxyGroup>(manager.Get("NO_REJECT"));
        Assert.DoesNotContain("n3", group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task ProviderFilterHelperSelectsByRegexAndType()
    {
        var entries = new List<ProxyConfigEntry>
        {
            Entry("hk-01", "ss"),
            Entry("hk-02", "ss"),
            Entry("us-01", "vmess"),
            Entry("relay-01", "reject"),
        };

        var filtered = ProxyFactory.ApplyFilters(
            entries,
            new ProxyProviderConfig { Filter = "^hk-", ExcludeType = "ss" },
            "p");

        Assert.Empty(filtered);

        var hk = ProxyFactory.ApplyFilters(entries, new ProxyProviderConfig { Filter = "^hk-" }, "p");
        Assert.Equal(["hk-01", "hk-02"], hk.Select(e => e.Name));

        var notRelay = ProxyFactory.ApplyFilters(entries, new ProxyProviderConfig { ExcludeFilter = "relay" }, "p");
        Assert.Equal(3, notRelay.Count);
    }

    [Fact]
    public void ProviderOverrideMergesButNeverRenames()
    {
        var entry = Entry("node", "ss", ("server", "1.1.1.1"), ("udp", false));
        var overrides = YamlReader.Parse("""
            name: renamed
            udp: true
            skip-cert-verify: true
            """);

        var merged = ProxyFactory.ApplyOverride(entry, overrides);

        Assert.Equal("node", merged.Name);                       // name is protected
        Assert.Equal("ss", merged.Type);
        Assert.Equal("1.1.1.1", merged.Map.GetString("server")); // untouched field survives
        Assert.True(merged.Map.GetBool("udp"));                  // overridden
        Assert.True(merged.Map.GetBool("skip-cert-verify"));     // added
    }

    [Fact]
    public void ProviderOverrideWithNothingToDoReturnsTheSameEntry()
    {
        var entry = Entry("node", "ss");
        Assert.Same(entry, ProxyFactory.ApplyOverride(entry, YamlMap.Empty));
    }

    [Fact]
    public async Task InvalidNodesAreSkippedWithoutFailingTheBuild()
    {
        var factory = Factory(out _);
        var config = new ClashConfig();
        config.Proxies.Add(Entry("ok", "direct"));
        config.Proxies.Add(Entry("broken", "not-a-protocol"));
        config.ProxyGroups.Add(new ProxyGroupConfig { Name = "PROXY", Type = "select", Proxies = ["ok"] });

        var manager = await factory.BuildAsync(config);

        Assert.NotNull(manager.Get("ok"));
        Assert.Null(manager.Get("broken"));
    }

    [Fact]
    public async Task InvalidGroupTypeIsSkippedWithoutFailingTheBuild()
    {
        var factory = Factory(out _);
        var config = ConfigWith(new ProxyGroupConfig { Name = "BROKEN", Type = "not-a-group-type" });

        var manager = await factory.BuildAsync(config);

        Assert.Null(manager.Get("BROKEN"));
        Assert.NotNull(manager.Get("n1"));
    }

    [Fact]
    public async Task GlobalExcludesTheBuiltinAdapters()
    {
        var factory = Factory(out _);
        var manager = await factory.BuildAsync(ConfigWith());

        var global = Assert.IsAssignableFrom<IProxyGroup>(manager.Global);
        var names = global.Members.Select(m => m.Name).ToList();

        Assert.Contains("n1", names);
        Assert.Contains("n3", names);
        Assert.DoesNotContain("DIRECT", names);
        Assert.DoesNotContain("REJECT", names);
    }

    [Fact]
    public async Task ReloadRebuildsTheRegistryCleanly()
    {
        var factory = Factory(out _);
        var first = await factory.BuildAsync(ConfigWith(new ProxyGroupConfig
        {
            Name = "PROXY",
            Type = "select",
            Proxies = ["n1"],
        }));

        Assert.Equal(["n1"], Assert.IsAssignableFrom<IProxyGroup>(first.Get("PROXY")).Members.Select(m => m.Name));

        var second = await factory.BuildAsync(ConfigWith(new ProxyGroupConfig
        {
            Name = "PROXY",
            Type = "select",
            Proxies = ["n1", "n2"],
        }));

        Assert.Equal(["n1", "n2"], Assert.IsAssignableFrom<IProxyGroup>(second.Get("PROXY")).Members.Select(m => m.Name));
    }
}
