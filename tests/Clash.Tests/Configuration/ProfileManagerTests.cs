using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Configuration;

public class ProfileManagerTests : IDisposable
{
    private readonly string _home;

    public ProfileManagerTests()
    {
        _home = Path.Combine(Path.GetTempPath(), "clash-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_home);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_home)) Directory.Delete(_home, recursive: true);
        }
        catch (IOException)
        {
            // A locked temp file must not fail the test run.
        }
        GC.SuppressFinalize(this);
    }

    private ProfileManager NewManager() => new(_home, NullLogger<ProfileManager>.Instance);

    [Fact]
    public void CreatingTheFirstProfileSelectsIt()
    {
        var manager = NewManager();
        var profile = manager.Create("first", "local", content: "port: 7890\n");

        Assert.True(profile.Selected);
        Assert.Same(profile.Id, manager.Selected?.Id);
        Assert.True(File.Exists(profile.Path));
        Assert.Equal("port: 7890\n", manager.ReadContent(profile.Id));
    }

    [Fact]
    public void SelectingAProfileClearsThePreviousSelection()
    {
        var manager = NewManager();
        var a = manager.Create("a", "local");
        var b = manager.Create("b", "local");

        Assert.True(manager.Select(b.Id));
        Assert.False(manager.Get(a.Id)!.Selected);
        Assert.True(manager.Get(b.Id)!.Selected);
        Assert.Equal(b.Id, manager.Selected?.Id);
    }

    [Fact]
    public void DeletingTheSelectedProfilePromotesAnother()
    {
        var manager = NewManager();
        var a = manager.Create("a", "local");
        var b = manager.Create("b", "local");
        manager.Select(b.Id);

        Assert.True(manager.Delete(b.Id));
        Assert.Null(manager.Get(b.Id));
        Assert.True(manager.Get(a.Id)!.Selected);
        Assert.Single(manager.List());
    }

    [Fact]
    public void ProfilesSurviveAReopen()
    {
        var first = NewManager();
        var created = first.Create("persisted", "local", content: "mode: global\n");
        first.Select(created.Id);

        var second = NewManager();
        var reloaded = second.Get(created.Id);

        Assert.NotNull(reloaded);
        Assert.Equal("persisted", reloaded!.Name);
        Assert.True(reloaded.Selected);
        Assert.Equal("mode: global\n", second.ReadContent(created.Id));
    }

    [Fact]
    public void ContentCanBeOverwritten()
    {
        var manager = NewManager();
        var profile = manager.Create("editable", "local", content: "port: 1\n");

        manager.WriteContent(profile.Id, "port: 2\n");

        Assert.Equal("port: 2\n", manager.ReadContent(profile.Id));
    }

    [Fact]
    public void UnknownProfilesThrow()
    {
        var manager = NewManager();
        Assert.Throws<ClashException>(() => manager.ReadContent("missing"));
        Assert.Throws<ClashException>(() => manager.WriteContent("missing", "x"));
        Assert.False(manager.Select("missing"));
        Assert.False(manager.Delete("missing"));
        Assert.False(manager.Update("missing", "n", null, null));
    }

    [Fact]
    public void ActiveConfigUsesTheSelectedProfile()
    {
        var manager = NewManager();
        manager.Create("base", "local", content: """
            mixed-port: 7899
            mode: global
            log-level: debug
            proxies:
              - name: n1
                type: ss
                server: 1.1.1.1
                port: 443
                cipher: aes-256-gcm
                password: pw
            """);

        var config = manager.BuildActiveConfig();

        Assert.Equal(7899, config.MixedPort);
        Assert.Equal(Mode.Global, config.Mode);
        Assert.Equal("debug", config.LogLevel);
        Assert.Single(config.Proxies);
        Assert.Equal("n1", config.Proxies[0].Name);
    }

    [Fact]
    public void MergeProfilesOverrideScalarsAndAppendLists()
    {
        var manager = NewManager();
        var baseProfile = manager.Create("base", "local", content: """
            mixed-port: 7890
            mode: rule
            proxies:
              - name: n1
                type: ss
                server: 1.1.1.1
                port: 443
            rules:
              - MATCH,DIRECT
            """);

        var merge = manager.Create("overlay", "merge", content: """
            mode: global
            log-level: warning
            proxies:
              - name: n2
                type: ss
                server: 2.2.2.2
                port: 443
            rules:
              - DOMAIN-SUFFIX,example.com,DIRECT
            """);

        manager.Select(baseProfile.Id);

        var config = manager.BuildActiveConfig();

        // Scalars are replaced.
        Assert.Equal(Mode.Global, config.Mode);
        Assert.Equal("warning", config.LogLevel);
        Assert.Equal(7890, config.MixedPort);

        // Lists are appended, preserving the base order.
        Assert.Equal(2, config.Proxies.Count);
        Assert.Equal("n1", config.Proxies[0].Name);
        Assert.Equal("n2", config.Proxies[1].Name);

        Assert.Equal(2, config.Rules.Count);
        Assert.Equal("MATCH,DIRECT", config.Rules[0]);
        Assert.Equal("DOMAIN-SUFFIX,example.com,DIRECT", config.Rules[1]);

        Assert.NotNull(merge);
    }

    [Fact]
    public void MergeRecursesIntoNestedMappings()
    {
        var root = YamlReader.Parse("""
            dns:
              enable: true
              nameserver:
                - 1.1.1.1
            tun:
              enable: false
            """);

        var overlay = YamlReader.Parse("""
            dns:
              nameserver:
                - 8.8.8.8
              ipv6: true
            tun:
              enable: true
            """);

        var merged = ProfileManager.Merge(root, overlay);

        var dns = merged.GetMap("dns");
        Assert.True(dns.GetBool("enable"));                       // kept from the base
        Assert.True(dns.GetBool("ipv6"));                         // added by the overlay
        Assert.Equal(2, dns.GetStringList("nameserver").Count);    // appended
        Assert.True(merged.GetMap("tun").GetBool("enable"));       // scalar replaced
    }

    [Fact]
    public void ActiveConfigFallsBackToTheDefaultWhenNothingIsStored()
    {
        var manager = NewManager();
        var config = manager.BuildActiveConfig();

        // The starter configuration is a valid Clash document.
        Assert.Equal(7890, config.MixedPort);
        Assert.NotEmpty(config.Rules);
        Assert.Contains(config.ProxyGroups, g => g.Name == "PROXY");
    }

    [Fact]
    public void ListOrdersSelectedFirst()
    {
        var manager = NewManager();
        var a = manager.Create("a", "local");
        var b = manager.Create("b", "local");
        var c = manager.Create("c", "local");
        manager.Select(c.Id);

        var list = manager.List();
        Assert.Equal(c.Id, list[0].Id);
        Assert.Equal(3, list.Count);
        Assert.Contains(list, p => p.Id == a.Id);
        Assert.Contains(list, p => p.Id == b.Id);
    }

    [Fact]
    public void UpdateRenamesAndSetsTheUrl()
    {
        var manager = NewManager();
        var profile = manager.Create("old", "remote", "https://example.com/sub");

        Assert.True(manager.Update(profile.Id, "new", "https://other.example/sub", "desc"));

        var updated = manager.Get(profile.Id)!;
        Assert.Equal("new", updated.Name);
        Assert.Equal("https://other.example/sub", updated.Url);
        Assert.Equal("desc", updated.Description);
    }

    [Fact]
    public async Task ImportUrlRejectsANonHttpScheme()
    {
        var manager = NewManager();
        await Assert.ThrowsAsync<ClashException>(() => manager.ImportUrlAsync("file:///etc/passwd", null));
        await Assert.ThrowsAsync<ClashException>(() => manager.ImportUrlAsync("not a url", null));
    }
}
