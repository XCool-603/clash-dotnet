using System.Net;
using System.Net.Sockets;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Runtime;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Runtime;

/// <summary>
/// Exercises the composition root: configuration in, a wired proxy stack out.
/// These are the tests that catch wiring mistakes before the smoke test does.
/// </summary>
public class ClashRuntimeTests : IDisposable
{
    private readonly string _home;
    private readonly List<ClashRuntime> _runtimes = [];

    public ClashRuntimeTests()
    {
        _home = Path.Combine(Path.GetTempPath(), "clash-runtime-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_home);
    }

    public void Dispose()
    {
        foreach (var runtime in _runtimes)
        {
            try { runtime.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { /* best effort */ }
        }
        try
        {
            if (Directory.Exists(_home)) Directory.Delete(_home, recursive: true);
        }
        catch (IOException)
        {
            // A locked temp file must not fail the run.
        }
        GC.SuppressFinalize(this);
    }

    private async Task<ClashRuntime> StartAsync(string yaml)
    {
        var runtime = await ClashRuntime.StartAsync(new ClashRuntimeOptions
        {
            HomeDir = _home,
            InlineYaml = yaml,
            LoggerFactory = NullLoggerFactory.Instance,
            StartListeners = false,
            CreateDefaultConfigIfMissing = false,
        });
        _runtimes.Add(runtime);
        return runtime;
    }

    private const string BasicYaml = """
        mixed-port: 17890
        mode: rule
        log-level: warning
        external-controller: 127.0.0.1:19090
        dns:
          enable: false
        proxies:
          - name: n1
            type: direct
          - name: n2
            type: direct
          - name: n3
            type: reject
        proxy-groups:
          - name: PROXY
            type: select
            proxies: [n1, n2, DIRECT]
          - name: AUTO
            type: url-test
            proxies: [n1, n2]
            url: https://www.gstatic.com/generate_204
            interval: 3600
            lazy: true
        rules:
          - DOMAIN-SUFFIX,example.com,PROXY
          - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
          - MATCH,PROXY
        """;

    [Fact]
    public async Task StartsAndWiresEverySubsystem()
    {
        var runtime = await StartAsync(BasicYaml);

        Assert.NotNull(runtime.Tunnel);
        Assert.NotNull(runtime.Dns);
        Assert.NotNull(runtime.Geo);
        Assert.NotNull(runtime.Rules);
        Assert.NotNull(runtime.Proxies);
        Assert.NotNull(runtime.Profiles);

        Assert.Equal(17890, runtime.Config.MixedPort);
        Assert.Equal(Mode.Rule, runtime.Tunnel.Mode);
    }

    [Fact]
    public async Task RegistersBuiltinsConfiguredProxiesAndGroups()
    {
        var runtime = await StartAsync(BasicYaml);

        Assert.NotNull(runtime.Proxies.Get("DIRECT"));
        Assert.NotNull(runtime.Proxies.Get("REJECT"));
        Assert.NotNull(runtime.Proxies.Get("GLOBAL"));
        Assert.NotNull(runtime.Proxies.Get("n1"));
        Assert.NotNull(runtime.Proxies.Get("n2"));
        Assert.NotNull(runtime.Proxies.Get("n3"));
        Assert.NotNull(runtime.Proxies.Get("PROXY"));
        Assert.NotNull(runtime.Proxies.Get("AUTO"));

        Assert.Equal("Direct", runtime.Proxies.Get("n1")!.TypeName);
        Assert.Equal("Reject", runtime.Proxies.Get("n3")!.TypeName);
    }

    [Fact]
    public async Task ResolvesGroupMembership()
    {
        var runtime = await StartAsync(BasicYaml);

        var group = Assert.IsAssignableFrom<IProxyGroup>(runtime.Proxies.Get("PROXY"));
        Assert.Equal(["n1", "n2", "DIRECT"], group.Members.Select(m => m.Name));

        var auto = Assert.IsAssignableFrom<IProxyGroup>(runtime.Proxies.Get("AUTO"));
        Assert.Equal(["n1", "n2"], auto.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task BuildsTheRuleListInOrder()
    {
        var runtime = await StartAsync(BasicYaml);

        Assert.Equal(3, runtime.Rules.Rules.Count);
        Assert.Equal("DOMAIN-SUFFIX", runtime.Rules.Rules[0].RuleTypeName);
        Assert.Equal("IP-CIDR", runtime.Rules.Rules[1].RuleTypeName);
        Assert.Equal("MATCH", runtime.Rules.Rules[2].RuleTypeName);
        Assert.Equal("PROXY", runtime.Rules.Rules[2].Adapter);
    }

    [Fact]
    public async Task MatchingHonoursFirstMatchWins()
    {
        var runtime = await StartAsync(BasicYaml);

        var domain = new Metadata
        {
            Network = Network.Tcp,
            DestinationAddress = "www.example.com",
            DestinationPort = 443,
            Host = "www.example.com",
        };

        var match = await runtime.Tunnel.MatchAsync(domain);
        Assert.NotNull(match);
        Assert.Equal("DOMAIN-SUFFIX", match!.Rule.RuleTypeName);
        Assert.Equal("PROXY", match.AdapterName);
    }

    [Fact]
    public async Task MatchingFallsThroughToTheCatchAll()
    {
        var runtime = await StartAsync(BasicYaml);

        var other = new Metadata
        {
            Network = Network.Tcp,
            DestinationAddress = "203.0.113.9",
            DestinationPort = 443,
        };

        var match = await runtime.Tunnel.MatchAsync(other);
        Assert.NotNull(match);
        Assert.Equal("MATCH", match!.Rule.RuleTypeName);
    }

    [Fact]
    public async Task ReloadSwapsModeAndRules()
    {
        var runtime = await StartAsync(BasicYaml);

        var updated = ConfigParser.Parse(YamlReader.Parse("""
            mixed-port: 17890
            mode: global
            log-level: debug
            external-controller: 127.0.0.1:19090
            dns:
              enable: false
            proxies:
              - name: n1
                type: direct
            proxy-groups:
              - name: PROXY
                type: select
                proxies: [n1]
            rules:
              - MATCH,DIRECT
            """));

        await runtime.ReloadAsync(updated);

        Assert.Equal(Mode.Global, runtime.Config.Mode);
        Assert.Equal(Mode.Global, runtime.Tunnel.Mode);
        Assert.Equal("debug", runtime.Config.LogLevel);
        Assert.Single(runtime.Rules.Rules);
        Assert.Equal("DIRECT", runtime.Rules.Rules[0].Adapter);
        Assert.NotNull(runtime.Proxies.Get("n1"));
    }

    [Fact]
    public async Task DialsThroughTheTunnelToALoopbackServer()
    {
        var runtime = await StartAsync(BasicYaml);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            var stream = client.GetStream();
            var buffer = new byte[64];
            var read = await stream.ReadAsync(buffer);
            await stream.WriteAsync(buffer.AsMemory(0, read));
        });

        var metadata = new Metadata
        {
            Network = Network.Tcp,
            DestinationAddress = "127.0.0.1",
            DestinationPort = (ushort)port,
            Host = "127.0.0.1",
        };

        await using var stream = await runtime.Tunnel.DialTcpAsync(metadata);

        var payload = "ping"u8.ToArray();
        await stream.WriteAsync(payload);
        await stream.FlushAsync();

        var response = new byte[payload.Length];
        var total = 0;
        while (total < response.Length)
        {
            var read = await stream.ReadAsync(response.AsMemory(total));
            if (read <= 0) break;
            total += read;
        }

        await serverTask;

        Assert.Equal(payload.Length, total);
        Assert.Equal(payload, response);

        // The catch-all rule sends the flow to PROXY, whose default member is the
        // first one (n1, itself a direct adapter); the chain records both hops.
        Assert.Equal(["PROXY", "n1"], metadata.Chain);

        listener.Stop();
    }

    [Fact]
    public async Task UnknownProxyTypesAreSkippedWithoutFailingStartup()
    {
        var runtime = await StartAsync("""
            mode: rule
            dns:
              enable: false
            proxies:
              - name: good
                type: direct
              - name: bad
                type: definitely-not-a-real-protocol
            proxy-groups:
              - name: PROXY
                type: select
                proxies: [good]
            rules:
              - MATCH,PROXY
            """);

        Assert.NotNull(runtime.Proxies.Get("good"));
        Assert.Null(runtime.Proxies.Get("bad"));
        Assert.Single(Assert.IsAssignableFrom<IProxyGroup>(runtime.Proxies.Get("PROXY")).Members);
    }

    [Fact]
    public async Task GroupsReferencingMissingProxiesStillLoad()
    {
        var runtime = await StartAsync("""
            mode: rule
            dns:
              enable: false
            proxies:
              - name: real
                type: direct
            proxy-groups:
              - name: PROXY
                type: select
                proxies: [real, ghost]
            rules:
              - MATCH,PROXY
            """);

        var group = Assert.IsAssignableFrom<IProxyGroup>(runtime.Proxies.Get("PROXY"));
        Assert.Equal(["real"], group.Members.Select(m => m.Name));
    }

    [Fact]
    public async Task InlineRuleProviderPayloadsBecomeRuleSets()
    {
        var runtime = await StartAsync("""
            mode: rule
            dns:
              enable: false
            rule-providers:
              blocked:
                type: inline
                behavior: domain
                payload:
                  - 'ads.example.com'
                  - 'tracker.example.net'
            rules:
              - RULE-SET,blocked,REJECT
              - MATCH,DIRECT
            """);

        Assert.True(runtime.RuleSets.ContainsKey("blocked"));
        Assert.Equal(2, runtime.RuleSets["blocked"].Count);

        var blocked = new Metadata
        {
            Network = Network.Tcp,
            DestinationAddress = "ads.example.com",
            DestinationPort = 443,
            Host = "ads.example.com",
        };

        var match = await runtime.Tunnel.MatchAsync(blocked);
        Assert.NotNull(match);
        Assert.Equal("RULE-SET", match!.Rule.RuleTypeName);
        Assert.Equal("REJECT", match.AdapterName);
    }

    [Fact]
    public async Task CreateDefaultConfigIsHonoured()
    {
        var missingHome = Path.Combine(_home, "fresh");

        var runtime = await ClashRuntime.StartAsync(new ClashRuntimeOptions
        {
            HomeDir = missingHome,
            LoggerFactory = NullLoggerFactory.Instance,
            StartListeners = false,
        });
        _runtimes.Add(runtime);

        Assert.True(File.Exists(Path.Combine(missingHome, "config.yaml")));
        Assert.Equal(7890, runtime.Config.MixedPort);
        Assert.NotEmpty(runtime.Rules.Rules);
    }

    [Fact]
    public async Task MissingConfigWithDefaultCreationDisabledThrows()
    {
        await Assert.ThrowsAsync<ClashConfigException>(() => ClashRuntime.StartAsync(new ClashRuntimeOptions
        {
            HomeDir = Path.Combine(_home, "empty"),
            LoggerFactory = NullLoggerFactory.Instance,
            StartListeners = false,
            CreateDefaultConfigIfMissing = false,
        }));
    }

    [Fact]
    public void ResolveConfigPathProbesTheStandardLocations()
    {
        Assert.Null(ClashRuntime.ResolveConfigPath(null, Path.Combine(_home, "nope")));

        var directory = Path.Combine(_home, "probe");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "config.yaml");
        File.WriteAllText(path, "port: 1\n");

        Assert.Equal(path, ClashRuntime.ResolveConfigPath(null, directory));
        Assert.Equal(path, ClashRuntime.ResolveConfigPath(path, directory));
    }
}
