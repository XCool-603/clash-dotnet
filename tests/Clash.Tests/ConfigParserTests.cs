using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Xunit;

namespace Clash.Tests;

public class ConfigParserTests
{
    private const string Sample = """
        port: 7890
        socks-port: 7891
        mixed-port: 7892
        allow-lan: true
        bind-address: '*'
        mode: rule
        log-level: warning
        ipv6: false
        external-controller: 127.0.0.1:9090
        secret: "s3cr3t"
        unified-delay: true
        tcp-concurrent: true

        dns:
          enable: true
          listen: 0.0.0.0:1053
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          fake-ip-filter:
            - '*.lan'
            - '+.local'
          nameserver:
            - 223.5.5.5
            - tls://1.1.1.1:853

        proxies:
          - name: "ss1"
            type: ss
            server: example.com
            port: 443
            cipher: aes-256-gcm
            password: "pw"
          - name: "http1"
            type: http
            server: 1.2.3.4
            port: 8080
            tls: true
            skip-cert-verify: true

        proxy-groups:
          - name: PROXY
            type: select
            proxies: [ss1, http1, DIRECT]
          - name: AUTO
            type: url-test
            use: [provider1]
            url: http://www.gstatic.com/generate_204
            interval: 300
            tolerance: 50

        proxy-providers:
          provider1:
            type: http
            url: "https://example.com/sub"
            path: ./providers/provider1.yaml
            interval: 3600
            health-check:
              enable: true
              url: http://www.gstatic.com/generate_204
              interval: 300

        rule-providers:
          reject:
            type: http
            behavior: domain
            format: yaml
            url: "https://example.com/reject.yaml"
            path: ./ruleset/reject.yaml
            interval: 86400

        rules:
          - DOMAIN-SUFFIX,google.com,PROXY
          - DOMAIN-KEYWORD,ads,REJECT
          - GEOIP,CN,DIRECT
          - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
          - RULE-SET,reject,REJECT
          - MATCH,PROXY
        """;

    [Fact]
    public void ParsesTopLevelScalars()
    {
        var config = ConfigParser.Parse(YamlReader.Parse(Sample));

        Assert.Equal(7890, config.Port);
        Assert.Equal(7891, config.SocksPort);
        Assert.Equal(7892, config.MixedPort);
        Assert.True(config.AllowLan);
        Assert.Equal("*", config.BindAddress);
        Assert.Equal(Mode.Rule, config.Mode);
        Assert.Equal("warning", config.LogLevel);
        Assert.Equal("127.0.0.1:9090", config.ExternalController);
        Assert.Equal("s3cr3t", config.Secret);
        Assert.True(config.UnifiedDelay);
        Assert.True(config.TcpConcurrent);
    }

    [Fact]
    public void ParsesDnsSection()
    {
        var dns = ConfigParser.Parse(YamlReader.Parse(Sample)).Dns;

        Assert.True(dns.Enable);
        Assert.Equal("0.0.0.0:1053", dns.Listen);
        Assert.Equal("fake-ip", dns.EnhancedMode);
        Assert.Equal("198.18.0.1/16", dns.FakeIpRange);
        Assert.Equal(["*.lan", "+.local"], dns.FakeIpFilter);
        Assert.Equal(["223.5.5.5", "tls://1.1.1.1:853"], dns.Nameserver);
    }

    [Fact]
    public void ParsesProxiesAndGroups()
    {
        var config = ConfigParser.Parse(YamlReader.Parse(Sample));

        Assert.Equal(2, config.Proxies.Count);
        Assert.Equal("ss1", config.Proxies[0].Name);
        Assert.Equal("ss", config.Proxies[0].Type);
        Assert.Equal("aes-256-gcm", config.Proxies[0].Map.GetString("cipher"));
        Assert.True(config.Proxies[1].Map.GetBool("tls"));

        Assert.Equal(2, config.ProxyGroups.Count);
        Assert.Equal(["ss1", "http1", "DIRECT"], config.ProxyGroups[0].Proxies);
        Assert.Equal("url-test", config.ProxyGroups[1].Type);
        Assert.Equal(["provider1"], config.ProxyGroups[1].Use);
        Assert.Equal(50, config.ProxyGroups[1].Tolerance);
    }

    [Fact]
    public void ParsesProvidersAndRules()
    {
        var config = ConfigParser.Parse(YamlReader.Parse(Sample));

        Assert.True(config.ProxyProviders.TryGetValue("provider1", out var provider));
        Assert.Equal("http", provider.Type);
        Assert.True(provider.HealthCheck.Enable);
        Assert.Equal(300, provider.HealthCheck.Interval);

        Assert.True(config.RuleProviders.TryGetValue("reject", out var ruleSet));
        Assert.Equal("domain", ruleSet.Behavior);
        Assert.Equal("yaml", ruleSet.Format);

        Assert.Equal(6, config.Rules.Count);
        Assert.Equal("MATCH,PROXY", config.Rules[^1]);
    }

    [Fact]
    public void PreservesUnknownKeysInRaw()
    {
        var config = ConfigParser.Parse(YamlReader.Parse("port: 1\nsome-future-key: hello\n"));
        Assert.Equal("hello", config.Raw.GetString("some-future-key"));
    }

    [Fact]
    public void RejectsNonMappingRoot()
    {
        Assert.Throws<ClashConfigException>(() => ConfigParser.Parse(YamlReader.Parse("- a\n- b\n")));
    }

    [Fact]
    public void YamlMapCoercesLooseScalars()
    {
        var map = YamlReader.Parse("""
            quoted-int: "8080"
            bool-string: "true"
            real-bool: true
            list: [1, two, 3.5]
            nested:
              a: 1
            """);

        Assert.Equal(8080, map.GetInt("quoted-int"));
        Assert.True(map.GetBool("bool-string"));
        Assert.True(map.GetBool("real-bool"));
        Assert.Equal(3, map.GetStringList("list").Count);
        Assert.Equal(1, map.GetMap("nested").GetInt("a"));
    }

    [Fact]
    public void ParsesNameServerUris()
    {
        var tls = NameServerParser.Parse("tls://1.1.1.1:853");
        Assert.Equal(NameServerParser.Transport.Tls, tls.Transport);
        Assert.Equal("1.1.1.1", tls.Host);
        Assert.Equal(853, tls.Port);

        var doh = NameServerParser.Parse("https://dns.google/dns-query");
        Assert.Equal(NameServerParser.Transport.Https, doh.Transport);
        Assert.Equal("dns.google", doh.Host);
        Assert.Equal(443, doh.Port);
        Assert.Equal("/dns-query", doh.Path);

        var plain = NameServerParser.Parse("223.5.5.5");
        Assert.Equal(NameServerParser.Transport.Udp, plain.Transport);
        Assert.Equal(53, plain.Port);
    }
}
