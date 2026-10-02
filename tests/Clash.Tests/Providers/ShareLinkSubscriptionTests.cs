using System.Text;
using Clash.Core.Providers;
using Xunit;

namespace Clash.Tests.Providers;

public sealed class ShareLinkSubscriptionTests
{
    private static readonly ShareLinkParser Parser = new();

    private const string SsLink = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#Hong%20Kong";
    private const string TrojanLink = "trojan://pw@trojan.example.com:443#Trojan%20Node";

    // ── base64 ───────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesABase64EncodedLinkList()
    {
        var links = string.Join('\n', SsLink, TrojanLink);
        var content = Convert.ToBase64String(Encoding.UTF8.GetBytes(links));

        var entries = Parser.ParseSubscription(content);

        Assert.Equal(2, entries.Count);
        Assert.Equal("Hong Kong", entries[0].Name);
        Assert.Equal("ss", entries[0].Type);
        Assert.Equal("Trojan Node", entries[1].Name);
        Assert.Equal("trojan", entries[1].Type);
    }

    [Fact]
    public void ParsesAUrlSafeBase64EncodedLinkList()
    {
        var links = string.Join('\n', SsLink, TrojanLink);
        var content = Convert.ToBase64String(Encoding.UTF8.GetBytes(links)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var entries = Parser.ParseSubscription(content);

        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public void ParsesBase64WithWrappedLines()
    {
        var links = string.Join('\n', SsLink, TrojanLink);
        var content = Convert.ToBase64String(Encoding.UTF8.GetBytes(links));

        var wrapped = string.Join('\n', content.Chunk(16).Select(chunk => new string(chunk)));

        Assert.Equal(2, Parser.ParseSubscription(wrapped).Count);
    }

    // ── plain ────────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesAPlainLinkListWithCrLf()
    {
        var entries = Parser.ParseSubscription($"{SsLink}\r\n{TrojanLink}\r\n");

        Assert.Equal(2, entries.Count);
        Assert.Equal("Hong Kong", entries[0].Name);
        Assert.Equal("Trojan Node", entries[1].Name);
    }

    [Fact]
    public void ParsesASpaceSeparatedLinkList()
    {
        var entries = Parser.ParseSubscription($"{SsLink} {TrojanLink}");

        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public void SkipsBlankLinesAndComments()
    {
        var content = $"# my subscription\n\n// another comment\n{SsLink}\n\n{TrojanLink}\n";

        var entries = Parser.ParseSubscription(content);

        Assert.Equal(2, entries.Count);
        Assert.Equal(new[] {"Hong Kong", "Trojan Node"}, entries.Select(e => e.Name));
    }

    [Fact]
    public void SkipsUnknownSchemesWithoutLosingTheRest()
    {
        var entries = Parser.ParseSubscription($"garbage://nope\n{SsLink}\nnot even a link\n{TrojanLink}");

        Assert.Equal(2, entries.Count);
    }

    // ── Clash YAML ───────────────────────────────────────────────────────────

    [Fact]
    public void ParsesAClashDocumentAndIgnoresProxyGroups()
    {
        const string yaml = """
            mixed-port: 7890
            proxies:
              - name: "yaml ss"
                type: ss
                server: yaml.example.com
                port: 8388
                cipher: aes-128-gcm
                password: pw
              - name: "yaml vmess"
                type: vmess
                server: vmess.example.com
                port: 443
                uuid: uuid-1
                alterId: 0
                cipher: auto
            proxy-groups:
              - name: PROXY
                type: select
                proxies: ["yaml ss", "yaml vmess"]
            rules:
              - MATCH,PROXY
            """;

        var entries = Parser.ParseSubscription(yaml);

        Assert.Equal(2, entries.Count);
        Assert.Equal(new[] {"yaml ss", "yaml vmess"}, entries.Select(e => e.Name));
        Assert.Equal("ss", entries[0].Type);
        Assert.Equal("yaml.example.com", entries[0].Map.GetString("server"));
        Assert.Equal(8388, entries[0].Map.GetInt("port"));
        Assert.Equal("vmess", entries[1].Type);
        Assert.DoesNotContain(entries, e => e.Type == "select");
    }

    [Fact]
    public void ParsesABareYamlProxyList()
    {
        const string yaml = """
            - name: bare
              type: ss
              server: bare.example.com
              port: 8388
              cipher: aes-128-gcm
              password: pw
            """;

        var entries = Parser.ParseSubscription(yaml);

        Assert.Single(entries);
        Assert.Equal("bare", entries[0].Name);
    }

    [Fact]
    public void IgnoresProxiesMissingANameOrType()
    {
        const string yaml = """
            proxies:
              - name: "ok"
                type: ss
                server: ok.example.com
                port: 8388
              - server: nameless.example.com
                port: 8388
              - name: "typeless"
                server: typeless.example.com
                port: 8388
            """;

        var entries = Parser.ParseSubscription(yaml);

        Assert.Single(entries);
        Assert.Equal("ok", entries[0].Name);
    }

    // ── SIP008 ───────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesASip008Document()
    {
        const string json = """
            {"version":1,
             "servers":[
               {"server":"1.2.3.4","server_port":8388,"method":"aes-256-gcm","password":"pw","remarks":"SIP008 node"},
               {"server":"5.6.7.8","server_port":8389,"method":"chacha20-ietf-poly1305","password":"pw2",
                "plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=bing.com"}
             ]}
            """;

        var entries = Parser.ParseSubscription(json);

        Assert.Equal(2, entries.Count);

        Assert.Equal("SIP008 node", entries[0].Name);
        Assert.Equal("ss", entries[0].Type);
        Assert.Equal("1.2.3.4", entries[0].Map.GetString("server"));
        Assert.Equal(8388, entries[0].Map.GetInt("port"));
        Assert.Equal("aes-256-gcm", entries[0].Map.GetString("cipher"));
        Assert.Equal("pw", entries[0].Map.GetString("password"));

        Assert.Equal("5.6.7.8:8389", entries[1].Name);
        Assert.Equal("obfs", entries[1].Map.GetString("plugin"));
        Assert.Equal("http", entries[1].Map.GetMap("plugin-opts").GetString("mode"));
        Assert.Equal("bing.com", entries[1].Map.GetMap("plugin-opts").GetString("host"));
    }

    [Fact]
    public void SkipsSip008ServersWithoutAHostOrPort()
    {
        const string json = """
            {"version":1,"servers":[
              {"server":"","server_port":8388,"method":"aes-256-gcm","password":"pw"},
              {"server":"1.2.3.4","method":"aes-256-gcm","password":"pw"},
              {"server":"5.6.7.8","server_port":8389,"method":"aes-256-gcm","password":"pw","remarks":"keep"}
            ]}
            """;

        var entries = Parser.ParseSubscription(json);

        Assert.Single(entries);
        Assert.Equal("keep", entries[0].Name);
    }

    // ── naming ───────────────────────────────────────────────────────────────

    [Fact]
    public void RenamesDuplicateNamesWithinASubscription()
    {
        var content = string.Join('\n', SsLink, SsLink, SsLink);

        var entries = Parser.ParseSubscription(content);

        Assert.Equal(3, entries.Count);
        Assert.Equal(new[] {"Hong Kong", "Hong Kong 2", "Hong Kong 3"}, entries.Select(e => e.Name));
        Assert.All(entries, e => Assert.Equal("1.2.3.4", e.Map.GetString("server")));
    }

    [Fact]
    public void RenamesDuplicatesAcrossMixedVehicles()
    {
        var content = string.Join('\n', SsLink, TrojanLink, SsLink);

        var entries = Parser.ParseSubscription(content);

        Assert.Equal(new[] {"Hong Kong", "Trojan Node", "Hong Kong 2"}, entries.Select(e => e.Name));
    }

    [Fact]
    public void RenamesDuplicatesInsideAClashDocument()
    {
        const string yaml = """
            proxies:
              - name: same
                type: ss
                server: a.example.com
                port: 1
              - name: same
                type: ss
                server: b.example.com
                port: 2
            """;

        var entries = Parser.ParseSubscription(yaml);

        Assert.Equal(new[] {"same", "same 2"}, entries.Select(e => e.Name));
        Assert.Equal("b.example.com", entries[1].Map.GetString("server"));
    }

    // ── degenerate input ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("nothing to see here")]
    [InlineData("!!!not base64 or links!!!")]
    public void DegenerateSubscriptionsProduceNoEntries(string content)
        => Assert.Empty(Parser.ParseSubscription(content));

    [Fact]
    public void NullContentProducesNoEntries() => Assert.Empty(Parser.ParseSubscription(null!));
}
