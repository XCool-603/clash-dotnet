using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Providers;
using Clash.Tests.Outbound;
using Xunit;

namespace Clash.Tests.Providers;

/// <summary>
/// A subscription link has to survive two independent steps: parsing it into a
/// configuration entry, and building a protocol adapter from that entry. Both
/// halves are tested separately — <see cref="ShareLinkParserTests"/> pins the
/// parser's output keys and the outbound tests build adapters from hand-written
/// entries — so nothing until now caught a *disagreement* between them.
/// <para>
/// That disagreement is exactly the failure mode a user would hit: the parser
/// emits <c>cipher</c> while an adapter reads <c>security</c>, the factory throws,
/// and the profile silently drops the node with a "skipping proxy" warning. These
/// tests run the real registry over real links.
/// </para>
/// </summary>
public sealed class ShareLinkToAdapterTests
{
    private static readonly ShareLinkParser Parser = new();

    private static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    /// <summary>Parses a link and builds the adapter the registry would build for it.</summary>
    private static IProxy Build(string link)
    {
        var entry = Parser.Parse(link)
                    ?? throw new Xunit.Sdk.XunitException($"the link did not parse: {link}");
        return OutboundHarness.Build(entry);
    }

    private static (string Host, int Port) Endpoint(IProxy proxy)
    {
        var outbound = Assert.IsAssignableFrom<IOutboundProxy>(proxy);
        return (outbound.ServerHost ?? string.Empty, outbound.ServerPort);
    }

    [Fact]
    public void ShadowsocksLinkBuildsAnAdapter()
    {
        var proxy = Build($"ss://{B64("aes-256-gcm:passw0rd")}@ss.example.com:8388#node");

        Assert.Equal("Shadowsocks", proxy.TypeName);
        Assert.Equal(("ss.example.com", 8388), Endpoint(proxy));
    }

    [Fact]
    public void VmessLinkBuildsAnAdapter()
    {
        // The parser emits `cipher`; the adapter must accept that spelling.
        var json = """
            {"v":"2","ps":"node","add":"vmess.example.com","port":"443",
             "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto",
             "net":"ws","type":"none","host":"vmess.example.com","path":"/ws",
             "tls":"tls","sni":"vmess.example.com"}
            """;

        var proxy = Build("vmess://" + B64(json));

        Assert.Equal("Vmess", proxy.TypeName);
        Assert.Equal(("vmess.example.com", 443), Endpoint(proxy));
    }

    [Fact]
    public void VlessLinkBuildsAnAdapter()
    {
        var link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443" +
                   "?encryption=none&security=tls&type=ws&host=vless.example.com&path=%2Fws" +
                   "&sni=vless.example.com#node";

        var proxy = Build(link);

        Assert.Equal("Vless", proxy.TypeName);
        Assert.Equal(("vless.example.com", 443), Endpoint(proxy));
    }

    [Fact]
    public void VlessVisionLinkBuildsAnAdapter()
    {
        // `flow` is the one option that changes the wire format, so it has to
        // survive parsing and be accepted by the adapter.
        var link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443" +
                   "?encryption=none&security=tls&type=tcp&flow=xtls-rprx-vision" +
                   "&sni=vless.example.com#vision";

        var proxy = Build(link);

        Assert.Equal("Vless", proxy.TypeName);
        Assert.Equal(("vless.example.com", 443), Endpoint(proxy));
    }

    [Fact]
    public void VlessRealityLinkIsParsedButRefusedWithAReason()
    {
        // Parsing must succeed — the node is real — and the adapter must refuse
        // it loudly rather than dialling a plain TLS handshake at a REALITY peer.
        var link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443" +
                   "?encryption=none&security=reality&pbk=0123456789abcdef&sid=ab&sni=www.example.com#reality";

        var entry = Parser.Parse(link);
        Assert.NotNull(entry);

        var exception = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry!));
        Assert.Contains("reality", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TrojanLinkBuildsAnAdapter()
    {
        var proxy = Build("trojan://password123@trojan.example.com:443?sni=trojan.example.com#node");

        Assert.Equal("Trojan", proxy.TypeName);
        Assert.Equal(("trojan.example.com", 443), Endpoint(proxy));
    }

    [Fact]
    public void MieruLinkBuildsAnAdapter()
    {
        var link = "mieru://mieru-user:mieru-pw@mieru.example.com:8964" +
                   "?transport=TCP&multiplexing=OFF#Mieru";

        var proxy = Build(link);

        Assert.Equal("Mieru", proxy.TypeName);
        Assert.Equal(("mieru.example.com", 8964), Endpoint(proxy));
    }

    [Fact]
    public void MieruLinkWithMultiplexingIsRefusedWithAReason()
    {
        var link = "mieru://mieru-user:mieru-pw@mieru.example.com:8964" +
                   "?transport=TCP&multiplexing=MULTIPLEXING_LOW#Mieru";

        var entry = Parser.Parse(link);
        Assert.NotNull(entry);

        var exception = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry!));
        Assert.Contains("multiplex", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EveryBuiltinPseudoNodeBuildsAnAdapter()
    {
        foreach (var name in new[] { "DIRECT", "REJECT", "REJECT-DROP" })
        {
            var proxy = Build(name);
            Assert.False(string.IsNullOrEmpty(proxy.TypeName));
            Assert.Equal(name, proxy.Name);
        }
    }
}
