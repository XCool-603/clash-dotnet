using System.Text;
using Clash.Core.Configuration;
using Clash.Core.Providers;
using Xunit;

namespace Clash.Tests.Providers;

public sealed class ShareLinkParserTests
{
    private static readonly ShareLinkParser Parser = new();

    private static ProxyConfigEntry Parse(string link)
        => Parser.Parse(link) ?? throw new Xunit.Sdk.XunitException($"expected the link to parse: {link}");

    private static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    private static string B64Url(string text)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ── ss ───────────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesSip002ShadowsocksLink()
    {
        var entry = Parse($"ss://{B64("aes-256-gcm:passw0rd")}@example.com:8388#%E9%A6%99%E6%B8%AF%2001");

        Assert.Equal("香港 01", entry.Name);
        Assert.Equal("ss", entry.Type);
        Assert.Equal("example.com", entry.Map.GetString("server"));
        Assert.Equal(8388, entry.Map.GetInt("port"));
        Assert.Equal("aes-256-gcm", entry.Map.GetString("cipher"));
        Assert.Equal("passw0rd", entry.Map.GetString("password"));
    }

    [Fact]
    public void ParsesSip002WithUnpaddedBase64UserInfo()
    {
        var entry = Parse($"ss://{B64("chacha20-ietf-poly1305:pw").TrimEnd('=')}@1.2.3.4:8388#node");

        Assert.Equal("chacha20-ietf-poly1305", entry.Map.GetString("cipher"));
        Assert.Equal("pw", entry.Map.GetString("password"));
    }

    [Fact]
    public void ParsesObfsPluginOptions()
    {
        var plugin = Uri.EscapeDataString("obfs-local;obfs=http;obfs-host=bing.com");
        var entry = Parse($"ss://{B64("aes-128-gcm:pw")}@1.2.3.4:8388?plugin={plugin}#obfs-node");

        Assert.Equal("obfs", entry.Map.GetString("plugin"));

        var options = entry.Map.GetMap("plugin-opts");
        Assert.Equal("http", options.GetString("mode"));
        Assert.Equal("bing.com", options.GetString("host"));
    }

    [Fact]
    public void ParsesV2rayPluginOptions()
    {
        var plugin = Uri.EscapeDataString("v2ray-plugin;mode=websocket;host=cdn.example.com;path=/ws;tls;mux=8");
        var entry = Parse($"ss://{B64("aes-128-gcm:pw")}@1.2.3.4:8388?plugin={plugin}#v2ray-node");

        Assert.Equal("v2ray-plugin", entry.Map.GetString("plugin"));

        var options = entry.Map.GetMap("plugin-opts");
        Assert.Equal("websocket", options.GetString("mode"));
        Assert.Equal("cdn.example.com", options.GetString("host"));
        Assert.Equal("/ws", options.GetString("path"));
        Assert.True(options.GetBool("tls"));
        Assert.True(options.GetBool("mux"));
    }

    [Fact]
    public void ParsesShadowTlsPluginOptions()
    {
        var plugin = Uri.EscapeDataString("shadow-tls;host=gateway.example.com;password=stls-pw;version=3");
        var entry = Parse($"ss://{B64("aes-128-gcm:pw")}@1.2.3.4:8388?plugin={plugin}#stls");

        Assert.Equal("shadow-tls", entry.Map.GetString("plugin"));

        var options = entry.Map.GetMap("plugin-opts");
        Assert.Equal("gateway.example.com", options.GetString("host"));
        Assert.Equal("stls-pw", options.GetString("password"));
        Assert.Equal(3, options.GetInt("version"));
    }

    [Fact]
    public void ParsesRestlsPluginOptions()
    {
        var plugin = Uri.EscapeDataString("restls;host=restls.example.com;password=restls-pw;version-hint=tls13;restls-script=300:1000,5");
        var entry = Parse($"ss://{B64("aes-128-gcm:pw")}@1.2.3.4:8388?plugin={plugin}#restls");

        Assert.Equal("restls", entry.Map.GetString("plugin"));

        var options = entry.Map.GetMap("plugin-opts");
        Assert.Equal("restls.example.com", options.GetString("host"));
        Assert.Equal("restls-pw", options.GetString("password"));
        Assert.Equal("tls13", options.GetString("version-hint"));
        Assert.Equal("300:1000,5", options.GetString("restls-script"));
    }

    [Fact]
    public void ParsesLegacyShadowsocksLink()
    {
        var entry = Parse($"ss://{B64("aes-256-cfb:legacy-pw@legacy.example.com:8388")}#Legacy");

        Assert.Equal("Legacy", entry.Name);
        Assert.Equal("legacy.example.com", entry.Map.GetString("server"));
        Assert.Equal(8388, entry.Map.GetInt("port"));
        Assert.Equal("aes-256-cfb", entry.Map.GetString("cipher"));
        Assert.Equal("legacy-pw", entry.Map.GetString("password"));
    }

    [Fact]
    public void ParsesLegacyShadowsocksLinkWithEmbeddedPlugin()
    {
        var inner = "aes-256-cfb:legacy-pw@legacy.example.com:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dlegacy.example.com";
        var entry = Parse($"ss://{B64(inner)}#LegacyPlugin");

        Assert.Equal("obfs", entry.Map.GetString("plugin"));
        Assert.Equal("tls", entry.Map.GetMap("plugin-opts").GetString("mode"));
        Assert.Equal("legacy.example.com", entry.Map.GetMap("plugin-opts").GetString("host"));
    }

    [Fact]
    public void FallsBackToHostAndPortWhenTheFragmentIsMissing()
    {
        var entry = Parse($"ss://{B64("aes-256-gcm:pw")}@1.2.3.4:8388");

        Assert.Equal("1.2.3.4:8388", entry.Name);
    }

    // ── ssr ──────────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesShadowsocksRLink()
    {
        var password = B64Url("realpassword");
        var payload =
            $"ssr.example.com:443:auth_aes128_md5:aes-256-cfb:plain:{password}/" +
            $"?obfsparam={B64Url("cloud.example.com")}&protoparam={B64Url("12345:abc")}" +
            $"&remarks={B64Url("SSR node")}&group={B64Url("my-group")}";

        var entry = Parse("ssr://" + B64Url(payload));

        Assert.Equal("SSR node", entry.Name);
        Assert.Equal("ssr", entry.Type);
        Assert.Equal("ssr.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("aes-256-cfb", entry.Map.GetString("cipher"));
        Assert.Equal("realpassword", entry.Map.GetString("password"));
        Assert.Equal("auth_aes128_md5", entry.Map.GetString("protocol"));
        Assert.Equal("plain", entry.Map.GetString("obfs"));
        Assert.Equal("12345:abc", entry.Map.GetString("protocol-param"));
        Assert.Equal("cloud.example.com", entry.Map.GetString("obfs-param"));
    }

    // ── vmess ────────────────────────────────────────────────────────────────

    private static string VmessLink(string json) => "vmess://" + B64(json);

    [Fact]
    public void ParsesVmessWebSocketLink()
    {
        var entry = Parse(VmessLink("""
            {"v":"2","ps":"VMess WS","add":"vmess.example.com","port":"443",
             "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto",
             "net":"ws","type":"none","host":"cdn.example.com","path":"/ws",
             "tls":"tls","sni":"sni.example.com","alpn":"h2,http/1.1","fp":"chrome"}
            """));

        Assert.Equal("VMess WS", entry.Name);
        Assert.Equal("vmess", entry.Type);
        Assert.Equal("vmess.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("b831381d-6324-4d53-ad4f-8cda48b30811", entry.Map.GetString("uuid"));
        Assert.Equal(0, entry.Map.GetInt("alterId"));
        Assert.Equal("auto", entry.Map.GetString("cipher"));
        Assert.True(entry.Map.GetBool("tls"));
        Assert.Equal("sni.example.com", entry.Map.GetString("servername"));
        Assert.Equal("ws", entry.Map.GetString("network"));
        Assert.Equal("chrome", entry.Map.GetString("client-fingerprint"));
        Assert.Equal(new[] {"h2", "http/1.1"}, entry.Map.GetStringList("alpn"));

        var ws = entry.Map.GetMap("ws-opts");
        Assert.Equal("/ws", ws.GetString("path"));
        Assert.Equal("cdn.example.com", ws.GetMap("headers").GetString("Host"));
    }

    [Fact]
    public void ParsesVmessGrpcLink()
    {
        var entry = Parse(VmessLink("""
            {"v":"2","ps":"VMess gRPC","add":"grpc.example.com","port":443,
             "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"scy":"auto",
             "net":"grpc","path":"grpc-service","tls":"tls","sni":"grpc.example.com"}
            """));

        Assert.Equal("grpc", entry.Map.GetString("network"));
        Assert.Equal("grpc-service", entry.Map.GetMap("grpc-opts").GetString("grpc-service-name"));
        Assert.True(entry.Map.GetBool("tls"));
    }

    [Fact]
    public void ParsesVmessHttpObfuscationLink()
    {
        var entry = Parse(VmessLink("""
            {"v":"2","ps":"VMess HTTP","add":"http.example.com","port":80,
             "id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,
             "net":"tcp","type":"http","host":"obfs.example.com","path":"/httppath"}
            """));

        Assert.Equal("http", entry.Map.GetString("network"));

        var http = entry.Map.GetMap("http-opts");
        Assert.Equal("GET", http.GetString("method"));
        Assert.Equal(new[] {"/httppath"}, http.GetStringList("path"));
        Assert.Equal(new[] {"obfs.example.com"}, http.GetMap("headers").GetStringList("Host"));
    }

    [Fact]
    public void VmessFallsBackToTheFragmentForItsName()
    {
        var entry = Parse(VmessLink("""{"v":"2","add":"1.2.3.4","port":"443","id":"u","net":"tcp"}""") + "#Fragment%20Name");

        Assert.Equal("Fragment Name", entry.Name);
    }

    // ── vless ────────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesVlessWebSocketTlsLink()
    {
        var entry = Parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443" +
            "?encryption=none&security=tls&sni=sni.example.com&fp=chrome&flow=xtls-rprx-vision" +
            "&type=ws&host=cdn.example.com&path=%2Fws#VLESS%20WS");

        Assert.Equal("VLESS WS", entry.Name);
        Assert.Equal("vless", entry.Type);
        Assert.Equal("vless.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("b831381d-6324-4d53-ad4f-8cda48b30811", entry.Map.GetString("uuid"));
        Assert.True(entry.Map.GetBool("tls"));
        Assert.Equal("sni.example.com", entry.Map.GetString("servername"));
        Assert.Equal("xtls-rprx-vision", entry.Map.GetString("flow"));
        Assert.Equal("chrome", entry.Map.GetString("client-fingerprint"));
        Assert.Equal("ws", entry.Map.GetString("network"));
        Assert.Equal("/ws", entry.Map.GetMap("ws-opts").GetString("path"));
        Assert.Equal("cdn.example.com", entry.Map.GetMap("ws-opts").GetMap("headers").GetString("Host"));
    }

    [Fact]
    public void ParsesVlessRealityGrpcLink()
    {
        var entry = Parse(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443" +
            "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBLICKEY&sid=abcd&spx=%2F" +
            "&type=grpc&serviceName=grpc-service&flow=xtls-rprx-vision#Reality");

        Assert.True(entry.Map.GetBool("tls"));

        var reality = entry.Map.GetMap("reality-opts");
        Assert.Equal("PUBLICKEY", reality.GetString("public-key"));
        Assert.Equal("abcd", reality.GetString("short-id"));
        Assert.Equal("/", reality.GetString("spider-x"));

        Assert.Equal("grpc", entry.Map.GetString("network"));
        Assert.Equal("grpc-service", entry.Map.GetMap("grpc-opts").GetString("grpc-service-name"));
    }

    [Fact]
    public void ParsesVlessWithoutSecurity()
    {
        var entry = Parse("vless://uuid-1@1.2.3.4:80?encryption=none&security=none&type=tcp#Plain");

        Assert.False(entry.Map.GetBool("tls"));
        Assert.False(entry.Map.Has("reality-opts"));
        Assert.Equal("tcp", entry.Map.GetString("network"));
    }

    // ── trojan ───────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesTrojanWebSocketLink()
    {
        var entry = Parse(
            "trojan://password123@trojan.example.com:443" +
            "?sni=trojan.example.com&allowInsecure=1&type=ws&path=%2Fws&host=cdn.example.com&alpn=h2%2Chttp%2F1.1#Trojan");

        Assert.Equal("Trojan", entry.Name);
        Assert.Equal("trojan", entry.Type);
        Assert.Equal("trojan.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("password123", entry.Map.GetString("password"));
        Assert.Equal("trojan.example.com", entry.Map.GetString("sni"));
        Assert.True(entry.Map.GetBool("skip-cert-verify"));
        Assert.Equal(new[] {"h2", "http/1.1"}, entry.Map.GetStringList("alpn"));
        Assert.Equal("ws", entry.Map.GetString("network"));
        Assert.Equal("/ws", entry.Map.GetMap("ws-opts").GetString("path"));
        Assert.Equal("cdn.example.com", entry.Map.GetMap("ws-opts").GetMap("headers").GetString("Host"));
    }

    [Fact]
    public void ParsesPlainTrojanLink()
    {
        var entry = Parse("trojan://pw@trojan.example.com:443#Plain");

        Assert.False(entry.Map.Has("network"));
        Assert.Equal("pw", entry.Map.GetString("password"));
    }

    // ── hysteria ─────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("hysteria2")]
    [InlineData("hy2")]
    public void ParsesHysteria2Link(string scheme)
    {
        var entry = Parse(
            $"{scheme}://letmein@hy2.example.com:443" +
            "?sni=hy2.example.com&insecure=1&obfs=salamander&obfs-password=obfspw&pinSHA256=deadbeef#HY2");

        Assert.Equal("HY2", entry.Name);
        Assert.Equal("hysteria2", entry.Type);
        Assert.Equal("hy2.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("letmein", entry.Map.GetString("password"));
        Assert.Equal("hy2.example.com", entry.Map.GetString("sni"));
        Assert.True(entry.Map.GetBool("skip-cert-verify"));
        Assert.Equal("salamander", entry.Map.GetString("obfs"));
        Assert.Equal("obfspw", entry.Map.GetString("obfs-password"));
        Assert.Equal("deadbeef", entry.Map.GetString("fingerprint"));
    }

    [Fact]
    public void ParsesHysteriaV1Link()
    {
        var entry = Parse(
            "hysteria://hysteria.example.com:443" +
            "?protocol=udp&auth=secret&peer=peer.example.com&insecure=1&upmbps=100&downmbps=200&alpn=h3#HY1");

        Assert.Equal("HY1", entry.Name);
        Assert.Equal("hysteria", entry.Type);
        Assert.Equal("hysteria.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("secret", entry.Map.GetString("auth-str"));
        Assert.Equal("udp", entry.Map.GetString("protocol"));
        Assert.Equal("peer.example.com", entry.Map.GetString("sni"));
        Assert.True(entry.Map.GetBool("skip-cert-verify"));
        Assert.Equal("100", entry.Map.GetString("up"));
        Assert.Equal("200", entry.Map.GetString("down"));
        Assert.Equal(new[] {"h3"}, entry.Map.GetStringList("alpn"));
    }

    // ── tuic ─────────────────────────────────────────────────────────────────

    [Fact]
    public void ParsesTuicLink()
    {
        var entry = Parse(
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:tuic-pw@tuic.example.com:443" +
            "?sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#TUIC");

        Assert.Equal("TUIC", entry.Name);
        Assert.Equal("tuic", entry.Type);
        Assert.Equal("tuic.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("b831381d-6324-4d53-ad4f-8cda48b30811", entry.Map.GetString("uuid"));
        Assert.Equal("tuic-pw", entry.Map.GetString("password"));
        Assert.Equal("tuic.example.com", entry.Map.GetString("sni"));
        Assert.Equal(new[] {"h3"}, entry.Map.GetStringList("alpn"));
        Assert.Equal("bbr", entry.Map.GetString("congestion-controller"));
        Assert.Equal("native", entry.Map.GetString("udp-relay-mode"));
    }

    // ── socks / http ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("socks", "socks5")]
    [InlineData("socks5", "socks5")]
    [InlineData("socks5h", "socks5")]
    public void ParsesSocksLinks(string scheme, string expectedType)
    {
        var entry = Parse($"{scheme}://user:pass@socks.example.com:1080#SOCKS");

        Assert.Equal(expectedType, entry.Type);
        Assert.Equal("socks.example.com", entry.Map.GetString("server"));
        Assert.Equal(1080, entry.Map.GetInt("port"));
        Assert.Equal("user", entry.Map.GetString("username"));
        Assert.Equal("pass", entry.Map.GetString("password"));
        Assert.False(entry.Map.GetBool("tls"));
    }

    [Fact]
    public void ParsesSocksLinkWithBase64Credentials()
    {
        var entry = Parse($"socks5://{B64("user:pass")}@socks.example.com:1080#SOCKS");

        Assert.Equal("user", entry.Map.GetString("username"));
        Assert.Equal("pass", entry.Map.GetString("password"));
    }

    [Fact]
    public void ParsesHttpLinkWithoutTls()
    {
        var entry = Parse("http://user:pass@http.example.com:8080#HTTP");

        Assert.Equal("http", entry.Type);
        Assert.Equal("http.example.com", entry.Map.GetString("server"));
        Assert.Equal(8080, entry.Map.GetInt("port"));
        Assert.Equal("user", entry.Map.GetString("username"));
        Assert.False(entry.Map.GetBool("tls"));
    }

    [Fact]
    public void ParsesHttpsLinkWithTls()
    {
        var entry = Parse("https://https.example.com:8443#HTTPS");

        Assert.Equal("http", entry.Type);
        Assert.Equal(8443, entry.Map.GetInt("port"));
        Assert.True(entry.Map.GetBool("tls"));
    }

    // ── snell / wireguard / anytls / mieru ───────────────────────────────────

    [Fact]
    public void ParsesSnellLink()
    {
        var entry = Parse("snell://psk123@snell.example.com:443?version=4&obfs=http&obfs-host=bing.com#Snell");

        Assert.Equal("snell", entry.Type);
        Assert.Equal("snell.example.com", entry.Map.GetString("server"));
        Assert.Equal(443, entry.Map.GetInt("port"));
        Assert.Equal("psk123", entry.Map.GetString("psk"));
        Assert.Equal(4, entry.Map.GetInt("version"));
        Assert.Equal("http", entry.Map.GetMap("obfs-opts").GetString("mode"));
        Assert.Equal("bing.com", entry.Map.GetMap("obfs-opts").GetString("host"));
    }

    [Fact]
    public void ParsesWireGuardLink()
    {
        var key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        var entry = Parse(
            $"wireguard://{Uri.EscapeDataString(key)}@wg.example.com:51820" +
            "?publickey=yAnz5TF%2BlXXJte14tji3zlMNq%2Bhd2rYUIgJBgB3fBmk%3D&address=10.0.0.2%2F32&mtu=1420" +
            "&reserved=1%2C2%2C3&dns=1.1.1.1#WG");

        Assert.Equal("WG", entry.Name);
        Assert.Equal("wireguard", entry.Type);
        Assert.Equal("wg.example.com", entry.Map.GetString("server"));
        Assert.Equal(51820, entry.Map.GetInt("port"));
        Assert.Equal(key, entry.Map.GetString("private-key"));
        Assert.Equal(key, entry.Map.GetString("public-key"));
        Assert.Equal(new[] {"10.0.0.2/32"}, entry.Map.GetStringList("ip"));
        Assert.Equal(1420, entry.Map.GetInt("mtu"));
        Assert.Equal(new object?[] { 1, 2, 3 }, entry.Map.GetList("reserved"));
        Assert.Equal(new[] {"1.1.1.1"}, entry.Map.GetStringList("dns"));
    }

    [Fact]
    public void ParsesAnyTlsLink()
    {
        var entry = Parse("anytls://anytls-pw@anytls.example.com:8443?sni=anytls.example.com&insecure=1#AnyTLS");

        Assert.Equal("anytls", entry.Type);
        Assert.Equal("anytls.example.com", entry.Map.GetString("server"));
        Assert.Equal(8443, entry.Map.GetInt("port"));
        Assert.Equal("anytls-pw", entry.Map.GetString("password"));
        Assert.Equal("anytls.example.com", entry.Map.GetString("sni"));
        Assert.True(entry.Map.GetBool("skip-cert-verify"));
    }

    [Fact]
    public void ParsesMieruLink()
    {
        var entry = Parse("mieru://mieru-user:mieru-pw@mieru.example.com:8964?transport=TCP&multiplexing=MULTIPLEXING_LOW#Mieru");

        Assert.Equal("mieru", entry.Type);
        Assert.Equal("mieru.example.com", entry.Map.GetString("server"));
        Assert.Equal(8964, entry.Map.GetInt("port"));
        Assert.Equal("mieru-user", entry.Map.GetString("username"));
        Assert.Equal("mieru-pw", entry.Map.GetString("password"));
        Assert.Equal("TCP", entry.Map.GetString("transport"));
        Assert.Equal("MULTIPLEXING_LOW", entry.Map.GetString("multiplexing"));
    }

    // ── built-ins ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("DIRECT", "direct")]
    [InlineData("direct", "direct")]
    [InlineData("REJECT", "reject")]
    [InlineData("REJECT-DROP", "reject")]
    public void ParsesBuiltinPseudoNodes(string link, string expectedType)
    {
        var entry = Parse(link);

        Assert.Equal(expectedType, entry.Type);
        Assert.Equal(link.ToUpperInvariant(), entry.Name);
    }

    // ── malformed input ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a link at all")]
    [InlineData("://host:443")]
    [InlineData("ss://")]
    [InlineData("ss://!!!not-base64!!!@1.2.3.4:8388")]
    [InlineData("ss://@:0")]
    [InlineData("ss://YWVzLTI1Ni1nY206cA==@host")]
    [InlineData("ss://YWVzLTI1Ni1nY206cA==@host:notaport")]
    [InlineData("ss://YWVzLTI1Ni1nY206cA==@host:99999")]
    [InlineData("ssr://")]
    [InlineData("ssr://bm90LWEtc3NyLXBheWxvYWQ")]
    [InlineData("vmess://")]
    [InlineData("vmess://bm90LWpzb24=")]
    [InlineData("vmess://eyJhZGQiOiIifQ==")]
    [InlineData("vless://")]
    [InlineData("vless://uuid-only")]
    [InlineData("vless://uuid@host")]
    [InlineData("trojan://")]
    [InlineData("trojan://password@host")]
    [InlineData("hysteria2://")]
    [InlineData("hysteria2://auth@host")]
    [InlineData("tuic://")]
    [InlineData("tuic://uuid:pw@host")]
    [InlineData("socks5://host")]
    [InlineData("snell://")]
    [InlineData("wireguard://host")]
    [InlineData("unknownscheme://host:443")]
    [InlineData("http://")]
    public void MalformedLinksReturnNullAndNeverThrow(string link)
    {
        var entry = Record.Exception(() => Parser.Parse(link));

        Assert.Null(entry);
        Assert.Null(Parser.Parse(link));
    }

    [Fact]
    public void NullLinkReturnsNull() => Assert.Null(Parser.Parse(null!));

    [Fact]
    public void TruncatedBase64ReturnsNull()
    {
        Assert.Null(Parser.Parse("vmess://eyJ2IjoiMiIsImFkZCI6ImV4YW1wbGUuY29t"));
        Assert.Null(Parser.Parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ"));
    }
}
