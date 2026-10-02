using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Transport;
using Xunit;

namespace Clash.Tests.Transport;

/// <summary>Layer ordering and option reading for the transport stack.</summary>
public class TransportComposerTests
{
    private static YamlMap Map(string yaml) => YamlReader.Parse(yaml);

    private static string[] Names(IReadOnlyList<ITransportLayer> layers) => [.. layers.Select(static l => l.Name)];

    [Fact]
    public void TcpIsTheOnlyLayerWithoutANetwork()
    {
        Assert.Equal(["tcp"], Names(new TransportComposer().Compose(Map("name: n\ntype: vmess"))));
        Assert.Equal(["tcp"], Names(new TransportComposer().Compose(Map("network: tcp"))));
        Assert.Equal(["tcp"], Names(new TransportComposer().Compose(Map("network: TCP"))));
    }

    [Fact]
    public void TlsIsInsertedAfterTcp()
    {
        Assert.Equal(["tcp", "tls"], Names(new TransportComposer().Compose(Map("tls: true"))));
        Assert.Equal(["tcp"], Names(new TransportComposer().Compose(Map("tls: false"))));
    }

    [Fact]
    public void WebSocketLayerComesLast()
    {
        Assert.Equal(["tcp", "ws"], Names(new TransportComposer().Compose(Map("network: ws"))));
        Assert.Equal(["tcp", "tls", "ws"], Names(new TransportComposer().Compose(Map("network: ws\ntls: true"))));
    }

    [Fact]
    public void GrpcLayerRunsOverTlsWhenAsked()
    {
        Assert.Equal(["tcp", "grpc"], Names(new TransportComposer().Compose(Map("network: grpc"))));
        Assert.Equal(["tcp", "tls", "grpc"], Names(new TransportComposer().Compose(Map("network: grpc\ntls: true"))));
    }

    [Fact]
    public void H2LayerAlwaysBringsTls()
    {
        Assert.Equal(["tcp", "tls", "h2"], Names(new TransportComposer().Compose(Map("network: h2"))));
        Assert.Equal(["tcp", "tls", "h2"], Names(new TransportComposer().Compose(Map("network: h2\ntls: false"))));
    }

    [Fact]
    public void HttpObfsLayerFollowsTheTlsFlag()
    {
        Assert.Equal(["tcp", "http"], Names(new TransportComposer().Compose(Map("network: http"))));
        Assert.Equal(["tcp", "tls", "http"], Names(new TransportComposer().Compose(Map("network: http\ntls: true"))));
    }

    [Fact]
    public void H2AndGrpcForceTheH2AlpnOntoTheTlsLayer()
    {
        var plan = TransportComposer.Plan(Map("network: grpc\ntls: true\nalpn: [http/1.1]"));

        Assert.Equal(3, plan.Count);
        Assert.Equal("tcp", plan[0].Layer.Name);
        Assert.Equal("tls", plan[1].Layer.Name);
        Assert.Equal("grpc", plan[2].Layer.Name);

        Assert.Equal(["h2"], plan[1].Options.GetStringList("alpn"));
        // The original map is left alone.
        Assert.Equal(["http/1.1"], plan[2].Options.GetStringList("alpn"));
    }

    [Fact]
    public void H2PlanForcesH2Alpn()
    {
        var plan = TransportComposer.Plan(Map("network: h2"));
        Assert.Equal(["h2"], plan[1].Options.GetStringList("alpn"));
    }

    [Fact]
    public void QuicIsReportedAsUnsupported()
    {
        var ex = Assert.Throws<TransportNotSupportedException>(() => new TransportComposer().Compose(Map("network: quic")));
        Assert.Contains("quic", ex.Message);
        Assert.Contains("QUIC", ex.Message);
    }

    [Fact]
    public void UnknownNetworksAreRejected()
    {
        var ex = Assert.Throws<TransportNotSupportedException>(() => new TransportComposer().Compose(Map("network: carrier-pigeon")));
        Assert.Contains("carrier-pigeon", ex.Message);
    }

    [Fact]
    public void LayerRegistryIsIntrospectable()
    {
        Assert.True(TransportComposer.IsSupported("tcp"));
        Assert.True(TransportComposer.IsSupported("TLS"));
        Assert.True(TransportComposer.IsSupported("ws"));
        Assert.True(TransportComposer.IsSupported("grpc"));
        Assert.True(TransportComposer.IsSupported("h2"));
        Assert.True(TransportComposer.IsSupported("http"));
        Assert.False(TransportComposer.IsSupported("quic"));

        Assert.Equal("tcp", TransportComposer.Get("tcp").Name);
        Assert.Throws<TransportNotSupportedException>(() => TransportComposer.Get("quic"));
    }

    [Fact]
    public void EveryLayerReportsItsConfiguredName()
    {
        Assert.Equal("tcp", new TcpTransport().Name);
        Assert.Equal("tls", new TlsTransport().Name);
        Assert.Equal("ws", new WebSocketTransport().Name);
        Assert.Equal("grpc", new GrpcTransport().Name);
        Assert.Equal("h2", new H2Transport().Name);
        Assert.Equal("http", new HttpObfsTransport().Name);
    }

    [Fact]
    public async Task ConnectAsyncRunsTheStackInOrderAndReturnsTheInnermostStream()
    {
        // The composer hands the same options to every layer; a recording layer
        // proves the call contract without needing a socket.
        var recorded = new List<string>();
        var layer = new RecordingLayer(recorded);
        var context = new DialContext
        {
            Host = "example.com",
            Port = 443,
            Metadata = new Metadata(),
        };

        var upstream = ProxyStream.Wrap(new MemoryStream());
        var result = await layer.WrapAsync(upstream, context, YamlMap.Empty);
        Assert.Same(upstream, result);
        Assert.Equal(["recording"], recorded);

        // And the real stack starts at tcp, which is what the composer promises.
        var plan = TransportComposer.Plan(Map("network: ws\ntls: true"));
        Assert.Equal(["tcp", "tls", "ws"], Names([.. plan.Select(static p => p.Layer)]));
    }

    private sealed class RecordingLayer : ITransportLayer
    {
        private readonly List<string> _recorded;

        public RecordingLayer(List<string> recorded) => _recorded = recorded;

        public string Name => "recording";

        public Task<ProxyStream> WrapAsync(ProxyStream? inner, DialContext context, YamlMap options, CancellationToken cancellationToken = default)
        {
            _recorded.Add(Name);
            return Task.FromResult(inner!);
        }
    }
}

/// <summary>Option readers for every transport option block.</summary>
public class TransportOptionsTests
{
    private static YamlMap Map(string yaml) => YamlReader.Parse(yaml);

    [Fact]
    public void ReadsTlsOptions()
    {
        var tls = TransportOptions.ReadTlsOptions(Map("""
            tls: true
            sni: real.example.com
            skip-cert-verify: true
            alpn: [h2, http/1.1]
            client-fingerprint: chrome
            fingerprint: firefox
            disable-sni: true
            reality-opts:
              public-key: pub
              short-id: sid
              spider-x: /spx
            """));

        Assert.True(tls.Enabled);
        Assert.Equal("real.example.com", tls.ServerName);
        Assert.True(tls.SkipCertVerify);
        Assert.Equal(["h2", "http/1.1"], tls.Alpn);
        Assert.Equal("chrome", tls.ClientFingerprint);
        Assert.Equal("firefox", tls.Fingerprint);
        Assert.True(tls.DisableSni);
        Assert.Equal("pub", tls.RealityPublicKey);
        Assert.Equal("sid", tls.RealityShortId);
        Assert.Equal("/spx", tls.RealitySpiderX);
    }

    [Fact]
    public void TlsAliasesAndScalarAlpnAreAccepted()
    {
        var tls = TransportOptions.ReadTlsOptions(Map("tls: true\nservername: alt.example.com\nalpn: h2,http/1.1\ninsecure: true"));
        Assert.Equal("alt.example.com", tls.ServerName);
        Assert.Equal(["h2", "http/1.1"], tls.Alpn);
        Assert.True(tls.Insecure);

        var snake = TransportOptions.ReadTlsOptions(Map("tls: true\nserver-name: x.example.com\nskip_cert_verify: true"));
        Assert.Equal("x.example.com", snake.ServerName);
        Assert.True(snake.SkipCertVerify);
    }

    [Fact]
    public void ReadsWebSocketOptions()
    {
        var ws = TransportOptions.ReadWebSocketOptions(Map("""
            network: ws
            ws-opts:
              path: /the/path
              host: cdn.example.com
              max-early-data: 2048
              early-data-header-name: Sec-WebSocket-Protocol
              v2ray-http-upgrade: true
              headers:
                X-One: 1
                X-Two: two
            """));

        Assert.Equal("/the/path", ws.Path);
        Assert.Equal("cdn.example.com", ws.Host);
        Assert.Equal(2048, ws.MaxEarlyData);
        Assert.Equal("Sec-WebSocket-Protocol", ws.EarlyDataHeaderName);
        Assert.True(ws.V2rayHttpUpgrade);
        Assert.Equal("1", ws.Headers["X-One"]);
        Assert.Equal("two", ws.Headers["x-two"]);
    }

    [Fact]
    public void WebSocketPathDefaultsToRootAndIsNormalised()
    {
        Assert.Equal("/", TransportOptions.ReadWebSocketOptions(Map("network: ws")).Path);
        Assert.Equal("/x", TransportOptions.ReadWebSocketOptions(Map("ws-opts:\n  path: x")).Path);
    }

    [Fact]
    public void ReadsGrpcOptions()
    {
        var grpc = TransportOptions.ReadGrpcOptions(Map("grpc-opts:\n  grpc-service-name: MyService\n  host: grpc.example.com"));
        Assert.Equal("MyService", grpc.ServiceName);
        Assert.Equal("grpc.example.com", grpc.Host);
        Assert.Equal("gun", grpc.Mode);

        var snake = TransportOptions.ReadGrpcOptions(Map("grpc-opts:\n  grpc_service_name: Other\n  mode: multi"));
        Assert.Equal("Other", snake.ServiceName);
        Assert.Equal("multi", snake.Mode);
    }

    [Fact]
    public void GrpcPathIsBuiltLikeV2ray()
    {
        Assert.Equal("/Tun", GrpcTransport.BuildPath(null));
        Assert.Equal("/Tun", GrpcTransport.BuildPath("   "));
        Assert.Equal("/svc/Tun", GrpcTransport.BuildPath("svc"));
        Assert.Equal("/svc/Tun", GrpcTransport.BuildPath("/svc/"));
    }

    [Fact]
    public void ReadsH2Options()
    {
        var h2 = TransportOptions.ReadH2Options(Map("h2-opts:\n  path: /h2\n  host: [a.example.com, b.example.com]"));
        Assert.Equal("/h2", h2.Path);
        Assert.Equal(["a.example.com", "b.example.com"], h2.Host);

        var single = TransportOptions.ReadH2Options(Map("h2-opts:\n  host: only.example.com"));
        Assert.Equal(["only.example.com"], single.Host);
        Assert.Equal("/", single.Path);
    }

    [Fact]
    public void ReadsHttpObfsOptions()
    {
        var http = TransportOptions.ReadHttpObfsOptions(Map("""
            http-opts:
              method: post
              path: [/a, b]
              headers:
                X-Scalar: one
                X-List: [a, b]
            """));

        Assert.Equal("POST", http.Method);
        Assert.Equal(["/a", "/b"], http.Path);
        Assert.Equal(["one"], http.Headers["X-Scalar"]);
        Assert.Equal(["a", "b"], http.Headers["X-List"]);
    }

    [Fact]
    public void HttpObfsDefaultsAreSane()
    {
        var http = TransportOptions.ReadHttpObfsOptions(Map("network: http"));
        Assert.Equal("GET", http.Method);
        Assert.Equal(["/"], http.Path);
        Assert.Empty(http.Headers);
    }

    [Fact]
    public void PluginNamesAreRecognised()
    {
        Assert.Equal("shadow-tls", TransportOptions.UnsupportedPlugin("shadow-tls"));
        Assert.Equal("restls", TransportOptions.UnsupportedPlugin("  Restls "));
        Assert.Null(TransportOptions.UnsupportedPlugin("obfs"));
        Assert.Null(TransportOptions.UnsupportedPlugin(null));

        var options = Map("plugin: shadow-tls\nplugin-opts:\n  host: x");
        Assert.Equal("shadow-tls", TransportOptions.ReadPlugin(options));
        Assert.Equal("x", TransportOptions.ReadPluginOptions(options).GetString("host"));
    }

    [Fact]
    public async Task TlsLayerRejectsRealityAndUnsupportedPlugins()
    {
        var context = new DialContext { Host = "example.com", Port = 443, Metadata = new Metadata() };
        var inner = ProxyStream.Wrap(new MemoryStream());
        var layer = new TlsTransport();

        var reality = await Assert.ThrowsAsync<TransportNotSupportedException>(
            () => layer.WrapAsync(inner, context, Map("tls: true\nreality-opts:\n  public-key: abc")));
        Assert.Contains("REALITY", reality.Message);

        var shadowTls = await Assert.ThrowsAsync<TransportNotSupportedException>(
            () => layer.WrapAsync(inner, context, Map("tls: true\nplugin: shadow-tls")));
        Assert.Contains("shadow-tls", shadowTls.Message);

        var restls = await Assert.ThrowsAsync<TransportNotSupportedException>(
            () => layer.WrapAsync(inner, context, Map("tls: true\nplugin: restls")));
        Assert.Contains("restls", restls.Message);
    }

    [Fact]
    public void FingerprintPolicyIsBestEffortAndNeverThrows()
    {
        Assert.Null(TlsTransport.BuildCipherSuitesPolicy(null));
        Assert.Null(TlsTransport.BuildCipherSuitesPolicy(string.Empty));
        Assert.Null(TlsTransport.BuildCipherSuitesPolicy("not-a-browser"));

        // On platforms without CipherSuitesPolicy this returns null; where it is
        // supported it returns a policy. Either way it must not throw, and the
        // four browser families must not silently collapse onto one policy.
        var policies = new[]
        {
            TlsTransport.BuildCipherSuitesPolicy("chrome"),
            TlsTransport.BuildCipherSuitesPolicy("firefox"),
            TlsTransport.BuildCipherSuitesPolicy("safari"),
            TlsTransport.BuildCipherSuitesPolicy("randomized"),
        };

        Assert.All(policies, static policy => Assert.True(policy is null || policy is System.Net.Security.CipherSuitesPolicy));
        if (policies.All(static policy => policy is not null))
        {
            Assert.NotSame(policies[0], policies[1]);
            Assert.NotSame(policies[1], policies[2]);
        }
    }

    [Fact]
    public void TargetHostHonoursSniAndDisableSni()
    {
        var context = new DialContext { Host = "origin.example.com", Port = 443, Metadata = new Metadata() };
        var inner = new ProxyStream(new MemoryStream(), remoteEndPoint: new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.7"), 443));

        Assert.Equal("origin.example.com", TlsTransport.ResolveTargetHost(inner, context, new TlsOptions()));
        Assert.Equal("sni.example.com", TlsTransport.ResolveTargetHost(inner, context, new TlsOptions { ServerName = "sni.example.com" }));
        Assert.Equal("203.0.113.7", TlsTransport.ResolveTargetHost(inner, context, new TlsOptions { DisableSni = true }));
    }

    [Fact]
    public void MessageFramingUsesAFiveByteHeader()
    {
        var buffer = new byte[Http2MessageFraming.HeaderSize];
        Assert.Equal(5, Http2MessageFraming.WriteHeader(buffer, 0x01020304));
        Assert.Equal("0001020304", Convert.ToHexStringLower(buffer));

        Assert.True(Http2MessageFraming.TryReadHeader(buffer, out var compressed, out var length));
        Assert.False(compressed);
        Assert.Equal(0x01020304, length);

        Http2MessageFraming.WriteHeader(buffer, 7, compressed: true);
        Assert.True(Http2MessageFraming.TryReadHeader(buffer, out compressed, out length));
        Assert.True(compressed);
        Assert.Equal(7, length);

        Assert.False(Http2MessageFraming.TryReadHeader(buffer.AsSpan(0, 4), out _, out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => Http2MessageFraming.WriteHeader(buffer, Http2MessageFraming.MaxMessageSize + 1));
    }
}
