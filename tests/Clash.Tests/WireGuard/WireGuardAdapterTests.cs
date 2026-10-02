using System.Security.Cryptography;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Clash.Core.Providers;
using Clash.Tests.Outbound;
using Xunit;

namespace Clash.Tests.WireGuard;

/// <summary>
/// Covers the configuration surface: the two shapes mihomo and the share-link
/// parser produce, and every option this adapter deliberately refuses.
/// </summary>
public class WireGuardAdapterTests
{
    private static readonly string PrivateKey = WireGuardCrypto.ToBase64(RandomNumberGenerator.GetBytes(32));
    private static readonly string PublicKey = WireGuardCrypto.ToBase64(RandomNumberGenerator.GetBytes(32));
    private static readonly string PresharedKey = WireGuardCrypto.ToBase64(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void TheFactoryRegistersBothSpellingsAndReportsTheApiTypeName()
    {
        Assert.True(AdapterRegistry.IsKnown("wireguard"));
        Assert.True(AdapterRegistry.IsKnown("wg"));

        var proxy = Build(Flat());

        Assert.Equal(ProxyType.Wireguard, proxy.Type);
        Assert.Equal("Wireguard", proxy.TypeName);

        var outbound = Assert.IsAssignableFrom<IOutboundProxy>(proxy);
        Assert.Equal("wg.example.com", outbound.ServerHost);
        Assert.Equal(51820, outbound.ServerPort);
        Assert.True(proxy.SupportUdp);
    }

    [Fact]
    public void TheFlatShapeTheShareLinkParserEmitsIsAccepted()
    {
        var proxy = Build(Flat());
        Assert.Equal("wg", proxy.Name);
    }

    [Fact]
    public void TheNestedPeersShapeMihomoEmitsIsAccepted()
    {
        var proxy = Build(Flat(peers: [new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["public-key"] = PublicKey,
            ["pre-shared-key"] = PresharedKey,
            ["reserved"] = new List<object?> { 1, 2, 3 },
            ["allowed-ips"] = new List<object?> { "0.0.0.0/0" },
        }]));

        Assert.Equal("Wireguard", proxy.TypeName);
    }

    [Fact]
    public void APreSharedKeyOfTheWrongLengthIsRefusedWhereverItIsWritten()
    {
        var shortKey = WireGuardCrypto.ToBase64(new byte[16]);

        var flat = Assert.Throws<ProxyCreationException>(() => Build(Flat(preSharedKey: shortKey)));
        Assert.Contains("pre-shared-key", flat.Message, StringComparison.Ordinal);

        var nested = Assert.Throws<ProxyCreationException>(() => Build(Flat(peers:
        [
            new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["public-key"] = PublicKey,
                ["pre-shared-key"] = shortKey,
            },
        ])));

        Assert.Contains("pre-shared-key", nested.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AMissingTunnelAddressIsRefusedWithAnExplanation()
    {
        var entry = OutboundHarness.Entry(
            "wg",
            "wireguard",
            ("server", "wg.example.com"),
            ("port", 51820),
            ("private-key", PrivateKey),
            ("public-key", PublicKey));

        var failure = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry));

        Assert.Contains("requires the tunnel's own IPv4 address", failure.Message, StringComparison.Ordinal);
        Assert.Contains("layer 3", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheTunnelAddressCanComeFromTheAddressKeyWithACidrSuffix()
    {
        var proxy = Build(Flat(ip: null, address: new List<object?> { "10.7.0.2/32" }));
        Assert.Equal("Wireguard", proxy.TypeName);
    }

    [Fact]
    public void MoreThanOnePeerIsRefused()
    {
        var peer = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["public-key"] = PublicKey };

        var failure = Assert.Throws<ProxyCreationException>(() => Build(Flat(peers: [peer, peer])));

        Assert.Contains("only one peer is supported", failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("amnezia-wg-option")]
    [InlineData("jc")]
    [InlineData("h1")]
    [InlineData("itime")]
    public void AmneziaWgOptionsAreRefusedRatherThanSpokenAsPlainWireGuard(string key)
    {
        var entry = OutboundHarness.Entry(
            "wg",
            "wireguard",
            ("server", "wg.example.com"),
            ("port", 51820),
            ("private-key", PrivateKey),
            ("public-key", PublicKey),
            ("ip", new List<object?> { "10.0.0.2/32" }),
            (key, key == "amnezia-wg-option" ? new Dictionary<string, object?>() : 4));

        var failure = Assert.Throws<ProxyCreationException>(() => OutboundHarness.Build(entry));

        Assert.Contains("AmneziaWG", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReservedMustBeExactlyThreeBytes()
    {
        var failure = Assert.Throws<ProxyCreationException>(() =>
            Build(Flat(reserved: new List<object?> { 1, 2 })));

        Assert.Contains("exactly 3 bytes", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DialerProxyIsRefusedBecauseThereIsNoDatagramDialerChain()
    {
        var failure = Assert.Throws<ProxyCreationException>(() => Build(Flat(dialerProxy: "DIRECT")));

        Assert.Contains("dialer-proxy", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DialTcpRefusesToChainAnUpstreamStream()
    {
        var proxy = Build(Flat());

        var failure = await Assert.ThrowsAsync<NotSupportedException>(() =>
            proxy.DialTcpAsync(OutboundHarness.Flow("1.1.1.1", 443), new MemoryStream()));

        Assert.Contains("layer-3", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DialUdpHonoursTheUdpSwitchWithoutTouchingTheNetwork()
    {
        var proxy = Build(Flat(udp: false));

        Assert.False(proxy.SupportUdp);
        await Assert.ThrowsAsync<NotSupportedException>(() => proxy.DialUdpAsync(OutboundHarness.UdpFlow("1.1.1.1", 53)));
    }

    [Fact]
    public void AnInvalidMtuIsRefused()
    {
        var failure = Assert.Throws<ProxyCreationException>(() => Build(Flat(mtu: 100)));
        Assert.Contains("'mtu' must be", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheShareLinkParserCarriesThePreSharedKeyAndTheIpStack()
    {
        var parser = new ShareLinkParser();
        var link = $"wireguard://{Uri.EscapeDataString(PrivateKey)}@wg.example.com:51820"
            + $"?publickey={Uri.EscapeDataString(PublicKey)}"
            + $"&pre-shared-key={Uri.EscapeDataString(PresharedKey)}"
            + "&ip-stack=gvisor&address=10.0.0.2%2F32#WG";

        var entry = parser.Parse(link);

        Assert.NotNull(entry);
        Assert.Equal("wireguard", entry!.Type);
        Assert.Equal(PresharedKey, entry.Map.GetString("pre-shared-key"));
        Assert.Equal("gvisor", entry.Map.GetString("ip-stack"));

        // And the entry the parser produced is one the adapter accepts.
        var proxy = OutboundHarness.Build(entry);
        Assert.Equal("Wireguard", proxy.TypeName);
    }

    private static IProxy Build(ProxyConfigEntry entry) => OutboundHarness.Build(entry);

    private static ProxyConfigEntry Flat(
        List<object?>? ip = null,
        List<object?>? address = null,
        List<object?>? peers = null,
        List<object?>? reserved = null,
        string? preSharedKey = null,
        string? dialerProxy = null,
        int? mtu = null,
        bool? udp = null)
    {
        var pairs = new List<(string Key, object? Value)>
        {
            ("server", "wg.example.com"),
            ("port", 51820),
            ("private-key", PrivateKey),
            ("public-key", PublicKey),
            ("ip", ip ?? new List<object?> { "10.0.0.2/32" }),
        };

        if (address is not null) pairs.Add(("address", address));
        if (peers is not null) pairs.Add(("peers", peers));
        if (reserved is not null) pairs.Add(("reserved", reserved));
        if (preSharedKey is not null) pairs.Add(("pre-shared-key", preSharedKey));
        if (dialerProxy is not null) pairs.Add(("dialer-proxy", dialerProxy));
        if (mtu is not null) pairs.Add(("mtu", mtu.Value));
        if (udp is not null) pairs.Add(("udp", udp.Value));

        return OutboundHarness.Entry("wg", "wireguard", [.. pairs]);
    }
}
