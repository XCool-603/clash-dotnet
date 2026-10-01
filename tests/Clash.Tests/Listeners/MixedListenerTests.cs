using System.Net;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Listeners;

public sealed class MixedListenerTests
{
    private static ClashConfig Config() => new()
    {
        MixedPort = 0,
        BindAddress = "127.0.0.1",
        AllowLan = false,
    };

    [Fact]
    public async Task Mixed_port_detects_socks5()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new MixedListener(config, NullLogger<MixedListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));
        await client.SendAsync(TestSockets.Socks5DomainRequest(0x01, "example.com", 443));
        Assert.Equal((byte)0x00, (await client.ReadSocks5ReplyAsync()).Reply);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("example.com", metadata.DestinationAddress);
        Assert.Equal(443, metadata.DestinationPort);
        Assert.Equal("mixed", metadata.InboundType);
    }

    [Fact]
    public async Task Mixed_port_detects_socks4a()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new MixedListener(config, NullLogger<MixedListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var request = new List<byte> { 0x04, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01 };
        request.Add(0x00);
        request.AddRange(Encoding.ASCII.GetBytes("mixed.example"));
        request.Add(0x00);
        await client.SendAsync(request.ToArray());

        var reply = await client.ReadExactlyAsync(8);
        Assert.Equal((byte)0x5A, reply[1]);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("mixed.example", metadata.DestinationAddress);
        Assert.Equal(80, metadata.DestinationPort);
    }

    [Fact]
    public async Task Mixed_port_detects_http_connect()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new MixedListener(config, NullLogger<MixedListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        await client.SendAsync(Encoding.ASCII.GetBytes(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nping"));

        var response = Encoding.ASCII.GetString(await client.ReadExactlyAsync(39));
        Assert.Equal("HTTP/1.1 200 Connection Established\r\n\r\n", response);

        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("example.com", metadata.DestinationAddress);
        Assert.Equal(443, metadata.DestinationPort);
        Assert.Equal("mixed", metadata.InboundType);
        Assert.Equal("ping", tunnel.ReceivedText);
    }

    [Fact]
    public async Task Mixed_port_detects_an_absolute_uri_http_request()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        var expected = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        tunnel.StopAfterBytes = Encoding.UTF8.GetByteCount(expected);

        await using var listener = new MixedListener(config, NullLogger<MixedListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        await client.SendAsync(Encoding.ASCII.GetBytes("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"));

        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal(expected, tunnel.ReceivedText);
        Assert.Equal("example.com", metadata.DestinationAddress);
        Assert.Equal(80, metadata.DestinationPort);
        Assert.Equal(Network.Tcp, metadata.Network);
    }
}
