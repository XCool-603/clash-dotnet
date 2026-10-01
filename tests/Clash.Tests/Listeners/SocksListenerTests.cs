using System.Net;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Listeners;

public sealed class SocksListenerTests
{
    private static ClashConfig Config(params string[] authentication) => new()
    {
        SocksPort = 0,
        BindAddress = "127.0.0.1",
        AllowLan = false,
        Authentication = [.. authentication],
    };

    [Fact]
    public async Task Socks5_no_auth_connect_to_a_domain()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));
        await client.SendAsync(TestSockets.Socks5DomainRequest(0x01, "example.com", 8443));
        var reply = await client.ReadSocks5ReplyAsync();
        Assert.Equal((byte)0x00, reply.Reply);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("example.com", metadata.DestinationAddress);
        Assert.Equal(8443, metadata.DestinationPort);
        Assert.Equal(Network.Tcp, metadata.Network);
        Assert.Equal("socks", metadata.InboundType);
        Assert.Equal("ping", tunnel.ReceivedText);
        Assert.Null(metadata.InboundUser);
    }

    [Fact]
    public async Task Socks5_no_auth_connect_to_an_ipv4_literal()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));
        await client.SendAsync(TestSockets.Socks5Request(0x01, IPAddress.Parse("10.1.2.3").GetAddressBytes(), 443));
        Assert.Equal((byte)0x00, (await client.ReadSocks5ReplyAsync()).Reply);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("10.1.2.3", metadata.DestinationAddress);
        Assert.Equal(443, metadata.DestinationPort);
    }

    [Fact]
    public async Task Socks5_no_auth_connect_to_an_ipv6_literal()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));
        await client.SendAsync(TestSockets.Socks5Request(0x01, IPAddress.Parse("2001:db8::1").GetAddressBytes(), 8080));
        Assert.Equal((byte)0x00, (await client.ReadSocks5ReplyAsync()).Reply);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("2001:db8::1", metadata.DestinationAddress);
        Assert.Equal(8080, metadata.DestinationPort);
    }

    [Fact]
    public async Task Socks5_bind_is_answered_with_command_not_supported()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));
        await client.SendAsync(TestSockets.Socks5DomainRequest(0x02, "example.com", 443));
        Assert.Equal((byte)0x07, (await client.ReadSocks5ReplyAsync()).Reply);
        Assert.False(tunnel.TcpHandled.IsCompleted);
    }

    [Fact]
    public async Task Socks5_username_password_authentication_succeeds()
    {
        var config = Config("user:pass");
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x02, await client.GreetSocks5Async(0x02, 0x00));
        await client.SendAsync(Encoding.ASCII.GetBytes("\u0001\u0004user\u0004pass"));
        Assert.Equal(new byte[] { 0x01, 0x00 }, await client.ReadExactlyAsync(2));

        await client.SendAsync(TestSockets.Socks5DomainRequest(0x01, "example.com", 80));
        Assert.Equal((byte)0x00, (await client.ReadSocks5ReplyAsync()).Reply);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("user", metadata.InboundUser);
        Assert.Equal("example.com", metadata.DestinationAddress);
    }

    [Fact]
    public async Task Socks5_username_password_authentication_rejects_a_bad_password()
    {
        var config = Config("user:pass");
        var tunnel = new FakeTunnel(config);

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0x02, await client.GreetSocks5Async(0x02));
        await client.SendAsync(Encoding.ASCII.GetBytes("\u0001\u0004user\u0004nope"));
        Assert.Equal(new byte[] { 0x01, 0x01 }, await client.ReadExactlyAsync(2));
        Assert.False(tunnel.TcpHandled.IsCompleted);
        Assert.Contains(tunnel.Logs, line => line.Contains("authentication failed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Socks5_offers_no_acceptable_method_when_a_client_refuses_authentication()
    {
        var config = Config("user:pass");
        var tunnel = new FakeTunnel(config);

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        Assert.Equal((byte)0xFF, await client.GreetSocks5Async(0x00));
        Assert.False(tunnel.TcpHandled.IsCompleted);
    }

    [Fact]
    public async Task Socks4a_connect_uses_the_domain_that_follows_the_user_id()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var request = new List<byte> { 0x04, 0x01, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01 };
        request.AddRange(Encoding.ASCII.GetBytes("tester"));
        request.Add(0x00);
        request.AddRange(Encoding.ASCII.GetBytes("example.net"));
        request.Add(0x00);
        await client.SendAsync(request.ToArray());

        var reply = await client.ReadExactlyAsync(8);
        Assert.Equal((byte)0x00, reply[0]);
        Assert.Equal((byte)0x5A, reply[1]);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("example.net", metadata.DestinationAddress);
        Assert.Equal(443, metadata.DestinationPort);
        Assert.Equal(Network.Tcp, metadata.Network);
    }

    [Fact]
    public async Task Socks4_connect_to_a_literal_address()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        tunnel.StopAfterBytes = 4;

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var request = new List<byte> { 0x04, 0x01, 0x00, 0x50, 192, 168, 1, 10 };
        request.Add(0x00);
        await client.SendAsync(request.ToArray());

        var reply = await client.ReadExactlyAsync(8);
        Assert.Equal((byte)0x5A, reply[1]);

        await client.SendAsync(Encoding.ASCII.GetBytes("ping"));
        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("192.168.1.10", metadata.DestinationAddress);
        Assert.Equal(80, metadata.DestinationPort);
    }

    [Fact]
    public async Task Socks4_bind_is_refused()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var request = new List<byte> { 0x04, 0x02, 0x00, 0x50, 192, 168, 1, 10 };
        request.Add(0x00);
        await client.SendAsync(request.ToArray());

        var reply = await client.ReadExactlyAsync(8);
        Assert.Equal((byte)0x5B, reply[1]);
        Assert.False(tunnel.TcpHandled.IsCompleted);
    }
}
