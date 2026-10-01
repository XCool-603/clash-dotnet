using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Listeners;

public sealed class ListenerManagerTests
{
    [Fact]
    public void Builds_one_listener_per_port_key_and_per_entry()
    {
        var config = new ClashConfig
        {
            Port = 7890,
            SocksPort = 7891,
            MixedPort = 7892,
            RedirPort = 7893,
            TProxyPort = 7894,
            BindAddress = "127.0.0.1",
        };
        config.Listeners.Add(new ListenerConfig { Name = "extra-http", Type = "http", Port = 7895 });
        config.Listeners.Add(new ListenerConfig { Name = "owned-by-tun", Type = "tun", Port = 7896 });
        config.Listeners.Add(new ListenerConfig { Name = "nonsense", Type = "carrier-pigeon", Port = 7897 });

        var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);

        Assert.Equal(
            new[] { "http", "socks", "mixed", "redir", "tproxy", "http" },
            manager.Listeners.Select(listener => listener.Type).ToArray());

        Assert.Equal(
            new[] { 7890, 7891, 7892, 7893, 7894, 7895 },
            manager.Listeners.Cast<ListenerBase>().Select(listener => listener.ConfiguredPort).ToArray());
        Assert.Null(manager.Listeners[0].Name);
        Assert.Equal("extra-http", manager.Listeners[^1].Name);
    }

    [Fact]
    public void Skips_zero_ports()
    {
        var config = new ClashConfig { BindAddress = "127.0.0.1" };

        var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);

        Assert.Empty(manager.Listeners);
    }

    [Fact]
    public async Task Starts_every_entry_listener_on_an_ephemeral_port()
    {
        var config = new ClashConfig { BindAddress = "127.0.0.1" };
        config.Listeners.Add(new ListenerConfig { Name = "entry-http", Type = "http", Port = 0 });
        config.Listeners.Add(new ListenerConfig { Name = "entry-socks", Type = "socks", Port = 0 });
        config.Listeners.Add(new ListenerConfig { Name = "entry-mixed", Type = "mixed", Port = 0 });
        config.Listeners.Add(new ListenerConfig { Name = "entry-tun", Type = "tun", Port = 0 });

        var tunnel = new FakeTunnel(config);
        await using var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);
        Assert.Equal(3, manager.Listeners.Count);

        await manager.StartAsync(tunnel);

        Assert.All(manager.Listeners, listener => Assert.NotNull(listener.Address));
        Assert.All(manager.Listeners, listener => Assert.True(listener.Port > 0));

        // The mixed entry really serves traffic on the port it reported.
        var mixed = manager.Listeners.First(listener => listener.Type == "mixed");
        using var client = await TestSockets.ConnectAsync(mixed.Port);
        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));

        await manager.StopAsync();
        Assert.All(manager.Listeners, listener => Assert.Null(listener.Address));
    }

    [Fact]
    public async Task Survives_a_bind_failure_and_keeps_serving_on_the_others()
    {
        var blocker = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        blocker.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        blocker.Listen(1);
        var occupied = ((IPEndPoint)blocker.LocalEndPoint!).Port;

        try
        {
            var config = new ClashConfig
            {
                Port = occupied,
                BindAddress = "127.0.0.1",
                AllowLan = false,
            };
            config.Listeners.Add(new ListenerConfig { Name = "fallback", Type = "mixed", Port = 0 });

            var tunnel = new FakeTunnel(config) { StopAfterBytes = 4 };
            await using var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);
            await manager.StartAsync(tunnel);

            Assert.Equal(2, manager.Listeners.Count);
            Assert.Null(manager.Listeners[0].Address);
            Assert.NotNull(manager.Listeners[1].Address);
            Assert.True(manager.Listeners[1].Port > 0);

            using var client = await TestSockets.ConnectAsync(manager.Listeners[1].Port);
            await client.SendAsync(Encoding.ASCII.GetBytes(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nping"));
            var response = Encoding.ASCII.GetString(await client.ReadExactlyAsync(39));
            Assert.Equal("HTTP/1.1 200 Connection Established\r\n\r\n", response);
            var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
            Assert.Equal("example.com", metadata.DestinationAddress);
        }
        finally
        {
            blocker.Dispose();
        }
    }

    [Fact]
    public async Task Reload_rebuilds_the_listener_set()
    {
        var first = new ClashConfig { BindAddress = "127.0.0.1" };
        first.Listeners.Add(new ListenerConfig { Name = "first-http", Type = "http", Port = 0 });

        var tunnel = new FakeTunnel(first);
        await using var manager = new ListenerManager(first, NullLogger<ListenerManager>.Instance);
        await manager.StartAsync(tunnel);
        Assert.Equal("http", Assert.Single(manager.Listeners).Type);

        var second = new ClashConfig { BindAddress = "127.0.0.1" };
        second.Listeners.Add(new ListenerConfig { Name = "second-socks", Type = "socks", Port = 0 });
        second.Listeners.Add(new ListenerConfig { Name = "second-mixed", Type = "mixed", Port = 0 });

        await manager.ReloadAsync(second, tunnel);

        Assert.Equal(
            new[] { "socks", "mixed" },
            manager.Listeners.Select(listener => listener.Type).ToArray());
        Assert.All(manager.Listeners, listener => Assert.NotNull(listener.Address));

        var socks = manager.Listeners[0];
        using var client = await TestSockets.ConnectAsync(socks.Port);
        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));
    }

    [Fact]
    public void Bind_address_wildcards_follow_allow_lan()
    {
        Assert.Equal(IPAddress.Loopback, ListenerBase.ResolveBindAddress("*", allowLan: false));
        Assert.Equal(IPAddress.Any, ListenerBase.ResolveBindAddress("*", allowLan: true));
        Assert.Equal(IPAddress.IPv6Loopback, ListenerBase.ResolveBindAddress("*", allowLan: false, ipv6: true));
        Assert.Equal(IPAddress.IPv6Any, ListenerBase.ResolveBindAddress("*", allowLan: true, ipv6: true));
        Assert.Equal(IPAddress.Any, ListenerBase.ResolveBindAddress("0.0.0.0", allowLan: false));
        Assert.Equal(IPAddress.IPv6Any, ListenerBase.ResolveBindAddress("::", allowLan: false));
        Assert.Equal(IPAddress.Parse("192.168.1.7"), ListenerBase.ResolveBindAddress("192.168.1.7", allowLan: true));
        Assert.Equal(IPAddress.Loopback, ListenerBase.ResolveBindAddress(null, allowLan: false));
    }
}
