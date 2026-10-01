using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Listeners;

public sealed class SocksUdpAssociateTests
{
    private static ClashConfig Config() => new()
    {
        SocksPort = 0,
        BindAddress = "127.0.0.1",
        AllowLan = false,
    };

    [Fact]
    public async Task Udp_associate_frames_replies_and_reports_the_requested_destination()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        var exchange = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var received = Array.Empty<byte>();
        var receivedRemote = string.Empty;

        tunnel.UdpHandler = async (inbound, metadata, cancellationToken) =>
        {
            var buffer = new byte[65535];
            var result = await inbound.ReceiveAsync(buffer, cancellationToken);
            received = buffer[..result.BytesRead];
            receivedRemote = result.Remote?.ToString() ?? string.Empty;
            if (result.Remote is not null)
            {
                await inbound.SendAsync(Encoding.UTF8.GetBytes("pong"), result.Remote, cancellationToken);
            }

            exchange.TrySetResult();
        };

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        var (control, bound) = await AssociateAsync(listener.Port);
        using var udp = TestSockets.CreateUdpClient();
        try
        {
            await udp.SendToAsync(
                TestSockets.Socks5UdpDatagram("ping", IPAddress.Parse("9.9.9.9"), 53),
                SocketFlags.None,
                bound);

            await exchange.Task.WaitAsync(TestSockets.Timeout);
            Assert.Equal("ping", Encoding.UTF8.GetString(received));
            Assert.Equal("9.9.9.9:53", receivedRemote);

            var metadata = await tunnel.UdpHandled.WaitAsync(TestSockets.Timeout);
            Assert.Equal(Network.Udp, metadata.Network);
            Assert.Equal("socks", metadata.InboundType);
            Assert.Equal(listener.Port, metadata.InboundPort);

            var buffer = new byte[2048];
            var from = new IPEndPoint(IPAddress.Any, 0);
            var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, from).WaitAsync(TestSockets.Timeout);
            var parsed = TestSockets.ParseSocks5UdpDatagram(buffer[..result.ReceivedBytes]);
            Assert.Equal((byte)0x00, parsed.Fragment);
            Assert.Equal("pong", parsed.Payload);
            Assert.Equal("9.9.9.9", parsed.Destination.ToString());
            Assert.Equal(53, parsed.Port);
        }
        finally
        {
            control.Dispose();
        }
    }

    [Fact]
    public async Task Udp_associate_drops_datagrams_whose_frag_field_is_not_zero()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        var exchange = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var received = string.Empty;

        tunnel.UdpHandler = async (inbound, metadata, cancellationToken) =>
        {
            var buffer = new byte[65535];
            var result = await inbound.ReceiveAsync(buffer, cancellationToken);
            received = Encoding.UTF8.GetString(buffer, 0, result.BytesRead);
            if (result.Remote is not null)
            {
                await inbound.SendAsync(Encoding.UTF8.GetBytes("ok:" + received), result.Remote, cancellationToken);
            }

            exchange.TrySetResult();
        };

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        var (control, bound) = await AssociateAsync(listener.Port);
        using var udp = TestSockets.CreateUdpClient();
        try
        {
            var destination = IPAddress.Parse("1.1.1.1");
            await udp.SendToAsync(
                TestSockets.Socks5UdpDatagram("dropped", destination, 53, fragment: 1),
                SocketFlags.None,
                bound);
            await udp.SendToAsync(
                TestSockets.Socks5UdpDatagram("kept", destination, 53),
                SocketFlags.None,
                bound);

            await exchange.Task.WaitAsync(TestSockets.Timeout);
            Assert.Equal("kept", received);

            var buffer = new byte[2048];
            var from = new IPEndPoint(IPAddress.Any, 0);
            var result = await udp.ReceiveFromAsync(buffer, SocketFlags.None, from).WaitAsync(TestSockets.Timeout);
            var parsed = TestSockets.ParseSocks5UdpDatagram(buffer[..result.ReceivedBytes]);
            Assert.Equal("ok:kept", parsed.Payload);
        }
        finally
        {
            control.Dispose();
        }
    }

    [Fact]
    public async Task Udp_associate_ends_when_the_control_connection_closes()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        tunnel.UdpHandler = async (inbound, metadata, cancellationToken) =>
        {
            entered.TrySetResult();
            var buffer = new byte[2048];
            try
            {
                await inbound.ReceiveAsync(buffer, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                completed.TrySetResult();
                throw;
            }

            completed.TrySetResult();
        };

        await using var listener = new SocksListener(config, NullLogger<SocksListener>.Instance);
        await listener.StartAsync(tunnel);
        var (control, _) = await AssociateAsync(listener.Port);

        await entered.Task.WaitAsync(TestSockets.Timeout);
        control.Dispose();
        await completed.Task.WaitAsync(TestSockets.Timeout);
    }

    private static async Task<(Socket Control, IPEndPoint Bound)> AssociateAsync(int port)
    {
        var control = await TestSockets.ConnectAsync(port);
        try
        {
            Assert.Equal((byte)0x00, await control.GreetSocks5Async(0x00));
            await control.SendAsync(TestSockets.Socks5Request(0x03, new byte[] { 0, 0, 0, 0 }, 0));
            var reply = await control.ReadSocks5ReplyAsync();
            Assert.Equal((byte)0x00, reply.Reply);
            Assert.NotNull(reply.Bound);
            return (control, reply.Bound!);
        }
        catch
        {
            control.Dispose();
            throw;
        }
    }
}
