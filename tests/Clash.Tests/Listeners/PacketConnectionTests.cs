using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Listeners;
using Xunit;

namespace Clash.Tests.Listeners;

public sealed class PacketConnectionTests
{
    [Fact]
    public async Task Connected_connection_round_trips_a_datagram()
    {
        using var server = TestSockets.CreateUdpClient();
        var serverEndpoint = (IPEndPoint)server.LocalEndPoint!;
        var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = Task.Run(
            async () =>
            {
                var buffer = new byte[64];
                var from = new IPEndPoint(IPAddress.Any, 0);
                var read = await server.ReceiveFromAsync(buffer, SocketFlags.None, from);
                received.TrySetResult(Encoding.UTF8.GetString(buffer, 0, read.ReceivedBytes));
                await server.SendToAsync(Encoding.UTF8.GetBytes("pong"), SocketFlags.None, read.RemoteEndPoint);
            });

        await using var connection = await ConnectedUdpPacketConnection.ConnectAsync(serverEndpoint);

        Assert.False(connection.SupportsMultipleDestinations);
        Assert.NotNull(connection.LocalEndPoint);
        Assert.NotNull(connection.RemoteEndPoint);

        await connection.SendAsync(Encoding.UTF8.GetBytes("ping"), serverEndpoint);
        Assert.Equal("ping", await received.Task.WaitAsync(TestSockets.Timeout));

        var buffer = new byte[64];
        var result = await connection.ReceiveAsync(buffer);
        Assert.Equal("pong", Encoding.UTF8.GetString(buffer, 0, result.BytesRead));
        Assert.NotNull(result.Remote);

        await serverTask.WaitAsync(TestSockets.Timeout);
    }

    [Fact]
    public async Task Nat_connection_routes_replies_to_the_client_that_asked_for_the_remote()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await using var connection = new NatPacketConnection(socket);

        Assert.True(connection.SupportsMultipleDestinations);
        Assert.NotNull(connection.LocalEndPoint);

        using var clientA = TestSockets.CreateUdpClient();
        using var clientB = TestSockets.CreateUdpClient();
        var remoteA = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
        var remoteB = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);

        connection.RegisterSource(clientA.LocalEndPoint!);
        connection.RegisterSource(clientB.LocalEndPoint!);
        connection.Associate(remoteA, clientA.LocalEndPoint!);
        connection.Associate(remoteB, clientB.LocalEndPoint!);
        Assert.Equal(2, connection.TrackedSources);

        await connection.SendAsync(Encoding.UTF8.GetBytes("for-a"), remoteA);
        Assert.Equal("for-a", await ReceiveAsync(clientA));

        await connection.SendAsync(Encoding.UTF8.GetBytes("for-b"), remoteB);
        Assert.Equal("for-b", await ReceiveAsync(clientB));
    }

    [Fact]
    public async Task Nat_connection_falls_back_to_the_most_recent_source()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await using var connection = new NatPacketConnection(socket);

        using var client = TestSockets.CreateUdpClient();
        connection.RegisterSource(client.LocalEndPoint!);

        // No association for this remote: a single-client association must still
        // deliver the reply rather than dropping it.
        var sent = await connection.SendAsync(
            Encoding.UTF8.GetBytes("late"),
            new IPEndPoint(IPAddress.Parse("9.9.9.9"), 53));

        Assert.Equal(4, sent);
        Assert.Equal("late", await ReceiveAsync(client));
    }

    [Fact]
    public async Task Nat_connection_reports_the_sender_of_each_datagram()
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        await using var connection = new NatPacketConnection(socket);

        using var client = TestSockets.CreateUdpClient();
        await client.SendToAsync(
            Encoding.UTF8.GetBytes("hello"),
            SocketFlags.None,
            connection.LocalEndPoint!);

        var buffer = new byte[64];
        var result = await connection.ReceiveAsync(buffer);

        Assert.Equal("hello", Encoding.UTF8.GetString(buffer, 0, result.BytesRead));
        Assert.Equal(client.LocalEndPoint!.ToString(), result.Remote!.ToString());
        Assert.Equal(1, connection.TrackedSources);
    }

    private static async Task<string> ReceiveAsync(Socket client)
    {
        var buffer = new byte[64];
        var from = new IPEndPoint(IPAddress.Any, 0);
        var result = await client.ReceiveFromAsync(buffer, SocketFlags.None, from).WaitAsync(TestSockets.Timeout);
        return Encoding.UTF8.GetString(buffer, 0, result.ReceivedBytes);
    }
}
