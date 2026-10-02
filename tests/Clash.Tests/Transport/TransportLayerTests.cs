using System.Net;
using System.Net.Sockets;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Transport;
using Xunit;

namespace Clash.Tests.Transport;

/// <summary>Behaviour of the base TCP layer and the framing helpers over streams.</summary>
public class TransportLayerTests
{
    private static DialContext Context(string host, int port, ProxyStream? upstream = null) => new()
    {
        Host = host,
        Port = port,
        Metadata = new Metadata(),
        Upstream = upstream,
    };

    [Fact]
    public async Task TcpLayerReturnsTheUpstreamUnchanged()
    {
        var upstream = ProxyStream.Wrap(new MemoryStream());
        var result = await new TcpTransport().WrapAsync(null, Context("example.com", 443, upstream), YamlMap.Empty);
        Assert.Same(upstream, result);
    }

    [Fact]
    public async Task TcpLayerReturnsAnInnerStreamUnchanged()
    {
        var inner = ProxyStream.Wrap(new MemoryStream());
        var result = await new TcpTransport().WrapAsync(inner, Context("example.com", 443), YamlMap.Empty);
        Assert.Same(inner, result);
    }

    [Fact]
    public async Task TcpLayerConnectsToALoopbackListener()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();

            await using var stream = await new TcpTransport().WrapAsync(null, Context("127.0.0.1", port), YamlMap.Empty);
            using var server = await accept;

            Assert.NotNull(stream.RemoteEndPoint);
            Assert.Equal(port, ((IPEndPoint)stream.RemoteEndPoint!).Port);

            await stream.WriteAsync("ping"u8.ToArray());
            await stream.FlushAsync();

            var buffer = new byte[4];
            var read = 0;
            while (read < buffer.Length) read += server.GetStream().Read(buffer, read, buffer.Length - read);
            Assert.Equal("ping", Encoding.ASCII.GetString(buffer));
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ConnectAnyAsyncUsesWhicheverAddressAnswersFirst()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();

            // 127.0.0.2 is not bound by the listener, so it refuses and the second
            // address must win the race.
            using var client = await TcpTransport.ConnectAnyAsync(
                [IPAddress.Parse("127.0.0.2"), IPAddress.Loopback],
                port,
                CancellationToken.None);

            using var server = await accept;
            Assert.True(client.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ConnectAnyAsyncSurfacesAFailureWhenNothingAnswers()
    {
        // Bind and immediately close a listener to get a port that refuses.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        await Assert.ThrowsAnyAsync<Exception>(() =>
            TcpTransport.ConnectAnyAsync([IPAddress.Loopback], port, CancellationToken.None));
    }

    [Fact]
    public async Task ResolveAsyncPrefersTheSystemResolverWithoutATunnel()
    {
        var addresses = await TcpTransport.ResolveAsync(Context("127.0.0.1", 1), CancellationToken.None);
        Assert.Equal([IPAddress.Loopback], addresses);
    }

    [Fact]
    public void ConfigureAppliesNoDelayAndKeepAlive()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);

        TcpTransport.Configure(client, new Clash.Core.Configuration.ClashConfig
        {
            KeepAliveIdle = 11,
            KeepAliveInterval = 22,
        });

        Assert.True(client.NoDelay);
        Assert.Equal(1, Convert.ToInt32(
            client.Client.GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive),
            System.Globalization.CultureInfo.InvariantCulture));
    }

    [Fact]
    public void ConfigureSkipsKeepAliveWhenDisabled()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        client.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);

        TcpTransport.Configure(client, new Clash.Core.Configuration.ClashConfig { DisableKeepAlive = true });
        Assert.True(client.NoDelay);
    }

    // ---- chunked transfer coding ------------------------------------------------

    [Fact]
    public async Task ChunkedStreamEncodesAndDecodes()
    {
        var wire = new MemoryStream();
        await using (var writer = new ChunkedStream(wire))
        {
            await writer.WriteAsync("hello"u8.ToArray());
            await writer.WriteAsync("world"u8.ToArray());
            await writer.FinishAsync();
        }

        Assert.Equal("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n", Encoding.ASCII.GetString(wire.ToArray()));

        wire.Position = 0;
        var reader = new ChunkedStream(wire);
        var output = new MemoryStream();
        var buffer = new byte[4];
        while (true)
        {
            var read = await reader.ReadAsync(buffer);
            if (read <= 0) break;
            output.Write(buffer, 0, read);
        }

        Assert.Equal("helloworld", Encoding.ASCII.GetString(output.ToArray()));
    }

    [Fact]
    public async Task ChunkedStreamHandlesChunkExtensionsAndTrailers()
    {
        var payload = Encoding.ASCII.GetBytes("5;ext=1\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n");
        var reader = new ChunkedStream(new MemoryStream(payload));

        var buffer = new byte[16];
        var read = await reader.ReadAsync(buffer);
        Assert.Equal(5, read);
        Assert.Equal("hello", Encoding.ASCII.GetString(buffer, 0, read));
        Assert.Equal(0, await reader.ReadAsync(buffer));
    }

    [Fact]
    public async Task ChunkedStreamReplaysAPrefixBeforeTheInnerStream()
    {
        var wire = new MemoryStream(Encoding.ASCII.GetBytes("world"));
        var reader = new ChunkedStream(wire, Encoding.ASCII.GetBytes("hello "), chunked: false);

        var buffer = new byte[32];
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await reader.ReadAsync(buffer.AsMemory(read));
            if (n <= 0) break;
            read += n;
        }

        Assert.Equal("hello world", Encoding.ASCII.GetString(buffer, 0, read));
    }

    [Fact]
    public async Task ChunkedStreamInPassThroughModeDoesNotFrame()
    {
        var wire = new MemoryStream();
        var writer = new ChunkedStream(wire, chunked: false);
        await writer.WriteAsync("raw"u8.ToArray());
        Assert.Equal("raw", Encoding.ASCII.GetString(wire.ToArray()));
    }

    [Fact]
    public async Task ChunkedStreamRejectsAMalformedChunkSize()
    {
        var reader = new ChunkedStream(new MemoryStream(Encoding.ASCII.GetBytes("zz\r\nhello\r\n0\r\n\r\n")));
        await Assert.ThrowsAsync<ClashException>(() => reader.ReadExactlyAsync(new byte[8]).AsTask());
    }

    // ---- HTTP obfuscation -------------------------------------------------------

    [Fact]
    public void HttpObfsRequestHeaderCarriesTheChunkedBody()
    {
        var options = new HttpObfsOptions
        {
            Method = "POST",
            Path = ["/a"],
            Headers = { ["X-Custom"] = ["one", "two"] },
        };

        var request = Encoding.ASCII.GetString(HttpObfsTransport.BuildRequestHeader(options, "example.com", 8443, "/a"));

        Assert.StartsWith("POST /a HTTP/1.1\r\n", request);
        Assert.Contains("Host: example.com:8443\r\n", request);
        Assert.Contains("X-Custom: one\r\n", request);
        Assert.Contains("X-Custom: two\r\n", request);
        Assert.Contains("Transfer-Encoding: chunked\r\n", request);
        Assert.EndsWith("\r\n\r\n", request);
    }

    [Fact]
    public void HttpObfsRequestHeaderDropsHeadersItManages()
    {
        var options = new HttpObfsOptions { Headers = { ["Host"] = ["evil.example.com"] } };
        var request = Encoding.ASCII.GetString(HttpObfsTransport.BuildRequestHeader(options, "real.example.com", 80, "/"));
        Assert.Contains("Host: real.example.com\r\n", request);
        Assert.DoesNotContain("evil.example.com", request);
    }
}
