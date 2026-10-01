using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Listeners;

public sealed class HttpListenerTests
{
    private static ClashConfig Config(params string[] authentication) => new()
    {
        Port = 0,
        BindAddress = "127.0.0.1",
        AllowLan = false,
        Authentication = [.. authentication],
    };

    [Fact]
    public async Task Connect_replies_established_and_replays_bytes_buffered_with_the_headers()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        const string hello = "CLIENT-HELLO-BYTES";
        tunnel.StopAfterBytes = hello.Length;

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        // The payload rides in the same TCP segment as the request head, which is
        // exactly the case a naive parser loses.
        var request = Encoding.ASCII.GetBytes(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" + hello);
        await client.SendAsync(request);

        var response = Encoding.ASCII.GetString(await client.ReadExactlyAsync(39));
        Assert.Equal("HTTP/1.1 200 Connection Established\r\n\r\n", response);

        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal(hello, tunnel.ReceivedText);
        Assert.Equal("example.com", metadata.DestinationAddress);
        Assert.Equal(443, metadata.DestinationPort);
        Assert.Equal(Network.Tcp, metadata.Network);
        Assert.Equal("http", metadata.InboundType);
        Assert.Equal(listener.Port, metadata.InboundPort);
        Assert.Equal("127.0.0.1", metadata.SourceAddress);
        Assert.True(metadata.SourcePort > 0);

        // The tunnel's writes reach the client too.
        Assert.Equal(hello, Encoding.ASCII.GetString(await client.ReadExactlyAsync(hello.Length)));
    }

    [Fact]
    public async Task Absolute_uri_request_is_rewritten_to_origin_form_and_the_body_is_replayed()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        var expected = "POST /upload?a=1 HTTP/1.1\r\nHost: example.org:8080\r\nContent-Length: 5\r\n\r\nHELLO";
        tunnel.StopAfterBytes = Encoding.UTF8.GetByteCount(expected);

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var request =
            "POST http://example.org:8080/upload?a=1 HTTP/1.1\r\n" +
            "Host: example.org:8080\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "Content-Length: 5\r\n\r\n" +
            "HELLO";
        await client.SendAsync(Encoding.ASCII.GetBytes(request));

        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal(expected, tunnel.ReceivedText);
        Assert.DoesNotContain("Proxy-Connection", tunnel.ReceivedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http://", tunnel.ReceivedText, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("example.org", metadata.DestinationAddress);
        Assert.Equal(8080, metadata.DestinationPort);
        Assert.Equal("http", metadata.InboundType);
    }

    [Fact]
    public async Task Origin_form_request_uses_the_host_header()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);
        var expected = "GET /index.html HTTP/1.1\r\nHost: example.net\r\n\r\n";
        tunnel.StopAfterBytes = Encoding.UTF8.GetByteCount(expected);

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        await client.SendAsync(Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1\r\nHost: example.net\r\n\r\n"));

        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal(expected, tunnel.ReceivedText);
        Assert.Equal("example.net", metadata.DestinationAddress);
        Assert.Equal(80, metadata.DestinationPort);
    }

    [Fact]
    public async Task Proxy_authorization_success_records_the_user()
    {
        var config = Config("user:pass");
        var tunnel = new FakeTunnel(config);
        var expected = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nHELLO";
        tunnel.StopAfterBytes = Encoding.UTF8.GetByteCount(expected);

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:pass"));
        await client.SendAsync(Encoding.ASCII.GetBytes(
            $"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {credentials}\r\n\r\nHELLO"));

        var metadata = await tunnel.TcpHandled.WaitAsync(TestSockets.Timeout);
        Assert.Equal("user", metadata.InboundUser);
        Assert.Equal(expected, tunnel.ReceivedText);
        Assert.DoesNotContain("Proxy-Authorization", tunnel.ReceivedText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Proxy_authorization_failure_returns_407_and_never_reaches_the_tunnel()
    {
        var config = Config("user:pass");
        var tunnel = new FakeTunnel(config);

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        var wrong = Convert.ToBase64String(Encoding.UTF8.GetBytes("user:wrong"));
        await client.SendAsync(Encoding.ASCII.GetBytes(
            $"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {wrong}\r\n\r\n"));

        var response = await client.ReadUntilAsync("\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407 Proxy Authentication Required", response);
        Assert.Contains("Proxy-Authenticate: Basic realm=\"Clash\"", response);
        Assert.False(tunnel.TcpHandled.IsCompleted);
        Assert.Contains(tunnel.Logs, line => line.Contains("authentication failed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Missing_credentials_are_rejected_with_407()
    {
        var config = Config("user:pass");
        var tunnel = new FakeTunnel(config);

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        await client.SendAsync(Encoding.ASCII.GetBytes("CONNECT example.com:443 HTTP/1.1\r\n\r\n"));

        var response = await client.ReadUntilAsync("\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 407", response);
        Assert.False(tunnel.TcpHandled.IsCompleted);
    }

    [Fact]
    public async Task Malformed_request_line_is_answered_with_400()
    {
        var config = Config();
        var tunnel = new FakeTunnel(config);

        await using var listener = new HttpListener(config, NullLogger<HttpListener>.Instance);
        await listener.StartAsync(tunnel);
        using var client = await TestSockets.ConnectAsync(listener.Port);

        await client.SendAsync(Encoding.ASCII.GetBytes("BOGUS\r\n\r\n"));

        var response = await client.ReadUntilAsync("\r\n\r\n");
        Assert.StartsWith("HTTP/1.1 400", response);
        Assert.False(tunnel.TcpHandled.IsCompleted);
    }
}
