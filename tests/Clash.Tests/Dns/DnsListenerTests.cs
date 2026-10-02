using System.Net;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class DnsListenerTests
{
    private static readonly DnsCodec Codec = new();

    [Theory]
    [InlineData("0.0.0.0:1053", "0.0.0.0", 1053)]
    [InlineData("*:1053", "0.0.0.0", 1053)]
    [InlineData(":1053", "0.0.0.0", 1053)]
    [InlineData("1053", "0.0.0.0", 1053)]
    [InlineData("127.0.0.1:5353", "127.0.0.1", 5353)]
    [InlineData("localhost:53", "127.0.0.1", 53)]
    [InlineData("[::]:1053", "::", 1053)]
    [InlineData("", "0.0.0.0", 1053)]
    public void ParseListenHandlesTheDocumentedForms(string listen, string address, int port)
    {
        var (parsedAddress, parsedPort) = DnsListener.ParseListen(listen);

        Assert.Equal(IPAddress.Parse(address), parsedAddress);
        Assert.Equal(port, parsedPort);
    }

    [Fact]
    public void ListenerReportsItsIdentityAndEndpoint()
    {
        var listener = new DnsListener(new DnsConfig { Listen = "127.0.0.1:15353" });

        Assert.Equal("dns", listener.Type);
        Assert.Equal("dns", listener.Name);
        Assert.Equal(15353, listener.Port);
        Assert.Equal(IPAddress.Loopback, listener.BindAddress);
        Assert.Equal(0, listener.ActiveConnections);
    }

    [Fact]
    public async Task HandlePacketAsyncAnswersThroughTheResolver()
    {
        var config = new DnsConfig { Enable = false, Nameserver = ["primary"] };
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, "1.1.1.1"));

        using var resolver = new DnsResolver(
            config,
            new Dictionary<string, object?>(),
            NullLogger<DnsResolver>.Instance,
            (_, _, _, _) => primary);

        await using var listener = new DnsListener(config, NullLogger<DnsListener>.Instance);
        await listener.StartAsync(new FakeTunnel(resolver));

        var wire = Codec.Encode(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 0x4321));

        byte[]? reply = null;
        await listener.HandlePacketAsync(
            wire,
            new IPEndPoint(IPAddress.Loopback, 5353),
            (data, _) =>
            {
                reply = data.ToArray();
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.NotNull(reply);
        var response = Codec.Decode(reply);
        Assert.True(response.IsResponse);
        Assert.Equal(0x4321, response.Id);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), Assert.Single(response.Answers).Address);
    }

    [Fact]
    public async Task HandlePacketAsyncDropsMalformedQueries()
    {
        var config = new DnsConfig { Enable = false };
        using var resolver = new DnsResolver(config, new Dictionary<string, object?>(), NullLogger<DnsResolver>.Instance);

        await using var listener = new DnsListener(config, NullLogger<DnsListener>.Instance);
        await listener.StartAsync(new FakeTunnel(resolver));

        var replied = false;
        await listener.HandlePacketAsync(
            new byte[] { 0x00, 0x01, 0x02 },
            new IPEndPoint(IPAddress.Loopback, 5353),
            (_, _) =>
            {
                replied = true;
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.False(replied);
    }

    [Fact]
    public async Task HandlePacketAsyncIgnoresResponses()
    {
        var config = new DnsConfig { Enable = false };
        using var resolver = new DnsResolver(config, new Dictionary<string, object?>(), NullLogger<DnsResolver>.Instance);

        await using var listener = new DnsListener(config, NullLogger<DnsListener>.Instance);
        await listener.StartAsync(new FakeTunnel(resolver));

        var response = DnsCodec.CreateResponse(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1), DnsResponseCode.NoError);
        var replied = false;

        await listener.HandlePacketAsync(
            Codec.Encode(response),
            new IPEndPoint(IPAddress.Loopback, 5353),
            (_, _) =>
            {
                replied = true;
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.False(replied);
    }

    [Fact]
    public async Task HandlePacketAsyncTruncatesOversizedUdpReplies()
    {
        var config = new DnsConfig { Enable = false, Nameserver = ["primary"] };
        var addresses = Enumerable.Range(1, 40).Select(i => $"10.0.0.{i}").ToArray();
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, 60, addresses));

        using var resolver = new DnsResolver(
            config,
            new Dictionary<string, object?>(),
            NullLogger<DnsResolver>.Instance,
            (_, _, _, _) => primary);

        await using var listener = new DnsListener(config, NullLogger<DnsListener>.Instance);
        await listener.StartAsync(new FakeTunnel(resolver));

        var wire = Codec.Encode(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1));

        byte[]? reply = null;
        await listener.HandlePacketAsync(
            wire,
            new IPEndPoint(IPAddress.Loopback, 5353),
            (data, _) =>
            {
                reply = data.ToArray();
                return Task.CompletedTask;
            },
            CancellationToken.None,
            DnsListener.MaxUdpPayload);

        Assert.NotNull(reply);
        Assert.True(reply.Length <= DnsListener.MaxUdpPayload);

        var response = Codec.Decode(reply);
        Assert.True(response.Truncated);
        Assert.Empty(response.Answers);
    }

    [Fact]
    public async Task HandlePacketAsyncDoesNotTruncateWhenNoLimitIsGiven()
    {
        var config = new DnsConfig { Enable = false, Nameserver = ["primary"] };
        var addresses = Enumerable.Range(1, 40).Select(i => $"10.0.0.{i}").ToArray();
        var primary = new FakeDnsUpstream(query => DnsAnswers.Addresses(query, 60, addresses));

        using var resolver = new DnsResolver(
            config,
            new Dictionary<string, object?>(),
            NullLogger<DnsResolver>.Instance,
            (_, _, _, _) => primary);

        await using var listener = new DnsListener(config, NullLogger<DnsListener>.Instance);
        await listener.StartAsync(new FakeTunnel(resolver));

        var wire = Codec.Encode(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1));

        byte[]? reply = null;
        await listener.HandlePacketAsync(
            wire,
            new IPEndPoint(IPAddress.Loopback, 5353),
            (data, _) =>
            {
                reply = data.ToArray();
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.NotNull(reply);
        Assert.True(reply.Length > DnsListener.MaxUdpPayload);

        var response = Codec.Decode(reply);
        Assert.False(response.Truncated);
        Assert.Equal(40, response.Answers.Count);
    }

    [Fact]
    public async Task HandlePacketAsyncBeforeStartIsANoOp()
    {
        var listener = new DnsListener(new DnsConfig { Enable = false });
        var wire = Codec.Encode(DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1));

        var replied = false;
        await listener.HandlePacketAsync(
            wire,
            new IPEndPoint(IPAddress.Loopback, 5353),
            (_, _) =>
            {
                replied = true;
                return Task.CompletedTask;
            },
            CancellationToken.None);

        Assert.False(replied);
        await listener.DisposeAsync();
    }

    [Fact]
    public async Task DisabledListenerDoesNotBind()
    {
        var config = new DnsConfig { Enable = false, Listen = "127.0.0.1:15354" };
        using var resolver = new DnsResolver(config, new Dictionary<string, object?>(), NullLogger<DnsResolver>.Instance);

        await using var listener = new DnsListener(config, NullLogger<DnsListener>.Instance);
        await listener.StartAsync(new FakeTunnel(resolver));

        Assert.Null(listener.Address);
        Assert.Equal(15354, listener.Port);

        await listener.StopAsync();
    }
}
