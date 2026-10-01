using Clash.Core.Dns;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class NameServerParserTests
{
    [Theory]
    [InlineData("1.1.1.1", NameServerParser.Transport.Udp, "1.1.1.1", 53)]
    [InlineData("8.8.8.8:5353", NameServerParser.Transport.Udp, "8.8.8.8", 5353)]
    [InlineData("tcp://9.9.9.9", NameServerParser.Transport.Tcp, "9.9.9.9", 53)]
    [InlineData("tcp://9.9.9.9:5300", NameServerParser.Transport.Tcp, "9.9.9.9", 5300)]
    [InlineData("tls://dns.google", NameServerParser.Transport.Tls, "dns.google", 853)]
    [InlineData("tls://1.1.1.1:8853", NameServerParser.Transport.Tls, "1.1.1.1", 8853)]
    [InlineData("https://cloudflare-dns.com/dns-query", NameServerParser.Transport.Https, "cloudflare-dns.com", 443)]
    [InlineData("quic://dns.adguard.com", NameServerParser.Transport.Quic, "dns.adguard.com", 853)]
    [InlineData("dhcp://en0", NameServerParser.Transport.Dhcp, "en0", 53)]
    [InlineData("hosts://", NameServerParser.Transport.Hosts, "", 53)]
    public void ParsesEveryTransport(string raw, NameServerParser.Transport transport, string host, int port)
    {
        var parsed = NameServerParser.Parse(raw);

        Assert.Equal(transport, parsed.Transport);
        Assert.Equal(host, parsed.Host);
        Assert.Equal(port, parsed.Port);
        Assert.Equal(raw, parsed.Raw);
    }

    [Fact]
    public void H3EntriesKeepThePathGluedToTheHost()
    {
        // The parser only splits the path off https:// URLs; DnsUpstreams
        // normalises h3:// itself, and this test pins that known behaviour.
        var parsed = NameServerParser.Parse("h3://dns.google/dns-query");

        Assert.Equal(NameServerParser.Transport.Quic, parsed.Transport);
        Assert.Equal("dns.google/dns-query", parsed.Host);
        Assert.Equal(853, parsed.Port);
        Assert.Null(parsed.Path);
    }

    [Fact]
    public void KeepsTheDohPath()
    {
        var parsed = NameServerParser.Parse("https://cloudflare-dns.com/dns-query");

        Assert.Equal("/dns-query", parsed.Path);
        Assert.True(parsed.UsesTls);
    }

    [Fact]
    public void DohWithoutAPathHasNoPath()
    {
        var parsed = NameServerParser.Parse("https://1.1.1.1");

        Assert.Null(parsed.Path);
        Assert.Equal("1.1.1.1", parsed.Host);
    }

    [Fact]
    public void ParsesBracketedIpv6Literals()
    {
        var parsed = NameServerParser.Parse("[2606:4700:4700::1111]:5353");

        Assert.Equal(NameServerParser.Transport.Udp, parsed.Transport);
        Assert.Equal("2606:4700:4700::1111", parsed.Host);
        Assert.Equal(5353, parsed.Port);
    }

    [Fact]
    public void ParsesBracketedIpv6WithScheme()
    {
        var parsed = NameServerParser.Parse("tls://[2606:4700:4700::1111]:853");

        Assert.Equal(NameServerParser.Transport.Tls, parsed.Transport);
        Assert.Equal("2606:4700:4700::1111", parsed.Host);
        Assert.Equal(853, parsed.Port);
    }

    [Fact]
    public void PlainUdpIsNotTls()
    {
        Assert.False(NameServerParser.Parse("1.1.1.1").UsesTls);
        Assert.False(NameServerParser.Parse("tcp://1.1.1.1").UsesTls);
        Assert.False(NameServerParser.Parse("dhcp://en0").UsesTls);
        Assert.True(NameServerParser.Parse("tls://1.1.1.1").UsesTls);
        Assert.True(NameServerParser.Parse("h3://1.1.1.1").UsesTls);
    }

    [Fact]
    public void UnknownSchemeFallsBackToUdp()
    {
        var parsed = NameServerParser.Parse("sdns://whatever");

        Assert.Equal(NameServerParser.Transport.Udp, parsed.Transport);
    }

    [Fact]
    public void SurroundingWhitespaceIsIgnored()
    {
        var parsed = NameServerParser.Parse("  1.1.1.1  ");

        Assert.Equal("1.1.1.1", parsed.Host);
        Assert.Equal(53, parsed.Port);
    }
}
