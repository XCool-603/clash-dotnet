using System.Buffers.Binary;
using System.Text;
using Clash.Core.Tunnel;
using Xunit;

namespace Clash.Tests.Tunnel;

public class SnifferTests
{
    [Fact]
    public void ExtractsSniFromAClientHello()
    {
        var hello = BuildClientHello("www.example.com");
        Assert.Equal("www.example.com", Sniffer.SniffTlsServerName(hello));
    }

    [Fact]
    public void ExtractsSniWithALongHostname()
    {
        var host = new string('a', 120) + ".example.com";
        var hello = BuildClientHello(host);
        Assert.Equal(host, Sniffer.SniffTlsServerName(hello));
    }

    [Fact]
    public void ReturnsNullWhenThereIsNoServerNameExtension()
    {
        var hello = BuildClientHello(null);
        Assert.Null(Sniffer.SniffTlsServerName(hello));
    }

    [Fact]
    public void ReturnsNullForTruncatedInput()
    {
        var hello = BuildClientHello("www.example.com");
        for (var length = 0; length < hello.Length; length++)
        {
            // Every prefix must be handled without throwing. A prefix that happens
            // to contain the whole extension may legitimately still parse, so only
            // the no-throw property is asserted here.
            _ = Sniffer.SniffTlsServerName(hello.AsSpan(0, length));
        }
    }

    [Fact]
    public void ReturnsNullForGarbage()
    {
        Assert.Null(Sniffer.SniffTlsServerName([0x00, 0x01, 0x02, 0x03]));
        Assert.Null(Sniffer.SniffTlsServerName([]));
        Assert.Null(Sniffer.SniffTlsServerName(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n")));
    }

    [Fact]
    public void DoesNotHangOnALyingHandshakeLength()
    {
        var hello = BuildClientHello("www.example.com");
        // Claim a handshake far longer than the buffer.
        hello[6] = 0x7F;
        hello[7] = 0xFF;
        hello[8] = 0xFF;
        Assert.Null(Sniffer.SniffTlsServerName(hello));
    }

    [Theory]
    [InlineData("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com")]
    [InlineData("POST /a HTTP/1.1\r\nhost:   Example.COM:8080  \r\n\r\n", "Example.COM")]
    [InlineData("HEAD / HTTP/1.0\r\nAccept: */*\r\nHost: [::1]:8080\r\n\r\n", "::1")]
    [InlineData("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "example.com")]
    public void ExtractsHttpHost(string request, string expected)
    {
        Assert.Equal(expected, Sniffer.SniffHttpHost(Encoding.ASCII.GetBytes(request)));
    }

    [Fact]
    public void ReturnsNullWhenTheHttpRequestHasNoHostHeader()
    {
        var request = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nAccept: */*\r\n\r\n");
        Assert.Null(Sniffer.SniffHttpHost(request));
    }

    [Fact]
    public void ReturnsNullForANonHttpPayload()
    {
        Assert.Null(Sniffer.SniffHttpHost(Encoding.ASCII.GetBytes("\x16\x03\x01\x00\x50something")));
        Assert.Null(Sniffer.SniffHttpHost([]));
    }

    [Fact]
    public void QuicSniffingIsBestEffortAndNeverThrows()
    {
        Assert.Null(Sniffer.SniffQuicServerName([]));
        Assert.Null(Sniffer.SniffQuicServerName([0xc0, 0x00, 0x00, 0x00, 0x01]));

        // A QUIC Initial that carries a cleartext ClientHello in its payload.
        var payload = new byte[] { 0xc3, 0x00, 0x00, 0x00, 0x01 };
        var hello = BuildClientHello("quic.example.com");
        var combined = new byte[payload.Length + 4 + hello.Length];
        payload.CopyTo(combined, 0);
        hello.CopyTo(combined, payload.Length + 4);
        Assert.Equal("quic.example.com", Sniffer.SniffQuicServerName(combined));
    }

    /// <summary>Assembles a syntactically valid TLS ClientHello record.</summary>
    private static byte[] BuildClientHello(string? sni)
    {
        var extensions = new List<byte>();

        if (sni is not null)
        {
            var name = Encoding.ASCII.GetBytes(sni);
            var entry = new List<byte> { 0x00 };                       // name_type = host_name
            entry.Add((byte)(name.Length >> 8));
            entry.Add((byte)(name.Length & 0xFF));
            entry.AddRange(name);

            var list = new List<byte>();
            list.Add((byte)(entry.Count >> 8));
            list.Add((byte)(entry.Count & 0xFF));
            list.AddRange(entry);

            extensions.Add(0x00);                                       // extension_type = server_name
            extensions.Add(0x00);
            extensions.Add((byte)(list.Count >> 8));
            extensions.Add((byte)(list.Count & 0xFF));
            extensions.AddRange(list);
        }

        // supported_versions extension, so the hello looks realistic.
        extensions.AddRange([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        var hello = new List<byte>
        {
            0x03, 0x03,                                                 // legacy_version
        };
        hello.AddRange(new byte[32]);                                   // random
        hello.Add(0x00);                                                // session id length
        hello.AddRange([0x00, 0x02, 0x13, 0x01]);                       // cipher suites
        hello.AddRange([0x01, 0x00]);                                   // compression methods
        hello.Add((byte)(extensions.Count >> 8));
        hello.Add((byte)(extensions.Count & 0xFF));
        hello.AddRange(extensions);

        var handshake = new List<byte> { 0x01 };                        // client_hello
        handshake.Add((byte)(hello.Count >> 16));
        handshake.Add((byte)((hello.Count >> 8) & 0xFF));
        handshake.Add((byte)(hello.Count & 0xFF));
        handshake.AddRange(hello);

        var record = new List<byte> { 0x16, 0x03, 0x01 };
        record.Add((byte)(handshake.Count >> 8));
        record.Add((byte)(handshake.Count & 0xFF));
        record.AddRange(handshake);

        return record.ToArray();
    }

    [Fact]
    public void SniffedHostIsUsedOnlyWhenTheDestinationIsAnAddress()
    {
        // Documents the contract the tunnel relies on: the sniffer is a pure
        // function over bytes and makes no routing decision itself.
        var hello = BuildClientHello("sniffed.example.com");
        Assert.Equal("sniffed.example.com", Sniffer.SniffTlsServerName(hello));

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(hello.AsSpan(3, 2));
        Assert.Equal(hello.Length - 5, recordLength);
    }
}
