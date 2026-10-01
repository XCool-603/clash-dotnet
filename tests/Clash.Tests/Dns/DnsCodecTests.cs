using System.Net;
using Clash.Core.Common;
using Clash.Core.Dns;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class DnsCodecTests
{
    private readonly DnsCodec _codec = new();

    // ── Round trips ─────────────────────────────────────────────────────────

    [Fact]
    public void RoundTripsAddressRecords()
    {
        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 0x1234);
        message.Answers.Add(DnsCodec.CreateAddressRecord("example.com", IPAddress.Parse("93.184.216.34"), 300));
        message.Answers.Add(DnsCodec.CreateAddressRecord("example.com", IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946"), 300));

        var decoded = _codec.Decode(_codec.Encode(message));

        Assert.Equal(0x1234, decoded.Id);
        Assert.Equal(2, decoded.Answers.Count);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), decoded.Answers[0].Address);
        Assert.Equal(DnsQueryType.A, decoded.Answers[0].Type);
        Assert.Equal(300u, decoded.Answers[0].Ttl);
        Assert.Equal(IPAddress.Parse("2606:2800:220:1:248:1893:25c8:1946"), decoded.Answers[1].Address);
        Assert.Equal(DnsQueryType.Aaaa, decoded.Answers[1].Type);
    }

    [Theory]
    [InlineData(DnsQueryType.Cname, "target.example.net")]
    [InlineData(DnsQueryType.Ns, "ns1.example.net")]
    [InlineData(DnsQueryType.Ptr, "host.example.net")]
    public void RoundTripsNameBearingRecords(DnsQueryType type, string target)
    {
        var message = DnsMessage.CreateQuery("example.com", type, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "example.com",
            Type = type,
            Class = 1,
            Ttl = 120,
            Target = target,
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal(type, record.Type);
        Assert.Equal(target, record.Target);
        Assert.Equal(120u, record.Ttl);
    }

    [Fact]
    public void RoundTripsMxRecord()
    {
        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.Mx, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "example.com",
            Type = DnsQueryType.Mx,
            Ttl = 60,
            Data = [0x00, 0x0A, 0x04, (byte)'m', (byte)'a', (byte)'i', (byte)'l', 0x00],
            Target = "mail",
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal(DnsQueryType.Mx, record.Type);
        byte[] expected = [0x00, 0x0A, 0x04, (byte)'m', (byte)'a', (byte)'i', (byte)'l', 0x00];
        Assert.Equal(expected, record.Data);
    }

    [Fact]
    public void RoundTripsTxtRecord()
    {
        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.Txt, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "example.com",
            Type = DnsQueryType.Txt,
            Ttl = 30,
            Data = [0x0B, .. "hello world"u8.ToArray()],
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal(DnsQueryType.Txt, record.Type);
        byte[] expected = [0x0B, .. "hello world"u8.ToArray()];
        Assert.Equal(expected, record.Data);
    }

    [Fact]
    public void RoundTripsSoaRecord()
    {
        var soa = new Wire()
            .Name("ns1.example.com")
            .Name("hostmaster.example.com")
            .U32(2024010101)
            .U32(7200)
            .U32(3600)
            .U32(1209600)
            .U32(3600)
            .ToArray();

        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.Soa, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "example.com",
            Type = DnsQueryType.Soa,
            Ttl = 900,
            Data = soa,
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal(DnsQueryType.Soa, record.Type);
        Assert.Equal(soa, record.Data);
    }

    [Fact]
    public void RoundTripsSrvRecord()
    {
        var srv = new Wire()
            .U16(10)
            .U16(20)
            .U16(5060)
            .Name("sip.example.com")
            .ToArray();

        var message = DnsMessage.CreateQuery("_sip._tcp.example.com", DnsQueryType.Srv, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "_sip._tcp.example.com",
            Type = DnsQueryType.Srv,
            Ttl = 300,
            Data = srv,
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal(DnsQueryType.Srv, record.Type);
        Assert.Equal(srv, record.Data);
    }

    [Fact]
    public void RoundTripsHttpsRecord()
    {
        var https = new Wire()
            .U16(1)
            .Name(".")
            .U16(1)
            .U16(3)
            .U16(2)
            .U16(0x01BB)
            .ToArray();

        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.Https, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "example.com",
            Type = DnsQueryType.Https,
            Ttl = 300,
            Data = https,
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal(DnsQueryType.Https, record.Type);
        Assert.Equal(https, record.Data);
    }

    [Fact]
    public void RoundTripsUnknownTypeAsOpaqueRdata()
    {
        var message = DnsMessage.CreateQuery("example.com", (DnsQueryType)65280, 7);
        message.Answers.Add(new DnsResourceRecord
        {
            Name = "example.com",
            Type = (DnsQueryType)65280,
            Ttl = 42,
            Data = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01],
        });

        var decoded = _codec.Decode(_codec.Encode(message));

        var record = Assert.Single(decoded.Answers);
        Assert.Equal((DnsQueryType)65280, record.Type);
        byte[] expected = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        Assert.Equal(expected, record.Data);
        Assert.Null(record.Address);
        Assert.Null(record.Target);
    }

    [Fact]
    public void RoundTripsHeaderFlagsAndSections()
    {
        var message = new DnsMessage
        {
            Id = 0xABCD,
            IsResponse = true,
            OpCode = 2,
            AuthoritativeAnswer = true,
            Truncated = false,
            RecursionDesired = true,
            RecursionAvailable = true,
            AuthenticatedData = true,
            ResponseCode = DnsResponseCode.NameError,
        };

        message.Questions.Add(new DnsQuestion { Name = "a.example.com", Type = DnsQueryType.A, Class = 1 });
        message.Authorities.Add(new DnsResourceRecord { Name = "example.com", Type = DnsQueryType.Ns, Ttl = 60, Target = "ns1.example.com" });
        message.Additionals.Add(DnsCodec.CreateAddressRecord("ns1.example.com", IPAddress.Parse("10.0.0.1"), 60));

        var decoded = _codec.Decode(_codec.Encode(message));

        Assert.Equal(0xABCD, decoded.Id);
        Assert.True(decoded.IsResponse);
        Assert.Equal(2, decoded.OpCode);
        Assert.True(decoded.AuthoritativeAnswer);
        Assert.False(decoded.Truncated);
        Assert.True(decoded.RecursionDesired);
        Assert.True(decoded.RecursionAvailable);
        Assert.True(decoded.AuthenticatedData);
        Assert.Equal(DnsResponseCode.NameError, decoded.ResponseCode);
        Assert.Single(decoded.Questions);
        Assert.Single(decoded.Authorities);
        Assert.Single(decoded.Additionals);
        Assert.Equal("a.example.com", decoded.Questions[0].Name);
        Assert.Equal("ns1.example.com", decoded.Authorities[0].Target);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), decoded.Additionals[0].Address);
    }

    [Fact]
    public void RoundTripsRootAndTrailingDotNames()
    {
        var message = DnsMessage.CreateQuery("example.com.", DnsQueryType.A, 1);
        var decoded = _codec.Decode(_codec.Encode(message));

        // Encoding normalises away the trailing dot.
        Assert.Equal("example.com", decoded.Questions[0].Name);
    }

    [Fact]
    public void CheckingDisabledBitIsSupportedByTheOverload()
    {
        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1);
        var wire = _codec.Encode(message, checkingDisabled: true);

        Assert.True(DnsCodec.IsCheckingDisabled(wire));

        var plain = _codec.Encode(message);
        Assert.False(DnsCodec.IsCheckingDisabled(plain));
    }

    // ── Compression ─────────────────────────────────────────────────────────

    [Fact]
    public void DecodeFollowsCompressionPointerForAnswerName()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(1).U16(1).U16(0).U16(0)
            .Name("foo.com").U16(1).U16(1)
            .U16(0xC00C).U16(1).U16(1).U32(60).U16(4).Raw(1, 2, 3, 4)
            .ToArray();

        var decoded = _codec.Decode(wire);

        var record = Assert.Single(decoded.Answers);
        Assert.Equal("foo.com", record.Name);
        Assert.Equal(IPAddress.Parse("1.2.3.4"), record.Address);
    }

    [Fact]
    public void DecodeFollowsChainedCompressionPointers()
    {
        // question name at 12..20; a second name at 25 is "www" + pointer to 12;
        // the answer name points at 25, so decoding takes two hops.
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(1).U16(1).U16(0).U16(0)
            .Name("foo.com").U16(1).U16(1)
            .Raw(3, (byte)'w', (byte)'w', (byte)'w', 0xC0, 0x0C)
            .U16(0xC019).U16(1).U16(1).U32(60).U16(4).Raw(1, 2, 3, 4)
            .ToArray();

        var decoded = _codec.Decode(wire);

        var record = Assert.Single(decoded.Answers);
        Assert.Equal("www.foo.com", record.Name);
    }

    [Fact(Timeout = 5000)]
    public async Task DecodeRejectsSelfReferencingPointerLoop()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(0).U16(1).U16(0).U16(0)
            .U16(0xC00C).U16(1).U16(1).U32(0).U16(0)
            .ToArray();

        var error = await Task.Run(() => Record.Exception(() => _codec.Decode(wire)));

        Assert.IsType<DnsException>(error);
    }

    [Fact(Timeout = 5000)]
    public async Task DecodeRejectsMutualPointerLoop()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(0).U16(1).U16(0).U16(0)
            .U16(0xC00E).U16(0xC00C)
            .U16(1).U16(1).U32(0).U16(0)
            .ToArray();

        var error = await Task.Run(() => Record.Exception(() => _codec.Decode(wire)));

        Assert.IsType<DnsException>(error);
    }

    [Fact]
    public void DecodeRejectsPointerThatSkipsForward()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(0).U16(1).U16(0).U16(0)
            .U16(0xC00E)
            .Name("foo.com")
            .ToArray();

        var error = Assert.Throws<DnsException>(() => _codec.Decode(wire));
        Assert.Contains("backwards", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecodeRejectsPointerPastEndOfMessage()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(0).U16(1).U16(0).U16(0)
            .U16(0xC0FF)
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void EncodeUsesPointerForMatchingAnswerName()
    {
        var message = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1);
        message.Answers.Add(DnsCodec.CreateAddressRecord("example.com", IPAddress.Parse("1.2.3.4"), 60));

        var wire = _codec.Encode(message);

        // Header (12) + name (13) + qtype/qclass (4) = offset 29; the answer name
        // must be the two-byte pointer to offset 12.
        Assert.Equal(0xC0, wire[29]);
        Assert.Equal(0x0C, wire[30]);
    }

    // ── Malformed input ─────────────────────────────────────────────────────

    [Fact]
    public void DecodeThrowsOnShortHeader()
    {
        var error = Assert.Throws<DnsException>(() => _codec.Decode([0x00, 0x01, 0x02]));
        Assert.Contains("truncated", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecodeThrowsOnTruncatedQuestion()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x0100)
            .U16(1).U16(0).U16(0).U16(0)
            .Name("example.com")
            .U16(1)
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void DecodeThrowsWhenRdataOverrunsMessage()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(1).U16(1).U16(0).U16(0)
            .Name("foo.com").U16(1).U16(1)
            .U16(0xC00C).U16(1).U16(1).U32(60).U16(16).Raw(1, 2, 3, 4)
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void DecodeThrowsOnOversizedLabel()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x0100)
            .U16(1).U16(0).U16(0).U16(0)
            .U8(200).Raw(new byte[10])
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void DecodeThrowsWhenNameRunsPastEnd()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x0100)
            .U16(1).U16(0).U16(0).U16(0)
            .U8(5).Raw((byte)'a', (byte)'b')
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void DecodeThrowsOnReservedLabelType()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x0100)
            .U16(1).U16(0).U16(0).U16(0)
            .U8(0x80).U8(0x00)
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void DecodeThrowsWhenARecordHasTheWrongLength()
    {
        var wire = new Wire()
            .U16(0x1234).U16(0x8180)
            .U16(1).U16(1).U16(0).U16(0)
            .Name("foo.com").U16(1).U16(1)
            .U16(0xC00C).U16(1).U16(1).U32(60).U16(3).Raw(1, 2, 3)
            .ToArray();

        Assert.Throws<DnsException>(() => _codec.Decode(wire));
    }

    [Fact]
    public void EncodeThrowsOnOversizedName()
    {
        var label = new string('a', 64);
        var message = DnsMessage.CreateQuery($"{label}.example.com", DnsQueryType.A, 1);

        Assert.Throws<DnsException>(() => _codec.Encode(message));
    }

    [Fact]
    public void SplitLabelsHandlesEscapes()
    {
        var labels = DnsCodec.SplitLabels(@"a\.b.example.com");

        Assert.Equal(new[] { "a.b", "example", "com" }, labels.ToArray());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    [Fact]
    public void CreateResponseMirrorsTheQuery()
    {
        var query = new DnsMessage
        {
            Id = 0x4242,
            OpCode = 0,
            RecursionDesired = true,
            Questions = [new DnsQuestion { Name = "example.com", Type = DnsQueryType.A }],
        };

        var response = DnsCodec.CreateResponse(query, DnsResponseCode.NameError);

        Assert.Equal(0x4242, response.Id);
        Assert.True(response.IsResponse);
        Assert.True(response.RecursionDesired);
        Assert.True(response.RecursionAvailable);
        Assert.Equal(DnsResponseCode.NameError, response.ResponseCode);
        Assert.Equal("example.com", Assert.Single(response.Questions).Name);
        Assert.Empty(response.Answers);
    }

    [Fact]
    public void WithAnswersForcesTheTtl()
    {
        var query = DnsMessage.CreateQuery("example.com", DnsQueryType.A, 1);
        var answers = new[]
        {
            DnsCodec.CreateAddressRecord("example.com", IPAddress.Parse("1.2.3.4"), 9999),
            DnsCodec.CreateAddressRecord("example.com", IPAddress.Parse("5.6.7.8"), 1),
        };

        var response = DnsCodec.WithAnswers(query, answers, 30);

        Assert.Equal(DnsResponseCode.NoError, response.ResponseCode);
        Assert.All(response.Answers, a => Assert.Equal(30u, a.Ttl));
        Assert.Equal(2, response.Answers.Count);
    }

    [Fact]
    public void CreateAddressRecordPicksTheRightType()
    {
        Assert.Equal(DnsQueryType.A, DnsCodec.CreateAddressRecord("a", IPAddress.Parse("1.2.3.4")).Type);
        Assert.Equal(DnsQueryType.Aaaa, DnsCodec.CreateAddressRecord("a", IPAddress.Parse("::1")).Type);
    }
}
