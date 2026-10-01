using System.Net;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;
using Clash.Core.Tunnel;

namespace Clash.Tests.Dns;

/// <summary>An upstream that answers from a delegate, counting the calls it receives.</summary>
internal sealed class FakeDnsUpstream : IDnsUpstream
{
    private readonly Func<DnsMessage, DnsMessage> _handler;
    private int _calls;

    public FakeDnsUpstream(Func<DnsMessage, DnsMessage> handler, string name = "fake://")
    {
        _handler = handler;
        Name = name;
    }

    public string Name { get; }

    public int Calls => Volatile.Read(ref _calls);

    public List<DnsQueryType> QueryTypes { get; } = [];

    public List<string> QueryNames { get; } = [];

    public Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);

        lock (QueryTypes)
        {
            QueryTypes.Add(query.Questions[0].Type);
            QueryNames.Add(query.Questions[0].Name);
        }

        var response = _handler(query);
        response.Id = query.Id;
        return Task.FromResult(response);
    }
}

/// <summary>Canned responses for <see cref="FakeDnsUpstream"/>.</summary>
internal static class DnsAnswers
{
    public static DnsMessage Addresses(DnsMessage query, params string[] addresses)
        => Addresses(query, 60, addresses);

    public static DnsMessage Addresses(DnsMessage query, uint ttl, params string[] addresses)
    {
        var question = query.Questions[0];
        var records = new List<DnsResourceRecord>();

        foreach (var text in addresses)
        {
            var address = IPAddress.Parse(text);
            if (question.Type == DnsQueryType.A && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
            if (question.Type == DnsQueryType.Aaaa && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) continue;
            records.Add(DnsCodec.CreateAddressRecord(question.Name, address, ttl));
        }

        return DnsCodec.WithAnswers(query, records, ttl);
    }

    public static DnsMessage Empty(DnsMessage query) => DnsCodec.CreateResponse(query, DnsResponseCode.NoError);

    public static DnsMessage NameError(DnsMessage query) => DnsCodec.CreateResponse(query, DnsResponseCode.NameError);

    public static DnsMessage Failure(DnsMessage query) => DnsCodec.CreateResponse(query, DnsResponseCode.ServerFailure);

    public static DnsMessage Explode(DnsMessage query) => throw new DnsException("upstream exploded");
}

/// <summary>A tunnel whose only useful member is <see cref="Dns"/>.</summary>
internal sealed class FakeTunnel(IDnsResolver dns) : ITunnel
{
    public ClashConfig Config { get; } = new();

    public IDnsResolver Dns { get; } = dns;

    public IGeoData Geo => null!;

    public IProxyManager Proxies => null!;

    public ConnectionManager Connections { get; } = new(new TrafficTracker());

    public IRuleEngine Rules => null!;

    public TrafficTracker Traffic { get; } = new();

    public IDelayTester DelayTester => null!;

    public Mode Mode { get; set; }

    public event Action<string, string>? LogEmitted;

    public Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult<RuleMatch?>(null);

    public Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default)
        => throw new NotSupportedException();

    public void Log(string level, string message)
    {
        LogEmitted?.Invoke(level, message);
    }
}

/// <summary>Byte-level builder so tests can hand-craft hostile packets.</summary>
internal sealed class Wire
{
    private readonly List<byte> _bytes = [];

    public int Length => _bytes.Count;

    public Wire U8(int value)
    {
        _bytes.Add((byte)value);
        return this;
    }

    public Wire U16(int value)
    {
        _bytes.Add((byte)(value >> 8));
        _bytes.Add((byte)(value & 0xFF));
        return this;
    }

    public Wire U32(uint value)
    {
        _bytes.Add((byte)(value >> 24));
        _bytes.Add((byte)((value >> 16) & 0xFF));
        _bytes.Add((byte)((value >> 8) & 0xFF));
        _bytes.Add((byte)(value & 0xFF));
        return this;
    }

    public Wire Raw(params byte[] bytes)
    {
        _bytes.AddRange(bytes);
        return this;
    }

    public Wire Name(string name)
    {
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            _bytes.Add((byte)label.Length);
            _bytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
        }

        _bytes.Add(0);
        return this;
    }

    public byte[] ToArray() => [.. _bytes];
}
