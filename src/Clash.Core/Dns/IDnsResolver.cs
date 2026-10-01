using System.Net;
using Clash.Core.Common;

namespace Clash.Core.Dns;

public enum DnsQueryType : ushort
{
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Https = 65,
    Any = 255,
}

public enum DnsResponseCode : byte
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
}

public sealed class DnsQuestion
{
    public string Name { get; set; } = string.Empty;
    public DnsQueryType Type { get; set; }
    public ushort Class { get; set; } = 1;
}

public sealed class DnsResourceRecord
{
    public string Name { get; set; } = string.Empty;
    public DnsQueryType Type { get; set; }
    public ushort Class { get; set; } = 1;
    public uint Ttl { get; set; }
    public byte[] Data { get; set; } = [];

    /// <summary>Decoded name for CNAME/NS/PTR records, when <see cref="Type"/> allows.</summary>
    public string? Target { get; set; }

    /// <summary>Decoded address for A/AAAA records.</summary>
    public IPAddress? Address { get; set; }
}

public sealed class DnsMessage
{
    public ushort Id { get; set; }
    public bool IsResponse { get; set; }
    public int OpCode { get; set; }
    public bool AuthoritativeAnswer { get; set; }
    public bool Truncated { get; set; }
    public bool RecursionDesired { get; set; }
    public bool RecursionAvailable { get; set; }
    public bool AuthenticatedData { get; set; }
    public DnsResponseCode ResponseCode { get; set; }
    public List<DnsQuestion> Questions { get; set; } = [];
    public List<DnsResourceRecord> Answers { get; set; } = [];
    public List<DnsResourceRecord> Authorities { get; set; } = [];
    public List<DnsResourceRecord> Additionals { get; set; } = [];

    public static DnsMessage CreateQuery(string name, DnsQueryType type, ushort id = 0) => new()
    {
        Id = id,
        RecursionDesired = true,
        Questions = [new DnsQuestion { Name = name, Type = type }],
    };
}

/// <summary>Wire-format codec for DNS messages (RFC 1035 plus common extensions).</summary>
public interface IDnsCodec
{
    byte[] Encode(DnsMessage message);
    DnsMessage Decode(ReadOnlySpan<byte> buffer);
}

/// <summary>
/// The resolver the tunnel consults. Implementations own hosts overrides,
/// nameserver policy, the fake-IP pool and upstream transport selection.
/// </summary>
public interface IDnsResolver
{
    Configuration.DnsConfig Config { get; }

    /// <summary>Resolves a name, honouring hosts, fake-IP state and nameserver policy.</summary>
    ValueTask<IPAddress[]> ResolveAsync(string host, bool ipv6 = true, CancellationToken cancellationToken = default);

    /// <summary>Resolves from the hosts table only; empty when there is no override.</summary>
    IPAddress[] ResolveHosts(string host);

    /// <summary>True when the address belongs to the configured fake-IP range.</summary>
    bool IsFakeIp(IPAddress address);

    /// <summary>Maps a fake address back to the domain it stands for.</summary>
    string? ReverseFakeIp(IPAddress address);

    /// <summary>Allocates (or returns) the fake address standing for <paramref name="host"/>.</summary>
    IPAddress? FakeIpFor(string host);

    /// <summary>True when <paramref name="host"/> is exempt from fake-IP allocation.</summary>
    bool ShouldFakeIp(string host);

    /// <summary>Full exchange against the upstream chain, used by the DNS listener and <c>/dns/query</c>.</summary>
    Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken = default);

    /// <summary>Drops the fake-IP pool, as <c>POST /cache/fakeip/flush</c> does.</summary>
    void FlushFakeIp();

    /// <summary>Drops the positive/negative answer cache.</summary>
    void FlushCache();
}

/// <summary>Shared helpers for nameserver strings such as <c>tls://1.1.1.1</c>.</summary>
public static class NameServerParser
{
    public enum Transport
    {
        Udp,
        Tcp,
        Tls,
        Https,
        Quic,
        Hosts,
        Dhcp,
    }

    public sealed record ParsedNameServer(Transport Transport, string Host, int Port, string? Path, string Raw)
    {
        public bool UsesTls => Transport is Transport.Tls or Transport.Https or Transport.Quic;
    }

    /// <summary>Parses one <c>nameserver</c> entry.</summary>
    public static ParsedNameServer Parse(string raw)
    {
        var value = raw.Trim();
        var transport = Transport.Udp;
        var path = (string?)null;

        var schemeEnd = value.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd > 0)
        {
            var scheme = value[..schemeEnd].ToLowerInvariant();
            value = value[(schemeEnd + 3)..];
            transport = scheme switch
            {
                "tcp" => Transport.Tcp,
                "tls" => Transport.Tls,
                "https" => Transport.Https,
                "h3" => Transport.Quic,
                "quic" => Transport.Quic,
                "dhcp" => Transport.Dhcp,
                "hosts" => Transport.Hosts,
                _ => Transport.Udp,
            };
        }

        if (transport == Transport.Https)
        {
            var slash = value.IndexOf('/');
            if (slash >= 0)
            {
                path = value[slash..];
                value = value[..slash];
            }
        }

        var host = value;
        var port = transport switch
        {
            Transport.Tls or Transport.Quic => 853,
            Transport.Https => 443,
            Transport.Tcp => 53,
            _ => 53,
        };

        // IPv6 literal handling: [::1]:53
        if (host.StartsWith('['))
        {
            var close = host.IndexOf(']');
            if (close > 0)
            {
                var literal = host[1..close];
                var rest = host[(close + 1)..];
                if (rest.StartsWith(':') && int.TryParse(rest[1..], out var p6)) port = p6;
                return new ParsedNameServer(transport, literal, port, path, raw);
            }
        }

        var colon = host.LastIndexOf(':');
        if (colon > 0 && host.IndexOf(':') == colon && int.TryParse(host[(colon + 1)..], out var parsedPort))
        {
            port = parsedPort;
            host = host[..colon];
        }

        return new ParsedNameServer(transport, host, port, path, raw);
    }
}
