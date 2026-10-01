using System.Net;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Rules;

namespace Clash.Tests.Rules;

/// <summary>A resolver whose answers are scripted per host, so resolution is observable.</summary>
internal sealed class FakeDnsResolver : IDnsResolver
{
    private readonly Dictionary<string, IPAddress[]> _answers = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Number of <see cref="ResolveAsync"/> calls made.</summary>
    public int Calls { get; private set; }

    /// <summary>When true every lookup fails.</summary>
    public bool Fail { get; set; }

    /// <inheritdoc />
    public DnsConfig Config { get; } = new();

    /// <summary>Scripts the answer for a host.</summary>
    public FakeDnsResolver Answer(string host, params string[] addresses)
    {
        _answers[host] = addresses.Select(IPAddress.Parse).ToArray();
        return this;
    }

    /// <inheritdoc />
    public ValueTask<IPAddress[]> ResolveAsync(string host, bool ipv6 = true, CancellationToken cancellationToken = default)
    {
        Calls++;
        if (Fail) throw new DnsException($"no answer for {host}");
        return new ValueTask<IPAddress[]>(_answers.TryGetValue(host, out var addresses) ? addresses : []);
    }

    /// <inheritdoc />
    public IPAddress[] ResolveHosts(string host) => _answers.TryGetValue(host, out var addresses) ? addresses : [];

    /// <inheritdoc />
    public bool IsFakeIp(IPAddress address) => false;

    /// <inheritdoc />
    public string? ReverseFakeIp(IPAddress address) => null;

    /// <inheritdoc />
    public IPAddress? FakeIpFor(string host) => null;

    /// <inheritdoc />
    public bool ShouldFakeIp(string host) => false;

    /// <inheritdoc />
    public Task<DnsMessage> ExchangeAsync(DnsMessage query, CancellationToken cancellationToken = default)
        => Task.FromResult(new DnsMessage { IsResponse = true });

    /// <inheritdoc />
    public void FlushFakeIp()
    {
    }

    /// <inheritdoc />
    public void FlushCache()
    {
    }
}

/// <summary>A geo database backed by in-memory tables.</summary>
internal sealed class FakeGeoData : IGeoData
{
    private readonly Dictionary<string, string> _countries = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, uint> _asns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _geoSites = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(IPAddress, int)>> _geoSiteCidrs = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Records a country for an address literal.</summary>
    public FakeGeoData Country(string address, string code)
    {
        _countries[address] = code;
        return this;
    }

    /// <summary>Records an ASN for an address literal.</summary>
    public FakeGeoData Asn(string address, uint asn)
    {
        _asns[address] = asn;
        return this;
    }

    /// <summary>Records a geosite category.</summary>
    public FakeGeoData Site(string code, params string[] domains)
    {
        _geoSites[code] = [.. domains];
        return this;
    }

    /// <summary>Records the <c>ipcidr</c> entries of a geosite category.</summary>
    public FakeGeoData SiteCidr(string code, string cidr)
    {
        var parts = cidr.Split('/');
        if (!_geoSiteCidrs.TryGetValue(code, out var list))
        {
            list = [];
            _geoSiteCidrs[code] = list;
        }

        list.Add((IPAddress.Parse(parts[0]), int.Parse(parts[1])));
        return this;
    }

    /// <inheritdoc />
    public Task LoadAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;

    /// <inheritdoc />
    public bool TryGetCountry(IPAddress address, out string countryCode)
        => _countries.TryGetValue(address.ToString(), out countryCode!);

    /// <inheritdoc />
    public bool TryGetAsn(IPAddress address, out uint asn) => _asns.TryGetValue(address.ToString(), out asn);

    /// <inheritdoc />
    public IReadOnlyCollection<string>? GetGeoSite(string code)
        => _geoSites.TryGetValue(code, out var domains) ? domains : null;

    /// <inheritdoc />
    public IReadOnlyList<(IPAddress Network, int PrefixLength)>? GetGeoSiteCidrs(string code)
        => _geoSiteCidrs.TryGetValue(code, out var cidrs) ? cidrs : null;

    /// <inheritdoc />
    public bool HasGeoSite(string code) => _geoSites.ContainsKey(code);

    /// <inheritdoc />
    public bool HasCountry(string code) => _countries.ContainsValue(code);
}

/// <summary>Shared helpers for the rule tests.</summary>
internal static class TestMetadata
{
    /// <summary>Builds a flow with sensible defaults.</summary>
    public static Metadata Flow(
        string destination,
        ushort destinationPort = 443,
        Network network = Network.Tcp,
        string? host = null)
        => new()
        {
            DestinationAddress = destination,
            DestinationPort = destinationPort,
            Host = host,
            Network = network,
            SourceAddress = "192.168.1.50",
            SourcePort = 51234,
            InboundPort = 7890,
            InboundType = "mixed",
        };

    /// <summary>Builds a set from payload lines.</summary>
    public static IRuleSet Set(string name, string behavior, params string[] payload)
        => RuleSet.FromPayload(name, behavior, payload);
}
