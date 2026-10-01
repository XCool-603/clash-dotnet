using System.Net;

namespace Clash.Core.Common;

/// <summary>
/// Everything the router knows about one flow. Created by an inbound listener,
/// progressively enriched (sniffing, DNS resolution, rule matching) and finally
/// recorded on the <c>/connections</c> snapshot.
/// </summary>
public sealed class Metadata
{
    public Network Network { get; set; }

    /// <summary>Client address, when the inbound knows it.</summary>
    public string? SourceAddress { get; set; }

    public ushort SourcePort { get; set; }

    /// <summary>
    /// The original destination as requested by the client: an IP literal or a
    /// domain name. Never rewritten once set.
    /// </summary>
    public string DestinationAddress { get; set; } = string.Empty;

    public ushort DestinationPort { get; set; }

    /// <summary>Domain name for this flow, once known (from the request, sniffing or a mapping).</summary>
    public string? Host { get; set; }

    /// <summary>Host recovered by the sniffer, kept separately for the API's <c>sniffHost</c>.</summary>
    public string? SniffHost { get; set; }

    public string? ProcessPath { get; set; }

    public string? ProcessName { get; set; }

    public string? Uid { get; set; }

    /// <summary>Inbound kind: <c>http</c>, <c>socks</c>, <c>mixed</c>, <c>tun</c>, <c>redir</c>, <c>tproxy</c>, <c>dns</c>.</summary>
    public string InboundType { get; set; } = "mixed";

    /// <summary>Authenticated user of the inbound listener, if any.</summary>
    public string? InboundUser { get; set; }

    public string? InboundName { get; set; }

    public ushort InboundPort { get; set; }

    public DnsMode DnsMode { get; set; } = DnsMode.Normal;

    /// <summary>DSCP / firewall mark carried by the inbound, when available.</summary>
    public int Dscp { get; set; }

    /// <summary>Adapter a "special proxy" rule forced, reported verbatim by the API.</summary>
    public string? SpecialProxy { get; set; }

    public List<string> SpecialRules { get; } = [];

    /// <summary>Rule type name that selected the outbound, e.g. <c>DOMAIN-SUFFIX</c>.</summary>
    public string? Rule { get; set; }

    /// <summary>Payload of the matched rule.</summary>
    public string? RulePayload { get; set; }

    /// <summary>Adapter names this flow traversed, innermost first.</summary>
    public List<string> Chain { get; } = [];

    /// <summary>Remote endpoint the outbound finally connected to, for the API's <c>remoteDestination</c>.</summary>
    public string? RemoteDestination { get; set; }

    /// <summary>True once the destination has been resolved to an address.</summary>
    public bool Resolved { get; set; }

    /// <summary>The domain used for rule matching: <see cref="Host"/> when present, else the literal destination.</summary>
    public string RuleHost
        => !string.IsNullOrEmpty(Host) ? Host : DestinationAddress;

    /// <summary>The value shown in the API's <c>host</c> field.</summary>
    public string ApiHost
        => !string.IsNullOrEmpty(Host) ? Host : DestinationAddress;

    /// <summary>True when <see cref="DestinationAddress"/> is an IP literal rather than a name.</summary>
    public bool DestinationIsIp => IPAddress.TryParse(DestinationAddress, out _);

    public Metadata Clone()
    {
        var copy = new Metadata
        {
            Network = Network,
            SourceAddress = SourceAddress,
            SourcePort = SourcePort,
            DestinationAddress = DestinationAddress,
            DestinationPort = DestinationPort,
            Host = Host,
            SniffHost = SniffHost,
            ProcessPath = ProcessPath,
            ProcessName = ProcessName,
            Uid = Uid,
            InboundType = InboundType,
            InboundUser = InboundUser,
            InboundName = InboundName,
            InboundPort = InboundPort,
            DnsMode = DnsMode,
            Dscp = Dscp,
            SpecialProxy = SpecialProxy,
            Rule = Rule,
            RulePayload = RulePayload,
            RemoteDestination = RemoteDestination,
            Resolved = Resolved,
        };
        copy.SpecialRules.AddRange(SpecialRules);
        copy.Chain.AddRange(Chain);
        return copy;
    }

    /// <summary>A short <c>host:port</c> rendering used in logs.</summary>
    public string DestinationString
        => DestinationPort == 0 ? RuleHost : $"{RuleHost}:{DestinationPort}";

    public override string ToString()
        => $"{Network.ToApiString()} {SourceAddress}:{SourcePort} -> {DestinationString} via {InboundType}";
}
