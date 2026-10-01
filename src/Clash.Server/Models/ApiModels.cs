using System.Text.Json.Serialization;

namespace Clash.Server.Models;

/// <summary>The body of <c>GET /connections</c>.</summary>
public sealed class ConnectionsResponse
{
    /// <summary>Bytes downloaded since the process started.</summary>
    public long DownloadTotal { get; init; }

    /// <summary>Bytes uploaded since the process started.</summary>
    public long UploadTotal { get; init; }

    /// <summary>Resident memory of the process, in bytes.</summary>
    public long Memory { get; init; }

    /// <summary>The live flows, newest first.</summary>
    public IReadOnlyList<ConnectionObject> Connections { get; init; } = [];
}

/// <summary>One live flow, in Clash's exact shape.</summary>
public sealed class ConnectionObject
{
    /// <summary>Opaque identifier used by <c>DELETE /connections/:id</c>.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>Bytes sent by the client on this flow.</summary>
    public long Upload { get; init; }

    /// <summary>Bytes received by the client on this flow.</summary>
    public long Download { get; init; }

    /// <summary>RFC3339 UTC timestamp of when the flow was accepted.</summary>
    public string Start { get; init; } = string.Empty;

    /// <summary>Adapter names the flow traversed, outermost first.</summary>
    public IReadOnlyList<string> Chains { get; init; } = [];

    /// <summary>Rule type that selected the outbound.</summary>
    public string Rule { get; init; } = string.Empty;

    /// <summary>Payload of the matched rule.</summary>
    public string RulePayload { get; init; } = string.Empty;

    /// <summary>Everything known about the flow's endpoints.</summary>
    public ConnectionMetadata Metadata { get; init; } = new();
}

/// <summary>The <c>metadata</c> object of one connection.</summary>
public sealed class ConnectionMetadata
{
    /// <summary><c>tcp</c> or <c>udp</c>.</summary>
    public string Network { get; init; } = "tcp";

    /// <summary>Inbound protocol that accepted the flow, e.g. <c>HTTP</c>.</summary>
    public string Type { get; init; } = string.Empty;

    /// <summary>Client address.</summary>
    public string SourceIP { get; init; } = string.Empty;

    /// <summary>Destination address as requested by the client.</summary>
    public string DestinationIP { get; init; } = string.Empty;

    /// <summary>Client port, as a string like Clash reports it.</summary>
    public string SourcePort { get; init; } = string.Empty;

    /// <summary>Destination port, as a string like Clash reports it.</summary>
    public string DestinationPort { get; init; } = string.Empty;

    /// <summary>Domain of the flow, when known.</summary>
    public string Host { get; init; } = string.Empty;

    /// <summary><c>normal</c>, <c>fake-ip</c> or <c>mapping</c>.</summary>
    public string DnsMode { get; init; } = string.Empty;

    /// <summary>Executable that owns the flow, when process matching is on.</summary>
    public string ProcessPath { get; init; } = string.Empty;

    /// <summary>Adapter a special-proxy rule forced.</summary>
    public string SpecialProxy { get; init; } = string.Empty;

    /// <summary>Comma separated special rules that applied.</summary>
    public string SpecialRules { get; init; } = string.Empty;

    /// <summary>Remote endpoint the outbound actually connected to.</summary>
    public string RemoteDestination { get; init; } = string.Empty;

    /// <summary>Host recovered by the sniffer.</summary>
    public string SniffHost { get; init; } = string.Empty;

    /// <summary>Name of the inbound listener, when it has one.</summary>
    public string InboundName { get; init; } = string.Empty;

    /// <summary>Port of the inbound listener.</summary>
    public string InboundPort { get; init; } = string.Empty;

    /// <summary>Unix user id of the owning process, when known.</summary>
    public int Uid { get; init; }

    /// <summary>DSCP / firewall mark carried by the inbound.</summary>
    public int Dscp { get; init; }
}

/// <summary>One frame of the <c>/traffic</c> stream.</summary>
public sealed class TrafficFrame
{
    /// <summary>Bytes uploaded during the last second.</summary>
    public long Up { get; init; }

    /// <summary>Bytes downloaded during the last second.</summary>
    public long Down { get; init; }
}

/// <summary>One frame of the <c>/memory</c> stream.</summary>
public sealed class MemoryFrame
{
    /// <summary>Memory in use, in bytes.</summary>
    public long Inuse { get; init; }

    /// <summary>Memory limit imposed by the OS; 0 when unlimited.</summary>
    public long Oslimit { get; init; }
}

/// <summary>One frame of the <c>/logs</c> stream.</summary>
public sealed class LogFrame
{
    /// <summary><c>debug</c>, <c>info</c>, <c>warning</c> or <c>error</c>.</summary>
    public string Type { get; init; } = "info";

    /// <summary>The log line.</summary>
    public string Payload { get; init; } = string.Empty;
}

/// <summary>The body of <c>GET /dns/query</c>.</summary>
public sealed class DnsQueryResponse
{
    /// <summary>DNS response code; 0 means success.</summary>
    [JsonPropertyName("Status")]
    public int Status { get; init; }

    /// <summary>The answer section.</summary>
    [JsonPropertyName("Answer")]
    public IReadOnlyList<DnsQueryAnswer> Answer { get; init; } = [];
}

/// <summary>One answer record of <c>GET /dns/query</c>.</summary>
public sealed class DnsQueryAnswer
{
    /// <summary>Owner name of the record.</summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    /// <summary>Record type, e.g. <c>A</c>.</summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    /// <summary>Time to live in seconds.</summary>
    [JsonPropertyName("TTL")]
    public uint TTL { get; init; }

    /// <summary>Rendered record data.</summary>
    [JsonPropertyName("data")]
    public string Data { get; init; } = string.Empty;
}

/// <summary>The body of <c>GET /rules</c>.</summary>
public sealed class RulesResponse
{
    /// <summary>The rules, in evaluation order.</summary>
    public IReadOnlyList<RuleObject> Rules { get; init; } = [];
}

/// <summary>One rule as reported by <c>GET /rules</c>.</summary>
public sealed class RuleObject
{
    /// <summary>Canonical rule type, e.g. <c>DOMAIN-SUFFIX</c>.</summary>
    public string Type { get; init; } = string.Empty;

    /// <summary>The value being matched.</summary>
    public string Payload { get; init; } = string.Empty;

    /// <summary>Target adapter name.</summary>
    public string Proxy { get; init; } = string.Empty;

    /// <summary>Entry count for <c>RULE-SET</c> rules, <c>-1</c> otherwise.</summary>
    public int Size { get; init; } = -1;
}

/// <summary>The body of <c>GET /proxies</c> and <c>GET /group</c>.</summary>
public sealed class ProxiesResponse
{
    /// <summary>Proxy objects keyed by adapter name.</summary>
    public IReadOnlyDictionary<string, Dictionary<string, object?>> Proxies { get; init; } =
        new Dictionary<string, Dictionary<string, object?>>(StringComparer.Ordinal);
}

/// <summary>The body of <c>GET /proxies/:name/delay</c>.</summary>
public sealed class DelayResponse
{
    /// <summary>Measured round trip in milliseconds; 0 means the probe failed.</summary>
    public int Delay { get; init; }
}

/// <summary>The body of <c>GET /providers/proxies</c> and <c>GET /providers/rules</c>.</summary>
public sealed class ProvidersResponse
{
    /// <summary>Providers keyed by name.</summary>
    public IReadOnlyDictionary<string, object> Providers { get; init; } =
        new Dictionary<string, object>(StringComparer.Ordinal);
}

/// <summary>The body of <c>GET /profiles</c>.</summary>
public sealed class ProfilesResponse
{
    /// <summary>The stored profiles, selected first.</summary>
    public IReadOnlyList<object> Profiles { get; init; } = [];
}

/// <summary>The body of <c>POST /subscription/parse</c>.</summary>
public sealed class ParsedSubscriptionResponse
{
    /// <summary>The nodes found in the subscription.</summary>
    public IReadOnlyList<ParsedNode> Proxies { get; init; } = [];
}

/// <summary>One node of a parsed subscription.</summary>
public sealed class ParsedNode
{
    /// <summary>Node name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Protocol type, e.g. <c>ss</c>.</summary>
    public string Type { get; init; } = string.Empty;
}

/// <summary>A plain <c>{"message": "..."}</c> error body, matching Clash.</summary>
public sealed class MessageResponse
{
    /// <summary>The error text.</summary>
    public string Message { get; init; } = string.Empty;
}
