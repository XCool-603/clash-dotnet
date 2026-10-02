using System.Globalization;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Tunnel;

namespace Clash.Server.Models;

/// <summary>Projects live adapters and flows onto Clash's REST shapes.</summary>
public static class ApiProjections
{
    private const string Rfc3339Milliseconds = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    /// <summary>Renders a timestamp the way Clash does: RFC3339 in UTC.</summary>
    public static string ToRfc3339(DateTimeOffset value)
        => value.ToUniversalTime().ToString(Rfc3339Milliseconds, CultureInfo.InvariantCulture);

    /// <summary>
    /// Builds the <c>ProxyObject</c> of one adapter. Groups gain the membership
    /// fields (<c>all</c>, <c>now</c>, <c>testUrl</c>, ...); concrete nodes only
    /// carry the base shape plus whatever <see cref="IProxy.ApiExtra"/> declares.
    /// </summary>
    public static Dictionary<string, object?> BuildProxy(IProxy proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);

        var extra = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (key, value) in proxy.ApiExtra) extra[key] = value;

        var result = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["name"] = proxy.Name,
            ["type"] = proxy.TypeName,
            ["udp"] = proxy.SupportUdp,
            ["alive"] = proxy.Alive,
            ["history"] = BuildHistory(proxy),
            ["extra"] = extra,
            ["xudp"] = ExtraFlag(proxy, "xudp"),
            ["tfo"] = ExtraFlag(proxy, "tfo"),
            ["mptcp"] = ExtraFlag(proxy, "mptcp"),
            ["smux"] = ExtraFlag(proxy, "smux"),
        };

        // Clash merges the adapter's extra fields into the object itself, so the
        // dashboard can read protocol specific keys such as `id` or `network`.
        foreach (var (key, value) in proxy.ApiExtra)
        {
            if (!result.ContainsKey(key)) result[key] = value;
        }

        if (proxy is IProxyGroup group)
        {
            result["all"] = group.Members.Select(member => member.Name).ToList();
            result["now"] = group.SelectedName ?? string.Empty;
            result["testUrl"] = group.TestUrl;
            result["expectedStatus"] = proxy is ProxyGroupBase groupBase && !string.IsNullOrEmpty(groupBase.ExpectedStatus)
                ? groupBase.ExpectedStatus
                : "*";
            result["hidden"] = group.Hidden;
            result["icon"] = group.Icon ?? string.Empty;
        }

        return result;
    }

    /// <summary>Builds the <c>/connections</c> entry of one tracked flow.</summary>
    public static ConnectionObject BuildConnection(TrackedConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        var metadata = connection.Metadata;

        return new ConnectionObject
        {
            Id = connection.Id,
            Upload = connection.Upload,
            Download = connection.Download,
            Start = ToRfc3339(connection.StartTime),
            Chains = connection.Chain.ToList(),
            Rule = connection.Rule ?? string.Empty,
            RulePayload = connection.RulePayload ?? string.Empty,
            Metadata = new ConnectionMetadata
            {
                Network = metadata.Network.ToApiString(),
                Type = InboundTypeName(metadata.InboundType),
                SourceIP = metadata.SourceAddress ?? string.Empty,
                DestinationIP = metadata.DestinationAddress,
                SourcePort = metadata.SourcePort.ToString(CultureInfo.InvariantCulture),
                DestinationPort = metadata.DestinationPort.ToString(CultureInfo.InvariantCulture),
                Host = metadata.ApiHost,
                DnsMode = metadata.DnsMode switch
                {
                    DnsMode.FakeIp => "fake-ip",
                    DnsMode.Mapping => "mapping",
                    _ => "normal",
                },
                ProcessPath = metadata.ProcessPath ?? string.Empty,
                SpecialProxy = metadata.SpecialProxy ?? string.Empty,
                SpecialRules = string.Join(",", metadata.SpecialRules),
                RemoteDestination = metadata.RemoteDestination ?? string.Empty,
                SniffHost = metadata.SniffHost ?? string.Empty,
                InboundName = metadata.InboundName ?? string.Empty,
                InboundPort = metadata.InboundPort == 0
                    ? string.Empty
                    : metadata.InboundPort.ToString(CultureInfo.InvariantCulture),
                InboundUser = metadata.InboundUser ?? string.Empty,
                Uid = int.TryParse(metadata.Uid, NumberStyles.Integer, CultureInfo.InvariantCulture, out var uid) ? uid : 0,
                Dscp = metadata.Dscp,
            },
        };
    }

    /// <summary>Maps an internal inbound kind onto the name Clash reports.</summary>
    public static string InboundTypeName(string? inboundType) => inboundType?.ToLowerInvariant() switch
    {
        "http" => "HTTP",
        "socks" => "SOCKS5",
        "mixed" => "Mixed",
        "redir" => "Redir",
        "tproxy" => "TProxy",
        "tun" => "TUN",
        "dns" => "Dns",
        "delay" => "Delay",
        null or "" => string.Empty,
        _ => inboundType!,
    };

    private static List<Dictionary<string, object?>> BuildHistory(IProxy proxy)
    {
        var history = new List<Dictionary<string, object?>>();
        foreach (var entry in proxy.History)
        {
            history.Add(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["time"] = ToRfc3339(entry.Time),
                ["delay"] = entry.Delay,
            });
        }

        return history;
    }

    private static object ExtraFlag(IProxy proxy, string key)
        => proxy.ApiExtra.TryGetValue(key, out var value) && value is not null ? value : false;
}
