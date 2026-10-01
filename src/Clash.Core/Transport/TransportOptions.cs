using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>
/// Reads the transport-related option blocks out of a proxy's <see cref="YamlMap"/>.
/// <para>
/// Every reader tolerates the loose shapes real subscriptions contain: a scalar
/// where a list is expected, a list where a scalar is expected, quoted booleans
/// and hyphenated or underscored key spellings. The record types themselves
/// (<see cref="TlsOptions"/>, <see cref="WebSocketOptions"/>, <see cref="GrpcOptions"/>,
/// <see cref="H2Options"/>, <see cref="HttpObfsOptions"/>) are part of the frozen
/// transport contract and are only populated, never changed.
/// </para>
/// </summary>
public static class TransportOptions
{
    /// <summary>Reads the <c>tls</c> flag and everything that goes with it.</summary>
    public static TlsOptions ReadTlsOptions(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var reality = options.GetMap("reality-opts");
        return new TlsOptions
        {
            Enabled = options.GetBool("tls"),
            ServerName = FirstNonEmpty(options.GetNonEmptyString("sni"), options.GetNonEmptyString("servername"), options.GetNonEmptyString("server-name")),
            SkipCertVerify = options.GetBool("skip-cert-verify") || options.GetBool("skip_cert_verify"),
            Insecure = options.GetBool("insecure"),
            Alpn = ReadStringListOrScalar(options, "alpn"),
            Fingerprint = FirstNonEmpty(options.GetNonEmptyString("fingerprint")),
            ClientFingerprint = FirstNonEmpty(
                options.GetNonEmptyString("client-fingerprint"),
                options.GetNonEmptyString("client_fingerprint"),
                options.GetNonEmptyString("fingerprint")),
            RealityPublicKey = FirstNonEmpty(reality.GetNonEmptyString("public-key"), reality.GetNonEmptyString("public_key")),
            RealityShortId = FirstNonEmpty(reality.GetNonEmptyString("short-id"), reality.GetNonEmptyString("short_id")),
            RealitySpiderX = FirstNonEmpty(reality.GetNonEmptyString("spider-x"), reality.GetNonEmptyString("spider_x"), reality.GetNonEmptyString("spiderx")),
            DisableSni = options.GetBool("disable-sni") || options.GetBool("disable_sni"),
        };
    }

    /// <summary>Reads <c>ws-opts</c>.</summary>
    public static WebSocketOptions ReadWebSocketOptions(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var ws = options.GetMap("ws-opts");

        return new WebSocketOptions
        {
            Path = NormalizePath(FirstNonEmpty(ws.GetNonEmptyString("path"), options.GetNonEmptyString("ws-path")) ?? "/"),
            Headers = ReadHeaders(ws.GetMap("headers")),
            MaxEarlyData = ws.GetInt("max-early-data", ws.GetInt("max_early_data")),
            EarlyDataHeaderName = FirstNonEmpty(ws.GetNonEmptyString("early-data-header-name"), ws.GetNonEmptyString("early_data_header_name")),
            Host = FirstNonEmpty(ws.GetNonEmptyString("host")),
            V2rayHttpUpgrade = ws.GetBool("v2ray-http-upgrade") || ws.GetBool("v2ray_http_upgrade"),
        };
    }

    /// <summary>Reads <c>grpc-opts</c>.</summary>
    public static GrpcOptions ReadGrpcOptions(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var grpc = options.GetMap("grpc-opts");

        return new GrpcOptions
        {
            ServiceName = FirstNonEmpty(
                grpc.GetNonEmptyString("grpc-service-name"),
                grpc.GetNonEmptyString("grpc_service_name"),
                grpc.GetNonEmptyString("service-name"),
                options.GetNonEmptyString("grpc-service-name")) ?? string.Empty,
            Host = FirstNonEmpty(grpc.GetNonEmptyString("host")),
            Mode = (FirstNonEmpty(grpc.GetNonEmptyString("mode")) ?? "gun").ToLowerInvariant(),
        };
    }

    /// <summary>Reads <c>h2-opts</c>.</summary>
    public static H2Options ReadH2Options(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var h2 = options.GetMap("h2-opts");

        return new H2Options
        {
            Path = NormalizePath(FirstNonEmpty(h2.GetNonEmptyString("path")) ?? "/"),
            Host = ReadStringListOrScalar(h2, "host"),
        };
    }

    /// <summary>Reads <c>http-opts</c>.</summary>
    public static HttpObfsOptions ReadHttpObfsOptions(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var http = options.GetMap("http-opts");

        var paths = ReadStringListOrScalar(http, "path");
        if (paths.Count == 0) paths = ["/"];

        return new HttpObfsOptions
        {
            Method = (FirstNonEmpty(http.GetNonEmptyString("method")) ?? "GET").ToUpperInvariant(),
            Path = paths.Select(NormalizePath).ToList(),
            Headers = ReadHeaderLists(http.GetMap("headers")),
        };
    }

    /// <summary>The <c>plugin</c> name a Shadowsocks proxy declares, if any.</summary>
    public static string? ReadPlugin(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return FirstNonEmpty(options.GetNonEmptyString("plugin"));
    }

    /// <summary>The <c>plugin-opts</c> block, as a map.</summary>
    public static YamlMap ReadPluginOptions(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.GetMap("plugin-opts");
    }

    /// <summary>
    /// The transport plugin names this build knows it cannot honour. Callers turn
    /// this into a <see cref="TransportNotSupportedException"/> with a precise
    /// message rather than silently connecting without the plugin.
    /// </summary>
    public static string? UnsupportedPlugin(string? plugin) => plugin?.Trim().ToLowerInvariant() switch
    {
        "shadow-tls" => "shadow-tls",
        "restls" => "restls",
        _ => null,
    };

    /// <summary>Reads a value that may be a scalar, a list, or absent.</summary>
    public static List<string> ReadStringListOrScalar(YamlMap map, string key)
    {
        ArgumentNullException.ThrowIfNull(map);
        var raw = map[key];
        return raw switch
        {
            null => [],
            string s => string.IsNullOrWhiteSpace(s)
                ? []
                : s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList(),
            List<object?> list => list.Select(x => Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty)
                .Where(x => x.Length > 0)
                .ToList(),
            _ => [Convert.ToString(raw, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty],
        };
    }

    private static Dictionary<string, string> ReadHeaders(YamlMap headers)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in headers.Raw)
        {
            var text = value switch
            {
                null => string.Empty,
                string s => s,
                List<object?> list => string.Join(", ", list.Select(x => Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture))),
                _ => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            };
            result[key] = text;
        }

        return result;
    }

    private static Dictionary<string, List<string>> ReadHeaderLists(YamlMap headers)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in headers.Raw)
        {
            result[key] = value switch
            {
                null => [],
                string s => [s],
                List<object?> list => list.Select(x => Convert.ToString(x, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty).ToList(),
                _ => [Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty],
            };
        }

        return result;
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrEmpty(path)) return "/";
        return path.StartsWith('/') ? path : "/" + path;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }

        return null;
    }
}
