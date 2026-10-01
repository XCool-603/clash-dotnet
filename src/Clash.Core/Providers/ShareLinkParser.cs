using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Clash.Core.Common;
using Clash.Core.Configuration;
using YamlDotNet.Core;
using YamlDotNet.Serialization;

namespace Clash.Core.Providers;

/// <summary>
/// Parses the share links subscriptions are usually distributed as — <c>ss://</c>,
/// <c>ssr://</c>, <c>vmess://</c>, <c>vless://</c>, <c>trojan://</c>,
/// <c>hysteria(2)://</c>, <c>tuic://</c>, <c>socks://</c>, <c>http(s)://</c>,
/// <c>snell://</c>, <c>wireguard://</c>, <c>anytls://</c> and <c>mieru://</c> —
/// into the same <see cref="YamlMap"/> shape a Clash <c>proxies:</c> entry uses,
/// so a converted subscription is indistinguishable from a hand written one.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Parse"/> is total: a malformed, truncated or unknown link yields
/// <see langword="null"/> instead of throwing, because a single bad line in a
/// subscription must never discard the other several hundred nodes.
/// </para>
/// <para>
/// A node is named after the URL-decoded <c>#fragment</c>, falling back to
/// <c>host:port</c>. <see cref="ParseSubscription"/> renames collisions to
/// <c>name 2</c>, <c>name 3</c>, … because the adapter registry is keyed by name
/// and a duplicate would silently drop a node.
/// </para>
/// </remarks>
public sealed class ShareLinkParser : IShareLinkParser
{
    private static readonly string[] ClashMarkers =
    [
        "proxies:", "proxy-groups:", "proxy-providers:", "rule-providers:",
        "mixed-port:", "socks-port:", "redir-port:", "rules:", "port:",
    ];

    /// <inheritdoc />
    public ProxyConfigEntry? Parse(string link)
    {
        if (string.IsNullOrWhiteSpace(link)) return null;

        var text = link.Trim();
        if (TryBuiltin(text, out var builtin)) return builtin;

        try
        {
            if (!TrySplit(text, out var scheme, out var body, out var fragment)) return null;

            return scheme switch
            {
                "ss" => ParseShadowsocks(body, fragment),
                "ssr" => ParseShadowsocksR(body, fragment),
                "vmess" => ParseVmess(body, fragment),
                "vless" => ParseVless(body, fragment),
                "trojan" or "trojan-go" => ParseTrojan(body, fragment),
                "hysteria2" or "hy2" => ParseHysteria2(body, fragment),
                "hysteria" => ParseHysteria(body, fragment),
                "tuic" => ParseTuic(body, fragment),
                "socks" or "socks5" or "socks5h" => ParseSocksLike(body, fragment, "socks5"),
                "http" => ParseSocksLike(body, fragment, "http"),
                "https" => ParseHttps(body, fragment),
                "snell" => ParseSnell(body, fragment),
                "wireguard" or "wg" => ParseWireGuard(body, fragment),
                "anytls" => ParseAnyTls(body, fragment),
                "mieru" => ParseMieru(body, fragment),
                _ => null,
            };
        }
        catch (Exception)
        {
            // Never let one malformed link break a whole subscription.
            return null;
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<ProxyConfigEntry> ParseSubscription(string content)
    {
        if (string.IsNullOrWhiteSpace(content)) return [];

        var text = content.TrimStart('\uFEFF').Trim();
        if (text.Length == 0) return [];

        try
        {
            // 1. A Clash document: only `proxies:` contributes; `proxy-groups:` is
            //    deliberately ignored because a provider supplies nodes, not groups.
            if (LooksLikeClashDocument(text))
            {
                var proxies = ReadClashProxies(text);
                return proxies.Count == 0 ? [] : Deduplicate(proxies);
            }

            // 2. A SIP008 JSON document.
            var sip008 = TryParseSip008(text);
            if (sip008 is { Count: > 0 }) return Deduplicate(sip008);

            // 3. A base64-encoded link list.
            var decoded = TryBase64String(text);
            if (decoded is not null && decoded.Contains("://", StringComparison.Ordinal))
            {
                return Deduplicate(ParseLinkList(decoded));
            }

            // 4. A plain link list.
            return Deduplicate(ParseLinkList(text));
        }
        catch (Exception)
        {
            return [];
        }
    }

    // ── document detection / Clash YAML ──────────────────────────────────────

    /// <summary>True when the body looks like a Clash document rather than a link list.</summary>
    internal static bool LooksLikeClashDocument(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;

        var trimmed = text.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('[')) return false;

        foreach (var marker in ClashMarkers)
        {
            if (text.Contains(marker, StringComparison.Ordinal)) return true;
        }

        // A bare sequence of proxies (`- name: … / type: …`) is a valid provider body too.
        return trimmed.StartsWith("- ", StringComparison.Ordinal) &&
               text.Contains("name:", StringComparison.Ordinal) &&
               text.Contains("type:", StringComparison.Ordinal);
    }

    /// <summary>Reads the <c>proxies:</c> list (or a bare list) out of a Clash document.</summary>
    internal static List<ProxyConfigEntry> ReadClashProxies(string text)
    {
        var result = new List<ProxyConfigEntry>();
        if (string.IsNullOrWhiteSpace(text)) return result;

        object? raw;
        try
        {
            raw = new DeserializerBuilder().Build().Deserialize<object?>(text);
        }
        catch (YamlException)
        {
            return result;
        }

        switch (YamlMap.Normalize(raw))
        {
            case Dictionary<string, object?> map when map.TryGetValue("proxies", out var proxies):
                CollectProxies(proxies, result);
                break;
            case List<object?> list:
                CollectProxies(list, result);
                break;
        }

        return result;
    }

    private static void CollectProxies(object? node, List<ProxyConfigEntry> into)
    {
        if (node is not IEnumerable<object?> items) return;

        foreach (var item in items)
        {
            var map = YamlMap.From(item);
            if (map.GetNonEmptyString("name") is null) continue;
            if (map.GetNonEmptyString("type") is null) continue;
            into.Add(new ProxyConfigEntry(map));
        }
    }

    // ── SIP008 ───────────────────────────────────────────────────────────────

    private static List<ProxyConfigEntry>? TryParseSip008(string text)
    {
        if (!text.TrimStart().StartsWith('{')) return null;

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(text);
        }
        catch (JsonException)
        {
            return null;
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            if (!root.TryGetProperty("servers", out var servers) || servers.ValueKind != JsonValueKind.Array) return null;

            var result = new List<ProxyConfigEntry>();
            foreach (var server in servers.EnumerateArray())
            {
                if (server.ValueKind != JsonValueKind.Object) continue;

                var host = JsonText(server, "server");
                if (string.IsNullOrWhiteSpace(host)) continue;
                if (!int.TryParse(JsonText(server, "server_port"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port)) continue;
                if (port is <= 0 or > 65535) continue;

                var name = JsonText(server, "remarks");
                if (string.IsNullOrWhiteSpace(name)) name = $"{host}:{port}";

                // SIP008 splits the plugin into a name and an option string; fold
                // them back into the `plugin=name;key=value` form the parser reads.
                var plugin = JsonText(server, "plugin");
                var pluginOptions = JsonText(server, "plugin_opts");
                var combined = plugin;
                if (!string.IsNullOrWhiteSpace(pluginOptions))
                {
                    combined = string.IsNullOrWhiteSpace(plugin) ? pluginOptions : $"{plugin};{pluginOptions}";
                }

                var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (!string.IsNullOrWhiteSpace(combined)) query["plugin"] = combined!;
                var (pluginName, pluginOpts) = ParseShadowsocksPlugin(query);

                result.Add(Create(name!,
                    "ss",
                    ("server", host),
                    ("port", port),
                    ("cipher", JsonText(server, "method")),
                    ("password", JsonText(server, "password")),
                    ("plugin", pluginName),
                    ("plugin-opts", pluginOpts)));
            }

            return result;
        }
    }

    private static string? JsonText(JsonElement element, string name)
    {
        if (!element.TryGetProperty(name, out var value)) return null;

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null,
        };
    }

    private static int? JsonInt(JsonElement element, string name)
    {
        var text = JsonText(element, name);
        if (text is null) return null;
        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) ? value : null;
    }

    // ── link list / naming ───────────────────────────────────────────────────

    private List<ProxyConfigEntry> ParseLinkList(string text)
    {
        var result = new List<ProxyConfigEntry>();

        foreach (var raw in text.Split(new[] { '\n', '\r', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith('#') || line.StartsWith("//", StringComparison.Ordinal)) continue;

            var entry = Parse(line);
            if (entry is not null) result.Add(entry);
        }

        return result;
    }

    private static List<ProxyConfigEntry> Deduplicate(List<ProxyConfigEntry> entries)
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<ProxyConfigEntry>(entries.Count);

        foreach (var entry in entries)
        {
            var name = entry.Name;
            if (used.Add(name))
            {
                result.Add(entry);
                continue;
            }

            var suffix = 2;
            string candidate;
            do
            {
                candidate = $"{name} {suffix++}";
            }
            while (!used.Add(candidate));

            var map = new Dictionary<string, object?>(entry.Map.Raw, StringComparer.OrdinalIgnoreCase)
            {
                ["name"] = candidate,
            };
            result.Add(new ProxyConfigEntry(new YamlMap(map)));
        }

        return result;
    }

    // ── ss ───────────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseShadowsocks(string body, string? fragment)
    {
        string? method;
        string? password;
        string host;
        int port;
        string? query;

        var at = body.LastIndexOf('@');
        if (at > 0)
        {
            // SIP002: base64(method:password)@host:port?plugin=…#tag
            var userinfo = body[..at];
            SplitQuery(body[(at + 1)..], out var hostPart, out query);

            var decoded = userinfo.Contains(':') ? Decode(userinfo) : TryBase64String(userinfo);
            if (decoded is null) return null;

            var colon = decoded.IndexOf(':');
            if (colon <= 0) return null;
            method = decoded[..colon];
            password = decoded[(colon + 1)..];
            if (!TryHostPort(hostPart, out host, out port)) return null;
        }
        else
        {
            // Legacy: base64(method:password@host:port[/?plugin=…])#tag
            var decoded = TryBase64String(body);
            if (decoded is null) return null;

            SplitQuery(decoded, out var core, out query);
            core = core.Trim().TrimEnd('/');

            var innerAt = core.LastIndexOf('@');
            if (innerAt <= 0) return null;

            var userinfo = core[..innerAt];
            var colon = userinfo.IndexOf(':');
            if (colon <= 0) return null;
            method = userinfo[..colon];
            password = userinfo[(colon + 1)..];
            if (!TryHostPort(core[(innerAt + 1)..], out host, out port)) return null;
        }

        if (string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(host)) return null;

        var options = ParseQuery(query);
        var (plugin, pluginOptions) = ParseShadowsocksPlugin(options);
        var name = NameFrom(fragment, host, port);

        return Create(name,
            "ss",
            ("server", host),
            ("port", port),
            ("cipher", method),
            ("password", password),
            ("plugin", plugin),
            ("plugin-opts", pluginOptions));
    }

    /// <summary>
    /// Maps a SIP002 <c>plugin</c> value (<c>name;key=value;flag</c>) onto Clash's
    /// <c>plugin</c> / <c>plugin-opts</c> pair.
    /// </summary>
    private static (string? Plugin, Dictionary<string, object?>? Options) ParseShadowsocksPlugin(Dictionary<string, string> query)
    {
        if (!query.TryGetValue("plugin", out var raw) || string.IsNullOrWhiteSpace(raw)) return (null, null);

        var parts = raw.Split(';');
        var pluginName = parts[0].Trim();
        if (pluginName.Length == 0) return (null, null);

        var args = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < parts.Length; i++)
        {
            var part = parts[i].Trim();
            if (part.Length == 0) continue;

            var eq = part.IndexOf('=');
            if (eq < 0) flags.Add(part);
            else args[part[..eq].Trim()] = part[(eq + 1)..].Trim();
        }

        string? Arg(params string[] keys)
        {
            foreach (var key in keys)
            {
                if (args.TryGetValue(key, out var value) && value.Length > 0) return value;
            }

            return null;
        }

        bool HasFlag(string key) => flags.Contains(key) || args.ContainsKey(key);

        switch (pluginName.ToLowerInvariant())
        {
            case "obfs-local":
            case "simple-obfs":
            case "obfs":
                return ("obfs", NewMap(
                    ("mode", Arg("obfs", "mode") ?? "http"),
                    ("host", Arg("obfs-host", "host"))));

            case "v2ray-plugin":
                return ("v2ray-plugin", NewMap(
                    ("mode", Arg("mode") ?? "websocket"),
                    ("host", Arg("host")),
                    ("path", Arg("path")),
                    ("tls", HasFlag("tls") ? true : null),
                    ("mux", HasFlag("mux") ? true : null),
                    ("skip-cert-verify", IsTrue(Arg("skip-cert-verify")) ? true : null)));

            case "shadow-tls":
                return ("shadow-tls", NewMap(
                    ("host", Arg("host")),
                    ("password", Arg("password")),
                    ("version", ArgInt("version", args)),
                    ("fingerprint", Arg("fingerprint"))));

            case "restls":
                return ("restls", NewMap(
                    ("host", Arg("host")),
                    ("password", Arg("password")),
                    ("version-hint", Arg("version-hint", "version")),
                    ("restls-script", Arg("restls-script"))));

            default:
                var generic = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var (key, value) in args) generic[key] = value;
                foreach (var flag in flags) generic[flag] = true;
                return (pluginName, generic.Count > 0 ? generic : null);
        }
    }

    // ── ssr ──────────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseShadowsocksR(string body, string? fragment)
    {
        var decoded = TryBase64String(body);
        if (decoded is null) return null;

        SplitQuery(decoded, out var core, out var query);
        core = core.Trim().TrimEnd('/');

        // host:port:protocol:method:obfs:base64url(password)
        var fields = core.Split(':');
        if (fields.Length < 6) return null;

        if (!int.TryParse(fields[^5], NumberStyles.Integer, CultureInfo.InvariantCulture, out var port)) return null;
        if (port is <= 0 or > 65535) return null;

        var host = string.Join(':', fields[..^5]);
        if (host.Length == 0) return null;

        var protocol = fields[^4];
        var method = fields[^3];
        var obfs = fields[^2];
        var rawPassword = fields[^1];
        var password = TryBase64String(rawPassword) ?? rawPassword;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);

        if (options.TryGetValue("remarks", out var remarks))
        {
            var decodedRemarks = TryBase64String(remarks) ?? remarks;
            if (!string.IsNullOrWhiteSpace(decodedRemarks)) name = decodedRemarks;
        }

        return Create(name,
            "ssr",
            ("server", host),
            ("port", port),
            ("cipher", method),
            ("password", password),
            ("protocol", protocol),
            ("obfs", obfs),
            ("protocol-param", SsrParameter(options, "protoparam")),
            ("obfs-param", SsrParameter(options, "obfsparam")));
    }

    private static string? SsrParameter(Dictionary<string, string> options, string key)
    {
        if (!options.TryGetValue(key, out var value) || value.Length == 0) return null;
        return TryBase64String(value) ?? value;
    }

    // ── vmess ────────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseVmess(string body, string? fragment)
    {
        var json = TryBase64String(body);
        if (json is null) return null;

        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return null;

        var server = JsonText(root, "add");
        if (string.IsNullOrWhiteSpace(server)) return null;
        if (!int.TryParse(JsonText(root, "port"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port)) return null;
        if (port is <= 0 or > 65535) return null;

        var uuid = JsonText(root, "id");
        if (string.IsNullOrWhiteSpace(uuid)) return null;

        var network = (JsonText(root, "net") ?? "tcp").Trim().ToLowerInvariant();
        var headerType = (JsonText(root, "type") ?? string.Empty).Trim().ToLowerInvariant();
        var host = JsonText(root, "host") ?? string.Empty;
        var path = JsonText(root, "path") ?? string.Empty;
        var tlsText = JsonText(root, "tls");
        var tls = string.Equals(tlsText, "tls", StringComparison.OrdinalIgnoreCase) || IsTrue(tlsText);
        var sni = JsonText(root, "sni");

        var name = JsonText(root, "ps");
        if (string.IsNullOrWhiteSpace(name)) name = NameFrom(fragment, server!, port);

        var fields = new List<(string Key, object? Value)>
        {
            ("server", server),
            ("port", port),
            ("uuid", uuid),
            ("alterId", JsonInt(root, "aid")),
            ("cipher", JsonText(root, "scy") is { Length: > 0 } scy ? scy : "auto"),
            ("tls", tls ? true : null),
            ("servername", string.IsNullOrWhiteSpace(sni) ? (tls ? NullIfEmpty(host) : null) : sni),
            ("client-fingerprint", JsonText(root, "fp")),
            ("alpn", SplitAlpn(JsonText(root, "alpn"))),
        };

        switch (network)
        {
            case "ws":
                fields.Add(("network", "ws"));
                fields.Add(("ws-opts", NewMap(
                    ("path", NullIfEmpty(path) ?? "/"),
                    ("headers", host.Length == 0 ? null : NewMap(("Host", host))))));
                break;

            case "grpc":
                fields.Add(("network", "grpc"));
                fields.Add(("grpc-opts", NewMap(("grpc-service-name", NullIfEmpty(path)))));
                break;

            case "h2":
                fields.Add(("network", "h2"));
                fields.Add(("h2-opts", NewMap(
                    ("path", NullIfEmpty(path) ?? "/"),
                    ("host", host.Length == 0 ? null : new List<object?> { host }))));
                break;

            case "tcp" when headerType == "http":
                // v2rayN's `net: tcp` + `type: http` is mihomo's `network: http`.
                fields.Add(("network", "http"));
                fields.Add(("http-opts", NewMap(
                    ("method", "GET"),
                    ("path", new List<object?> { NullIfEmpty(path) ?? "/" }),
                    ("headers", host.Length == 0 ? null : NewMap(("Host", new List<object?> { host }))))));
                break;

            default:
                fields.Add(("network", network.Length > 0 ? network : "tcp"));
                break;
        }

        return Create(name!, "vmess", [.. fields]);
    }

    // ── vless ────────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseVless(string body, string? fragment)
    {
        var at = body.LastIndexOf('@');
        if (at <= 0) return null;

        var uuid = Decode(body[..at]);
        if (uuid.Length == 0) return null;

        SplitQuery(body[(at + 1)..], out var hostPart, out var query);
        if (!TryHostPort(hostPart, out var host, out var port)) return null;

        var options = ParseQuery(query);
        var security = (Opt(options, "security") ?? "none").ToLowerInvariant();
        var tls = security is "tls" or "reality" or "xtls";
        var reality = security == "reality";
        var transport = (Opt(options, "type") ?? "tcp").ToLowerInvariant();
        var hostHeader = Opt(options, "host") ?? string.Empty;
        var path = Opt(options, "path") ?? string.Empty;
        var serviceName = Opt(options, "serviceName", "servicename", "service-name");
        var name = NameFrom(fragment, host, port);

        var fields = new List<(string Key, object? Value)>
        {
            ("server", host),
            ("port", port),
            ("uuid", uuid),
            ("tls", tls ? true : null),
            ("servername", Opt(options, "sni", "peer") ?? (tls ? NullIfEmpty(hostHeader) : null)),
            ("flow", Opt(options, "flow")),
            ("client-fingerprint", Opt(options, "fp")),
            ("skip-cert-verify", IsTrue(Opt(options, "allowInsecure", "allow_insecure", "insecure")) ? true : null),
            ("alpn", SplitAlpn(Opt(options, "alpn"))),
            ("reality-opts", reality
                ? NewMap(
                    ("public-key", Opt(options, "pbk")),
                    ("short-id", Opt(options, "sid")),
                    ("spider-x", Opt(options, "spx")))
                : null),
        };

        switch (transport)
        {
            case "ws":
                fields.Add(("network", "ws"));
                fields.Add(("ws-opts", NewMap(
                    ("path", NullIfEmpty(path) ?? "/"),
                    ("headers", hostHeader.Length == 0 ? null : NewMap(("Host", hostHeader))))));
                break;

            case "grpc":
                fields.Add(("network", "grpc"));
                fields.Add(("grpc-opts", NewMap(
                    ("grpc-service-name", serviceName ?? NullIfEmpty(path)))));
                break;

            case "h2":
                fields.Add(("network", "h2"));
                fields.Add(("h2-opts", NewMap(
                    ("path", NullIfEmpty(path) ?? "/"),
                    ("host", hostHeader.Length == 0 ? null : new List<object?> { hostHeader }))));
                break;

            case "http":
                fields.Add(("network", "http"));
                fields.Add(("http-opts", NewMap(
                    ("method", "GET"),
                    ("path", new List<object?> { NullIfEmpty(path) ?? "/" }),
                    ("headers", hostHeader.Length == 0 ? null : NewMap(("Host", new List<object?> { hostHeader }))))));
                break;

            default:
                fields.Add(("network", transport.Length > 0 ? transport : "tcp"));
                break;
        }

        return Create(name, "vless", [.. fields]);
    }

    // ── trojan ───────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseTrojan(string body, string? fragment)
    {
        var at = body.LastIndexOf('@');
        if (at <= 0) return null;

        var password = Decode(body[..at]);
        SplitQuery(body[(at + 1)..], out var hostPart, out var query);
        if (!TryHostPort(hostPart, out var host, out var port)) return null;

        var options = ParseQuery(query);
        var transport = (Opt(options, "type") ?? "tcp").ToLowerInvariant();
        var hostHeader = Opt(options, "host") ?? string.Empty;
        var path = Opt(options, "path") ?? string.Empty;
        var name = NameFrom(fragment, host, port);

        var fields = new List<(string Key, object? Value)>
        {
            ("server", host),
            ("port", port),
            ("password", password),
            ("sni", Opt(options, "sni", "peer")),
            ("skip-cert-verify", IsTrue(Opt(options, "allowInsecure", "allow_insecure", "insecure")) ? true : null),
            ("alpn", SplitAlpn(Opt(options, "alpn"))),
            ("client-fingerprint", Opt(options, "fp")),
        };

        switch (transport)
        {
            case "ws":
                fields.Add(("network", "ws"));
                fields.Add(("ws-opts", NewMap(
                    ("path", NullIfEmpty(path) ?? "/"),
                    ("headers", hostHeader.Length == 0 ? null : NewMap(("Host", hostHeader))))));
                break;

            case "grpc":
                fields.Add(("network", "grpc"));
                fields.Add(("grpc-opts", NewMap(
                    ("grpc-service-name", Opt(options, "serviceName", "servicename", "service-name") ?? NullIfEmpty(path)))));
                break;

            default:
                if (transport is not ("tcp" or "")) fields.Add(("network", transport));
                break;
        }

        return Create(name, "trojan", [.. fields]);
    }

    // ── hysteria ─────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseHysteria2(string body, string? fragment)
    {
        if (!TrySplitAuthority(body, out var auth, out var host, out var port, out var query)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);
        var password = auth ?? Opt(options, "password", "auth", "auth-str");

        return Create(name,
            "hysteria2",
            ("server", host),
            ("port", port),
            ("password", password),
            ("sni", Opt(options, "sni", "peer")),
            ("skip-cert-verify", IsTrue(Opt(options, "insecure", "allowInsecure", "allow_insecure")) ? true : null),
            ("obfs", Opt(options, "obfs")),
            ("obfs-password", Opt(options, "obfs-password", "obfs_password")),
            ("fingerprint", Opt(options, "pinSHA256", "pin-sha256", "fingerprint")),
            ("alpn", SplitAlpn(Opt(options, "alpn"))),
            ("ports", Opt(options, "mport", "ports")),
            ("up", Opt(options, "up", "upmbps")),
            ("down", Opt(options, "down", "downmbps")));
    }

    private static ProxyConfigEntry? ParseHysteria(string body, string? fragment)
    {
        if (!TrySplitAuthority(body, out var auth, out var host, out var port, out var query)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);

        return Create(name,
            "hysteria",
            ("server", host),
            ("port", port),
            ("auth-str", auth ?? Opt(options, "auth", "auth-str", "auth_str")),
            ("protocol", Opt(options, "protocol")),
            ("sni", Opt(options, "peer", "sni")),
            ("skip-cert-verify", IsTrue(Opt(options, "insecure", "allowInsecure", "allow_insecure")) ? true : null),
            ("up", Opt(options, "upmbps", "up")),
            ("down", Opt(options, "downmbps", "down")),
            ("alpn", SplitAlpn(Opt(options, "alpn"))),
            ("obfs", Opt(options, "obfs")),
            ("ports", Opt(options, "mport", "ports")));
    }

    // ── tuic ─────────────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseTuic(string body, string? fragment)
    {
        var at = body.LastIndexOf('@');
        if (at <= 0) return null;

        var userinfo = Decode(body[..at]);
        var colon = userinfo.IndexOf(':');
        var uuid = colon < 0 ? userinfo : userinfo[..colon];
        var password = colon < 0 ? null : userinfo[(colon + 1)..];

        SplitQuery(body[(at + 1)..], out var hostPart, out var query);
        if (!TryHostPort(hostPart, out var host, out var port)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);

        return Create(name,
            "tuic",
            ("server", host),
            ("port", port),
            ("uuid", uuid),
            ("password", password),
            ("token", Opt(options, "token")),
            ("sni", Opt(options, "sni", "peer")),
            ("alpn", SplitAlpn(Opt(options, "alpn"))),
            ("congestion-controller", Opt(options, "congestion_control", "congestion-controller")),
            ("udp-relay-mode", Opt(options, "udp_relay_mode", "udp-relay-mode")),
            ("reduce-rtt", IsTrue(Opt(options, "reduce_rtt", "reduce-rtt")) ? true : null),
            ("skip-cert-verify", IsTrue(Opt(options, "allow_insecure", "allowInsecure", "insecure")) ? true : null));
    }

    // ── socks / http ─────────────────────────────────────────────────────────

    private static ProxyConfigEntry? ParseSocksLike(string body, string? fragment, string type)
    {
        if (!TrySplitAuthority(body, out var userinfo, out var host, out var port, out var query)) return null;

        var (username, password) = SplitCredentials(userinfo);
        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);

        return Create(name,
            type,
            ("server", host),
            ("port", port),
            ("username", username ?? Opt(options, "username", "user")),
            ("password", password ?? Opt(options, "password", "pass")),
            ("skip-cert-verify", IsTrue(Opt(options, "allowInsecure", "skip-cert-verify")) ? true : null));
    }

    private static ProxyConfigEntry? ParseHttps(string body, string? fragment)
    {
        var entry = ParseSocksLike(body, fragment, "http");
        if (entry is null) return null;

        var map = new Dictionary<string, object?>(entry.Map.Raw, StringComparer.OrdinalIgnoreCase) { ["tls"] = true };
        return new ProxyConfigEntry(new YamlMap(map));
    }

    private static (string? Username, string? Password) SplitCredentials(string? userinfo)
    {
        var decoded = DecodeUserinfo(userinfo);
        if (decoded is null) return (null, null);

        var colon = decoded.IndexOf(':');
        return colon < 0 ? (NullIfEmpty(decoded), null) : (NullIfEmpty(decoded[..colon]), decoded[(colon + 1)..]);
    }

    /// <summary>
    /// Decodes a userinfo field. A value without a colon may be base64 — the
    /// convention <c>socks://</c> and SIP002 <c>ss://</c> links use — so both
    /// readings are attempted and the raw text is the last resort.
    /// </summary>
    private static string? DecodeUserinfo(string? userinfo)
    {
        if (string.IsNullOrEmpty(userinfo)) return null;
        if (userinfo.Contains(':')) return Decode(userinfo);
        return TryBase64String(userinfo) ?? Decode(userinfo);
    }

    // ── snell / wireguard / anytls / mieru ───────────────────────────────────

    private static ProxyConfigEntry? ParseSnell(string body, string? fragment)
    {
        if (!TrySplitAuthority(body, out var userinfo, out var host, out var port, out var query)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);
        // A Snell PSK is opaque text, never base64.
        var psk = NullIfEmpty(userinfo) ?? Opt(options, "psk", "password");
        var obfs = Opt(options, "obfs");

        return Create(name,
            "snell",
            ("server", host),
            ("port", port),
            ("psk", psk),
            ("version", OptInt(options, "version")),
            ("obfs-opts", obfs is null ? null : NewMap(
                ("mode", obfs),
                ("host", Opt(options, "obfs-host", "host")))),
            ("reuse", IsTrue(Opt(options, "reuse")) ? true : null));
    }

    private static ProxyConfigEntry? ParseWireGuard(string body, string? fragment)
    {
        if (!TrySplitAuthority(body, out var userinfo, out var host, out var port, out var query)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);

        return Create(name,
            "wireguard",
            ("server", host),
            ("port", port),
            ("private-key", NullIfEmpty(userinfo) ?? Opt(options, "privatekey", "private-key")),
            ("public-key", Opt(options, "publickey", "public-key", "peer-public-key")),
            ("ip", SplitList(Opt(options, "address", "ip"))),
            ("ipv6", SplitList(Opt(options, "address6", "ipv6"))),
            ("mtu", OptInt(options, "mtu")),
            ("reserved", SplitInts(Opt(options, "reserved"))),
            ("dns", SplitList(Opt(options, "dns"))),
            ("allowed-ips", SplitList(Opt(options, "allowed-ips", "allowed_ips"))),
            ("persistent-keepalive", OptInt(options, "persistent-keepalive", "keepalive")));
    }

    private static ProxyConfigEntry? ParseAnyTls(string body, string? fragment)
    {
        if (!TrySplitAuthority(body, out var userinfo, out var host, out var port, out var query)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);

        return Create(name,
            "anytls",
            ("server", host),
            ("port", port),
            ("password", SplitCredentials(userinfo).Password ?? userinfo ?? Opt(options, "password")),
            ("sni", Opt(options, "sni", "peer")),
            ("skip-cert-verify", IsTrue(Opt(options, "insecure", "allowInsecure", "allow_insecure")) ? true : null),
            ("client-fingerprint", Opt(options, "fp")),
            ("alpn", SplitAlpn(Opt(options, "alpn"))),
            ("udp", IsTrue(Opt(options, "udp")) ? true : null));
    }

    private static ProxyConfigEntry? ParseMieru(string body, string? fragment)
    {
        if (!TrySplitAuthority(body, out var userinfo, out var host, out var port, out var query)) return null;

        var options = ParseQuery(query);
        var name = NameFrom(fragment, host, port);
        var (username, password) = SplitCredentials(userinfo);

        return Create(name,
            "mieru",
            ("server", host),
            ("port", port),
            ("username", username ?? Opt(options, "username", "user")),
            ("password", password ?? Opt(options, "password")),
            ("transport", Opt(options, "transport", "protocol")),
            ("multiplexing", Opt(options, "multiplexing", "multiplex")),
            ("port-range", Opt(options, "port-range", "port_range")),
            ("skip-cert-verify", IsTrue(Opt(options, "insecure", "allowInsecure")) ? true : null));
    }

    // ── entry building ───────────────────────────────────────────────────────

    private static bool TryBuiltin(string text, out ProxyConfigEntry? entry)
    {
        entry = null;
        switch (text.ToUpperInvariant())
        {
            case "DIRECT":
                entry = Create("DIRECT", "direct");
                return true;
            case "REJECT":
                entry = Create("REJECT", "reject");
                return true;
            case "REJECT-DROP":
                entry = Create("REJECT-DROP", "reject");
                return true;
            default:
                return false;
        }
    }

    private static ProxyConfigEntry Create(string name, string type, params (string Key, object? Value)[] fields)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = name,
            ["type"] = type,
        };

        foreach (var (key, value) in fields)
        {
            if (value is null) continue;
            if (value is string text && text.Length == 0) continue;
            map[key] = value;
        }

        return new ProxyConfigEntry(new YamlMap(map));
    }

    private static Dictionary<string, object?>? NewMap(params (string Key, object? Value)[] fields)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in fields)
        {
            if (value is null) continue;
            if (value is string text && text.Length == 0) continue;
            map[key] = value;
        }

        return map.Count == 0 ? null : map;
    }

    private static string NameFrom(string? fragment, string host, int port)
    {
        var name = Decode(fragment).Trim();
        if (name.Length > 0) return name;
        return port > 0 ? $"{host}:{port}" : host;
    }

    // ── URL plumbing ─────────────────────────────────────────────────────────

    private static bool TrySplit(string link, out string scheme, out string body, out string? fragment)
    {
        scheme = string.Empty;
        body = string.Empty;
        fragment = null;

        var mark = link.IndexOf("://", StringComparison.Ordinal);
        if (mark <= 0) return false;

        scheme = link[..mark].Trim().ToLowerInvariant();
        var rest = link[(mark + 3)..];

        var hash = rest.LastIndexOf('#');
        if (hash >= 0)
        {
            fragment = rest[(hash + 1)..];
            rest = rest[..hash];
        }

        body = rest.Trim();
        return scheme.Length > 0 && body.Length > 0;
    }

    /// <summary>
    /// Splits <c>[userinfo@]host:port[?query]</c>, which every userinfo-style
    /// scheme shares.
    /// </summary>
    private static bool TrySplitAuthority(string body, out string? userinfo, out string host, out int port, out string? query)
    {
        userinfo = null;
        host = string.Empty;
        port = 0;
        query = null;

        var at = body.LastIndexOf('@');
        if (at > 0)
        {
            userinfo = Decode(body[..at]);
            SplitQuery(body[(at + 1)..], out var hostPart, out query);
            return TryHostPort(hostPart, out host, out port);
        }

        SplitQuery(body, out var rest, out query);
        return TryHostPort(rest, out host, out port);
    }

    private static void SplitQuery(string text, out string before, out string? query)
    {
        var mark = text.IndexOf('?');
        if (mark < 0)
        {
            before = text;
            query = null;
        }
        else
        {
            before = text[..mark];
            query = text[(mark + 1)..];
        }
    }

    private static bool TryHostPort(string text, out string host, out int port)
    {
        host = string.Empty;
        port = 0;

        var value = text.Trim();
        var cut = value.IndexOfAny(new[] { '/', '?', ' ' });
        if (cut >= 0) value = value[..cut];
        value = value.Trim();
        if (value.Length == 0) return false;

        string portText;
        if (value.StartsWith('['))
        {
            var close = value.IndexOf(']');
            if (close < 0) return false;
            host = value[1..close];
            var rest = value[(close + 1)..];
            if (!rest.StartsWith(':')) return false;
            portText = rest[1..];
        }
        else
        {
            var colon = value.LastIndexOf(':');
            if (colon <= 0) return false;
            host = value[..colon];
            portText = value[(colon + 1)..];
        }

        if (host.Length == 0) return false;
        return int.TryParse(portText, NumberStyles.Integer, CultureInfo.InvariantCulture, out port) && port is > 0 and <= 65535;
    }

    private static Dictionary<string, string> ParseQuery(string? query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return result;

        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            var key = Decode(eq < 0 ? pair : pair[..eq]).Trim();
            if (key.Length == 0) continue;

            result[key] = eq < 0 ? string.Empty : Decode(pair[(eq + 1)..]);
        }

        return result;
    }

    private static string? Opt(Dictionary<string, string> options, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (options.TryGetValue(key, out var value) && value.Length > 0) return value;
        }

        return null;
    }

    private static int? OptInt(Dictionary<string, string> options, params string[] keys)
    {
        var value = Opt(options, keys);
        if (value is null) return null;
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number) ? number : null;
    }

    private static int? ArgInt(string key, Dictionary<string, string> args)
        => args.TryGetValue(key, out var value) && int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)
            ? number
            : null;

    private static string Decode(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;

        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static bool IsTrue(string? value)
        => value?.Trim().ToLowerInvariant() is "1" or "true" or "yes" or "on";

    private static List<object?>? SplitAlpn(string? value)
    {
        var list = SplitList(value);
        return list;
    }

    private static List<object?>? SplitList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var items = value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Cast<object?>()
            .ToList();

        return items.Count == 0 ? null : items;
    }

    private static List<object?>? SplitInts(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        var items = new List<object?>();
        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)) items.Add(number);
        }

        return items.Count == 0 ? null : items;
    }

    private static byte[]? TryBase64Bytes(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;

        var cleaned = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            if (!char.IsWhiteSpace(c)) cleaned.Append(c);
        }

        var value = cleaned.ToString().Replace('-', '+').Replace('_', '/');
        var remainder = value.Length % 4;
        if (remainder == 1) return null;
        if (remainder > 0) value = value.PadRight(value.Length + (4 - remainder), '=');

        foreach (var c in value)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('+' or '/' or '=')) return null;
        }

        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string? TryBase64String(string text)
    {
        var bytes = TryBase64Bytes(text);
        if (bytes is null) return null;

        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }
}

/// <summary>
/// Installs <see cref="ShareLinkParser"/> as the process-wide
/// <see cref="ShareLinks"/> implementation so no other file has to know about it.
/// </summary>
internal static class ShareLinkParserRegistration
{
    [ModuleInitializer]
    internal static void Register() => ShareLinks.Use(new ShareLinkParser());
}
