using System.Buffers.Binary;
using System.Security.Cryptography;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Clash.Core.Transport;

namespace Clash.Core.Proxies.Outbound;

/// <summary>Which framing a Shadowsocks method uses.</summary>
internal enum ShadowsocksKind
{
    /// <summary>SIP004 AEAD: salt plus length-prefixed AEAD chunks.</summary>
    Aead,

    /// <summary>SIP022 AEAD: a 2022 header inside the first chunk, BLAKE3 session subkeys.</summary>
    Aead2022,

    /// <summary>A legacy byte-stream cipher: IV followed by a raw keystream.</summary>
    Stream,
}

/// <summary>
/// A resolved Shadowsocks method: the cipher to frame with, the master key and the
/// framing family. Immutable and safe to share across connections; the AEAD
/// primitives are stateless and the stream ciphers are created per direction.
/// </summary>
internal sealed class ShadowsocksMethod
{
    internal ShadowsocksMethod(string name, ShadowsocksKind kind, IAeadCipher? aead, byte[] key, int ivSize)
    {
        Name = name;
        Kind = kind;
        Aead = aead;
        Key = key;
        IvSize = ivSize;
    }

    /// <summary>The canonical cipher name.</summary>
    internal string Name { get; }

    /// <summary>The framing family.</summary>
    internal ShadowsocksKind Kind { get; }

    /// <summary>The AEAD primitive for the AEAD families, otherwise null.</summary>
    internal IAeadCipher? Aead { get; }

    /// <summary>The master key: <c>EVP_BytesToKey(password)</c> or the decoded 2022 PSK.</summary>
    internal byte[] Key { get; }

    /// <summary>The IV width for the stream family, otherwise 0.</summary>
    internal int IvSize { get; }

    /// <summary>True when this is a Shadowsocks 2022 method.</summary>
    internal bool Is2022 => Kind == ShadowsocksKind.Aead2022;

    /// <summary>
    /// Resolves a configuration cipher name against the frozen cipher registries.
    /// The 2022 names take the PSK straight from <c>password</c> (base64), every
    /// other name derives the master key with <c>EVP_BytesToKey</c>.
    /// </summary>
    internal static ShadowsocksMethod Resolve(string cipher, string password, string proxyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cipher);
        ArgumentNullException.ThrowIfNull(password);

        if (AeadCiphers.TryGet(cipher, out var aead))
        {
            var is2022 = cipher.StartsWith("2022-", StringComparison.OrdinalIgnoreCase);
            byte[] key;
            if (is2022)
            {
                if (!ClashBase64.TryDecode(password, out var psk) || psk.Length != aead.KeySize)
                {
                    throw new ProxyCreationException(
                        $"proxy [{proxyName}] (ss): cipher '{cipher}' needs a base64 pre-shared key of {aead.KeySize} bytes "
                        + $"in 'password', got '{password}'");
                }

                key = psk;
            }
            else
            {
                key = ShadowsocksKey.DeriveMasterKey(password, aead.KeySize);
            }

            return new ShadowsocksMethod(aead.Name, is2022 ? ShadowsocksKind.Aead2022 : ShadowsocksKind.Aead, aead, key, 0);
        }

        if (StreamCiphers.TryGet(cipher, out var stream))
        {
            return new ShadowsocksMethod(
                stream.Name,
                ShadowsocksKind.Stream,
                null,
                ShadowsocksKey.DeriveMasterKey(password, stream.KeySize),
                stream.IvSize);
        }

        throw new ProxyCreationException(
            $"proxy [{proxyName}] (ss): unsupported cipher '{cipher}'. Known AEAD ciphers: "
            + $"{string.Join(", ", AeadCiphers.Names.Order(StringComparer.Ordinal))}. Known stream ciphers: "
            + $"{string.Join(", ", StreamCiphers.Names.Order(StringComparer.Ordinal))}.");
    }
}

/// <summary>What a Shadowsocks <c>plugin</c> asks for.</summary>
internal enum ShadowsocksPluginKind
{
    /// <summary>No plugin.</summary>
    None,

    /// <summary>simple-obfs: an HTTP or fake-TLS header in front of the ciphertext.</summary>
    Obfs,

    /// <summary>v2ray-plugin in websocket mode: handled by the transport stack.</summary>
    WebSocket,
}

/// <summary>The parsed <c>plugin</c> / <c>plugin-opts</c> pair.</summary>
internal sealed class ShadowsocksPlugin
{
    private ShadowsocksPlugin(ShadowsocksPluginKind kind, string name, SimpleObfsMode obfsMode, string? host, YamlMap options)
    {
        Kind = kind;
        Name = name;
        ObfsMode = obfsMode;
        Host = host;
        Options = options;
    }

    /// <summary>The resolved plugin family.</summary>
    internal ShadowsocksPluginKind Kind { get; }

    /// <summary>The plugin name as written in the configuration.</summary>
    internal string Name { get; }

    /// <summary>The simple-obfs mode, when <see cref="Kind"/> is <see cref="ShadowsocksPluginKind.Obfs"/>.</summary>
    internal SimpleObfsMode ObfsMode { get; }

    /// <summary>The <c>host</c> the obfuscation presents, when configured.</summary>
    internal string? Host { get; }

    /// <summary>The raw <c>plugin-opts</c> map (or the legacy key=value form).</summary>
    internal YamlMap Options { get; }

    /// <summary>
    /// Parses the plugin configuration, accepting both the modern map form
    /// (<c>plugin: obfs</c> plus <c>plugin-opts</c>) and the legacy single-string
    /// form (<c>plugin: "obfs-local;obfs=http;obfs-host=x"</c>).
    /// </summary>
    internal static ShadowsocksPlugin? Parse(YamlMap map, string proxyName)
    {
        ArgumentNullException.ThrowIfNull(map);

        var raw = map.GetNonEmptyString("plugin");
        if (raw is null) return null;

        var options = map.GetMap("plugin-opts");
        var name = raw.Trim();
        var separator = name.IndexOf(';');
        if (separator >= 0)
        {
            // Legacy "name;k=v;k=v" form.
            var legacy = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in name[(separator + 1)..].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var equals = part.IndexOf('=');
                if (equals <= 0)
                {
                    legacy[part] = "true";
                    continue;
                }

                legacy[part[..equals].Trim()] = part[(equals + 1)..].Trim();
            }

            name = name[..separator].Trim();
            options = new YamlMap(legacy);
        }

        var normalized = name.ToLowerInvariant();
        switch (normalized)
        {
            case "obfs":
            case "obfs-local":
            case "simple-obfs":
            {
                var mode = (options.GetNonEmptyString("mode") ?? options.GetNonEmptyString("obfs") ?? "http").ToLowerInvariant();
                var host = options.GetNonEmptyString("host") ?? options.GetNonEmptyString("obfs-host");
                var resolved = mode switch
                {
                    "http" => SimpleObfsMode.Http,
                    "tls" => SimpleObfsMode.Tls,
                    _ => throw new ProxyCreationException(
                        $"proxy [{proxyName}] (ss): obfs plugin mode '{mode}' is not supported (expected 'http' or 'tls')"),
                };

                return new ShadowsocksPlugin(ShadowsocksPluginKind.Obfs, name, resolved, host, options);
            }

            case "v2ray-plugin":
            {
                var mode = (options.GetNonEmptyString("mode") ?? "websocket").ToLowerInvariant();
                if (mode != "websocket")
                {
                    throw new ProxyCreationException(
                        $"proxy [{proxyName}] (ss): v2ray-plugin mode '{mode}' is not supported (only 'websocket')");
                }

                var host = options.GetNonEmptyString("host");
                return new ShadowsocksPlugin(ShadowsocksPluginKind.WebSocket, name, SimpleObfsMode.Http, host, options);
            }

            case "shadow-tls":
                throw new TransportNotSupportedException(
                    $"proxy [{proxyName}] (ss): the '{name}' plugin cannot be driven by this build "
                    + "(it wraps the stream in its own TLS-in-TLS record layer with a password-derived handshake)");

            case "restls":
                throw new TransportNotSupportedException(
                    $"proxy [{proxyName}] (ss): the '{name}' plugin cannot be driven by this build "
                    + "(it forges TLS records around a real session and needs full control of the record layer)");

            default:
                throw new ProxyCreationException(
                    $"proxy [{proxyName}] (ss): unknown plugin '{name}' (known: obfs, obfs-local, simple-obfs, v2ray-plugin)");
        }
    }
}

/// <summary>
/// The <c>ss</c> adapter: Shadowsocks with every AEAD cipher, every legacy stream
/// cipher, the Shadowsocks 2022 methods, the <c>obfs</c> and <c>v2ray-plugin</c>
/// plugins, and UDP for all three framing families.
/// </summary>
public sealed class ShadowsocksAdapter : OutboundAdapter
{
    private readonly ShadowsocksMethod _method;
    private readonly ShadowsocksPlugin? _plugin;
    private readonly YamlMap _transportOptions;

    internal ShadowsocksAdapter(
        ProxyConfigEntry entry,
        AdapterBuildContext context,
        ShadowsocksMethod method,
        ShadowsocksPlugin? plugin,
        bool udp)
        : base(entry, context, ProxyType.Shadowsocks, udp)
    {
        _method = method;
        _plugin = plugin;
        _transportOptions = BuildTransportOptions(entry.Map, plugin);
    }

    /// <summary>The resolved cipher/framing family.</summary>
    internal ShadowsocksMethod Method => _method;

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static ShadowsocksAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var map = entry.Map;
        var cipher = map.GetNonEmptyString("cipher");
        if (cipher is null)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (ss) requires a 'cipher' (for example 'aes-256-gcm' or '2022-blake3-aes-256-gcm')");
        }

        var password = map.GetString("password");
        if (string.IsNullOrEmpty(password))
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (ss) requires a non-empty 'password'");
        }

        var method = ShadowsocksMethod.Resolve(cipher, password, entry.Name);
        var plugin = ShadowsocksPlugin.Parse(map, entry.Name);
        return new ShadowsocksAdapter(entry, context, method, plugin, map.GetBool("udp"));
    }

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        var raw = await OpenAsync(metadata, upstream, cancellationToken).ConfigureAwait(false);
        try
        {
            Stream pipe = raw;
            if (_plugin is { Kind: ShadowsocksPluginKind.Obfs } obfs)
            {
                pipe = new SimpleObfsStream(raw, obfs.ObfsMode, obfs.Host ?? ServerHost!, ServerPort);
            }

            var framed = new ShadowsocksTcpStream(pipe, _method, BuildFirstHeader(metadata));
            return Complete(Wrap(framed, raw));
        }
        catch (Exception ex)
        {
            await raw.DisposeAsync().ConfigureAwait(false);
            throw Fail(ex);
        }
    }

    /// <inheritdoc />
    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (!UdpEnabled)
        {
            throw new NotSupportedException($"proxy [{Name}] of type [{TypeName}] has UDP disabled in its configuration");
        }

        var (resolver, ipv6, interfaceName) = SocketHints();
        var socket = await SocketDialer
            .ConnectUdpAsync(ServerHost!, ServerPort, resolver, ipv6, interfaceName, cancellationToken)
            .ConfigureAwait(false);

        var connection = new ShadowsocksPacketConnection(socket, _method);
        TrackConnection(new AsyncDisposeBridge(connection));
        return connection;
    }

    /// <summary>
    /// The bytes that precede the first payload byte: the SOCKS5 address, preceded
    /// by the 2022 body header for the 2022 methods.
    /// </summary>
    private byte[] BuildFirstHeader(Metadata metadata)
    {
        var addressSize = Socks5Address.Size(OutboundOptions.Destination(metadata));
        if (!_method.Is2022)
        {
            var address = new byte[addressSize];
            OutboundOptions.WriteDestination(address, metadata);
            return address;
        }

        var header = new byte[Shadowsocks2022.UdpBodyHeaderSize + addressSize];
        Shadowsocks2022.WriteUdpBodyHeader(
            header,
            Shadowsocks2022PacketType.ClientStream,
            Shadowsocks2022.NowUnixSeconds(),
            paddingLength: 0);
        OutboundOptions.WriteDestination(header.AsSpan(Shadowsocks2022.UdpBodyHeaderSize), metadata);
        return header;
    }

    /// <summary>
    /// Turns a <c>v2ray-plugin</c> into the equivalent websocket transport options,
    /// so the frozen transport stack builds the layer instead of this adapter.
    /// </summary>
    private static YamlMap BuildTransportOptions(YamlMap map, ShadowsocksPlugin? plugin)
    {
        if (plugin is not { Kind: ShadowsocksPluginKind.WebSocket } ws) return map;

        var path = ws.Options.GetNonEmptyString("path") ?? "/";
        var headers = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(ws.Host)) headers["Host"] = ws.Host;

        var wsOptions = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["path"] = path,
            ["headers"] = headers,
        };

        var result = map.With("network", "ws").With("ws-opts", new YamlMap(wsOptions));
        if (ws.Options.GetBool("tls")) result = result.With("tls", true);
        return result;
    }

    /// <inheritdoc />
    protected override YamlMap DialOptions => _transportOptions;
}

/// <summary>Builds <see cref="ShadowsocksAdapter"/> instances.</summary>
internal sealed class ShadowsocksAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "ss";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => ["shadowsocks"];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => ShadowsocksAdapter.Create(entry, context);
}
