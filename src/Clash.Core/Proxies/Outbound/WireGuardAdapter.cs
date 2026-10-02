using System.Net;
using System.Net.Sockets;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Crypto;
using Clash.Core.Netstack;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The <c>wireguard</c> adapter: a WireGuard v1 client that carries TCP through a
/// userspace stack and UDP best-effort, over one peer.
/// <para>
/// Why a netstack is unavoidable here: WireGuard is layer 3. It hands the peer raw
/// IP packets and gets raw IP packets back; it has no notion of a connection, a
/// port or a stream. A Clash-style outbound must relay <see cref="Stream"/>s, so
/// this adapter terminates the application's TCP connection against
/// <see cref="NetstackHost"/> and translates the resulting segments into inner IP
/// packets for the tunnel. The session is created once per adapter and shared by
/// every flow, because a WireGuard peer has exactly one session per key pair.
/// </para>
/// <para>
/// Configuration, in the flat shape the share-link parser emits and the nested
/// <c>peers:</c> shape mihomo uses (both are accepted):
/// <c>server</c>, <c>port</c>, <c>private-key</c>, <c>public-key</c> (or
/// <c>peers[0].public-key</c>), <c>pre-shared-key</c>, <c>reserved</c>,
/// <c>allowed-ips</c>, <c>mtu</c>, <c>ip</c>/<c>address</c> (the tunnel's own
/// address), and <c>udp</c>.
/// </para>
/// <para>
/// Out of scope, refused or ignored deliberately rather than approximated:
/// </para>
/// <list type="bullet">
/// <item><description><b>Multiple peers.</b> A <c>peers:</c> list with more than
/// one entry is rejected: one session binds one static key pair to one peer, and
/// routing between several would need a per-peer index map this client does not
/// keep.</description></item>
/// <item><description><b>IPv6.</b> The netstack is IPv4-only and so is the UDP
/// view; an <c>ipv6</c> entry is logged and ignored, and an IPv6 destination is
/// refused with a clear exception.</description></item>
/// <item><description><b>Roaming and endpoint updates.</b> The peer's endpoint is
/// fixed for the session's life; a reply from a different address is not
/// accepted as a roaming signal.</description></item>
/// <item><description><b>Persistent keepalive tuning.</b> <c>persistent-keepalive</c>
/// is logged and ignored; the standard keepalive timer governs.</description></item>
/// <item><description><b>IP fragmentation.</b> A fragmented inner packet is
/// dropped, in both directions.</description></item>
/// <item><description><b>The OS WireGuard driver.</b> This is an in-process
/// adapter and never creates a network interface, so it needs no administrator
/// rights.</description></item>
/// <item><description><b>AmneziaWG.</b> <c>amnezia-wg-option</c> and the fork's
/// flat keys are rejected outright: its wire format differs, and speaking plain
/// WireGuard at it would fail in a way that looks like a network problem.</description></item>
/// <item><description><b>dialer-proxy.</b> Rejected: the session runs over a raw
/// UDP socket to the peer's endpoint and there is no datagram dialer chain to
/// route it through, so honouring the option would be a lie.</description></item>
/// </list>
/// </summary>
public sealed class WireGuardAdapter : OutboundAdapter
{
    /// <summary>The inner MTU WireGuard conventionally uses.</summary>
    private const int DefaultMtu = 1420;

    /// <summary>
    /// Headroom subtracted from the MTU to get the MSS this stack advertises:
    /// 20 bytes of IPv4 and 20 of TCP plus a conservative 20 for the encapsulation
    /// the tunnel adds around the inner packet.
    /// </summary>
    private const int MtuToMssOverhead = 60;

    /// <summary>The smallest inner MTU whose MSS still fits the netstack's floor.</summary>
    private const int MinMtu = 316;

    /// <summary>The largest inner MTU this adapter will accept.</summary>
    private const int MaxMtu = ushort.MaxValue;

    /// <summary>Options that only exist in the AmneziaWG fork, which is not this protocol.</summary>
    private static readonly string[] AmneziaKeys =
    [
        "amnezia-wg-option", "jc", "jmin", "jmax",
        "s1", "s2", "s3", "s4",
        "h1", "h2", "h3", "h4",
        "i1", "i2", "i3", "i4", "i5",
        "j1", "j2", "j3",
        "itime", "header-protection-key", "content-padding-addition",
    ];

    private readonly WireGuardSessionOptions _sessionOptions;
    private readonly IPAddress _localAddress;
    private readonly int _mss;
    private readonly Lock _gate = new();
    private readonly SemaphoreSlim _tunnelGate = new(1, 1);
    private WireGuardTunnel? _tunnel;
    private int _generation;

    internal WireGuardAdapter(
        ProxyConfigEntry entry,
        AdapterBuildContext context,
        WireGuardSessionOptions sessionOptions,
        IPAddress localAddress,
        int mss,
        bool udp)
        : base(entry, context, ProxyType.Wireguard, udp)
    {
        _sessionOptions = sessionOptions;
        _localAddress = localAddress;
        _mss = mss;
    }

    /// <summary>Validates the entry and builds the adapter.</summary>
    internal static WireGuardAdapter Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        var map = entry.Map;
        RejectAmnezia(entry, map);

        var peer = SelectPeer(entry, map);

        if (OutboundOptions.ReadDialerProxy(map) is { Length: > 0 } dialer)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (wireguard): 'dialer-proxy' ({dialer}) is not supported — the session runs over a raw UDP "
                + "socket to the peer's endpoint and there is no datagram dialer chain to route it through");
        }

        var privateKey = RequireKey(entry, map, map, "private-key");
        var publicKey = RequireKey(entry, peer, map, "public-key", "peer-public-key");

        var sessionOptions = new WireGuardSessionOptions
        {
            LocalPrivateKey = privateKey,
            PeerPublicKey = publicKey,
            PresharedKey = OptionalKey(entry, peer, map, "pre-shared-key", "preshared-key", "psk"),
            Reserved = ReadReserved(entry, peer, map),
        };

        sessionOptions.Validate();

        var localAddress = RequireLocalAddress(entry, map);
        var mtu = ReadMtu(entry, map);

        WarnAboutIgnoredKeys(context, entry, map);

        return new WireGuardAdapter(
            entry,
            context,
            sessionOptions,
            localAddress,
            mtu - MtuToMssOverhead,
            udp: map.GetBool("udp", true));
    }

    /// <inheritdoc />
    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        if (upstream is not null)
        {
            // There is no way to express "tunnel this byte stream" to a layer-3
            // peer, so this refuses rather than silently ignoring the hop.
            throw new NotSupportedException(
                $"proxy [{Name}] (wireguard) cannot chain an upstream stream: WireGuard is a layer-3 tunnel and has no "
                + "way to hand an existing byte stream to the peer");
        }

        try
        {
            var remote = await ResolveAsync(metadata, cancellationToken).ConfigureAwait(false);
            var tunnel = await EnsureTunnelAsync(cancellationToken).ConfigureAwait(false);
            var stream = await tunnel.Host.ConnectAsync(remote, cancellationToken).ConfigureAwait(false);
            return Complete(Track(new ProxyStream(stream, tunnel.LocalEndPoint, remote)));
        }
        catch (Exception ex)
        {
            throw Fail(ex);
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// The returned association is the UDP view of the one session this adapter
    /// owns. It is shared by every UDP flow — there is one session per peer — and
    /// disposing it is deliberately a no-op, because the adapter, not the flow,
    /// owns the tunnel.
    /// </remarks>
    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metadata);

        if (!UdpEnabled)
        {
            throw new NotSupportedException($"proxy [{Name}] of type [{TypeName}] has UDP disabled in its configuration");
        }

        try
        {
            var tunnel = await EnsureTunnelAsync(cancellationToken).ConfigureAwait(false);
            MarkAlive();
            return tunnel.Udp;
        }
        catch (Exception ex)
        {
            throw Fail(ex);
        }
    }

    /// <summary>
    /// Drops every flow and tears the session, the netstack and the UDP socket
    /// down. A later dial builds a fresh tunnel, which is what makes this usable as
    /// a health-check reset rather than only as shutdown.
    /// </summary>
    public override void CloseConnections()
    {
        base.CloseConnections();

        WireGuardTunnel? tunnel;
        lock (_gate)
        {
            _generation++;
            tunnel = _tunnel;
            _tunnel = null;
        }

        if (tunnel is not null) _ = DisposeQuietlyAsync(tunnel);
    }

    /// <summary>
    /// Resolves the flow's destination to an inner IPv4 endpoint. A name is
    /// resolved here, before the packet ever enters the tunnel, because the inner
    /// packet needs a literal address.
    /// </summary>
    private async Task<IPEndPoint> ResolveAsync(Metadata metadata, CancellationToken cancellationToken)
    {
        var host = OutboundOptions.Destination(metadata);

        if (IPAddress.TryParse(host, out var literal))
        {
            if (literal.AddressFamily != AddressFamily.InterNetwork)
            {
                throw new NotSupportedException($"proxy [{Name}] (wireguard): IPv6 is out of scope ({literal})");
            }

            return new IPEndPoint(literal, metadata.DestinationPort);
        }

        var (resolver, _, _) = SocketHints();
        var addresses = await SocketDialer
            .ResolveAsync(host, resolver, allowIpv6: false, cancellationToken)
            .ConfigureAwait(false);

        var ipv4 = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        if (ipv4 is null)
        {
            throw new ClashException($"proxy [{Name}] (wireguard): could not resolve [{host}] to an IPv4 address");
        }

        return new IPEndPoint(ipv4, metadata.DestinationPort);
    }

    /// <summary>
    /// Creates the one session, packet connection, netstack host and UDP socket
    /// this adapter owns, or returns the existing set.
    /// </summary>
    private async ValueTask<WireGuardTunnel> EnsureTunnelAsync(CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            if (_tunnel is not null) return _tunnel;
        }

        await _tunnelGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            int generation;
            lock (_gate)
            {
                if (_tunnel is not null) return _tunnel;
                generation = _generation;
            }

            var (resolver, _, interfaceName) = SocketHints();
            var socket = await SocketDialer
                .ConnectUdpAsync(ServerHost!, ServerPort, resolver, allowIpv6: false, interfaceName, cancellationToken)
                .ConfigureAwait(false);

            var transport = new WireGuardUdpTransport(socket);
            try
            {
                var session = new WireGuardSession(_sessionOptions, transport);
                var connection = new WireGuardPacketConnection(session);
                var host = new NetstackHost(new NetstackOptions { LocalAddress = _localAddress, Mss = _mss });
                var bridge = new NetstackPacketConnectionAdapter(
                    host,
                    connection,
                    transport.RemoteEndPoint ?? new IPEndPoint(IPAddress.Any, 0));

                var tunnel = new WireGuardTunnel(connection, host, bridge);

                lock (_gate)
                {
                    if (_generation != generation)
                    {
                        // CloseConnections ran while the socket was being opened.
                        _ = DisposeQuietlyAsync(tunnel);
                        throw new ClashException($"proxy [{Name}] (wireguard): the adapter was closed while its tunnel was being built");
                    }

                    _tunnel = tunnel;
                }

                return tunnel;
            }
            catch (Exception)
            {
                // The transport owns the socket from here, so disposing it closes the
                // socket even when the failure came from the session's own setup.
                await transport.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        finally
        {
            _tunnelGate.Release();
        }
    }

    private static async Task DisposeQuietlyAsync(WireGuardTunnel tunnel)
    {
        try
        {
            await tunnel.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Teardown of a tunnel that is already broken; nothing useful to report.
        }
    }

    // ── configuration ────────────────────────────────────────────────────────

    /// <summary>
    /// Picks the peer's option map: mihomo nests the peer fields inside a
    /// <c>peers:</c> list while the share-link parser emits them flat, so both
    /// shapes are read through the same code afterwards.
    /// </summary>
    private static YamlMap SelectPeer(ProxyConfigEntry entry, YamlMap map)
    {
        var peers = map.GetList("peers");
        if (peers.Count == 0) return map;

        if (peers.Count > 1)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (wireguard): only one peer is supported, but 'peers' lists {peers.Count}");
        }

        return YamlMap.From(peers[0]);
    }

    /// <summary>Rejects the AmneziaWG fork, whose wire format is not WireGuard v1.</summary>
    private static void RejectAmnezia(ProxyConfigEntry entry, YamlMap map)
    {
        foreach (var key in AmneziaKeys)
        {
            if (!map.Has(key)) continue;

            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (wireguard): '{key}' is an AmneziaWG option; the fork's wire format differs from "
                + "WireGuard v1 and is not implemented");
        }
    }

    private static byte[] RequireKey(ProxyConfigEntry entry, YamlMap peer, YamlMap map, params string[] names)
    {
        var value = OptionalKey(entry, peer, map, names);
        if (value is not null) return value;

        throw new ProxyCreationException(
            $"proxy [{entry.Name}] (wireguard) requires a base64 '{names[0]}' of {WireGuardCrypto.KeySize} bytes");
    }

    private static byte[]? OptionalKey(ProxyConfigEntry entry, YamlMap peer, YamlMap map, params string[] names)
    {
        foreach (var name in names)
        {
            var text = peer.GetNonEmptyString(name) ?? map.GetNonEmptyString(name);
            if (text is null) continue;

            if (!WireGuardCrypto.TryDecodeKey(text, WireGuardCrypto.KeySize, out var value))
            {
                throw new ProxyCreationException(
                    $"proxy [{entry.Name}] (wireguard): '{name}' is not base64 for {WireGuardCrypto.KeySize} bytes");
            }

            return value;
        }

        return null;
    }

    /// <summary>
    /// Reads the three WARP reserved bytes. mihomo requires exactly three; anything
    /// else is refused rather than truncated, because a wrong length would silently
    /// land in the middle of the sender index.
    /// </summary>
    private static byte[]? ReadReserved(ProxyConfigEntry entry, YamlMap peer, YamlMap map)
    {
        var raw = peer.GetList("reserved");
        if (raw.Count == 0) raw = map.GetList("reserved");
        if (raw.Count == 0) return null;

        if (raw.Count != 3)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (wireguard): 'reserved' must be exactly 3 bytes, got {raw.Count}");
        }

        var reserved = new byte[3];
        for (var i = 0; i < 3; i++)
        {
            var value = Convert.ToInt32(raw[i], System.Globalization.CultureInfo.InvariantCulture);
            if (value is < 0 or > 255)
            {
                throw new ProxyCreationException(
                    $"proxy [{entry.Name}] (wireguard): 'reserved[{i}]' must be 0-255, got {value}");
            }

            reserved[i] = (byte)value;
        }

        return reserved;
    }

    /// <summary>
    /// The tunnel's own inner address. It is required: the userspace stack answers
    /// for exactly one address, and without it no inner packet could be addressed
    /// to us. <c>allowed-ips</c> is consulted last because it normally describes the
    /// <em>peer's</em> routing table, not ours — but some share links carry the
    /// local address there and nowhere else.
    /// </summary>
    private static IPAddress RequireLocalAddress(ProxyConfigEntry entry, YamlMap map)
    {
        foreach (var key in new[] { "ip", "address", "allowed-ips", "allowed_ips" })
        {
            foreach (var raw in map.GetStringList(key))
            {
                var text = raw.Contains('/') ? raw[..raw.IndexOf('/')] : raw;
                if (IPAddress.TryParse(text, out var address) && address.AddressFamily == AddressFamily.InterNetwork)
                {
                    return address;
                }
            }
        }

        throw new ProxyCreationException(
            $"proxy [{entry.Name}] (wireguard) requires the tunnel's own IPv4 address in 'ip' (or 'address'); "
            + "WireGuard is layer 3, so the userspace stack cannot answer for an address it was not given");
    }

    private static int ReadMtu(ProxyConfigEntry entry, YamlMap map)
    {
        var mtu = map.Has("mtu") ? map.GetInt("mtu") : DefaultMtu;
        if (mtu is < MinMtu or > MaxMtu)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (wireguard): 'mtu' must be {MinMtu}-{MaxMtu}, got {mtu}");
        }

        return mtu;
    }

    /// <summary>
    /// Logs the options this adapter deliberately does not honour, so an operator
    /// sees the difference between "configured and working" and "configured and
    /// silently ignored".
    /// </summary>
    private static void WarnAboutIgnoredKeys(AdapterBuildContext context, ProxyConfigEntry entry, YamlMap map)
    {
        var logger = context.LoggerFactory.CreateLogger<WireGuardAdapter>();

        if (map.Has("ipv6") && map.GetStringList("ipv6").Count > 0)
        {
            // Logged, not refused: a WARP link routinely carries both addresses and
            // still works perfectly over IPv4.
            logger.LogWarning("proxy [{Name}] (wireguard): 'ipv6' is out of scope and will be ignored", entry.Name);
        }

        if (map.Has("persistent-keepalive") || map.Has("keepalive"))
        {
            logger.LogWarning(
                "proxy [{Name}] (wireguard): 'persistent-keepalive' is out of scope; the standard keepalive timer governs",
                entry.Name);
        }

        if (map.Has("dns"))
        {
            logger.LogWarning(
                "proxy [{Name}] (wireguard): 'dns' needs a resolver inside the tunnel, which is out of scope; it will be ignored",
                entry.Name);
        }
    }

    /// <summary>The per-adapter session, netstack and packet plumbing.</summary>
    private sealed class WireGuardTunnel : IAsyncDisposable
    {
        internal WireGuardTunnel(
            WireGuardPacketConnection connection,
            NetstackHost host,
            NetstackPacketConnectionAdapter bridge)
        {
            Connection = connection;
            Host = host;
            Bridge = bridge;
            Udp = connection.CreateUdpView(host.LocalAddress);
        }

        internal WireGuardPacketConnection Connection { get; }

        internal NetstackHost Host { get; }

        internal NetstackPacketConnectionAdapter Bridge { get; }

        internal WireGuardUdpPacketConnection Udp { get; }

        internal EndPoint? LocalEndPoint => Connection.LocalEndPoint;

        public async ValueTask DisposeAsync()
        {
            try
            {
                await Host.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                // A host that is already broken must not stop the socket closing.
            }

            // The bridge owns the packet connection, which owns the session, which
            // owns the UDP socket: disposing it here is what closes everything.
            await Bridge.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>Builds <see cref="WireGuardAdapter"/> instances.</summary>
internal sealed class WireGuardAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "wireguard";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => ["wg"];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context) => WireGuardAdapter.Create(entry, context);
}
