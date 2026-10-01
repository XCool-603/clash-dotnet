using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Adapter;

/// <summary>The <c>DIRECT</c> adapter: connects without any proxy.</summary>
public sealed class DirectAdapter : ProxyAdapter, IOutboundProxy
{
    private readonly ITunnelAccessor _tunnel;
    private readonly ILogger _logger;

    public DirectAdapter(string name, ITunnelAccessor tunnel, ILogger logger)
        : base(name, ProxyType.Direct)
    {
        _tunnel = tunnel;
        _logger = logger;
    }

    public string? ServerHost => null;

    public int ServerPort => 0;

    public string? DialerProxy => null;

    public override bool SupportUdp => true;

    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        // A relay chain ending in DIRECT simply reuses the stream the previous
        // hop already established.
        if (upstream is not null) return new ProxyStream(upstream);

        var (host, port) = ResolveTarget(metadata);
        var resolver = _tunnel.IsReady ? _tunnel.Tunnel.Dns : null;
        var allowIpv6 = _tunnel.IsReady ? _tunnel.Tunnel.Config.Ipv6 : true;
        var interfaceName = _tunnel.IsReady ? _tunnel.Tunnel.Config.InterfaceName : null;

        var socket = await SocketDialer
            .ConnectTcpAsync(host, port, resolver, allowIpv6, interfaceName, _logger, cancellationToken)
            .ConfigureAwait(false);

        MarkAlive();
        return Track(new ProxyStream(new SocketStream(socket), socket.LocalEndPoint, socket.RemoteEndPoint, socket));
    }

    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        var (host, port) = ResolveTarget(metadata);
        var resolver = _tunnel.IsReady ? _tunnel.Tunnel.Dns : null;
        var allowIpv6 = _tunnel.IsReady ? _tunnel.Tunnel.Config.Ipv6 : true;
        var interfaceName = _tunnel.IsReady ? _tunnel.Tunnel.Config.InterfaceName : null;

        var socket = await SocketDialer
            .ConnectUdpAsync(host, port, resolver, allowIpv6, interfaceName, cancellationToken)
            .ConfigureAwait(false);

        return new DirectPacketConnection(socket);
    }

    /// <summary>
    /// Chooses the address to connect to. In fake-IP mode the metadata carries the
    /// real domain in <see cref="Metadata.Host"/>, so the placeholder address must
    /// never be dialed.
    /// </summary>
    private static (string Host, int Port) ResolveTarget(Metadata metadata)
    {
        var host = metadata.DnsMode == DnsMode.FakeIp && !string.IsNullOrEmpty(metadata.Host)
            ? metadata.Host!
            : metadata.DestinationAddress;

        return (host, metadata.DestinationPort);
    }
}

/// <summary>The <c>REJECT</c> adapter: terminates the flow without contacting anything.</summary>
public sealed class RejectAdapter : ProxyAdapter
{
    private readonly bool _drop;

    public RejectAdapter(string name, bool drop = false)
        : base(name, ProxyType.Reject)
    {
        _drop = drop;
    }

    /// <summary>True for <c>REJECT-DROP</c>, which black-holes rather than resetting.</summary>
    public bool Drop => _drop;

    public override Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        // Returning an immediately-EOF stream makes the relay close the client
        // connection, which is what Clash's REJECT does.
        return Task.FromResult(new ProxyStream(NullStream.Instance));
    }

    public override Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
        => Task.FromResult<IPacketConnection>(new DiscardPacketConnection());
}

/// <summary>The <c>dns</c> adapter: resolves the destination and then connects directly.</summary>
public sealed class DnsAdapter : ProxyAdapter, IOutboundProxy
{
    private readonly ITunnelAccessor _tunnel;
    private readonly ILogger _logger;

    public DnsAdapter(string name, ITunnelAccessor tunnel, ILogger logger)
        : base(name, ProxyType.Dns)
    {
        _tunnel = tunnel;
        _logger = logger;
    }

    public string? ServerHost => null;

    public int ServerPort => 0;

    public string? DialerProxy => null;

    public override bool SupportUdp => true;

    public override async Task<ProxyStream> DialTcpAsync(
        Metadata metadata,
        Stream? upstream = null,
        CancellationToken cancellationToken = default)
    {
        if (upstream is not null) return new ProxyStream(upstream);

        if (!_tunnel.IsReady) throw new InvalidOperationException("the tunnel is not attached yet");
        var tunnel = _tunnel.Tunnel;

        var host = metadata.RuleHost;
        var addresses = await tunnel.Dns.ResolveAsync(host, tunnel.Config.Ipv6, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0) throw new SocketException((int)SocketError.HostNotFound);

        var socket = await SocketDialer
            .ConnectTcpAsync(addresses[0].ToString(), metadata.DestinationPort, null, tunnel.Config.Ipv6,
                tunnel.Config.InterfaceName, _logger, cancellationToken)
            .ConfigureAwait(false);

        return Track(new ProxyStream(new SocketStream(socket), socket.LocalEndPoint, socket.RemoteEndPoint, socket));
    }

    public override async Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
    {
        if (!_tunnel.IsReady) throw new InvalidOperationException("the tunnel is not attached yet");
        var tunnel = _tunnel.Tunnel;

        var addresses = await tunnel.Dns
            .ResolveAsync(metadata.RuleHost, tunnel.Config.Ipv6, cancellationToken)
            .ConfigureAwait(false);
        if (addresses.Length == 0) throw new SocketException((int)SocketError.HostNotFound);

        var socket = await SocketDialer
            .ConnectUdpAsync(addresses[0].ToString(), metadata.DestinationPort, null, tunnel.Config.Ipv6,
                tunnel.Config.InterfaceName, cancellationToken)
            .ConfigureAwait(false);

        return new DirectPacketConnection(socket);
    }
}

/// <summary>A packet association that silently drops everything.</summary>
internal sealed class DiscardPacketConnection : IPacketConnection
{
    public bool SupportsMultipleDestinations => true;

    public EndPoint? LocalEndPoint => null;

    public ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(payload.Length);

    public ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => new(new PacketResult(0, null));

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

// ── Factories ────────────────────────────────────────────────────────────────

internal sealed class DirectAdapterFactory : IAdapterFactory
{
    public string Type => "direct";

    public IReadOnlyList<string> Aliases => ["compatible"];

    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context)
        => new DirectAdapter(entry.Name, context.Tunnel, context.LoggerFactory.CreateLogger<DirectAdapter>());
}

internal sealed class RejectAdapterFactory : IAdapterFactory
{
    public string Type => "reject";

    public IReadOnlyList<string> Aliases => [];

    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context)
        => new RejectAdapter(entry.Name, entry.Map.GetBool("drop"));
}

internal sealed class DnsAdapterFactory : IAdapterFactory
{
    public string Type => "dns";

    public IReadOnlyList<string> Aliases => [];

    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context)
        => new DnsAdapter(entry.Name, context.Tunnel, context.LoggerFactory.CreateLogger<DnsAdapter>());
}
