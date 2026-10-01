using System.Net;

namespace Clash.Core.Common;

/// <summary>Result of one datagram receive.</summary>
public readonly record struct PacketResult(int BytesRead, EndPoint? Remote);

/// <summary>
/// A UDP association. Implementations range from a plain connected socket
/// (direct) to a multiplexed tunnel carrying many destinations at once
/// (Shadowsocks, VMess, TUIC).
/// </summary>
public interface IPacketConnection : IAsyncDisposable
{
    /// <summary>
    /// True when the association can address more than one remote endpoint.
    /// Callers may then skip per-destination association caching.
    /// </summary>
    bool SupportsMultipleDestinations { get; }

    /// <summary>The address the association is bound to, when meaningful.</summary>
    EndPoint? LocalEndPoint { get; }

    ValueTask<int> SendAsync(ReadOnlyMemory<byte> payload, EndPoint destination, CancellationToken cancellationToken = default);

    ValueTask<PacketResult> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);
}

/// <summary>An association that can also surface inbound source addresses for NAT bookkeeping.</summary>
public interface INatPacketConnection : IPacketConnection
{
    /// <summary>Called by the NAT table when a new inbound source appears.</summary>
    void RegisterSource(EndPoint source);
}
