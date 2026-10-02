using System.Buffers;
using System.Net;
using System.Threading.Channels;
using Clash.Core.Common;

namespace Clash.Core.Netstack;

/// <summary>
/// Glues a <see cref="NetstackHost"/> to an <see cref="IPacketConnection"/>: the
/// inbound datagrams of the association become <see cref="NetstackHost.ProcessPacket"/>
/// calls, and the host's outbound packets are sent to the association's peer.
/// <para>
/// Why an adapter and not a method on the host: the host's sink is synchronous
/// and must not retain its buffer, while <see cref="IPacketConnection.SendAsync"/>
/// is asynchronous and may hold the memory until it completes. The queue between
/// them is what reconciles the two contracts without copying twice or blocking
/// the packet path.
/// </para>
/// <para>
/// One adapter owns the host's <see cref="NetstackHost.PacketSink"/>; two of them
/// over the same host would fight over it. The wrapped connection is disposed
/// with the adapter, and it must honour the cancellation token it is given.
/// </para>
/// </summary>
public sealed class NetstackPacketConnectionAdapter : IAsyncDisposable
{
    private const int MaxDatagram = ushort.MaxValue;

    private readonly record struct OutboundPacket(byte[] Buffer, int Length);

    private readonly NetstackHost _host;
    private readonly IPacketConnection _connection;
    private readonly EndPoint _peer;
    private readonly Action<ReadOnlyMemory<byte>> _sink;
    private readonly Channel<OutboundPacket> _outbound = Channel.CreateUnbounded<OutboundPacket>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _receiveLoop;
    private readonly Task _sendLoop;
    private int _disposed;

    /// <summary>Creates and starts the adapter.</summary>
    /// <param name="host">The host whose packets this adapter carries.</param>
    /// <param name="connection">The packet association to the tunnel peer.</param>
    /// <param name="peer">The endpoint every outbound packet is sent to.</param>
    public NetstackPacketConnectionAdapter(NetstackHost host, IPacketConnection connection, EndPoint peer)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _peer = peer ?? throw new ArgumentNullException(nameof(peer));

        _sink = Enqueue;
        _host.PacketSink = _sink;
        _receiveLoop = Task.Run(ReceiveLoopAsync);
        _sendLoop = Task.Run(SendLoopAsync);
    }

    /// <summary>Stops both pumps and disposes the wrapped association.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (ReferenceEquals(_host.PacketSink, _sink))
        {
            _host.PacketSink = null;
        }

        await _lifetime.CancelAsync().ConfigureAwait(false);
        _outbound.Writer.TryComplete();

        try
        {
            // A peer connection that ignores cancellation must not hold up
            // shutdown; the loops own their buffers and clean up when they end.
            await Task.WhenAll(_receiveLoop, _sendLoop).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation or a stalled transport; the association is disposed next.
        }

        await _connection.DisposeAsync().ConfigureAwait(false);
    }

    private void Enqueue(ReadOnlyMemory<byte> packet)
    {
        if (packet.IsEmpty)
        {
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(packet.Length);
        packet.CopyTo(buffer);

        if (!_outbound.Writer.TryWrite(new OutboundPacket(buffer, packet.Length)))
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task ReceiveLoopAsync()
    {
        var token = _lifetime.Token;
        var buffer = ArrayPool<byte>.Shared.Rent(MaxDatagram);
        try
        {
            while (!token.IsCancellationRequested)
            {
                var received = await _connection.ReceiveAsync(buffer, token).ConfigureAwait(false);
                if (received.BytesRead <= 0)
                {
                    continue;
                }

                _host.ProcessPacket(buffer.AsMemory(0, received.BytesRead));
            }
        }
        catch (Exception)
        {
            // Cancellation, or the association is gone: either way this pump ends.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task SendLoopAsync()
    {
        var token = _lifetime.Token;
        try
        {
            while (await _outbound.Reader.WaitToReadAsync(token).ConfigureAwait(false))
            {
                while (_outbound.Reader.TryRead(out var packet))
                {
                    try
                    {
                        await _connection.SendAsync(packet.Buffer.AsMemory(0, packet.Length), _peer, token)
                            .ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        // A failed send ends this packet, not the association.
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(packet.Buffer);
                    }
                }
            }
        }
        catch (Exception)
        {
            // Cancellation, or the channel was completed while reading.
        }
    }
}
