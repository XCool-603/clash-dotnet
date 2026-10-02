using System.Threading.Channels;
using Clash.Core.Netstack;

namespace Clash.Tests.Netstack;

/// <summary>
/// A hand-written IPv4/TCP peer for driving <see cref="NetstackHost"/> without a
/// socket anywhere in sight. It receives the client's packets through the host's
/// sink, parses them with <see cref="TestPackets"/> (an independent codec), and
/// replies by feeding hand-built packets back into
/// <see cref="NetstackHost.ProcessPacket"/>.
/// <para>
/// All bookkeeping happens on the pump task before a segment becomes visible to
/// the test, so an assertion that reads <see cref="ClientNextSequence"/> after
/// <see cref="WaitForAsync"/> can never race the peer's own state. Replies also
/// run on the pump rather than inside the sink, because the sink is invoked while
/// the connection holds its lock — replying synchronously there would deadlock.
/// </para>
/// </summary>
internal sealed class FakeTcpPeer : IAsyncDisposable
{
    [Flags]
    private enum Reaction
    {
        None = 0,
        SendSynAck = 1,
        SendAck = 2,
    }

    private readonly NetstackHost _host;
    private readonly Channel<byte[]> _inbox = Channel.CreateUnbounded<byte[]>();
    private readonly Lock _gate = new();
    private readonly List<ParsedPacket> _received = [];
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _pump;
    private Exception? _handlerFailure;

    public FakeTcpPeer(NetstackHost host)
    {
        _host = host;
        host.PacketSink = packet => _inbox.Writer.TryWrite(packet.ToArray());
        _pump = Task.Run(PumpAsync);
    }

    /// <summary>Answer the client's SYN with a SYN-ACK automatically.</summary>
    public bool AutoHandshake { get; set; } = true;

    /// <summary>Acknowledge payload automatically (turn off to script loss).</summary>
    public bool AutoAcknowledgeData { get; set; } = true;

    /// <summary>Runs for every valid segment, after the automatic behaviour.</summary>
    public Func<ParsedPacket, ValueTask>? OnSegment { get; set; }

    /// <summary>The peer's own initial sequence number.</summary>
    public uint ServerInitialSequence { get; set; } = 100_000;

    /// <summary>The sequence number the peer will use for its next byte.</summary>
    public uint ServerNextSequence { get; private set; }

    /// <summary>The client's initial sequence number, learned from its SYN.</summary>
    public uint ClientInitialSequence { get; private set; }

    /// <summary>The sequence number the peer expects from the client next.</summary>
    public uint ClientNextSequence { get; private set; }

    /// <summary>The client's ephemeral port, learned from its SYN.</summary>
    public ushort ClientPort { get; private set; }

    /// <summary>The port the client addressed, learned from its SYN.</summary>
    public ushort ServerPort { get; private set; }

    /// <summary>The client's address, learned from its SYN.</summary>
    public uint ClientAddress { get; private set; }

    /// <summary>The address the client addressed, learned from its SYN.</summary>
    public uint ServerAddress { get; private set; }

    /// <summary>True once the client's handshake acknowledgement has arrived.</summary>
    public bool HandshakeComplete { get; private set; }

    /// <summary>How many segments the peer has parsed.</summary>
    public int ReceivedCount
    {
        get
        {
            lock (_gate)
            {
                return _received.Count;
            }
        }
    }

    /// <summary>A snapshot of everything the peer has parsed.</summary>
    public IReadOnlyList<ParsedPacket> Received
    {
        get
        {
            lock (_gate)
            {
                return [.. _received];
            }
        }
    }

    /// <summary>Sends one segment to the client.</summary>
    public void Send(
        uint sequence,
        uint acknowledgment,
        byte flags,
        ReadOnlySpan<byte> payload = default,
        ushort window = 65535,
        int mss = -1,
        bool corruptChecksum = false)
    {
        var packet = TestPackets.Build(
            ServerAddress,
            ClientAddress,
            ServerPort,
            ClientPort,
            sequence,
            acknowledgment,
            flags,
            payload,
            window,
            mss,
            corruptChecksum);
        _host.ProcessPacket(packet);
    }

    /// <summary>Sends payload at the peer's current sequence number.</summary>
    public void SendData(ReadOnlySpan<byte> payload)
    {
        Send(ServerNextSequence, ClientNextSequence, (byte)(TestPackets.FlagAck | TestPackets.FlagPsh), payload);
        ServerNextSequence += (uint)payload.Length;
    }

    /// <summary>Sends a bare acknowledgement.</summary>
    public void SendAck(uint acknowledgment)
        => Send(ServerNextSequence, acknowledgment, TestPackets.FlagAck);

    /// <summary>Sends a FIN, consuming one sequence number.</summary>
    public void SendFin()
    {
        Send(ServerNextSequence, ClientNextSequence, (byte)(TestPackets.FlagFin | TestPackets.FlagAck));
        ServerNextSequence += 1;
    }

    /// <summary>Sends a reset.</summary>
    public void SendReset()
        => Send(ServerNextSequence, ClientNextSequence, (byte)(TestPackets.FlagRst | TestPackets.FlagAck));

    /// <summary>
    /// Waits until the <paramref name="skip"/>-th (zero-based) segment matching
    /// <paramref name="predicate"/> has arrived. This is an event-driven wait with
    /// a bounded timeout, so a missing packet fails the test instead of hanging it.
    /// </summary>
    public async Task<ParsedPacket> WaitForAsync(
        Func<ParsedPacket, bool> predicate,
        int skip = 0,
        int timeoutMilliseconds = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        while (true)
        {
            if (_handlerFailure is not null)
            {
                throw new InvalidOperationException("the peer's segment handler threw", _handlerFailure);
            }

            lock (_gate)
            {
                var matches = 0;
                foreach (var packet in _received)
                {
                    if (!predicate(packet))
                    {
                        continue;
                    }

                    if (matches == skip)
                    {
                        return packet;
                    }

                    matches++;
                }
            }

            var remaining = (int)(deadline - Environment.TickCount64);
            if (remaining <= 0)
            {
                throw new TimeoutException($"the peer never saw the expected segment ({ReceivedCount} received)");
            }

            await _signal.WaitAsync(remaining).ConfigureAwait(false);
        }
    }

    /// <summary>Waits for the <paramref name="skip"/>-th payload segment.</summary>
    public Task<ParsedPacket> WaitForDataAsync(int skip = 0, int timeoutMilliseconds = 5000)
        => WaitForAsync(static packet => packet.Payload.Length > 0, skip, timeoutMilliseconds);

    /// <summary>Waits for the <paramref name="skip"/>-th payload segment carrying exactly this text.</summary>
    public Task<ParsedPacket> WaitForTextAsync(string text, int skip = 0, int timeoutMilliseconds = 5000)
        => WaitForAsync(packet => packet.Payload.Length > 0 && packet.Text == text, skip, timeoutMilliseconds);

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _lifetime.CancelAsync().ConfigureAwait(false);
        _inbox.Writer.TryComplete();

        try
        {
            await _pump.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Cancellation; the pump owns nothing that needs unwinding.
        }

        if (_host.PacketSink is not null)
        {
            _host.PacketSink = null;
        }
    }

    private async Task PumpAsync()
    {
        try
        {
            await foreach (var raw in _inbox.Reader.ReadAllAsync(_lifetime.Token).ConfigureAwait(false))
            {
                if (!TestPackets.TryParse(raw, out var segment))
                {
                    continue;
                }

                Reaction reaction;
                lock (_gate)
                {
                    _received.Add(segment);
                    reaction = segment.ChecksumValid ? Record(segment) : Reaction.None;
                    _signal.Release();
                }

                try
                {
                    if ((reaction & Reaction.SendSynAck) != 0)
                    {
                        Send(
                            ServerInitialSequence,
                            ClientNextSequence,
                            (byte)(TestPackets.FlagSyn | TestPackets.FlagAck),
                            default,
                            65535,
                            mss: 1400);
                    }

                    if ((reaction & Reaction.SendAck) != 0)
                    {
                        SendAck(ClientNextSequence);
                    }

                    if (OnSegment is not null && segment.ChecksumValid)
                    {
                        await OnSegment(segment).ConfigureAwait(false);
                    }
                }
                catch (Exception exception)
                {
                    _handlerFailure ??= exception;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Disposed.
        }
    }

    /// <summary>Updates the peer's view of the connection; called under the lock.</summary>
    private Reaction Record(ParsedPacket segment)
    {
        if (segment.Syn && !segment.Ack)
        {
            ClientInitialSequence = segment.Sequence;
            ClientNextSequence = segment.Sequence + 1;
            ClientAddress = segment.SourceAddress;
            ClientPort = segment.SourcePort;
            ServerAddress = segment.DestinationAddress;
            ServerPort = segment.DestinationPort;
            ServerNextSequence = ServerInitialSequence + 1;
            return AutoHandshake ? Reaction.SendSynAck : Reaction.None;
        }

        if (segment.Ack && !segment.Syn && !HandshakeComplete)
        {
            HandshakeComplete = true;
        }

        var reaction = Reaction.None;

        if (segment.Payload.Length > 0 && AutoAcknowledgeData && !segment.Syn)
        {
            if (segment.Sequence == ClientNextSequence)
            {
                ClientNextSequence += (uint)segment.Payload.Length;
            }

            reaction |= Reaction.SendAck;
        }

        if (segment.Fin && segment.Sequence + (uint)segment.Payload.Length == ClientNextSequence)
        {
            // The FIN consumes one sequence number, which the peer must
            // acknowledge to let the client leave FIN-WAIT-1.
            ClientNextSequence += 1;
            reaction |= Reaction.SendAck;
        }

        return reaction;
    }
}
