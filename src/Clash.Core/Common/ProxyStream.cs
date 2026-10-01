using System.Net;

namespace Clash.Core.Common;

/// <summary>
/// A stream whose send direction can be closed independently of its receive
/// direction. TCP relays need this: when the client finishes sending it must
/// signal EOF to the outbound without tearing down the response path.
/// </summary>
public interface IHalfCloseable
{
    /// <summary>Signals end-of-stream to the peer while leaving reads working.</summary>
    void ShutdownSend();
}

/// <summary>
/// A fully delegating <see cref="Stream"/> wrapper that carries the endpoints of
/// the underlying transport. Adapters return one of these so the tunnel can
/// report <c>remoteDestination</c> without knowing which protocol produced it.
/// </summary>
public class ProxyStream : Stream
{
    private readonly Stream _inner;
    private readonly IDisposable? _owner;

    public ProxyStream(Stream inner, EndPoint? localEndPoint = null, EndPoint? remoteEndPoint = null, IDisposable? owner = null)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        LocalEndPoint = localEndPoint;
        RemoteEndPoint = remoteEndPoint;
        _owner = owner;
    }

    /// <summary>The wrapped transport.</summary>
    public Stream Inner => _inner;

    public EndPoint? LocalEndPoint { get; }

    public EndPoint? RemoteEndPoint { get; }

    /// <summary>
    /// Half-closes the send direction, unwrapping any nested
    /// <see cref="ProxyStream"/> layers to reach the transport. A no-op when no
    /// layer supports it, in which case the caller relies on the drain timeout.
    /// </summary>
    public void ShutdownSend()
    {
        switch (_inner)
        {
            case IHalfCloseable halfCloseable:
                try { halfCloseable.ShutdownSend(); } catch { /* peer already gone */ }
                break;
            case ProxyStream nested:
                nested.ShutdownSend();
                break;
        }
    }

    /// <summary>True when some layer in this stack can half-close.</summary>
    public bool SupportsHalfClose => _inner switch
    {
        IHalfCloseable => true,
        ProxyStream nested => nested.SupportsHalfClose,
        _ => false,
    };

    /// <summary>Human readable <c>ip:port</c> of the remote peer, or null when unknown.</summary>
    public string? RemoteAddressString => RemoteEndPoint switch
    {
        IPEndPoint ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{ip.Address}]:{ip.Port}"
            : $"{ip.Address}:{ip.Port}",
        null => null,
        var e => e.ToString(),
    };

    /// <summary>Wraps a stream that already reports its own endpoints.</summary>
    public static ProxyStream Wrap(Stream stream, IDisposable? owner = null) => new(stream, null, null, owner);

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanWrite => _inner.CanWrite;
    public override long Length => _inner.Length;

    public override long Position
    {
        get => _inner.Position;
        set => _inner.Position = value;
    }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override int Read(Span<byte> buffer) => _inner.Read(buffer);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.ReadAsync(buffer, cancellationToken);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.ReadAsync(buffer, offset, count, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
    public override void SetLength(long value) => _inner.SetLength(value);
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
    public override void Write(ReadOnlySpan<byte> buffer) => _inner.Write(buffer);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _inner.WriteAsync(buffer, cancellationToken);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _inner.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try { _inner.Dispose(); } catch { /* transport already gone */ }
            try { _owner?.Dispose(); } catch { /* ignore */ }
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        try { await _inner.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
        if (_owner is not null)
        {
            try { _owner.Dispose(); } catch { /* ignore */ }
        }
        GC.SuppressFinalize(this);
    }
}
