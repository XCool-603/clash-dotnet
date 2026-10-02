using System.Net;
using Clash.Core.Common;

namespace Clash.Core.Netstack;

/// <summary>
/// A <see cref="Stream"/> over one <see cref="TcpConnection"/>, so the tunnel can
/// relay a userspace TCP flow exactly like any other outbound.
/// <para>
/// Why it is a real stream rather than an <c>IPacketConnection</c>: the tunnel
/// relays with <see cref="Stream"/> pumps and relies on half-close to let a
/// response drain after the request is finished. This type implements
/// <see cref="IHalfCloseable"/> so <c>ShutdownSend</c> becomes a FIN instead of a
/// teardown, and it is disposable without blocking: <see cref="Dispose"/> sends
/// the FIN and returns, leaving the connection to finish closing in the
/// background under <see cref="NetstackOptions.CloseTimeout"/>.
/// </para>
/// <para>
/// Out of scope, as in <see cref="TcpConnection"/>: seeking, length, timeouts,
/// and any buffering beyond the connection's receive window.
/// </para>
/// </summary>
public sealed class TcpFlowStream : Stream, IHalfCloseable
{
    private readonly TcpConnection _connection;
    private int _disposed;

    internal TcpFlowStream(TcpConnection connection) => _connection = connection;

    /// <summary>The peer this flow is connected to.</summary>
    public IPEndPoint RemoteEndPoint => _connection.RemoteEndPoint;

    /// <summary>The ephemeral local port of this flow.</summary>
    public int LocalPort => _connection.LocalPort;

    /// <inheritdoc />
    public override bool CanRead => Volatile.Read(ref _disposed) == 0;

    /// <inheritdoc />
    public override bool CanWrite => Volatile.Read(ref _disposed) == 0 && !_connection.SendClosed;

    /// <inheritdoc />
    public override bool CanSeek => false;

    /// <inheritdoc />
    public override long Length => throw new NotSupportedException();

    /// <inheritdoc />
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <inheritdoc />
    public void ShutdownSend()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _connection.ShutdownSend();
    }

    /// <inheritdoc />
    public override int Read(byte[] buffer, int offset, int count)
    {
        ValidateRange(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public override int Read(Span<byte> buffer)
        => ReadAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _connection.ReadAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateRange(buffer, offset, count);
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override void Write(byte[] buffer, int offset, int count)
    {
        ValidateRange(buffer, offset, count);
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray()).AsTask().GetAwaiter().GetResult();

    /// <inheritdoc />
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        return _connection.WriteAsync(buffer, cancellationToken);
    }

    /// <inheritdoc />
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        ValidateRange(buffer, offset, count);
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public override void Flush()
    {
        // Every write is emitted immediately; there is nothing buffered here.
    }

    /// <inheritdoc />
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <inheritdoc />
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    /// <inheritdoc />
    public override void SetLength(long value) => throw new NotSupportedException();

    /// <summary>
    /// Closes the flow gracefully: a FIN is sent when the connection is still
    /// open, and the peer's remaining data is discarded. The connection finishes
    /// closing in the background.
    /// </summary>
    /// <param name="disposing">True when called from user code.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _connection.Close();
        }

        base.Dispose(disposing);
    }

    /// <inheritdoc />
    public override ValueTask DisposeAsync()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    private static void ValidateRange(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (buffer.Length - offset < count)
        {
            throw new ArgumentException("offset and count exceed the buffer length");
        }
    }
}
