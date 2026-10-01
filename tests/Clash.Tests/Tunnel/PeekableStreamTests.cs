using Clash.Core.Tunnel;
using Xunit;

namespace Clash.Tests.Tunnel;

public class PeekableStreamTests
{
    private sealed class ScriptedStream(byte[] data) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => data.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var available = Math.Min(count, data.Length - _position);
            if (available <= 0) return 0;
            Array.Copy(data, _position, buffer, offset, available);
            _position += available;
            return available;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var available = Math.Min(buffer.Length, data.Length - _position);
            if (available <= 0) return ValueTask.FromResult(0);
            data.AsSpan(_position, available).CopyTo(buffer.Span);
            _position += available;
            return ValueTask.FromResult(available);
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) { }
    }

    [Fact]
    public async Task PeekDoesNotConsumeBytes()
    {
        var payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody"u8.ToArray();
        var stream = new PeekableStream(new ScriptedStream(payload));

        var buffered = await stream.PeekAsync(payload.Length, TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.Equal(payload.Length, buffered);
        Assert.Equal(payload, stream.Peeked.ToArray());

        // The full payload must still be readable afterwards, exactly once.
        var read = new byte[payload.Length];
        var total = 0;
        while (total < payload.Length)
        {
            var n = await stream.ReadAsync(read.AsMemory(total));
            if (n <= 0) break;
            total += n;
        }

        Assert.Equal(payload.Length, total);
        Assert.Equal(payload, read);
    }

    [Fact]
    public async Task PeekReturnsEarlyOnEndOfStream()
    {
        var payload = "short"u8.ToArray();
        var stream = new PeekableStream(new ScriptedStream(payload));

        var buffered = await stream.PeekAsync(4096, TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.Equal(payload.Length, buffered);
        Assert.Equal(payload, stream.Peeked.ToArray());
    }

    [Fact]
    public async Task PeekTimesOutWithoutFailing()
    {
        var stream = new PeekableStream(new ScriptedStream("abc"u8.ToArray()));

        var started = DateTime.UtcNow;
        var buffered = await stream.PeekAsync(4096, TimeSpan.FromMilliseconds(120), CancellationToken.None);
        var elapsed = DateTime.UtcNow - started;

        Assert.Equal(3, buffered);
        Assert.True(elapsed >= TimeSpan.FromMilliseconds(80), $"peek returned too early: {elapsed}");
        Assert.True(elapsed < TimeSpan.FromSeconds(3), $"peek did not respect the timeout: {elapsed}");
    }

    [Fact]
    public async Task PeekGrowsBeyondTheInitialCapacity()
    {
        var payload = new byte[20_000];
        Random.Shared.NextBytes(payload);
        var stream = new PeekableStream(new ScriptedStream(payload), capacity: 512);

        var buffered = await stream.PeekAsync(20_000, TimeSpan.FromSeconds(2), CancellationToken.None);

        Assert.Equal(payload.Length, buffered);
        Assert.Equal(payload, stream.Peeked.ToArray());
    }

    [Fact]
    public async Task ReadsSpanTheBufferAndTheUnderlyingStream()
    {
        var payload = Enumerable.Range(0, 5000).Select(i => (byte)(i % 251)).ToArray();
        var stream = new PeekableStream(new ScriptedStream(payload), capacity: 1024);

        await stream.PeekAsync(600, TimeSpan.FromSeconds(1), CancellationToken.None);

        var read = new byte[payload.Length];
        var total = 0;
        while (total < payload.Length)
        {
            var n = await stream.ReadAsync(read.AsMemory(total));
            if (n <= 0) break;
            total += n;
        }

        Assert.Equal(payload.Length, total);
        Assert.Equal(payload, read);
    }

    [Fact]
    public async Task PeekedIsEmptyBeforeAnyPeek()
    {
        var stream = new PeekableStream(new ScriptedStream("x"u8.ToArray()));
        Assert.Equal(0, stream.BufferedCount);
        Assert.True(stream.Peeked.IsEmpty);
        await Task.CompletedTask;
    }
}
