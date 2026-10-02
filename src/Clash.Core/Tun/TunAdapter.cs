using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Tun;

/// <summary>
/// A Wintun session: the layer-3 interface TUN mode reads IP packets from and
/// writes them back to.
/// <para>
/// The driver's rings are the whole interface. <see cref="Read"/> blocks until a
/// packet arrives or the timeout expires, which is why the packet pump that
/// drives this type runs on its own thread rather than through the thread pool:
/// blocking a pool thread for the lifetime of the tunnel would starve everything
/// else.
/// </para>
/// <para>
/// Buffers are owned by the driver until they are released, so every path here
/// copies out (on receive) or in (on send) before releasing or sending. Nothing
/// keeps a driver pointer past the call that produced it.
/// </para>
/// </summary>
internal sealed class TunAdapter : IDisposable
{
    private const string TunnelType = "Clash";

    private const uint WaitObject0 = 0;
    private const uint WaitTimeout = 258;

    /// <summary>How long a send retries while the ring is full before giving up.</summary>
    private const int SendRetryLimit = 200;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    private IntPtr _adapter;
    private IntPtr _session;
    private IntPtr _readEvent;
    private int _disposed;

    private TunAdapter(IntPtr adapter, IntPtr session, IntPtr readEvent, string name)
    {
        _adapter = adapter;
        _session = session;
        _readEvent = readEvent;
        Name = name;
    }

    /// <summary>The adapter's name, as it appears in the Windows interface list.</summary>
    public string Name { get; }

    /// <summary>The driver version, for diagnostics. Zero when the driver is not running.</summary>
    public static uint DriverVersion => WintunInterop.WintunGetRunningDriverVersion();

    /// <summary>
    /// Opens the adapter, creating it when it is not there yet, and starts a
    /// session on it.
    /// </summary>
    /// <param name="name">The adapter name; also seeds its stable GUID.</param>
    /// <param name="ringCapacity">Ring size in bytes, within the driver's documented bounds.</param>
    public static TunAdapter Open(string name, uint ringCapacity = WintunInterop.MinRingCapacity)
    {
        // Arguments are validated before privileges are checked: a bad ring size is
        // a bad ring size whether or not this process could have used it.
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (ringCapacity is < WintunInterop.MinRingCapacity or > WintunInterop.MaxRingCapacity)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ringCapacity),
                ringCapacity,
                $"the tun ring must be between {WintunInterop.MinRingCapacity} and {WintunInterop.MaxRingCapacity} bytes");
        }

        if (name.Length >= WintunInterop.MaxAdapterName)
        {
            throw new ArgumentException($"the adapter name must be under {WintunInterop.MaxAdapterName} characters", nameof(name));
        }

        TunElevation.Require();

        // Reusing the adapter keeps its interface index, so routes added against
        // the name keep working across restarts.
        var adapter = WintunInterop.WintunOpenAdapter(name);
        if (adapter == IntPtr.Zero) adapter = CreateAdapter(name);

        var session = WintunInterop.WintunStartSession(adapter, ringCapacity);
        if (session == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            WintunInterop.WintunCloseAdapter(adapter);
            throw new ClashException($"tun: could not start a session on adapter [{name}] (win32 error {error})");
        }

        var readEvent = WintunInterop.WintunGetReadWaitEvent(session);
        if (readEvent == IntPtr.Zero)
        {
            WintunInterop.WintunEndSession(session);
            WintunInterop.WintunCloseAdapter(adapter);
            throw new ClashException($"tun: adapter [{name}] started a session without a read event");
        }

        return new TunAdapter(adapter, session, readEvent, name);
    }

    private static IntPtr CreateAdapter(string name)
    {
        var guid = DeriveAdapterGuid(name);
        var guidBytes = guid.ToByteArray();
        var handle = GCHandle.Alloc(guidBytes, GCHandleType.Pinned);
        try
        {
            var adapter = WintunInterop.WintunCreateAdapter(name, TunnelType, handle.AddrOfPinnedObject());
            if (adapter != IntPtr.Zero) return adapter;

            var error = Marshal.GetLastWin32Error();
            if (error == WintunInterop.ErrorAccessDenied)
            {
                // The elevation probe passed but the driver still refused: report
                // the driver's answer rather than the probe's.
                throw new ClashException(TunElevation.NotElevatedMessage);
            }

            throw new ClashException($"tun: could not create adapter [{name}] (win32 error {error})");
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// A GUID derived from the adapter name, so the same name always produces the
    /// same adapter identity (and therefore the same interface index) instead of a
    /// new interface on every start.
    /// </summary>
    private static Guid DeriveAdapterGuid(string name)
    {
        var hash = SHA256.HashData(Encoding.Unicode.GetBytes("clash-tun:" + name));
        var bytes = hash[..16];

        // Stamp the RFC 4122 version and variant bits so the value is a
        // well-formed GUID rather than 16 arbitrary bytes.
        bytes[7] = (byte)((bytes[7] & 0x0F) | 0x40);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes);
    }

    /// <summary>
    /// Waits for one packet and copies it into <paramref name="destination"/>.
    /// </summary>
    /// <returns>
    /// The number of bytes written, or 0 when the timeout expired. A packet larger
    /// than the destination is truncated and reported at the destination's length;
    /// callers should size the buffer to <see cref="WintunInterop.MaxIpPacketSize"/>.
    /// </returns>
    public int Read(Span<byte> destination, int timeoutMilliseconds)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        while (true)
        {
            var packet = WintunInterop.WintunReceivePacket(_session, out var size);
            if (packet != IntPtr.Zero)
            {
                var copied = CopyOut(packet, size, destination);
                WintunInterop.WintunReleaseReceivePacket(_session, packet);
                return copied;
            }

            var error = Marshal.GetLastWin32Error();
            switch (error)
            {
                case WintunInterop.ErrorNoMoreItems:
                    // The ring is empty: the wait event fires when it is not.
                    if (WaitForSingleObject(_readEvent, (uint)timeoutMilliseconds) == WaitTimeout) return 0;
                    continue;

                case WintunInterop.ErrorHandleEof:
                    throw new ClashException("tun: the session ended (the driver was stopped)");

                default:
                    throw new ClashException($"tun: receiving a packet failed (win32 error {error})");
            }
        }
    }

    private static unsafe int CopyOut(IntPtr packet, uint size, Span<byte> destination)
    {
        var length = (int)Math.Min(size, (uint)destination.Length);
        new ReadOnlySpan<byte>((void*)packet, length).CopyTo(destination);
        return length;
    }

    /// <summary>
    /// Hands one IP packet to the driver. Blocks briefly while the send ring is
    /// full, which is backpressure from the host stack rather than an error.
    /// </summary>
    public void Write(ReadOnlySpan<byte> packet)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (packet.IsEmpty) return;

        for (var attempt = 0; ; attempt++)
        {
            var destination = WintunInterop.WintunAllocateSendPacket(_session, (uint)packet.Length);
            if (destination != IntPtr.Zero)
            {
                CopyIn(packet, destination);
                WintunInterop.WintunSendPacket(_session, destination);
                return;
            }

            var error = Marshal.GetLastWin32Error();
            if (error == WintunInterop.ErrorBufferOverflow)
            {
                throw new ClashException($"tun: a {packet.Length}-byte packet does not fit the ring");
            }

            if (error == WintunInterop.ErrorHandleEof)
            {
                throw new ClashException("tun: the session ended (the driver was stopped)");
            }

            if (attempt >= SendRetryLimit)
            {
                throw new ClashException($"tun: the send ring stayed full for {SendRetryLimit} attempts");
            }

            Thread.Sleep(1);
        }
    }

    private static unsafe void CopyIn(ReadOnlySpan<byte> packet, IntPtr destination)
        => packet.CopyTo(new Span<byte>((void*)destination, packet.Length));

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        if (_session != IntPtr.Zero)
        {
            WintunInterop.WintunEndSession(_session);
            _session = IntPtr.Zero;
        }

        if (_adapter != IntPtr.Zero)
        {
            // The driver's own rule: closing a handle releases the resources and
            // removes the adapter if it was created here, while an adapter that was
            // merely opened survives. So one call is correct for both paths, and
            // there is nothing for this type to decide.
            WintunInterop.WintunCloseAdapter(_adapter);
            _adapter = IntPtr.Zero;
        }

        _readEvent = IntPtr.Zero;
    }
}
