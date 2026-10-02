using System.Runtime.InteropServices;

namespace Clash.Core.Tun;

/// <summary>
/// The P/Invoke surface of the Wintun driver.
/// <para>
/// Wintun is the layer-3 TUN driver TUN mode runs on. Only the entry points
/// declared in the vendor's <c>wintun.h</c> are used, which is the condition its
/// prebuilt-binaries licence attaches to redistribution — see
/// <c>third_party/wintun/README.md</c>. Nothing here wraps a private structure:
/// the adapter and session are opaque handles, and packets are plain byte
/// buffers the caller owns until it releases them.
/// </para>
/// <para>
/// Wintun signals the interesting conditions through <c>GetLastError</c> rather
/// than return values, so the constants below are part of the API contract, not
/// implementation detail.
/// </para>
/// </summary>
internal static class WintunInterop
{
    /// <summary>Shipped next to the executable; see third_party/wintun.</summary>
    public const string Library = "wintun.dll";

    // ── GetLastError values the driver actually returns ──────────────────────

    /// <summary>The receive ring is momentarily empty: retry after the wait event.</summary>
    public const int ErrorNoMoreItems = 259;

    /// <summary>The session has ended (the driver was stopped or the ring closed).</summary>
    public const int ErrorHandleEof = 38;

    /// <summary>The packet does not fit the ring.</summary>
    public const int ErrorBufferOverflow = 111;

    /// <summary>Adapter creation was refused — almost always because the process is not elevated.</summary>
    public const int ErrorAccessDenied = 5;

    /// <summary>No adapter with that name exists (from <c>WintunOpenAdapter</c>).</summary>
    public const int ErrorFileNotFound = 2;

    /// <summary>An adapter with that name is already present.</summary>
    public const int ErrorAlreadyExists = 183;

    // ── Ring capacity bounds, from wintun.h ─────────────────────────────────

    public const uint MinRingCapacity = 0x20000;   // 128 KiB
    public const uint MaxRingCapacity = 0x4000000; // 64 MiB

    /// <summary>The largest IP packet Wintun will carry (the IPv4 total-length field).</summary>
    public const int MaxIpPacketSize = 0xFFFF;

    /// <summary>Adapter names are limited to 128 characters including the terminator.</summary>
    public const int MaxAdapterName = 128;

    [DllImport(Library, SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern IntPtr WintunCreateAdapter(string name, string tunnelType, IntPtr requestedGuid);

    [DllImport(Library, SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern IntPtr WintunOpenAdapter(string name);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern void WintunCloseAdapter(IntPtr adapter);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WintunDeleteDriver();

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern void WintunGetAdapterLuid(IntPtr adapter, out ulong luid);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern uint WintunGetRunningDriverVersion();

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern void WintunEndSession(IntPtr session);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr WintunGetReadWaitEvent(IntPtr session);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr WintunReceivePacket(IntPtr session, out uint packetSize);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

    [DllImport(Library, SetLastError = true, ExactSpelling = true)]
    public static extern void WintunSendPacket(IntPtr session, IntPtr packet);
}
