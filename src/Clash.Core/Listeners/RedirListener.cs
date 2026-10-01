using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// The transparent-proxy inbound for Linux and macOS (<c>redir-port</c>).
/// Connections are accepted as if the listener were the origin server, so the
/// original destination is recovered from the socket with
/// <c>SO_ORIGINAL_DST</c> / <c>IP6T_SO_ORIGINAL_DST</c>.
/// </summary>
public sealed class RedirListener : ListenerBase
{
    /// <summary>Creates the listener.</summary>
    /// <param name="config">Configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="port">Overrides <see cref="ClashConfig.RedirPort"/>; 0 binds an ephemeral port.</param>
    /// <param name="name">Configured name, for <c>listeners</c> entries.</param>
    /// <param name="bindAddress">Overrides <see cref="ClashConfig.BindAddress"/>.</param>
    public RedirListener(ClashConfig config, ILogger logger, int? port = null, string? name = null, string? bindAddress = null)
        : base("redir", name, port ?? (config ?? throw new ArgumentNullException(nameof(config))).RedirPort, config, logger, bindAddress)
    {
    }

    /// <inheritdoc />
    protected override Task OnStartAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException(
                "the redir inbound needs SO_ORIGINAL_DST, which only Linux and macOS provide; " +
                "use a tun inbound or the mixed port on Windows");
        }

        return StartTcpListenerAsync(cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task HandleClientAsync(Socket socket, CancellationToken cancellationToken)
    {
        var destination = OriginalDestination.TryGet(socket)
            ?? throw new ClashException("redir: SO_ORIGINAL_DST did not return a usable destination");

        var metadata = CreateMetadata(socket.RemoteEndPoint, destination.Address, destination.Port, Network.Tcp);
        await using var stream = CreateInboundStream(socket);
        await RequireTunnel().HandleTcpAsync(stream, metadata, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Reads the pre-redirect destination of an accepted socket. Linux answers
/// <c>SO_ORIGINAL_DST</c> (level <c>SOL_IP</c>, option 80) and
/// <c>IP6T_SO_ORIGINAL_DST</c> (level <c>SOL_IPV6</c>, option 80); Darwin uses
/// the same idea with a different option number.
/// </summary>
internal static class OriginalDestination
{
    private const int SolIp = 0;
    private const int SolIpv6 = 41;
    private const int SoOriginalDstLinux = 80;
    private const int SoOriginalDstDarwin = 0x400;
    private const int AddressFamilyInet = 2;
    private const int AddressFamilyInet6Linux = 10;
    private const int AddressFamilyInet6Darwin = 30;

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(int socket, int level, int optionName, byte[] optionValue, ref int optionLength);

    /// <summary>Returns the original destination of an accepted socket, when the platform exposes one.</summary>
    public static (string Address, ushort Port)? TryGet(Socket socket)
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
        {
            return null;
        }

        int descriptor;
        try
        {
            descriptor = checked((int)socket.Handle.ToInt64());
        }
        catch (OverflowException)
        {
            return null;
        }

        var optionName = OperatingSystem.IsMacOS() ? SoOriginalDstDarwin : SoOriginalDstLinux;
        var buffer = new byte[128];

        if (TryQuery(descriptor, SolIp, optionName, buffer, out var length)
            && TryParse(buffer.AsSpan(0, length), out var ipv4))
        {
            return ipv4;
        }

        if (TryQuery(descriptor, SolIpv6, optionName, buffer, out length)
            && TryParse(buffer.AsSpan(0, length), out var ipv6))
        {
            return ipv6;
        }

        return null;
    }

    private static bool TryQuery(int descriptor, int level, int optionName, byte[] buffer, out int length)
    {
        length = buffer.Length;
        try
        {
            return getsockopt(descriptor, level, optionName, buffer, ref length) == 0;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    private static bool TryParse(ReadOnlySpan<byte> data, out (string Address, ushort Port) result)
    {
        result = default;
        if (data.Length < 8)
        {
            return false;
        }

        var family = BitConverter.ToUInt16(data[..2]);
        var port = (ushort)((data[2] << 8) | data[3]);
        if (family == AddressFamilyInet)
        {
            result = (new IPAddress(data.Slice(4, 4)).ToString(), port);
            return true;
        }

        if (family is AddressFamilyInet6Linux or AddressFamilyInet6Darwin && data.Length >= 24)
        {
            result = (new IPAddress(data.Slice(8, 16)).ToString(), port);
            return true;
        }

        return false;
    }
}
