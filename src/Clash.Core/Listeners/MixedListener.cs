using System.Net.Sockets;
using Clash.Core.Configuration;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// The combined inbound (<c>mixed-port</c>): one port serving both HTTP proxy
/// and SOCKS5/4 clients. The first byte selects the protocol — <c>0x05</c> and
/// <c>0x04</c> are SOCKS, anything else is HTTP — and the flow is then handed to
/// the same protocol handlers the dedicated listeners use.
/// </summary>
public sealed class MixedListener : ListenerBase
{
    private const byte Socks5Version = 0x05;
    private const byte Socks4Version = 0x04;

    /// <summary>Creates the listener.</summary>
    /// <param name="config">Configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="port">Overrides <see cref="ClashConfig.MixedPort"/>; 0 binds an ephemeral port.</param>
    /// <param name="name">Configured name, for <c>listeners</c> entries.</param>
    /// <param name="bindAddress">Overrides <see cref="ClashConfig.BindAddress"/>.</param>
    public MixedListener(ClashConfig config, ILogger logger, int? port = null, string? name = null, string? bindAddress = null)
        : base("mixed", name, port ?? (config ?? throw new ArgumentNullException(nameof(config))).MixedPort, config, logger, bindAddress)
    {
    }

    /// <inheritdoc />
    protected override Task OnStartAsync(CancellationToken cancellationToken) => StartTcpListenerAsync(cancellationToken);

    /// <inheritdoc />
    protected override async Task HandleClientAsync(Socket socket, CancellationToken cancellationToken)
    {
        await using var stream = CreateInboundStream(socket);
        var first = await stream.PeekByteAsync(cancellationToken).ConfigureAwait(false);
        switch (first)
        {
            case -1:
                return;
            case Socks5Version:
            case Socks4Version:
                await SocksProxyProtocol.HandleAsync(this, stream, socket, cancellationToken).ConfigureAwait(false);
                break;
            default:
                await HttpProxyProtocol.HandleAsync(this, stream, socket, cancellationToken).ConfigureAwait(false);
                break;
        }
    }
}
