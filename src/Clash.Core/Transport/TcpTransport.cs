using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Configuration;

namespace Clash.Core.Transport;

/// <summary>
/// The base layer. It never wraps anything: it either hands back the stream the
/// caller already has, dials through a <c>dialer-proxy</c>, or opens the TCP
/// connection itself.
/// <para>
/// Resolution prefers the tunnel's DNS resolver (so hosts overrides, fake-IP
/// reversal and nameserver policy all apply) and falls back to the system
/// resolver. Every resolved address is tried concurrently with a short head
/// start for the first one, which gives happy-eyeballs behaviour without pinning
/// the family: whichever address answers first wins and the rest are cancelled.
/// </para>
/// </summary>
public sealed class TcpTransport : ITransportLayer
{
    /// <summary>How long the first resolved address is given before the others race it.</summary>
    public const int FirstAddressHeadStartMs = 250;

    public string Name => "tcp";

    public async Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Already connected: chained dials and relay groups hand the stream in.
        if (context.Upstream is not null) return context.Upstream;
        if (inner is not null) return inner;

        if (!string.IsNullOrEmpty(context.DialerProxy) && context.Tunnel is not null)
        {
            return await DialThroughProxyAsync(context, cancellationToken).ConfigureAwait(false);
        }

        var client = await ConnectAsync(context, cancellationToken).ConfigureAwait(false);
        Configure(client, context.Tunnel?.Config);
        return new ProxyStream(client.GetStream(), client.Client.LocalEndPoint, client.Client.RemoteEndPoint, owner: client);
    }

    /// <summary>
    /// Routes the dial through the tunnel with the <c>dialer-proxy</c> pinned as
    /// the special proxy, which is how Clash expresses "connect to this server
    /// through that other outbound".
    /// </summary>
    private static Task<ProxyStream> DialThroughProxyAsync(DialContext context, CancellationToken cancellationToken)
    {
        var metadata = context.Metadata.Clone();
        metadata.Network = Network.Tcp;
        metadata.DestinationAddress = context.Host;
        metadata.DestinationPort = (ushort)context.Port;
        metadata.SpecialProxy = context.DialerProxy;
        return context.Tunnel!.DialTcpAsync(metadata, cancellationToken);
    }

    /// <summary>Resolves the target and connects to the first address that answers.</summary>
    public static async Task<TcpClient> ConnectAsync(DialContext context, CancellationToken cancellationToken)
    {
        var addresses = await ResolveAsync(context, cancellationToken).ConfigureAwait(false);
        if (addresses.Length == 0) throw new ClashException($"tcp: could not resolve {context.Host}");

        return await ConnectAnyAsync(addresses, context.Port, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Resolves <see cref="DialContext.Host"/>, honouring the configured IPv6 preference.</summary>
    public static async ValueTask<IPAddress[]> ResolveAsync(DialContext context, CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(context.Host, out var literal)) return [literal];

        var ipv6 = context.Tunnel?.Config.Ipv6 ?? true;

        if (context.Tunnel is not null)
        {
            try
            {
                var resolved = await context.Tunnel.Dns.ResolveAsync(context.Host, ipv6, cancellationToken).ConfigureAwait(false);
                if (resolved.Length > 0) return resolved;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Fall through to the system resolver; the tunnel's DNS is advisory here.
            }
        }

        try
        {
            var system = await Dns.GetHostAddressesAsync(context.Host, cancellationToken).ConfigureAwait(false);
            return ipv6 ? system : [.. system.Where(a => a.AddressFamily == AddressFamily.InterNetwork)];
        }
        catch (SocketException ex)
        {
            throw new ClashException($"tcp: could not resolve {context.Host}", ex);
        }
    }

    /// <summary>
    /// Races every address. The first one gets a head start so a healthy IPv6
    /// path is preferred, then the rest are started and the first success wins.
    /// </summary>
    public static async Task<TcpClient> ConnectAnyAsync(IReadOnlyList<IPAddress> addresses, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        if (addresses.Count == 0) throw new ArgumentException("at least one address is required", nameof(addresses));

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var attempts = new List<Task<TcpClient>>(addresses.Count);
        Exception? lastError = null;

        try
        {
            for (var i = 0; i < addresses.Count; i++)
            {
                attempts.Add(ConnectOneAsync(addresses[i], port, linked.Token));

                if (i == 0 && addresses.Count > 1)
                {
                    var first = attempts[0];
                    var raced = await Task.WhenAny(first, Task.Delay(FirstAddressHeadStartMs, cancellationToken)).ConfigureAwait(false);
                    if (raced == first && first.IsCompletedSuccessfully)
                    {
                        var winner = await first.ConfigureAwait(false);
                        attempts.RemoveAt(0);
                        return winner;
                    }
                }
            }

            while (attempts.Count > 0)
            {
                var finished = await Task.WhenAny(attempts).ConfigureAwait(false);
                attempts.Remove(finished);
                try
                {
                    return await finished.ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    lastError = ex;
                }
            }

            cancellationToken.ThrowIfCancellationRequested();
            throw new ClashException("tcp: no resolved address accepted the connection", lastError!);
        }
        finally
        {
            linked.Cancel();
            foreach (var attempt in attempts) Discard(attempt);
        }
    }

    /// <summary>Applies <c>NoDelay</c> and the configured keep-alive timers.</summary>
    public static void Configure(TcpClient client, ClashConfig? config)
    {
        ArgumentNullException.ThrowIfNull(client);

        try
        {
            client.NoDelay = true;
        }
        catch (SocketException)
        {
            // The socket is already gone; the connect result will surface it.
        }

        var socket = client.Client;
        if (socket is null || config?.DisableKeepAlive == true) return;

        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        }
        catch (SocketException)
        {
            return;
        }

        TrySetKeepAlive(socket, config?.KeepAliveIdle ?? 15, config?.KeepAliveInterval ?? 30);
    }

    private static void TrySetKeepAlive(Socket socket, int idleSeconds, int intervalSeconds)
    {
        try
        {
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, Math.Max(1, idleSeconds));
        }
        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException or ArgumentException)
        {
        }

        try
        {
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, Math.Max(1, intervalSeconds));
        }
        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException or ArgumentException)
        {
        }

        try
        {
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
        }
        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException or ArgumentException)
        {
        }
    }

    private static async Task<TcpClient> ConnectOneAsync(IPAddress address, int port, CancellationToken cancellationToken)
    {
        var client = new TcpClient(address.AddressFamily);
        try
        {
            await client.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static void Discard(Task<TcpClient> attempt)
    {
        _ = attempt.ContinueWith(
            static t =>
            {
                if (t.Status == TaskStatus.RanToCompletion) t.Result.Dispose();
                else _ = t.Exception;
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}
