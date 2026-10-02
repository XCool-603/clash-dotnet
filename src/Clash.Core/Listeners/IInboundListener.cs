using Clash.Core.Common;
using Clash.Core.Tunnel;

namespace Clash.Core.Listeners;

/// <summary>
/// An inbound server: HTTP proxy, SOCKS5, mixed, redir, tproxy, TUN or the DNS
/// listener. Listeners only decode the client protocol and hand a stream (or a
/// packet association) plus a populated <see cref="Metadata"/> to the tunnel.
/// </summary>
public interface IInboundListener : IAsyncDisposable
{
    /// <summary><c>http</c>, <c>socks</c>, <c>mixed</c>, <c>redir</c>, <c>tproxy</c>, <c>tun</c>, <c>dns</c>.</summary>
    string Type { get; }

    /// <summary>Configured name, for <c>listeners</c> entries and the API.</summary>
    string? Name { get; }

    /// <summary>Bound address, available after <see cref="StartAsync"/>.</summary>
    string? Address { get; }

    int Port { get; }

    /// <summary>Number of clients currently being served.</summary>
    int ActiveConnections { get; }

    Task StartAsync(ITunnel tunnel, CancellationToken cancellationToken = default);

    Task StopAsync();
}

/// <summary>Raised when an inbound cannot bind, e.g. the port is taken.</summary>
public sealed class ListenerBindException(string type, string address, Exception inner)
    : ClashException($"listener [{type}] failed to bind {address}", inner);

/// <summary>Raised when inbound authentication fails.</summary>
public sealed class AuthenticationException(string message)
    : ClashException(message)
{
    /// <summary>The refusal of the credentials a client presented.</summary>
    public static AuthenticationException ForUser(string user)
        => new($"authentication failed for [{user}]");

    /// <summary>
    /// True when the listener already reported the failure at the point of
    /// refusal, so the generic per-connection error hook must not log it again.
    /// </summary>
    public bool Reported { get; set; }
}
