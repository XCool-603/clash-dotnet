using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// Shared plumbing for every inbound that accepts TCP clients: the accept loop,
/// per-connection task tracking (so <see cref="StopAsync"/> can drain), the
/// active connection counter, error reporting through <see cref="ITunnel.Log"/>
/// and graceful shutdown on the startup token.
/// </summary>
public abstract class ListenerBase : IInboundListener
{
    private const int Backlog = 512;
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    private readonly List<Task> _pending = [];
    private readonly Lock _pendingGate = new();
    private readonly ILogger _logger;
    private readonly int _configuredPort;
    private readonly string? _bindAddressOverride;

    private Socket? _listenSocket;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private IPAddress? _boundAddress;
    private int _boundPort;
    private int _active;
    private int _started;
    private int _disposed;

    /// <summary>Creates the shared listener state.</summary>
    /// <param name="type">Listener kind: <c>http</c>, <c>socks</c>, <c>mixed</c>, <c>redir</c>, <c>tproxy</c>.</param>
    /// <param name="name">Configured name, when the listener came from a <c>listeners</c> entry.</param>
    /// <param name="port">Port to bind; 0 asks the OS for an ephemeral port.</param>
    /// <param name="config">The configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="bindAddress">Per-listener override of <see cref="ClashConfig.BindAddress"/>.</param>
    protected ListenerBase(string type, string? name, int port, ClashConfig config, ILogger logger, string? bindAddress = null)
    {
        Type = type;
        Name = name;
        _configuredPort = port;
        _bindAddressOverride = bindAddress;
        Config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public string Type { get; }

    /// <inheritdoc />
    public string? Name { get; }

    /// <inheritdoc />
    public string? Address => _boundAddress is null ? null : FormatEndpoint(_boundAddress, Port);

    /// <summary>
    /// The port clients reach this listener on. Before <see cref="StartAsync"/>
    /// this is the configured port; afterwards it is the port actually bound, so
    /// a configured port of 0 reports the ephemeral port the OS picked.
    /// </summary>
    public int Port => _boundPort != 0 ? _boundPort : _configuredPort;

    /// <summary>The port from the configuration, before any ephemeral bind.</summary>
    public int ConfiguredPort => _configuredPort;

    /// <inheritdoc />
    public int ActiveConnections => Volatile.Read(ref _active);

    /// <summary>The configuration this listener was built from.</summary>
    public ClashConfig Config { get; }

    /// <summary>The tunnel flows are handed to; null until <see cref="StartAsync"/> ran.</summary>
    internal ITunnel? Tunnel { get; private set; }

    /// <summary>The diagnostics sink shared with <see cref="ListenerManager"/>.</summary>
    protected ILogger Logger => _logger;

    /// <inheritdoc />
    public virtual async Task StartAsync(ITunnel tunnel, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(tunnel);
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            throw new InvalidOperationException($"listener [{Type}] is already started");
        }

        Tunnel = tunnel;
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _cts = cts;
        try
        {
            await OnStartAsync(cts.Token).ConfigureAwait(false);
        }
        catch
        {
            Interlocked.Exchange(ref _started, 0);
            _cts = null;
            cts.Dispose();
            throw;
        }
    }

    /// <inheritdoc />
    public virtual async Task StopAsync()
    {
        var cts = Interlocked.Exchange(ref _cts, null);
        var listener = Interlocked.Exchange(ref _listenSocket, null);
        var acceptLoop = _acceptLoop;
        _acceptLoop = null;
        Interlocked.Exchange(ref _started, 0);

        try
        {
            cts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already torn down.
        }

        try
        {
            listener?.Dispose();
        }
        catch (SocketException)
        {
            // Socket already closed.
        }

        if (acceptLoop is not null)
        {
            try
            {
                await acceptLoop.ConfigureAwait(false);
            }
            catch
            {
                // The accept loop reports its own failures.
            }
        }

        Task[] pending;
        lock (_pendingGate)
        {
            pending = [.. _pending];
            _pending.Clear();
        }

        if (pending.Length > 0)
        {
            try
            {
                await Task.WhenAll(pending).WaitAsync(DrainTimeout).ConfigureAwait(false);
            }
            catch
            {
                // Either the drain timed out or a connection faulted; both are already logged.
            }
        }

        await OnStoppedAsync().ConfigureAwait(false);
        cts?.Dispose();
        _boundPort = 0;
        _boundAddress = null;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
    }

    /// <summary>Starts the listener's transport. Called once per successful <see cref="StartAsync"/>.</summary>
    protected abstract Task OnStartAsync(CancellationToken cancellationToken);

    /// <summary>Serves one accepted client until it disconnects or the token fires.</summary>
    protected abstract Task HandleClientAsync(Socket socket, CancellationToken cancellationToken);

    /// <summary>Releases transport owned outside the accept loop (UDP sockets, monitors).</summary>
    protected virtual ValueTask OnStoppedAsync() => ValueTask.CompletedTask;

    /// <summary>Resolves the effective bind address for this listener.</summary>
    protected IPAddress ResolveBindAddress()
        => ResolveBindAddress(_bindAddressOverride ?? Config.BindAddress, Config.AllowLan, Config.Ipv6);

    /// <summary>
    /// Resolves a configured <c>bind-address</c> value to an address.
    /// <c>*</c> (or an empty value) means "every interface" when
    /// <paramref name="allowLan"/> is set and loopback otherwise; <c>::</c> and
    /// <c>0.0.0.0</c> are honoured literally, as is any explicit literal.
    /// </summary>
    /// <param name="bindAddress">Value of the <c>bind-address</c> key.</param>
    /// <param name="allowLan">Value of the <c>allow-lan</c> key.</param>
    /// <param name="ipv6">Value of the <c>ipv6</c> key, used to pick the wildcard family.</param>
    /// <exception cref="ClashException">The value is neither a wildcard nor a parseable address.</exception>
    public static IPAddress ResolveBindAddress(string? bindAddress, bool allowLan, bool ipv6 = false)
    {
        var value = bindAddress?.Trim();
        if (string.IsNullOrEmpty(value) || value == "*")
        {
            if (!allowLan)
            {
                return ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            }

            return ipv6 ? IPAddress.IPv6Any : IPAddress.Any;
        }

        if (value == "0.0.0.0")
        {
            return IPAddress.Any;
        }

        if (value == "::")
        {
            return IPAddress.IPv6Any;
        }

        if (value.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        }

        if (IPAddress.TryParse(value, out var parsed))
        {
            return parsed;
        }

        try
        {
            // Fully qualified: Clash.Core.Dns shadows System.Net.Dns inside this namespace.
            var resolved = System.Net.Dns.GetHostAddresses(value);
            var preferred = ipv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
            var fallback = ipv6 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
            var pick = Array.Find(resolved, a => a.AddressFamily == preferred)
                       ?? Array.Find(resolved, a => a.AddressFamily == fallback);
            if (pick is not null)
            {
                return pick;
            }
        }
        catch (SocketException ex)
        {
            throw new ClashException($"bind-address [{value}] could not be resolved", ex);
        }

        throw new ClashException($"bind-address [{value}] could not be resolved");
    }

    /// <summary>
    /// Binds and starts the TCP accept loop on <see cref="ResolveBindAddress"/>.
    /// Bind failures surface as <see cref="ListenerBindException"/>.
    /// </summary>
    protected Task StartTcpListenerAsync(CancellationToken cancellationToken)
    {
        var address = ResolveBindAddress();
        Socket socket;
        try
        {
            socket = CreateListenSocket(address, _configuredPort);
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException or InvalidOperationException)
        {
            throw new ListenerBindException(Type, FormatEndpoint(address, _configuredPort), ex);
        }

        var local = socket.LocalEndPoint as IPEndPoint;
        _boundAddress = local?.Address ?? address;
        _boundPort = local?.Port ?? _configuredPort;
        _listenSocket = socket;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(socket, cancellationToken), CancellationToken.None);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Creates, binds and starts listening on the socket the accept loop reads
    /// from. Overridden by TProxy, which must set <c>IP_TRANSPARENT</c> before
    /// the bind.
    /// </summary>
    /// <param name="address">Address resolved from <c>bind-address</c>.</param>
    /// <param name="port">Port to bind, possibly 0 for an ephemeral one.</param>
    protected virtual Socket CreateListenSocket(IPAddress address, int port)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            socket.Bind(new IPEndPoint(address, port));
            socket.Listen(Backlog);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        return socket;
    }

    /// <summary>Wraps the accepted socket in the buffered stream protocol handlers parse from.</summary>
    private protected static InboundStream CreateInboundStream(Socket socket) => InboundStream.ForSocket(socket);

    /// <summary>Returns the tunnel, or throws when the listener was never started.</summary>
    internal ITunnel RequireTunnel()
        => Tunnel ?? throw new InvalidOperationException($"listener [{Type}] is not started");

    /// <summary>Reports a per-connection failure to the log stream and the diagnostics sink.</summary>
    internal void ReportError(Exception exception)
    {
        var level = exception is AuthenticationException ? "warning" : "error";
        var message = $"[{Type}] {exception.Message}";
        try
        {
            Tunnel?.Log(level, message);
        }
        catch
        {
            // A misbehaving log subscriber must never take the listener down.
        }

        if (exception is AuthenticationException)
        {
            _logger.LogWarning("{Message}", message);
        }
        else
        {
            _logger.LogError(exception, "{Message}", message);
        }
    }

    /// <summary>Builds the metadata a listener hands to the tunnel.</summary>
    internal Metadata CreateMetadata(EndPoint? remote, string destinationAddress, ushort destinationPort, Network network)
    {
        var metadata = new Metadata
        {
            Network = network,
            DestinationAddress = destinationAddress,
            DestinationPort = destinationPort,
            InboundType = Type,
            InboundName = Name,
            InboundPort = (ushort)Math.Clamp(Port, 0, ushort.MaxValue),
        };

        if (remote is IPEndPoint ip)
        {
            metadata.SourceAddress = ip.Address.ToString();
            metadata.SourcePort = (ushort)ip.Port;
        }
        else if (remote is not null)
        {
            metadata.SourceAddress = remote.ToString();
        }

        return metadata;
    }

    /// <summary>Renders an endpoint the way Clash's API does.</summary>
    internal static string FormatEndpoint(IPAddress address, int port)
        => address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";

    private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                ReportError(ex);
                continue;
            }

            Track(socket, cancellationToken);
        }
    }

    private void Track(Socket socket, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _active);
        var task = Task.Run(
            async () =>
            {
                try
                {
                    await HandleClientAsync(socket, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown.
                }
                catch (Exception ex)
                {
                    ReportError(ex);
                }
                finally
                {
                    try
                    {
                        socket.Dispose();
                    }
                    catch
                    {
                        // Already closed by the protocol handler.
                    }

                    Interlocked.Decrement(ref _active);
                }
            },
            CancellationToken.None);

        lock (_pendingGate)
        {
            _pending.RemoveAll(t => t.IsCompleted);
            _pending.Add(task);
        }
    }
}
