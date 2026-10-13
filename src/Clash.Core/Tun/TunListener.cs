using System.Net;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Clash.Core.Netstack;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Tun;

/// <summary>
/// Opens the packet device for TUN mode, reporting the session it must be released
/// with. The real implementation is <see cref="TunAdapter.Open(string, uint)"/>; the
/// seam exists so the listener can be assembled and driven without the Wintun driver
/// (which needs an administrator process) and without loading <c>wintun.dll</c>.
/// </summary>
/// <param name="name">The adapter name, from <c>tun.device</c>.</param>
/// <param name="ringCapacity">Ring size in bytes, already validated against the driver's bounds.</param>
internal delegate (ITunPacketDevice Device, IDisposable? Session) TunDeviceFactory(string name, uint ringCapacity);

/// <summary>
/// The TUN inbound: it owns the Wintun session, the packet pump and the accept
/// loop that together make the operating system's traffic reach the tunnel.
/// <para>
/// Shape of the thing: one device, one read ring. <see cref="TunUdpRelay"/> is the
/// ring's only reader — it answers hijacked DNS queries itself, hands every other
/// datagram to the tunnel's UDP path, and passes the packets it does not carry
/// (TCP) to <see cref="TcpAcceptor.ProcessPacket"/>. TCP replies leave through
/// <see cref="TcpAcceptor.PacketSink"/> and UDP replies through the relay, both of
/// which write straight back to the device.
/// </para>
/// <para>
/// Why this type is not a <see cref="ListenerBase"/>: there is no socket and no
/// port. Its <see cref="Address"/> is the adapter name once the interface is up,
/// and its <see cref="Port"/> is always 0, so the API reports it as a TUN inbound
/// rather than pretending it bound something.
/// </para>
/// <para>
/// Elevation is checked <b>before</b> the device is opened, so a non-administrator
/// process gets one sentence naming the missing privilege instead of a driver
/// error code. The failure is thrown from <see cref="StartAsync"/> and therefore
/// only fails this listener: <see cref="ListenerManager"/> logs it and starts the
/// rest, so HTTP/SOCKS keep serving.
/// </para>
/// </summary>
internal sealed class TunListener : IInboundListener
{
    /// <summary>How long shutdown waits for in-flight flows before giving up on them.</summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    private readonly TunDeviceFactory _openDevice;
    private readonly ITunInterfaceConfigurator _interface;
    private readonly TunConfig _tun;
    private readonly ClashConfig _config;
    private readonly ILogger _logger;
    private readonly List<Task> _flows = [];
    private readonly Lock _flowGate = new();

    private ITunnel? _tunnel;
    private ITunPacketDevice? _device;
    private IDisposable? _session;
    private TcpAcceptor? _acceptor;
    private TunUdpRelay? _relay;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;

    /// <summary>
    /// The UDP relay's pump loop.
    /// <para>
    /// Kept rather than awaited: <see cref="TunUdpRelay.Start"/> returns the pump,
    /// which by design runs until the relay is stopped. Awaiting it here made
    /// <see cref="StartAsync"/> never return, which hung the whole core on a
    /// machine where tun mode was on — and hung the test suite, hiding the
    /// listener's own tests behind an aborted run.
    /// </para>
    /// </summary>
    private Task? _relayPump;
    private string? _interfaceName;
    private int _active;
    private int _started;
    private int _disposed;

    /// <summary>Creates the listener that owns a real Wintun session.</summary>
    /// <param name="config">The configuration in force; its <c>tun</c> section drives everything.</param>
    /// <param name="logger">Diagnostics sink.</param>
    public TunListener(ClashConfig config, ILogger logger)
        : this(config, logger, OpenWintun, NetshTunInterfaceConfigurator.Instance)
    {
    }

    /// <summary>
    /// Creates the listener over an injected packet device, configuring the
    /// machine's interfaces and routes the way production does.
    /// </summary>
    /// <param name="config">The configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="openDevice">How the packet device is obtained.</param>
    internal TunListener(ClashConfig config, ILogger logger, TunDeviceFactory openDevice)
        : this(config, logger, openDevice, NetshTunInterfaceConfigurator.Instance)
    {
    }

    /// <summary>
    /// Creates the listener over an injected packet device and an injected
    /// interface configurator.
    /// <para>
    /// Both halves are seams for the same reason. A device that only exists
    /// inside the test has no interface on this machine, so the address and the
    /// routes it needs cannot be real ones: leaving the real <c>netsh</c> calls
    /// in place made every test that reached this point fail with "no such
    /// interface" instead of testing the listener.
    /// </para>
    /// </summary>
    /// <param name="config">The configuration in force.</param>
    /// <param name="logger">Diagnostics sink.</param>
    /// <param name="openDevice">How the packet device is obtained.</param>
    /// <param name="interfaceConfigurator">How the adapter's address and routes are set and removed.</param>
    internal TunListener(
        ClashConfig config,
        ILogger logger,
        TunDeviceFactory openDevice,
        ITunInterfaceConfigurator interfaceConfigurator)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _tun = config.Tun ?? throw new ArgumentNullException(nameof(config), "the tun section must not be null");
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _openDevice = openDevice ?? throw new ArgumentNullException(nameof(openDevice));
        _interface = interfaceConfigurator ?? throw new ArgumentNullException(nameof(interfaceConfigurator));
    }

    /// <inheritdoc />
    public string Type => "tun";

    /// <inheritdoc />
    public string? Name => null;

    /// <summary>
    /// The adapter's name once the session is open, which is what
    /// <c>GET /configs</c> reports as the inbound's address. Null before
    /// <see cref="StartAsync"/> and after <see cref="StopAsync"/>, like a socket
    /// listener that is not bound.
    /// </summary>
    public string? Address => _interfaceName;

    /// <summary>TUN mode has no port; the adapter is addressed by name.</summary>
    public int Port => 0;

    /// <inheritdoc />
    public int ActiveConnections => Volatile.Read(ref _active);

    /// <summary>The configured adapter name, or the default when the config left it empty.</summary>
    public string AdapterName => string.IsNullOrWhiteSpace(_tun.Device) ? DefaultAdapterName : _tun.Device.Trim();

    /// <summary>True while the packet pump is running.</summary>
    public bool IsRunning => _relay?.IsRunning == true;

    /// <summary>How many TCP flows the acceptor is tracking, handshakes included.</summary>
    public int TcpConnectionCount => _acceptor?.ConnectionCount ?? 0;

    /// <summary>The UDP relay, once started; null before <see cref="StartAsync"/>.</summary>
    internal TunUdpRelay? Relay => _relay;

    /// <summary>The TCP acceptor, once started; null before <see cref="StartAsync"/>.</summary>
    internal TcpAcceptor? Acceptor => _acceptor;

    /// <summary>The adapter name used when the configuration does not name one.</summary>
    internal const string DefaultAdapterName = "Clash";

    /// <inheritdoc />
    public async Task StartAsync(ITunnel tunnel, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(tunnel);

        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            throw new InvalidOperationException("listener [tun] is already started");
        }

        _tunnel = tunnel;
        try
        {
            // The switch is settled before the device, so a listener assembled
            // from a disabled section cannot reach the driver even when something
            // starts it directly. ListenerManager never builds it in that state,
            // and this is the other half of the same rule: the switch alone
            // decides whether a session is opened.
            if (!_tun.Enable)
            {
                throw new ClashException("tun mode is off: set tun.enable to true before starting the tun inbound");
            }

            // Privileges are checked where they are actually needed — inside
            // OpenWintun, on the real device path. Doing it here made the listener
            // refuse to start with an injected device, which is how every test of
            // the packet path drives it, so the data plane could not be tested off
            // an elevated host at all.
            var adapterName = AdapterName;
            var opened = _openDevice(adapterName, RingCapacity(_tun));
            _device = opened.Device;
            _session = opened.Session;

            // The acceptor is built first because the relay needs to hand it the
            // packets it does not carry; its sink is filled in once the device is
            // known.
            _acceptor = new TcpAcceptor(NetstackOptions(_tun, LocalAddress(_tun)))
            {
                DestinationFilter = AcceptsDestination,
                PacketSink = packet => _device?.Write(packet.Span),
            };

            _relay = new TunUdpRelay(
                _device,
                tunnel,
                _tun,
                dnsHandler: null,
                inboundName: null,
                logger: _logger,
                codec: null,
                observer: packet => _acceptor?.ProcessPacket(packet));

            var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _cts = cts;

            // Not awaited: this is the pump loop, which runs for as long as the
            // relay is up. Its failure is surfaced through the continuation
            // instead, so a dead pump cannot pass unnoticed.
            _relayPump = _relay.Start(cts.Token);
            _ = _relayPump.ContinueWith(
                static (task, state) =>
                {
                    var (logger, name) = ((ILogger, string?))state!;
                    logger.LogError(task.Exception, "the tun UDP relay stopped unexpectedly [{Name}]", name ?? "tun");
                },
                (_logger, _tun.Device),
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);

            _acceptLoop = Task.Run(() => AcceptLoopAsync(cts.Token), CancellationToken.None);

            // Routing last: the interface is only worth pointing traffic at once
            // something is listening on it.
            if (opened.Session is not null)
            {
                _interfaceName = adapterName;
                ConfigureRouting(adapterName);
            }

            _logger.LogInformation(
                "listener [tun] attached to adapter {Adapter} (stack {Stack}, mtu {Mtu}, auto-route {AutoRoute}, dns-hijack {Hijack})",
                adapterName,
                _tun.Stack,
                _tun.Mtu,
                _tun.AutoRoute,
                _relay.DnsHijackEnabled);
        }
        catch
        {
            // A half-built listener must not leave a session, a pump or a route
            // behind, so the unwind is the same one StopAsync performs.
            Interlocked.Exchange(ref _started, 0);
            await OnStoppedAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task StopAsync()
    {
        Interlocked.Exchange(ref _started, 0);

        var cts = Interlocked.Exchange(ref _cts, null);
        var acceptLoop = _acceptLoop;
        _acceptLoop = null;

        try
        {
            cts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already torn down.
        }

        if (acceptLoop is not null)
        {
            try
            {
                await acceptLoop.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The accept loop reports its own failures.
            }
        }

        Task[] flows;
        lock (_flowGate)
        {
            flows = [.. _flows];
            _flows.Clear();
        }

        if (flows.Length > 0)
        {
            try
            {
                await Task.WhenAll(flows).WaitAsync(DrainTimeout).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Either the drain timed out or a flow faulted; both are logged.
            }
        }

        await OnStoppedAsync().ConfigureAwait(false);
        cts?.Dispose();
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    // ── The accept loop ─────────────────────────────────────────────────────

    /// <summary>
    /// Takes established flows off the acceptor and runs each one on its own task.
    /// The accept loop itself never blocks on a flow: one long-lived connection
    /// must not stop the next one from being served.
    /// </summary>
    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpAcceptStream stream;
            try
            {
                stream = await _acceptor!.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                _logger.LogError(ex, "listener [tun] failed to accept a flow");
                continue;
            }

            Track(stream, cancellationToken);
        }
    }

    private void Track(TcpAcceptStream stream, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _active);
        var task = Task.Run(
            async () =>
            {
                try
                {
                    await _tunnel!.HandleTcpAsync(stream, MetadataFor(stream), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown.
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "listener [tun] failed to serve a flow from {Source}", stream.RemoteEndPoint);
                }
                finally
                {
                    try
                    {
                        await stream.DisposeAsync().ConfigureAwait(false);
                    }
                    catch (Exception)
                    {
                        // Already gone.
                    }

                    Interlocked.Decrement(ref _active);
                }
            },
            CancellationToken.None);

        lock (_flowGate)
        {
            _flows.RemoveAll(static flow => flow.IsCompleted);
            _flows.Add(task);
        }
    }

    /// <summary>
    /// Builds the metadata for one flow. The destination is the address the
    /// operating system connected to — the fake-IP address in fake-IP mode — which
    /// is what the rules and the fake-IP reverse lookup need.
    /// </summary>
    private static Metadata MetadataFor(TcpAcceptStream stream)
    {
        var remote = stream.RemoteEndPoint;
        var local = stream.LocalEndPoint;
        return new Metadata
        {
            Network = Network.Tcp,
            SourceAddress = remote.Address.ToString(),
            SourcePort = (ushort)remote.Port,
            DestinationAddress = local.Address.ToString(),
            DestinationPort = (ushort)local.Port,
            InboundType = "tun",
            InboundName = null,
        };
    }

    // ── Teardown ────────────────────────────────────────────────────────────

    /// <summary>
    /// Releases everything <see cref="StartAsync"/> created, in the reverse order
    /// it was created: routes first (so traffic stops being pointed at an
    /// interface that is about to disappear), then the pump, the acceptor and
    /// finally the session.
    /// </summary>
    private async Task OnStoppedAsync()
    {
        var interfaceName = _interfaceName;
        _interfaceName = null;

        if (interfaceName is not null) TryRemoveRouting(interfaceName);

        var relay = Interlocked.Exchange(ref _relay, null);
        if (relay is not null)
        {
            try
            {
                await relay.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "listener [tun] failed to stop the UDP relay cleanly");
            }
        }

        var acceptor = Interlocked.Exchange(ref _acceptor, null);
        if (acceptor is not null)
        {
            try
            {
                await acceptor.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "listener [tun] failed to release the TCP acceptor cleanly");
            }
        }

        _device = null;

        var session = Interlocked.Exchange(ref _session, null);
        session?.Dispose();
    }

    // ── Address, MSS and routing ────────────────────────────────────────────

    /// <summary>
    /// The address this stack answers for. <c>tun.inet4-address</c> wins when it
    /// is set, because that is the address the interface is given; otherwise the
    /// adapter's own default is used.
    /// </summary>
    internal static IPAddress LocalAddress(TunConfig tun)
    {
        foreach (var candidate in tun.Inet4Address ?? [])
        {
            var value = candidate.Trim();
            var slash = value.IndexOf('/');
            if (slash >= 0) value = value[..slash];
            if (IPAddress.TryParse(value, out var parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return parsed;
            }
        }

        return IPAddress.Parse(TunInterface.AdapterAddress);
    }

    /// <summary>
    /// The stack tuning for TUN mode. The MSS follows the configured MTU
    /// (<c>mtu - 20 - 20</c>), so a 9000-byte adapter does not advertise a 1400-byte
    /// segment; an MTU that cannot carry a legal MSS falls back to the default
    /// rather than failing startup.
    /// </summary>
    internal static NetstackOptions NetstackOptions(TunConfig tun, IPAddress localAddress)
    {
        var options = new NetstackOptions { LocalAddress = localAddress };

        var mss = tun.Mtu - 40;
        if (mss is >= 256 and <= ushort.MaxValue - 40 && mss <= options.ReceiveWindowSize)
        {
            options.Mss = mss;
        }

        return options;
    }

    /// <summary>
    /// Whether a destination address belongs to this inbound. Both the adapter's
    /// own address and the fake-IP range are accepted: the first is what a plain
    /// <c>tun</c> route delivers, the second is what the fake-IP resolver's
    /// answers resolve to.
    /// </summary>
    internal bool AcceptsDestination(uint address)
    {
        if (address == Ipv4Header.ToNumeric(LocalAddress(_tun)))
        {
            return true;
        }

        return TryFakeIpRange(_config.Dns?.FakeIpRange, out var network, out var prefix)
               && PrefixContains(network, prefix, address);
    }

    /// <summary>Parses <c>fake-ip-range</c>, e.g. <c>198.18.0.1/16</c>.</summary>
    internal static bool TryFakeIpRange(string? range, out uint network, out int prefix)
    {
        network = 0;
        prefix = 0;

        var value = range?.Trim();
        if (string.IsNullOrEmpty(value)) return false;

        var slash = value.IndexOf('/');
        if (slash <= 0 || !int.TryParse(value[(slash + 1)..], out prefix)) return false;
        if (prefix is < 0 or > 32) return false;

        if (!IPAddress.TryParse(value[..slash], out var parsed)) return false;
        if (parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;

        // A range written as 198.18.0.1/16 means "the /16 this address sits in",
        // so the host bits are masked off rather than trusted.
        network = Ipv4Header.ToNumeric(parsed) & MaskFor(prefix);
        return true;
    }

    private static uint MaskFor(int prefix)
        => prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);

    private static bool PrefixContains(uint network, int prefix, uint address)
        => (address & MaskFor(prefix)) == network;

    /// <summary>
    /// Points the machine's traffic at the adapter, the way <c>auto-route</c> is
    /// documented to. Only <c>store=active</c> changes are made, so a crash cannot
    /// leave a persistent route behind.
    /// <para>
    /// The changes go through the injected <see cref="ITunInterfaceConfigurator"/>
    /// rather than straight to <c>netsh</c>. The listener decides <i>what</i> the
    /// machine should be told; the configurator carries it out, and production
    /// always supplies the <c>netsh</c> one.
    /// </para>
    /// </summary>
    private void ConfigureRouting(string adapterName)
    {
        _interface.SetAddress(adapterName, LocalAddress(_tun).ToString());

        if (_tun.AutoRoute)
        {
            _interface.AddDefaultRoutes(adapterName, metric: 1);
        }

        foreach (var excluded in _tun.RouteExcludeAddress ?? [])
        {
            var prefix = NormalizePrefix(excluded);
            if (prefix is null)
            {
                _logger.LogWarning("tun: route-exclude-address [{Entry}] is not an IPv4 prefix and was skipped", excluded);
                continue;
            }

            if (_interface.AddExclusion(prefix))
            {
                continue;
            }

            _logger.LogWarning(
                "tun: no physical default route was found, so [{Prefix}] could not be kept out of the tunnel",
                prefix);
        }
    }

    private void TryRemoveRouting(string adapterName)
    {
        try
        {
            if (_tun.AutoRoute) _interface.RemoveDefaultRoutes(adapterName);

            foreach (var excluded in _tun.RouteExcludeAddress ?? [])
            {
                if (NormalizePrefix(excluded) is { } prefix) _interface.RemoveExclusion(prefix);
            }

            _interface.TryClearAddress(adapterName);
        }
        catch (Exception ex)
        {
            // Removing a route that is already gone is the normal case; a real
            // failure must not stop the rest of the shutdown.
            _logger.LogWarning(ex, "tun: restoring the routing table for adapter [{Adapter}] failed", adapterName);
        }
    }

    /// <summary>Renders an exclude entry as a bare IPv4 address, or null when it is not one.</summary>
    private static string? NormalizePrefix(string entry)
    {
        var value = entry?.Trim();
        if (string.IsNullOrEmpty(value)) return null;

        var slash = value.IndexOf('/');
        if (slash >= 0) value = value[..slash];

        return IPAddress.TryParse(value, out var parsed)
               && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? parsed.ToString()
            : null;
    }

    // ── The driver ──────────────────────────────────────────────────────────

    /// <summary>The real device: a Wintun session opened by name.</summary>
    private static (ITunPacketDevice Device, IDisposable? Session) OpenWintun(string name, uint ringCapacity)
    {
        // The one operation that needs an administrator: creating the adapter.
        // Checked here rather than in StartAsync so that a listener built over an
        // injected device — every test of the packet path — does not demand
        // privileges it never uses.
        RequireElevation();

        var adapter = TunAdapter.Open(name, ringCapacity);
        return (new DelegateTunPacketDevice(adapter.Read, adapter.Write), adapter);
    }

    /// <summary>
    /// The ring size for the configured MTU, rounded up to something the driver
    /// accepts: the bounds are powers of two, and the MTU decides how much the
    /// ring has to hold.
    /// </summary>
    internal static uint RingCapacity(TunConfig tun)
    {
        var wanted = (uint)Math.Clamp(tun.Mtu, 1280, WintunInterop.MaxIpPacketSize) * 8;
        var capacity = WintunInterop.MinRingCapacity;
        while (capacity < wanted && capacity < WintunInterop.MaxRingCapacity) capacity <<= 1;
        return Math.Min(capacity, WintunInterop.MaxRingCapacity);
    }

    /// <summary>
    /// Refuses to start where the adapter cannot exist. The check runs before the
    /// session is opened so the user sees the reason, not a driver error code.
    /// </summary>
    private static void RequireElevation()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("tun mode is implemented for Windows only in this build");
        }

        TunElevation.Require();
    }
}
