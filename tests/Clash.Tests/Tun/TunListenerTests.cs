using System.Net;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Listeners;
using Clash.Core.Rules;
using Clash.Core.Tun;
using Clash.Core.Tunnel;
using Clash.Tests.Listeners;
using Clash.Tests.Netstack;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Tun;

/// <summary>
/// The TUN inbound and its wiring into <see cref="ListenerManager"/>.
/// <para>
/// Two seams keep this file free of the Wintun driver and of administrator rights:
/// the packet device is injected through <see cref="TunListener"/>'s internal
/// constructor, so the whole pipeline — device → relay → acceptor → tunnel — is
/// driven by synthetic IP packets; and the listener set is built from a
/// configuration object, so "was anything created at all" is observable.
/// </para>
/// <para>
/// Elevation cannot be faked: the tests covering the failure path return early when
/// the host really is elevated, because on such a host there is no failure to
/// observe. The message they pin is the one a normal (non-elevated) run produces.
/// </para>
/// </summary>
public sealed class TunListenerTests
{
    private const ushort ClientPort = 51000;
    private const ushort ServerPort = 443;
    private const string TestAdapterName = "ClashTunRuntimeTest";

    /// <summary>The address a fake-IP answer resolves to.</summary>
    private static readonly uint FakeIpAddress = TestPackets.Address("198.18.0.5");

    /// <summary>The address the host that opened the connection reports.</summary>
    private static readonly uint ClientAddress = TestPackets.Address("10.0.0.2");

    // ── Wiring: the switch decides whether anything is created ──────────────

    [Fact]
    public void ATunListenerIsCreatedOnlyWhenTheTunSectionEnablesIt()
    {
        var off = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };
        var offManager = new ListenerManager(off, NullLogger<ListenerManager>.Instance);

        Assert.DoesNotContain(offManager.Listeners, listener => listener.Type == "tun");
        Assert.Equal(["mixed"], offManager.Listeners.Select(listener => listener.Type));

        var on = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };
        on.Tun.Enable = true;
        var onManager = new ListenerManager(on, NullLogger<ListenerManager>.Instance);

        Assert.Contains(onManager.Listeners, listener => listener.Type == "tun");
        Assert.Equal(["mixed", "tun"], onManager.Listeners.Select(listener => listener.Type));

        var tun = Assert.IsType<TunListener>(onManager.Listeners[1]);
        Assert.Equal("tun", tun.Type);
        Assert.Equal(0, tun.Port);

        // No adapter name is invented before a session exists.
        Assert.Null(tun.Address);
    }

    [Fact]
    public async Task ADisabledTunSectionStartsNothingAndCreatesNoListener()
    {
        var config = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };

        await using var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);
        await manager.StartAsync(new TunFlowTunnel(config));

        // The strongest thing the manager can be asked: nothing of type tun exists
        // to have loaded wintun.dll, and the listener that did start is untouched.
        Assert.DoesNotContain(manager.Listeners, listener => listener.Type == "tun");
        Assert.Equal(["mixed"], manager.Listeners.Select(listener => listener.Type));
        Assert.NotNull(manager.Listeners[0].Address);

        await manager.StopAsync();
    }

    [Fact]
    public async Task ATunListenerBuiltFromADisabledSectionNeverAsksForADevice()
    {
        // The manager never constructs this listener while `tun.enable` is false;
        // this pins the second half of the same rule — that the listener itself
        // cannot open a device either. The failure that comes back is the switch or
        // the platform guard, never the device factory.
        var config = new ClashConfig { BindAddress = "127.0.0.1" };
        var calls = 0;

        await using var listener = new TunListener(config, NullLogger<TunListener>.Instance, (_, _) =>
        {
            Interlocked.Increment(ref calls);
            throw new InvalidOperationException("a disabled tun section must not open a device");
        });

        await Assert.ThrowsAnyAsync<Exception>(() => listener.StartAsync(new TunFlowTunnel(config)));
        Assert.Equal(0, Volatile.Read(ref calls));
        Assert.Null(listener.Address);
        Assert.False(listener.IsRunning);
    }

    [Fact]
    public async Task ADisabledTunSectionNeverAsksForADeviceEvenWhenAListenerEntryNamesIt()
    {
        var config = new ClashConfig { BindAddress = "127.0.0.1" };
        config.Listeners.Add(new ListenerConfig { Name = "entry-tun", Type = "tun", Port = 0 });

        await using var listener = new TunListener(config, NullLogger<TunListener>.Instance, (_, _) =>
        {
            throw new InvalidOperationException("the device factory must not be called");
        });

        // A `listeners` entry of type tun is not a second switch for the adapter: it
        // names the inbound, and tun mode stays off until `tun.enable` is true.
        await Assert.ThrowsAnyAsync<Exception>(() => listener.StartAsync(new TunFlowTunnel(config)));
        Assert.Null(listener.Address);
        Assert.False(listener.IsRunning);
    }

    [Fact]
    public async Task AHotReloadAddsAndRemovesTheTunListenerWithTheSwitch()
    {
        var off = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };
        var tunnel = new TunFlowTunnel(off);
        await using var manager = new ListenerManager(off, NullLogger<ListenerManager>.Instance);
        await manager.StartAsync(tunnel);
        Assert.DoesNotContain(manager.Listeners, listener => listener.Type == "tun");

        var on = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };
        on.Tun.Enable = true;
        await manager.ReloadAsync(on, tunnel);
        Assert.Contains(manager.Listeners, listener => listener.Type == "tun");

        var offAgain = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };
        await manager.ReloadAsync(offAgain, tunnel);
        Assert.DoesNotContain(manager.Listeners, listener => listener.Type == "tun");
    }

    // ── The elevation failure path ──────────────────────────────────────────

    [Fact]
    public async Task WithoutAdministratorRightsTheFailureNamesTheMissingPrivilege()
    {
        if (!OperatingSystem.IsWindows()) return;
        if (TunElevation.IsElevated) return; // nothing to observe on an elevated host

        var config = new ClashConfig { BindAddress = "127.0.0.1" };
        config.Tun.Enable = true;
        config.Tun.Device = TestAdapterName;

        // Built over the real device path on purpose: the privilege check lives in
        // OpenWintun, so only the real factory can exercise it. An injected factory
        // would be called and would never reach the check.
        await using var listener = new TunListener(config, NullLogger<TunListener>.Instance);

        var error = await Assert.ThrowsAsync<ClashException>(
            () => listener.StartAsync(new TunFlowTunnel(config)));

        // The refusal happens before the driver is touched, which the fact that it
        // threw at all demonstrates: TunAdapter.Open would have failed differently.
        Assert.Contains("administrator", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(listener.Address);
        Assert.False(listener.IsRunning);
    }

    [Fact]
    public async Task ATunFailureLeavesTheOtherListenersServing()
    {
        if (!OperatingSystem.IsWindows()) return;

        var config = new ClashConfig { MixedPort = 7890, BindAddress = "127.0.0.1" };
        config.Tun.Enable = true;

        await using var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);
        await manager.StartAsync(new TunFlowTunnel(config));

        // The port-based listeners are built first and the tun inbound is added
        // after them: the switch adds an inbound, it does not replace the ones the
        // ports asked for. So the mixed listener is the one whose survival this
        // test is about, and it is the one the manager starts first.
        Assert.Equal(["mixed", "tun"], manager.Listeners.Select(listener => listener.Type));

        var mixed = manager.Listeners[0];
        var tun = manager.Listeners[1];

        if (!TunElevation.IsElevated)
        {
            // The failure is contained in the one listener: it reports no address.
            Assert.Null(tun.Address);
        }

        Assert.NotNull(mixed.Address);
        Assert.True(mixed.Port > 0);

        using var client = await TestSockets.ConnectAsync(mixed.Port);
        Assert.Equal((byte)0x00, await client.GreetSocks5Async(0x00));

        await manager.StopAsync();
    }

    // ── The packet path ─────────────────────────────────────────────────────

    [Fact]
    public async Task ASynToAFakeIpAddressIsAnsweredFromTheTunInbound()
    {
        using var device = new FakeTunDevice();
        await using var harness = await TunHarness.StartAsync(device);
        const uint clientIsn = 0x0BAD_F00D;

        device.Inject(TestPackets.Build(
            ClientAddress,
            FakeIpAddress,
            ClientPort,
            ServerPort,
            clientIsn,
            0,
            TestPackets.FlagSyn, default));

        var synAck = await WaitForTcpAsync(device, packet => packet.Syn);

        Assert.True(synAck.Ack, "the answer must acknowledge the SYN");
        Assert.False(synAck.Rst);
        Assert.True(synAck.ChecksumValid, "the TCP checksum must be correct");
        Assert.True(synAck.IpChecksumValid, "the IPv4 header checksum must be correct");

        // The reply comes from the address the SYN was sent to, so the host's stack
        // matches it to the socket that opened the connection.
        Assert.Equal("198.18.0.5", synAck.SourceText);
        Assert.Equal(ServerPort, synAck.SourcePort);
        Assert.Equal("10.0.0.2", synAck.DestinationText);
        Assert.Equal(ClientPort, synAck.DestinationPort);
        Assert.Equal(clientIsn + 1, synAck.Acknowledgment);
        Assert.Equal(1, harness.Listener.TcpConnectionCount);
        Assert.True(harness.Listener.IsRunning);
    }

    [Fact]
    public async Task ADestinationOutsideTheTunInboundIsIgnored()
    {
        using var device = new FakeTunDevice();
        await using var harness = await TunHarness.StartAsync(device);

        device.Inject(TestPackets.Build(
            ClientAddress,
            TestPackets.Address("1.2.3.4"),
            ClientPort,
            ServerPort,
            0x0BAD_F00D,
            0,
            TestPackets.FlagSyn, default));

        await Assert.ThrowsAsync<TimeoutException>(() => WaitForTcpAsync(device, packet => packet.Syn, 1500));
        Assert.Equal(0, harness.Listener.TcpConnectionCount);
    }

    [Fact]
    public async Task DataFlowsBothWaysThroughTheTunInbound()
    {
        using var device = new FakeTunDevice();
        await using var harness = await TunHarness.StartAsync(device);
        const uint clientIsn = 0x0BAD_F00D;

        device.Inject(TestPackets.Build(
            ClientAddress,
            FakeIpAddress,
            ClientPort,
            ServerPort,
            clientIsn,
            0,
            TestPackets.FlagSyn, default));

        var synAck = await WaitForTcpAsync(device, packet => packet.Syn);
        var serverIsn = synAck.Sequence;

        device.Inject(TestPackets.Build(
            ClientAddress,
            FakeIpAddress,
            ClientPort,
            ServerPort,
            clientIsn + 1,
            serverIsn + 1,
            TestPackets.FlagAck, default));

        // The tunnel echoes whatever it reads, which is what a flow through
        // HandleTcpAsync does.
        device.Inject(TestPackets.Build(
            ClientAddress,
            FakeIpAddress,
            ClientPort,
            ServerPort,
            clientIsn + 1,
            serverIsn + 1,
            (byte)(TestPackets.FlagPsh | TestPackets.FlagAck),
            "ping"u8));

        var echoed = await WaitForTcpAsync(device, packet => packet.Text == "ping");

        Assert.Equal("198.18.0.5", echoed.SourceText);
        Assert.Equal(ServerPort, echoed.SourcePort);
        Assert.Equal("10.0.0.2", echoed.DestinationText);
        Assert.Equal(ClientPort, echoed.DestinationPort);
        Assert.Equal(serverIsn + 1, echoed.Sequence);
        Assert.Equal(clientIsn + 5, echoed.Acknowledgment);
        Assert.True(echoed.ChecksumValid);
        Assert.True(echoed.IpChecksumValid);

        Assert.Equal(1, harness.Listener.ActiveConnections);
    }

    [Fact]
    public async Task AUdpDatagramReachesTheRelaysDnsHijack()
    {
        using var device = new FakeTunDevice();
        await using var harness = await TunHarness.StartAsync(device);

        var relay = harness.Listener.Relay;
        Assert.NotNull(relay);
        Assert.True(relay!.DnsHijackEnabled);

        // A query to a hijacked address never reaches the tunnel's UDP path: the
        // relay answers it, which is R2's behaviour. What this pins is that the TUN
        // inbound wired the relay to the device at all.
        device.Inject(UdpPackets.BuildText("10.0.0.2", "198.18.0.1", 40000, 53, "not-a-dns-message"));

        await WaitUntilAsync(
            () => harness.Listener.Relay!.QueriesHijacked == 1,
            TimeSpan.FromSeconds(5),
            "the relay to hijack the query");

        // The relay's forwarded-datagram counter, not the tunnel's HandleUdpAsync
        // call count: the association is handed to the tunnel once at start and
        // then runs for the lifetime of the inbound, so that call count is 1
        // whether or not anything is forwarded. What the hijack promises is that
        // the query never becomes a forwarded datagram.
        Assert.Equal(0, harness.Listener.Relay!.DatagramsForwarded);
    }

    [Fact]
    public async Task StoppingTheTunInboundReleasesTheDeviceAndThePump()
    {
        using var device = new FakeTunDevice();
        await using var harness = await TunHarness.StartAsync(device);

        Assert.True(harness.Listener.IsRunning);
        Assert.Equal(TestAdapterName, harness.Listener.Address);
        Assert.False(harness.Session.Disposed);

        // A session on its own carries nothing: the adapter has to be addressed
        // before traffic can be routed to it, and that is what the machine is told
        // to do here.
        Assert.Equal(
            [$"set-address {TestAdapterName} {TunInterface.AdapterAddress}"],
            harness.Interface.Calls);

        await harness.Listener.StopAsync();

        Assert.False(harness.Listener.IsRunning);
        Assert.Null(harness.Listener.Address);
        Assert.True(harness.Session.Disposed, "the session must be released on stop");

        // Shutdown hands the address back, so a stopped tunnel does not leave the
        // machine configured for an adapter that is about to disappear.
        Assert.Equal(
            [
                $"set-address {TestAdapterName} {TunInterface.AdapterAddress}",
                $"clear-address {TestAdapterName}",
            ],
            harness.Interface.Calls);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// <summary>Waits for the next TCP packet the listener writes that matches.</summary>
    private static async Task<ParsedPacket> WaitForTcpAsync(
        FakeTunDevice device,
        Func<ParsedPacket, bool> predicate,
        int timeoutMilliseconds = 5000)
    {
        var deadline = Environment.TickCount64 + timeoutMilliseconds;
        while (true)
        {
            var remaining = (int)(deadline - Environment.TickCount64);
            if (remaining <= 0)
            {
                throw new TimeoutException("the listener never wrote the expected packet");
            }

            var written = device.NextWritten(TimeSpan.FromMilliseconds(remaining));
            if (written is null)
            {
                throw new TimeoutException("the listener never wrote the expected packet");
            }

            if (TestPackets.TryParse(written, out var parsed) && predicate(parsed))
            {
                return parsed;
            }
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout, string what)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (!condition())
        {
            if (Environment.TickCount64 > deadline)
            {
                throw new TimeoutException($"waited for {what}");
            }

            await Task.Delay(5);
        }
    }

    /// <summary>
    /// A started <see cref="TunListener"/> over an injected device, plus the tunnel
    /// it was handed, the session handle it must release and the interface
    /// configuration it asked the machine for.
    /// </summary>
    private sealed class TunHarness : IAsyncDisposable
    {
        private TunHarness(
            TunListener listener,
            TunFlowTunnel tunnel,
            TunSession session,
            FakeInterfaceConfigurator interfaceConfigurator)
        {
            Listener = listener;
            Tunnel = tunnel;
            Session = session;
            Interface = interfaceConfigurator;
        }

        public TunListener Listener { get; }

        public TunFlowTunnel Tunnel { get; }

        public TunSession Session { get; }

        /// <summary>What the listener asked the machine's interface configuration to do.</summary>
        public FakeInterfaceConfigurator Interface { get; }

        public static async Task<TunHarness> StartAsync(FakeTunDevice device)
        {
            var config = new ClashConfig { BindAddress = "127.0.0.1" };
            config.Tun.Enable = true;
            config.Tun.Device = TestAdapterName;
            config.Dns.EnhancedMode = "fake-ip";

            var tunnel = new TunFlowTunnel(config);
            var session = new TunSession(device);
            var interfaceConfigurator = new FakeInterfaceConfigurator();
            var listener = new TunListener(
                config,
                NullLogger<TunListener>.Instance,
                (_, _) => (device, session),
                interfaceConfigurator);

            await listener.StartAsync(tunnel);
            return new TunHarness(listener, tunnel, session, interfaceConfigurator);
        }

        public async ValueTask DisposeAsync()
        {
            await Listener.DisposeAsync();
            await Tunnel.DisposeAsync();
        }
    }

    /// <summary>
    /// The session handle the listener was given. It reports its own disposal,
    /// which is how the tests observe that shutdown released the device.
    /// </summary>
    private sealed class TunSession(FakeTunDevice device) : IDisposable
    {
        private int _disposed;

        public bool Disposed => Volatile.Read(ref _disposed) != 0;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            device.Dispose();
        }
    }

    /// <summary>
    /// The interface and routing configuration the listener asks for, recorded
    /// instead of performed.
    /// <para>
    /// The injected device exists only inside this test, so there is no interface
    /// on the machine for <c>netsh</c> to address: the real configurator would fail
    /// with "no such interface" and hide whatever the test was actually asking.
    /// Recording the requests also makes the listener's own half of the contract
    /// observable — that it addresses the adapter on start and gives the address
    /// back on stop — which is what production depends on.
    /// </para>
    /// </summary>
    private sealed class FakeInterfaceConfigurator : ITunInterfaceConfigurator
    {
        private readonly List<string> _calls = [];
        private readonly Lock _gate = new();

        /// <summary>Every request the listener made, in the order it made them.</summary>
        public IReadOnlyList<string> Calls
        {
            get
            {
                lock (_gate)
                {
                    return [.. _calls];
                }
            }
        }

        /// <inheritdoc />
        public void SetAddress(string adapterName, string address) => Record($"set-address {adapterName} {address}");

        /// <inheritdoc />
        public void AddDefaultRoutes(string adapterName, int metric) => Record($"add-default-routes {adapterName} {metric}");

        /// <inheritdoc />
        public bool AddExclusion(string address)
        {
            Record($"add-exclusion {address}");
            return true;
        }

        /// <inheritdoc />
        public void RemoveDefaultRoutes(string adapterName) => Record($"remove-default-routes {adapterName}");

        /// <inheritdoc />
        public bool RemoveExclusion(string address)
        {
            Record($"remove-exclusion {address}");
            return true;
        }

        /// <inheritdoc />
        public bool TryClearAddress(string adapterName)
        {
            Record($"clear-address {adapterName}");
            return true;
        }

        private void Record(string call)
        {
            lock (_gate)
            {
                _calls.Add(call);
            }
        }
    }

    /// <summary>
    /// A tunnel stand-in for the TUN inbound: it echoes TCP flows back to the
    /// listener (so a synthetic packet round-trip is observable) and records the UDP
    /// associations it is handed. Its resolver is deliberately unreachable — the
    /// DNS-hijack path itself is R2's to prove.
    /// </summary>
    private sealed class TunFlowTunnel : ITunnel, IAsyncDisposable
    {
        private readonly ClashConfig _config;
        private int _udpCalls;

        public TunFlowTunnel(ClashConfig config) => _config = config;

        public ClashConfig Config => _config;

        public IDnsResolver Dns => throw new NotSupportedException("this test tunnel has no resolver");

        public IGeoData Geo => throw new NotSupportedException();

        public IProxyManager Proxies => throw new NotSupportedException();

        public ConnectionManager Connections { get; } = new(new TrafficTracker());

        public IRuleEngine Rules => throw new NotSupportedException();

        public TrafficTracker Traffic { get; } = new();

        public IDelayTester DelayTester => throw new NotSupportedException();

        public Mode Mode { get; set; } = Mode.Rule;

        /// <summary>How many times a UDP association was handed over.</summary>
        public int HandleUdpCalls => Volatile.Read(ref _udpCalls);

        public event Action<string, string>? LogEmitted;

        public Task<RuleMatch?> MatchAsync(Metadata metadata, CancellationToken cancellationToken = default)
            => Task.FromResult<RuleMatch?>(null);

        public Task<ProxyStream> DialTcpAsync(Metadata metadata, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<IPacketConnection> DialUdpAsync(Metadata metadata, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public async Task HandleTcpAsync(Stream inbound, Metadata metadata, CancellationToken cancellationToken = default)
        {
            var buffer = new byte[4096];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var read = await inbound.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read <= 0) break;

                    await inbound.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    await inbound.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception)
            {
                // The flow was torn down; the listener reports its own failures.
            }
        }

        public Task HandleUdpAsync(IPacketConnection inbound, Metadata metadata, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _udpCalls);
            return Task.CompletedTask;
        }

        public void Log(string level, string message) => LogEmitted?.Invoke(level, message);

        public ValueTask DisposeAsync()
        {
            LogEmitted = null;
            return ValueTask.CompletedTask;
        }
    }
}
