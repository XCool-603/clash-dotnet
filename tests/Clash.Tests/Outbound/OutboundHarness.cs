using System.Net;
using System.Net.Sockets;
using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Transport;
using Clash.Tests.Support;
using Microsoft.Extensions.Logging.Abstractions;

namespace Clash.Tests.Outbound;

/// <summary>
/// A real <see cref="ITransportComposer"/> that only knows the plain TCP layer.
/// The production composer is built elsewhere in the tree; the outbound adapters
/// only need the contract, so the tests supply a composer that opens a genuine
/// socket with <see cref="TcpTransport"/> and nothing else.
/// </summary>
internal sealed class PlainTcpComposer : ITransportComposer
{
    private readonly TcpTransport _tcp = new();

    public IReadOnlyList<ITransportLayer> Compose(YamlMap proxyOptions) => [_tcp];

    public Task<ProxyStream> ConnectAsync(DialContext context, YamlMap proxyOptions, CancellationToken cancellationToken = default)
        => _tcp.WrapAsync(null, context, proxyOptions, cancellationToken);
}

/// <summary>Shared construction helpers for the outbound tests.</summary>
internal static class OutboundHarness
{
    /// <summary>A build context wired to a fake tunnel and the plain TCP composer.</summary>
    internal static AdapterBuildContext BuildContext()
    {
        var tunnel = new FakeTunnel();
        return new AdapterBuildContext
        {
            Config = tunnel.Config,
            Tunnel = new FakeTunnelAccessor(tunnel),
            Transports = new PlainTcpComposer(),
            LoggerFactory = NullLoggerFactory.Instance,
        };
    }

    /// <summary>Builds a configuration entry from a name, a type and the raw option pairs.</summary>
    internal static ProxyConfigEntry Entry(string name, string type, params (string Key, object? Value)[] pairs)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = name,
            ["type"] = type,
        };

        foreach (var (key, value) in pairs) map[key] = value;
        return new ProxyConfigEntry(new YamlMap(map));
    }

    /// <summary>Builds a configuration entry with no server/port, for validation tests.</summary>
    internal static ProxyConfigEntry EntryWithoutEndpoint(string name, string type, params (string Key, object? Value)[] pairs)
        => Entry(name, type, pairs);

    /// <summary>Runs the registered factory for the entry.</summary>
    internal static IProxy Build(ProxyConfigEntry entry) => AdapterRegistry.Create(entry, BuildContext());

    /// <summary>A TCP flow towards <paramref name="host"/>.</summary>
    internal static Metadata Flow(string host, int port, string? apiHost = null) => new()
    {
        Network = Network.Tcp,
        DestinationAddress = host,
        DestinationPort = (ushort)port,
        Host = apiHost ?? host,
    };

    /// <summary>A UDP flow towards <paramref name="host"/>.</summary>
    internal static Metadata UdpFlow(string host, int port) => new()
    {
        Network = Network.Udp,
        DestinationAddress = host,
        DestinationPort = (ushort)port,
    };

    /// <summary>Loops <paramref name="stream"/> until the peer closes it.</summary>
    internal static async Task DrainAsync(Stream stream, CancellationToken cancellationToken)
    {
        var scratch = new byte[4096];
        while (await stream.ReadAsync(scratch, cancellationToken) > 0)
        {
        }
    }
}

/// <summary>
/// A single-connection TCP server on the loopback interface. The handler runs on a
/// background task; <see cref="WaitAsync"/> surfaces the handler's own failure so a
/// broken assertion inside it fails the test rather than hanging.
/// </summary>
internal sealed class FakeTcpServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    internal FakeTcpServer(Func<NetworkStream, CancellationToken, Task> handler)
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _loop = Task.Run(async () =>
        {
            using var client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            client.NoDelay = true;
            using var stream = client.GetStream();
            await handler(stream, _cts.Token).ConfigureAwait(false);
        });
    }

    internal int Port { get; }

    /// <summary>Waits for the handler to finish, surfacing its exception.</summary>
    internal async Task WaitAsync()
    {
        var completed = await Task.WhenAny(_loop, Task.Delay(TimeSpan.FromSeconds(15))).ConfigureAwait(false);
        if (completed != _loop) throw new TimeoutException("the fake TCP server handler did not finish in time");
        await _loop.ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        try { _listener.Stop(); } catch { /* already gone */ }

        try { await _loop.ConfigureAwait(false); } catch { /* cancellation or teardown */ }
        _cts.Dispose();
    }
}

/// <summary>A loopback UDP server driven by a per-datagram handler.</summary>
internal sealed class FakeUdpServer : IAsyncDisposable
{
    private readonly UdpClient _client;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    internal FakeUdpServer(Func<byte[], IPEndPoint, byte[]?> handler)
    {
        _client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)_client.Client.LocalEndPoint!).Port;

        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                var received = await _client.ReceiveAsync(_cts.Token).ConfigureAwait(false);
                var reply = handler(received.Buffer, received.RemoteEndPoint);
                if (reply is not null)
                {
                    await _client.SendAsync(reply, received.RemoteEndPoint, _cts.Token).ConfigureAwait(false);
                }
            }
        });
    }

    internal int Port { get; }

    /// <summary>Completed by the handler once it has seen what the test needs.</summary>
    internal TaskCompletionSource<bool> Done { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Waits for the handler to signal completion.</summary>
    internal async Task WaitAsync()
    {
        var completed = await Task.WhenAny(Done.Task, Task.Delay(TimeSpan.FromSeconds(15))).ConfigureAwait(false);
        if (completed != Done.Task) throw new TimeoutException("the fake UDP server did not receive a datagram in time");
        await Done.Task.ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);
        try { _client.Dispose(); } catch { /* already gone */ }

        try { await _loop.ConfigureAwait(false); } catch { /* cancellation or teardown */ }
        _cts.Dispose();
    }
}

/// <summary>Assertion helpers shared by the protocol tests.</summary>
internal static class ByteAssert
{
    /// <summary>Asserts that <paramref name="actual"/> starts with <paramref name="expected"/>.</summary>
    internal static void StartsWith(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        Xunit.Assert.True(
            actual.Length >= expected.Length && actual[..expected.Length].SequenceEqual(expected),
            $"expected the payload to start with {Show(expected)} but it was {Show(actual)}");
    }

    /// <summary>Renders a byte range for an assertion message.</summary>
    internal static string Show(ReadOnlySpan<byte> bytes)
        => bytes.Length == 0 ? "<empty>" : Convert.ToHexString(bytes[..Math.Min(bytes.Length, 64)]);

    /// <summary>Renders a string as bytes for an expectation.</summary>
    internal static byte[] Ascii(string value) => System.Text.Encoding.ASCII.GetBytes(value);
}
