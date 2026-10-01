using Clash.Core.Configuration;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Listeners;

/// <summary>
/// Owns every inbound listener derived from a configuration: one per non-zero
/// port key plus one per <c>listeners</c> entry. A listener that fails to bind is
/// logged and skipped so the remaining ones still serve traffic, exactly like
/// Clash.
/// </summary>
public sealed class ListenerManager : IAsyncDisposable
{
    private readonly ILogger<ListenerManager> _logger;
    private readonly List<IInboundListener> _listeners = [];
    private int _disposed;

    /// <summary>Builds the listener set for <paramref name="config"/>.</summary>
    /// <param name="config">Configuration in force.</param>
    /// <param name="logger">Diagnostics sink, also handed to every listener.</param>
    public ListenerManager(ClashConfig config, ILogger<ListenerManager> logger)
    {
        Config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _listeners.AddRange(Build(config));
    }

    /// <summary>The configuration the current listener set was built from.</summary>
    public ClashConfig Config { get; private set; }

    /// <summary>Every listener the manager owns, in configuration order.</summary>
    public IReadOnlyList<IInboundListener> Listeners => _listeners;

    /// <summary>Starts every listener; individual bind failures are logged, never thrown.</summary>
    /// <param name="tunnel">The tunnel flows are handed to.</param>
    /// <param name="cancellationToken">Stops the listeners when cancelled.</param>
    public async Task StartAsync(ITunnel tunnel, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(tunnel);
        foreach (var listener in _listeners)
        {
            try
            {
                await listener.StartAsync(tunnel, cancellationToken).ConfigureAwait(false);
                _logger.LogInformation("listener [{Type}] listening on {Address}", listener.Type, listener.Address);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "listener [{Type}] failed to start on port {Port}", listener.Type, listener.Port);
            }
        }
    }

    /// <summary>Stops every listener, draining the connections they are serving.</summary>
    public async Task StopAsync()
    {
        foreach (var listener in _listeners)
        {
            try
            {
                await listener.StopAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "listener [{Type}] failed to stop", listener.Type);
            }
        }
    }

    /// <summary>Rebuilds the listener set after a config reload.</summary>
    /// <param name="config">The new configuration.</param>
    /// <param name="tunnel">The tunnel flows are handed to.</param>
    /// <param name="cancellationToken">Stops the new listeners when cancelled.</param>
    public async Task ReloadAsync(ClashConfig config, ITunnel tunnel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await StopAsync().ConfigureAwait(false);
        foreach (var listener in _listeners)
        {
            try
            {
                await listener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "listener [{Type}] failed to dispose during reload", listener.Type);
            }
        }

        _listeners.Clear();
        Config = config;
        _listeners.AddRange(Build(config));
        await StartAsync(tunnel, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await StopAsync().ConfigureAwait(false);
        foreach (var listener in _listeners)
        {
            try
            {
                await listener.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "listener [{Type}] failed to dispose", listener.Type);
            }
        }

        _listeners.Clear();
    }

    private List<IInboundListener> Build(ClashConfig config)
    {
        var listeners = new List<IInboundListener>();
        if (config.Port != 0)
        {
            listeners.Add(new HttpListener(config, _logger));
        }

        if (config.SocksPort != 0)
        {
            listeners.Add(new SocksListener(config, _logger));
        }

        if (config.MixedPort != 0)
        {
            listeners.Add(new MixedListener(config, _logger));
        }

        if (config.RedirPort != 0)
        {
            listeners.Add(new RedirListener(config, _logger));
        }

        if (config.TProxyPort != 0)
        {
            listeners.Add(new TProxyListener(config, _logger));
        }

        foreach (var entry in config.Listeners)
        {
            var type = entry.Type?.Trim().ToLowerInvariant() ?? string.Empty;
            var name = string.IsNullOrWhiteSpace(entry.Name) ? null : entry.Name;
            var (host, port) = SplitListen(entry);
            switch (type)
            {
                case "http":
                    listeners.Add(new HttpListener(config, _logger, port, name, host));
                    break;
                case "socks":
                    listeners.Add(new SocksListener(config, _logger, port, name, host));
                    break;
                case "mixed":
                    listeners.Add(new MixedListener(config, _logger, port, name, host));
                    break;
                case "redir":
                    listeners.Add(new RedirListener(config, _logger, port, name, host));
                    break;
                case "tproxy":
                    listeners.Add(new TProxyListener(config, _logger, port, name, host));
                    break;
                case "tun":
                    _logger.LogInformation(
                        "listener [{Name}] of type tun is owned by the TUN subsystem and was skipped",
                        name ?? "tun");
                    break;
                default:
                    _logger.LogWarning("listener [{Name}] has unsupported type [{Type}] and was skipped", name ?? "?", type);
                    break;
            }
        }

        return listeners;
    }

    /// <summary>Splits a <c>listeners[].listen</c> value into host and port.</summary>
    private static (string? Host, int Port) SplitListen(ListenerConfig entry)
    {
        var listen = entry.Listen?.Trim();
        if (string.IsNullOrEmpty(listen))
        {
            return (null, entry.Port);
        }

        if (listen[0] == '[')
        {
            var close = listen.IndexOf(']');
            if (close > 0)
            {
                var bracketed = listen[1..close];
                var rest = listen[(close + 1)..];
                if (rest.StartsWith(':') && int.TryParse(rest[1..], out var bracketedPort))
                {
                    return (bracketed, bracketedPort);
                }

                return (bracketed, entry.Port);
            }
        }

        var colon = listen.LastIndexOf(':');
        if (colon > 0 && listen[..colon].IndexOf(':') < 0 && int.TryParse(listen[(colon + 1)..], out var port))
        {
            return (listen[..colon], port);
        }

        return (listen, entry.Port);
    }
}
