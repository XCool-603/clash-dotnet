using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Runtime;
using Microsoft.Extensions.Logging;

namespace Clash.Server.Services;

/// <summary>
/// Raised when an endpoint needs the running core but the core is not up (either
/// because it failed to start or because it is being restarted).
/// </summary>
public sealed class ClashCoreUnavailableException : Exception
{
    /// <summary>Creates the exception with a human readable reason.</summary>
    public ClashCoreUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Owns the single <see cref="ClashRuntime"/> behind the control API.
/// <para>
/// The service is registered as a singleton and as an <see cref="IHostedService"/>,
/// so the web host owns the core's lifetime: it starts with the host and is
/// disposed with it. A core that fails to start is <em>not</em> fatal — the error
/// is recorded and surfaced through <c>GET /version</c> and <c>GET /configs</c> so
/// a broken configuration can still be repaired from the dashboard.
/// </para>
/// </summary>
public sealed class ClashService : IHostedService, IAsyncDisposable
{
    private readonly ClashRuntimeOptions _options;
    private readonly ILogger<ClashService> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private ClashRuntime? _runtime;
    private Exception? _startupError;
    private Exception? _lastError;
    private int _disposed;

    /// <summary>Creates the service for a set of runtime options.</summary>
    public ClashService(ClashRuntimeOptions options, ILogger<ClashService> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>The live runtime, or null while the core is down.</summary>
    public ClashRuntime? RuntimeOrNull => Volatile.Read(ref _runtime);

    /// <summary>The live runtime. Throws <see cref="ClashCoreUnavailableException"/> when it is down.</summary>
    public ClashRuntime Runtime => RuntimeOrNull ?? throw new ClashCoreUnavailableException(UnavailableMessage);

    /// <summary>Why the core is not running, when it failed to start.</summary>
    public Exception? StartupError => Volatile.Read(ref _startupError);

    /// <summary>The error raised by the most recent failed reload or restart.</summary>
    public Exception? LastError => Volatile.Read(ref _lastError);

    /// <summary>True once the core is up.</summary>
    public bool IsReady => RuntimeOrNull is not null;

    /// <summary>A message explaining why the core is unavailable.</summary>
    public string UnavailableMessage => StartupError is { } error
        ? $"the clash core is not running: {error.Message}"
        : "the clash core is not running";

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (RuntimeOrNull is not null) return;
            await StartCoreAsync(_options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => DisposeRuntimeAsync();

    /// <summary>Disposes the current runtime and starts a brand new one from the original options.</summary>
    public async Task RestartAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await DisposeRuntimeAsync().ConfigureAwait(false);
            await StartCoreAsync(_options, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("the clash core was restarted");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Applies a fully parsed configuration to the live runtime. When the core is
    /// down the configuration is used to start it, which is how a broken profile
    /// gets fixed from the UI.
    /// </summary>
    /// <returns>True when the configuration was applied.</returns>
    public async Task<bool> ReloadConfigAsync(ClashConfig config, bool force, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var runtime = RuntimeOrNull;
            if (runtime is null)
            {
                await StartCoreAsync(WithConfig(config), cancellationToken).ConfigureAwait(false);
                return RuntimeOrNull is not null;
            }

            await runtime.ReloadAsync(config, force, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _startupError, null);
            Volatile.Write(ref _lastError, null);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Volatile.Write(ref _lastError, ex);
            _logger.LogError(ex, "the configuration could not be applied");
            return false;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Merges a partial JSON/YAML update into the running configuration and
    /// reloads, which is what <c>PATCH /configs</c> does.
    /// </summary>
    public async Task ApplyPatchAsync(YamlMap patch, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(patch);

        var runtime = Runtime;
        var merged = MergePatch(runtime.Config.Raw, patch);
        var config = ConfigParser.Parse(merged);

        if (!await ReloadConfigAsync(config, force: false, cancellationToken).ConfigureAwait(false))
        {
            throw new ClashConfigException(LastError?.Message ?? "the configuration could not be applied");
        }
    }

    /// <summary>
    /// Deep-merges a partial document onto a base document. Mappings merge key by
    /// key; every other node replaces the base value (unlike merge profiles, a
    /// patch never appends to sequences).
    /// </summary>
    public static YamlMap MergePatch(YamlMap baseMap, YamlMap patch)
    {
        ArgumentNullException.ThrowIfNull(baseMap);
        ArgumentNullException.ThrowIfNull(patch);

        var result = new Dictionary<string, object?>(baseMap.Raw, StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in patch.Raw)
        {
            if (result.TryGetValue(key, out var existing) &&
                existing is Dictionary<string, object?> existingMap &&
                value is Dictionary<string, object?> patchMap)
            {
                result[key] = MergePatch(new YamlMap(existingMap), new YamlMap(patchMap)).Raw;
                continue;
            }

            result[key] = value;
        }

        return new YamlMap(result);
    }

    /// <summary>Builds the runtime options from the command line and the hosting services.</summary>
    public static ClashRuntimeOptions CreateOptions(string[] args, IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(services);

        var (configPath, homeDir) = ParseArguments(args);
        return new ClashRuntimeOptions
        {
            ConfigPath = configPath,
            HomeDir = homeDir,
            LoggerFactory = services.GetRequiredService<ILoggerFactory>(),
            // A first run with no configuration must come up usable: the runtime
            // writes a working starter config into the home directory, which the
            // user then edits (or replaces via Profiles) instead of staring at a
            // failed start.
            CreateDefaultConfigIfMissing = true,
        };
    }

    /// <summary>
    /// Recognises <c>--config &lt;path&gt;</c> / <c>-f &lt;path&gt;</c> and
    /// <c>-d &lt;dir&gt;</c> / <c>--home &lt;dir&gt;</c>. Both <c>--key value</c>
    /// and <c>--key=value</c> are accepted.
    /// </summary>
    public static (string? ConfigPath, string? HomeDir) ParseArguments(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        string? configPath = null;
        string? homeDir = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (TryMatchOption(arg, ["--config", "-f", "--config-file", "-config"], out var inlineConfig))
            {
                configPath = inlineConfig ?? NextValue(args, ref i) ?? configPath;
                continue;
            }

            if (TryMatchOption(arg, ["-d", "--home", "--dir", "--home-dir"], out var inlineHome))
            {
                homeDir = inlineHome ?? NextValue(args, ref i) ?? homeDir;
            }
        }

        return (configPath, homeDir);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        try
        {
            await _gate.WaitAsync().ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        try
        {
            await DisposeRuntimeAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    // ── Internals ────────────────────────────────────────────────────────────

    private async Task StartCoreAsync(ClashRuntimeOptions options, CancellationToken cancellationToken)
    {
        try
        {
            _runtime = await ClashRuntime.StartAsync(options, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _startupError, null);
            Volatile.Write(ref _lastError, null);
            _logger.LogInformation("the clash core is running (home: {Home})", _runtime.HomeDir);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            Volatile.Write(ref _runtime, null);
            Volatile.Write(ref _startupError, ex);
            Volatile.Write(ref _lastError, ex);
            _logger.LogError(
                ex,
                "the clash core could not start; the control API stays up so the configuration can be repaired");
        }
    }

    private async Task DisposeRuntimeAsync()
    {
        var runtime = Interlocked.Exchange(ref _runtime, null);
        if (runtime is null) return;

        try
        {
            await runtime.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "disposing the clash core failed");
        }
    }

    private ClashRuntimeOptions WithConfig(ClashConfig config) => new()
    {
        ConfigPath = _options.ConfigPath,
        HomeDir = _options.HomeDir,
        InlineConfig = config,
        LoggerFactory = _options.LoggerFactory,
        StartListeners = _options.StartListeners,
        ProxyProviderLoader = _options.ProxyProviderLoader,
        RuleProviderLoader = _options.RuleProviderLoader,
        CreateDefaultConfigIfMissing = _options.CreateDefaultConfigIfMissing,
    };

    private static bool TryMatchOption(string arg, string[] names, out string? value)
    {
        value = null;
        foreach (var name in names)
        {
            if (arg.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;

            var prefix = name + "=";
            if (arg.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                value = arg[prefix.Length..];
                return true;
            }
        }

        return false;
    }

    private static string? NextValue(string[] args, ref int index)
    {
        if (index + 1 >= args.Length) return null;

        var next = args[index + 1];
        if (next.Length > 1 && next[0] == '-') return null;

        index++;
        return next;
    }
}
