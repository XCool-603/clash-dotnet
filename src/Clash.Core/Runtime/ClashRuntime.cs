using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Dns;
using Clash.Core.Listeners;
using Clash.Core.Providers;
using Clash.Core.Rules;
using Clash.Core.Transport;
using Clash.Core.Tunnel;
using Microsoft.Extensions.Logging;

namespace Clash.Core.Runtime;

/// <summary>Everything needed to bring a Clash instance up.</summary>
public sealed class ClashRuntimeOptions
{
    /// <summary>Explicit configuration file. When null the standard locations are probed.</summary>
    public string? ConfigPath { get; init; }

    /// <summary>Home directory for profiles, providers and caches. Defaults to <c>%USERPROFILE%\.config\clash</c>.</summary>
    public string? HomeDir { get; init; }

    /// <summary>A configuration supplied inline instead of from disk (used by tests).</summary>
    public ClashConfig? InlineConfig { get; init; }

    /// <summary>Raw YAML supplied inline, parsed when <see cref="InlineConfig"/> is null.</summary>
    public string? InlineYaml { get; init; }

    public required ILoggerFactory LoggerFactory { get; init; }

    /// <summary>Starts the inbound listeners. Disabled by tests.</summary>
    public bool StartListeners { get; init; } = true;

    /// <summary>Optional provider loader; providers are skipped when null.</summary>
    public IProxyProviderLoader? ProxyProviderLoader { get; init; }

    public IRuleProviderLoader? RuleProviderLoader { get; init; }

    /// <summary>Writes a starter configuration when none exists. Disabled by tests.</summary>
    public bool CreateDefaultConfigIfMissing { get; init; } = true;
}

/// <summary>
/// Owns the live proxy stack: configuration, DNS, geo data, the rule engine, the
/// proxy registry, the tunnel and the inbound listeners. Reloading a profile is
/// an operation on this object.
/// </summary>
public sealed class ClashRuntime : IAsyncDisposable
{
    private readonly ILogger<ClashRuntime> _logger;
    private readonly ClashRuntimeOptions _options;
    private readonly ITunnelAccessor _accessor = new TunnelAccessor();
    private readonly SemaphoreSlim _reloadGate = new(1, 1);
    private readonly List<IInboundListener> _extraListeners = [];
    private readonly IReadOnlyDictionary<string, IRuleSet> _ruleSets;

    private ListenerManager? _listenerManager;
    private int _disposed;

    private ClashRuntime(
        ClashConfig config,
        ClashRuntimeOptions options,
        IDnsResolver dns,
        IGeoData geo,
        IRuleEngine rules,
        IReadOnlyDictionary<string, IRuleSet> ruleSets,
        ProxyManager proxies,
        Tunnel.Tunnel tunnel,
        string? configPath,
        string homeDir)
    {
        Config = config;
        _options = options;
        _logger = options.LoggerFactory.CreateLogger<ClashRuntime>();
        Dns = dns;
        Geo = geo;
        Rules = rules;
        _ruleSets = ruleSets;
        Proxies = proxies;
        Tunnel = tunnel;
        ConfigPath = configPath;
        HomeDir = homeDir;
        Profiles = new ProfileManager(homeDir, options.LoggerFactory.CreateLogger<ProfileManager>());
    }

    public ClashConfig Config { get; private set; }

    public IDnsResolver Dns { get; }

    public IGeoData Geo { get; }

    public IRuleEngine Rules { get; }

    public ProxyManager Proxies { get; }

    public Tunnel.Tunnel Tunnel { get; }

    /// <summary>Profile (subscription) storage and activation.</summary>
    public ProfileManager Profiles { get; }

    /// <summary>The configuration file this instance was loaded from, when any.</summary>
    public string? ConfigPath { get; private set; }

    /// <summary>Directory holding profiles, providers and caches.</summary>
    public string HomeDir { get; }

    /// <summary>Every rule set loaded from <c>rule-providers</c>.</summary>
    public IReadOnlyDictionary<string, IRuleSet> RuleSets => _ruleSets;

    /// <summary>Extra listeners created by subsystems such as TUN.</summary>
    public IReadOnlyList<IInboundListener> ExtraListeners => _extraListeners;

    public static async Task<ClashRuntime> StartAsync(ClashRuntimeOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(options.LoggerFactory);

        var logger = options.LoggerFactory.CreateLogger<ClashRuntime>();
        var homeDir = ResolveHomeDir(options);

        // 1. Configuration -----------------------------------------------------
        var (config, configPath) = LoadConfiguration(options, homeDir, logger);

        // 2. Components --------------------------------------------------------
        var dns = Components.CreateDns(config, options.LoggerFactory);
        var geo = Components.CreateGeo(config, options.LoggerFactory);
        try
        {
            await geo.LoadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            logger.LogWarning("geo data could not be loaded, GEOIP/GEOSITE rules will not match: {Message}", ex.Message);
        }

        var ruleSets = await LoadRuleSetsAsync(config, options, cancellationToken).ConfigureAwait(false);
        var rules = Components.CreateRules(config, dns, geo, ruleSets, options.LoggerFactory);

        var transports = Components.CreateTransports(options.LoggerFactory);
        var accessor = new TunnelAccessor();

        var factory = new ProxyFactory(
            new AdapterBuildContext
            {
                Config = config,
                Tunnel = accessor,
                Transports = transports,
                LoggerFactory = options.LoggerFactory,
                Log = (level, message) => logger.LogInformation("{Message}", message),
            },
            Components.CreateSelectionStore(homeDir, config),
            options.ProxyProviderLoader);

        var proxies = await factory.BuildAsync(config, cancellationToken).ConfigureAwait(false);

        // 3. Tunnel ------------------------------------------------------------
        var tunnel = new Tunnel.Tunnel(
            config, dns, geo, proxies, rules, options.LoggerFactory.CreateLogger<Tunnel.Tunnel>());
        accessor.Attach(tunnel);

        var runtime = new ClashRuntime(
            config, options, dns, geo, rules, ruleSets, proxies, tunnel, configPath, homeDir);

        // 4. Listeners ---------------------------------------------------------
        if (options.StartListeners)
        {
            await runtime.StartListenersAsync(cancellationToken).ConfigureAwait(false);
        }

        logger.LogInformation(
            "clash runtime started: {Proxies} adapters, {Rules} rules, mode {Mode}",
            proxies.All.Count, rules.Rules.Count, config.Mode.ToApiString());

        return runtime;
    }

    /// <summary>Starts (or restarts) the inbound listeners for the current config.</summary>
    public async Task StartListenersAsync(CancellationToken cancellationToken = default)
    {
        _listenerManager ??= new ListenerManager(Config, _options.LoggerFactory.CreateLogger<ListenerManager>());
        await _listenerManager.StartAsync(Tunnel, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Registers a listener owned by another subsystem so it is stopped with the runtime.</summary>
    public void RegisterExtraListener(IInboundListener listener)
    {
        ArgumentNullException.ThrowIfNull(listener);
        _extraListeners.Add(listener);
    }

    /// <summary>
    /// Applies a new configuration. <paramref name="force"/> restarts the listeners
    /// even when only the ports changed; a non-forced reload keeps existing
    /// listeners when the ports are unchanged.
    /// </summary>
    public async Task ReloadAsync(ClashConfig config, bool force = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(config);
        await _reloadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previousPorts = Ports(Config);
            var previousMode = Config.Mode;

            // Rule sets first: the engine needs them to parse RULE-SET rules.
            var ruleSets = await LoadRuleSetsAsync(config, _options, cancellationToken).ConfigureAwait(false);
            var rules = Components.CreateRules(config, Dns, Geo, ruleSets, _options.LoggerFactory);

            var factory = new ProxyFactory(
                new AdapterBuildContext
                {
                    Config = config,
                    Tunnel = _accessor,
                    Transports = Components.CreateTransports(_options.LoggerFactory),
                    LoggerFactory = _options.LoggerFactory,
                },
                Components.CreateSelectionStore(HomeDir, config),
                _options.ProxyProviderLoader);

            var proxies = await factory.BuildAsync(config, cancellationToken).ConfigureAwait(false);

            // Swap the registry contents into the live tunnel without dropping it,
            // so in-flight flows keep their accounting.
            Tunnel.ReplaceProxies(proxies, rules);
            Tunnel.UpdateConfig(config);
            Tunnel.Mode = config.Mode;

            Config = config;

            if (_listenerManager is not null)
            {
                if (force || !previousPorts.SetEquals(Ports(config)))
                {
                    await _listenerManager.ReloadAsync(config, Tunnel, cancellationToken).ConfigureAwait(false);
                }
            }

            _logger.LogInformation(
                "configuration reloaded (mode {Old} -> {New}, {Proxies} adapters, {Rules} rules)",
                previousMode.ToApiString(), config.Mode.ToApiString(), proxies.All.Count, rules.Rules.Count);
        }
        finally
        {
            _reloadGate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

        if (_listenerManager is not null)
        {
            try { await _listenerManager.StopAsync().ConfigureAwait(false); } catch { /* shutting down */ }
            try { await _listenerManager.DisposeAsync().ConfigureAwait(false); } catch { /* shutting down */ }
        }

        foreach (var listener in _extraListeners)
        {
            try { await listener.StopAsync().ConfigureAwait(false); } catch { /* shutting down */ }
            try { await listener.DisposeAsync().ConfigureAwait(false); } catch { /* shutting down */ }
        }
        _extraListeners.Clear();

        await Tunnel.DisposeAsync().ConfigureAwait(false);
        _reloadGate.Dispose();
        GC.SuppressFinalize(this);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static HashSet<int> Ports(ClashConfig config)
        => [config.Port, config.SocksPort, config.MixedPort, config.RedirPort, config.TProxyPort];

    private static string ResolveHomeDir(ClashRuntimeOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.HomeDir)) return options.HomeDir!;

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(profile, ".config", "clash");
    }

    private static (ClashConfig Config, string? Path) LoadConfiguration(
        ClashRuntimeOptions options,
        string homeDir,
        ILogger logger)
    {
        if (options.InlineConfig is not null) return (options.InlineConfig, null);

        if (options.InlineYaml is not null)
        {
            return (ConfigParser.Parse(YamlReader.Parse(options.InlineYaml)), null);
        }

        var path = ResolveConfigPath(options.ConfigPath, homeDir);
        if (path is null)
        {
            if (!options.CreateDefaultConfigIfMissing)
            {
                throw new ClashConfigException("no configuration file found and default creation is disabled");
            }

            Directory.CreateDirectory(homeDir);
            path = Path.Combine(homeDir, "config.yaml");
            File.WriteAllText(path, DefaultConfiguration.Yaml);
            logger.LogInformation("wrote a starter configuration to {Path}", path);
        }

        var text = File.ReadAllText(path);
        return (ConfigParser.Parse(YamlReader.Parse(text)), path);
    }

    /// <summary>Probes the standard locations for a configuration file.</summary>
    public static string? ResolveConfigPath(string? explicitPath, string homeDir)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return File.Exists(explicitPath) ? Path.GetFullPath(explicitPath) : explicitPath;
        }

        var candidates = new[]
        {
            Path.Combine(homeDir, "config.yaml"),
            Path.Combine(homeDir, "config.yml"),
            Path.Combine(AppContext.BaseDirectory, "config.yaml"),
            Path.Combine(Directory.GetCurrentDirectory(), "config.yaml"),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static async Task<IReadOnlyDictionary<string, IRuleSet>> LoadRuleSetsAsync(
        ClashConfig config,
        ClashRuntimeOptions options,
        CancellationToken cancellationToken)
    {
        var sets = new Dictionary<string, IRuleSet>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, providerConfig) in config.RuleProviders)
        {
            // An inline payload needs no loader.
            if (providerConfig.Payload is { Count: > 0 } inline)
            {
                sets[name] = Components.CreateRuleSet(name, providerConfig.Behavior, inline);
                continue;
            }

            if (options.RuleProviderLoader is null) continue;

            try
            {
                var result = await options.RuleProviderLoader.LoadAsync(name, providerConfig, cancellationToken)
                    .ConfigureAwait(false);
                sets[name] = options.RuleProviderLoader.ToRuleSet(name, result);
            }
            catch (Exception ex)
            {
                options.LoggerFactory.CreateLogger<ClashRuntime>()
                    .LogWarning("rule provider [{Name}] failed: {Message}", name, ex.Message);
            }
        }

        return sets;
    }
}
