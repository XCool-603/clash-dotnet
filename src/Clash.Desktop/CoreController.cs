using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Clash.Core.Configuration;
using Clash.Core.Runtime;
using Clash.Server;
using Microsoft.AspNetCore.Builder;

namespace Clash.Desktop;

/// <summary>
/// Owns the embedded core: starts and stops <see cref="ClashHost"/> in-process and
/// talks to it over HTTP for everything the tray needs (mode, groups, config).
/// </summary>
internal sealed class CoreController : IAsyncDisposable
{
    private readonly string[] _args;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(10) };

    private WebApplication? _app;
    private string _secret = string.Empty;
    private int _mixedPort;
    private bool _disposed;

    public CoreController(string[] args)
    {
        _args = args;
        HomeDir = ResolveHomeDir(args);
        ConfigPath = ClashRuntime.ResolveConfigPath(ResolveConfigArgument(args), HomeDir);
        ControllerAddress = "127.0.0.1:9090";
        BaseUrl = "http://127.0.0.1:9090";
    }

    /// <summary>Directory holding the configuration, profiles and providers.</summary>
    public string HomeDir { get; }

    /// <summary>The active configuration file, when one exists.</summary>
    public string? ConfigPath { get; private set; }

    /// <summary>The <c>host:port</c> the control API listens on.</summary>
    public string ControllerAddress { get; private set; }

    /// <summary>Base URL of the control API.</summary>
    public string BaseUrl { get; private set; }

    /// <summary>Dashboard URL opened in the browser.</summary>
    public string DashboardUrl => BaseUrl + "/";

    /// <summary>The configured mixed proxy port, once the config has been read.</summary>
    public int MixedPort => _mixedPort;

    /// <summary>True while the embedded host is running.</summary>
    public bool IsRunning => _app is not null;

    /// <summary>Raised when the core stops unexpectedly.</summary>
    public event Action<string>? Faulted;

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_app is not null) return;

            ReadConfiguration();

            var app = ClashHost.Build(_args);
            try
            {
                await app.StartAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await app.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException(DescribeStartFailure(ex), ex);
            }

            _app = app;
            _client.DefaultRequestHeaders.Authorization = string.IsNullOrEmpty(_secret)
                ? null
                : new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _secret);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task StopAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var app = _app;
            _app = null;
            if (app is null) return;

            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await app.StopAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Shutting down; a slow stop is not worth surfacing.
            }
            finally
            {
                await app.DisposeAsync().ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RestartAsync(CancellationToken cancellationToken = default)
    {
        await StopAsync().ConfigureAwait(false);
        await StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Waits until <c>/version</c> answers, so the UI never reports "running" too early.</summary>
    public async Task<bool> WaitUntilReadyAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline && !cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var response = await _client.GetAsync(BaseUrl + "/version", cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode) return true;
            }
            catch (Exception)
            {
                // Not up yet.
            }

            try
            {
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        return false;
    }

    /// <summary>Reads <c>GET /configs</c> and returns the parsed object.</summary>
    public async Task<JsonNode?> GetConfigsAsync(CancellationToken cancellationToken = default)
        => await GetJsonAsync("/configs", cancellationToken).ConfigureAwait(false);

    /// <summary>The current routing mode, or null when the core is unreachable.</summary>
    public async Task<string?> GetModeAsync(CancellationToken cancellationToken = default)
        => (await GetConfigsAsync(cancellationToken).ConfigureAwait(false))?["mode"]?.GetValue<string>();

    /// <summary>Switches the routing mode via <c>PATCH /configs</c>.</summary>
    public Task<bool> SetModeAsync(string mode, CancellationToken cancellationToken = default)
        => PatchAsync("/configs", new JsonObject { ["mode"] = mode }, cancellationToken);

    /// <summary>Every <c>Selector</c> group with its members and current choice.</summary>
    public async Task<IReadOnlyList<SelectorGroupInfo>> GetSelectorGroupsAsync(CancellationToken cancellationToken = default)
    {
        var proxies = await GetJsonAsync("/proxies", cancellationToken).ConfigureAwait(false);
        var result = new List<SelectorGroupInfo>();
        if (proxies?["proxies"] is not JsonObject all) return result;

        foreach (var (name, node) in all)
        {
            if (node is null) continue;

            var type = node["type"]?.GetValue<string>();
            if (!string.Equals(type, "Selector", StringComparison.OrdinalIgnoreCase)) continue;

            var members = node["all"] is JsonArray array
                ? array.Select(x => x?.GetValue<string>() ?? string.Empty).Where(s => s.Length > 0).ToArray()
                : [];

            result.Add(new SelectorGroupInfo(name, node["now"]?.GetValue<string>() ?? string.Empty, members));
        }

        return result;
    }

    /// <summary>Selects a member of a group via <c>PUT /proxies/:name</c>.</summary>
    public Task<bool> SelectProxyAsync(string group, string proxy, CancellationToken cancellationToken = default)
        => PatchAsync($"/proxies/{Uri.EscapeDataString(group)}", new JsonObject { ["name"] = proxy }, cancellationToken, "PUT");

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        await StopAsync().ConfigureAwait(false);
        _client.Dispose();
        _gate.Dispose();
    }

    // ── Internals ────────────────────────────────────────────────────────────

    private async Task<JsonNode?> GetJsonAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _client.GetAsync(BaseUrl + path, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return null;

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return JsonNode.Parse(body);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"GET {path} failed: {ex.Message}");
            return null;
        }
    }

    private async Task<bool> PatchAsync(string path, JsonNode payload, CancellationToken cancellationToken, string method = "PATCH")
    {
        try
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), BaseUrl + path)
            {
                Content = new StringContent(payload.ToJsonString(), Encoding.UTF8, "application/json"),
            };

            using var response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"{method} {path} failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>Reads the control address, secret and mixed port out of the configuration file.</summary>
    private void ReadConfiguration()
    {
        if (ConfigPath is null || !File.Exists(ConfigPath)) return;

        try
        {
            var config = ConfigParser.Parse(YamlReader.Parse(File.ReadAllText(ConfigPath)));
            _secret = config.Secret;
            _mixedPort = config.MixedPort != 0 ? config.MixedPort : config.Port;

            if (!string.IsNullOrWhiteSpace(config.ExternalController))
            {
                ControllerAddress = config.ExternalController;
                BaseUrl = BuildBaseUrl(config.ExternalController);
            }
        }
        catch (Exception ex)
        {
            Faulted?.Invoke($"the configuration could not be read ({ex.Message}); using defaults");
        }
    }

    private static string BuildBaseUrl(string controller)
    {
        var address = controller.Trim();
        if (address.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            address.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return address.TrimEnd('/');
        }

        // Clash writes the bare `host:port` form; `:9090` means "all interfaces".
        if (address.StartsWith(':')) address = "127.0.0.1" + address;
        if (address.StartsWith("0.0.0.0", StringComparison.Ordinal))
        {
            address = "127.0.0.1" + address["0.0.0.0".Length..];
        }

        return "http://" + address;
    }

    /// <summary>Turns a bind failure into something a user can act on.</summary>
    private string DescribeStartFailure(Exception ex)
    {
        var port = ExtractPort(ControllerAddress);
        if (port > 0 && IsPortInUse(port))
        {
            return $"The control port {port} is already in use. Another Clash instance (or another " +
                   $"program) is holding it. Close it, or change `external-controller` in {ConfigPath ?? "the configuration"}.";
        }

        return $"The core failed to start: {ex.Message}";
    }

    private static int ExtractPort(string address)
    {
        var colon = address.LastIndexOf(':');
        return colon > 0 && int.TryParse(address[(colon + 1)..], out var port) ? port : 0;
    }

    private static bool IsPortInUse(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return false;
        }
        catch (SocketException)
        {
            return true;
        }
    }

    private static string? ResolveConfigArgument(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--config" or "-f" && i + 1 < args.Length) return args[i + 1];
            if (args[i].StartsWith("--config=", StringComparison.Ordinal)) return args[i]["--config=".Length..];
        }
        return null;
    }

    private static string ResolveHomeDir(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is "--home" or "-d" && i + 1 < args.Length) return Path.GetFullPath(args[i + 1]);
            if (args[i].StartsWith("--home=", StringComparison.Ordinal)) return Path.GetFullPath(args[i]["--home=".Length..]);
            if (args[i].StartsWith("-d=", StringComparison.Ordinal)) return Path.GetFullPath(args[i][3..]);
        }

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".config",
            "clash");
    }
}

/// <summary>One <c>Selector</c> group as the tray needs it.</summary>
internal sealed record SelectorGroupInfo(string Name, string Now, IReadOnlyList<string> Members);
