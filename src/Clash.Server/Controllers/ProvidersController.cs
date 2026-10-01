using Clash.Core.Adapter;
using Clash.Core.Configuration;
using Clash.Core.Providers;
using Clash.Core.Runtime;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary>
/// <c>/providers</c>: the <c>proxy-providers</c> and <c>rule-providers</c>
/// entries, their contents, and the refresh/health-check triggers.
/// <para>
/// The provider loaders are optional services. When none is registered the
/// endpoints answer <c>501</c> with an explanation instead of throwing.
/// </para>
/// </summary>
[ApiController]
public sealed class ProvidersController : ControllerBase
{
    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public ProvidersController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /providers/proxies</c> — every proxy provider.</summary>
    [HttpGet("/providers/proxies")]
    public IActionResult ListProxyProviders()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var providers = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var (name, config) in runtime.Config.ProxyProviders)
        {
            providers[name] = BuildProxyProvider(runtime, name, config);
        }

        return Ok(new ProvidersResponse { Providers = providers });
    }

    /// <summary><c>GET /providers/proxies/:name</c> — one proxy provider.</summary>
    [HttpGet("/providers/proxies/{name}")]
    public IActionResult GetProxyProvider(string name)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        if (!runtime.Config.ProxyProviders.TryGetValue(name, out var config))
        {
            return NotFound(new MessageResponse { Message = $"proxy provider [{name}] not found" });
        }

        return Ok(BuildProxyProvider(runtime, name, config));
    }

    /// <summary><c>PUT /providers/proxies/:name</c> — forces a re-fetch, then reloads.</summary>
    [HttpPut("/providers/proxies/{name}")]
    public async Task<IActionResult> RefreshProxyProvider(string name, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var loader = HttpContext.RequestServices.GetService<IProxyProviderLoader>();
        if (loader is null) return NotRegistered("proxy provider");

        if (!runtime.Config.ProxyProviders.TryGetValue(name, out var config))
        {
            return NotFound(new MessageResponse { Message = $"proxy provider [{name}] not found" });
        }

        try
        {
            await loader.RefreshAsync(name, config, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        if (!await _clash.ReloadConfigAsync(runtime.Config, force: false, cancellationToken).ConfigureAwait(false))
        {
            return BadRequest(new MessageResponse { Message = _clash.LastError?.Message ?? "the reload failed" });
        }

        return NoContent();
    }

    /// <summary><c>GET /providers/proxies/:name/healthcheck</c> — probes every node of a provider.</summary>
    [HttpGet("/providers/proxies/{name}/healthcheck")]
    public async Task<IActionResult> HealthCheck(string name, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        if (!runtime.Config.ProxyProviders.TryGetValue(name, out var config))
        {
            return NotFound(new MessageResponse { Message = $"proxy provider [{name}] not found" });
        }

        var members = MembersOf(runtime, name);
        var url = string.IsNullOrWhiteSpace(config.HealthCheck.Url) ? ProxiesController.DefaultTestUrl : config.HealthCheck.Url;
        var timeout = config.HealthCheck.Timeout > 0 ? config.HealthCheck.Timeout : 5000;

        using var gate = new SemaphoreSlim(8);
        var tasks = members.Select(async member =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var probe = await runtime.Tunnel.DelayTester
                    .TestAsync(member, url, timeout, cancellationToken)
                    .ConfigureAwait(false);
                if (member is ProxyAdapter adapter) adapter.PushHistory(Math.Max(0, probe.DelayMs));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                // A failed probe simply leaves the node marked dead.
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return NoContent();
    }

    /// <summary><c>GET /providers/rules</c> — every rule provider.</summary>
    [HttpGet("/providers/rules")]
    public IActionResult ListRuleProviders()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var providers = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var (name, config) in runtime.Config.RuleProviders)
        {
            providers[name] = BuildRuleProvider(runtime, name, config);
        }

        return Ok(new ProvidersResponse { Providers = providers });
    }

    /// <summary><c>PUT /providers/rules/:name</c> — forces a re-fetch of a rule provider.</summary>
    [HttpPut("/providers/rules/{name}")]
    public async Task<IActionResult> RefreshRuleProvider(string name, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var loader = HttpContext.RequestServices.GetService<IRuleProviderLoader>();
        if (loader is null) return NotRegistered("rule provider");

        if (!runtime.Config.RuleProviders.TryGetValue(name, out var config))
        {
            return NotFound(new MessageResponse { Message = $"rule provider [{name}] not found" });
        }

        try
        {
            await loader.RefreshAsync(name, config, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        if (!await _clash.ReloadConfigAsync(runtime.Config, force: false, cancellationToken).ConfigureAwait(false))
        {
            return BadRequest(new MessageResponse { Message = _clash.LastError?.Message ?? "the reload failed" });
        }

        return NoContent();
    }

    // ── Projections ──────────────────────────────────────────────────────────

    private static Dictionary<string, object?> BuildProxyProvider(
        ClashRuntime runtime,
        string name,
        ProxyProviderConfig config)
    {
        var provider = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["name"] = name,
            ["type"] = "Proxy",
            ["vehicleType"] = VehicleType(config.Type),
            ["proxies"] = MembersOf(runtime, name).Select(ApiProjections.BuildProxy).ToList(),
        };

        AddIfKnown(provider, "updatedAt", ProviderUpdatedAt(runtime, config.Path));

        // `subscriptionInfo` is only known once a provider has actually been
        // fetched with subscription headers; the loader does not retain it, so the
        // field is omitted rather than reported as zeroes.
        return provider;
    }

    private static Dictionary<string, object?> BuildRuleProvider(
        ClashRuntime runtime,
        string name,
        RuleProviderConfig config)
    {
        var ruleSets = runtime.Tunnel.Rules.RuleSets;
        var count = ruleSets.TryGetValue(name, out var set) ? set.Count : 0;

        var provider = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["name"] = name,
            ["type"] = "Rule",
            ["behavior"] = config.Behavior,
            ["ruleCount"] = count,
            ["vehicleType"] = VehicleType(config.Type),
            ["format"] = config.Format,
        };

        AddIfKnown(provider, "updatedAt", ProviderUpdatedAt(runtime, config.Path));
        return provider;
    }

    private static IReadOnlyList<IProxy> MembersOf(ClashRuntime runtime, string providerName)
        => runtime.Tunnel.Proxies.ProviderProxies.TryGetValue(providerName, out var members) ? members : [];

    private static void AddIfKnown(Dictionary<string, object?> target, string key, object? value)
    {
        if (value is not null) target[key] = value;
    }

    private static DateTimeOffset? ProviderUpdatedAt(ClashRuntime runtime, string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;

        var resolved = System.IO.Path.IsPathRooted(path)
            ? path
            : System.IO.Path.Combine(runtime.HomeDir, path);

        return System.IO.File.Exists(resolved) ? System.IO.File.GetLastWriteTimeUtc(resolved) : null;
    }

    private static string VehicleType(string? type) => type?.Trim().ToLowerInvariant() switch
    {
        "file" => "File",
        "inline" => "Inline",
        _ => "HTTP",
    };

    private ObjectResult CoreUnavailable()
        => StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = _clash.UnavailableMessage });

    private ObjectResult NotRegistered(string kind) => StatusCode(
        StatusCodes.Status501NotImplemented,
        new MessageResponse { Message = $"no {kind} loader is registered in this build" });
}
