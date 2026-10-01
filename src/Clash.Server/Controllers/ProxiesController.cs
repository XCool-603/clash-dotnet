using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary>
/// <c>/proxies</c> and <c>/group</c>: listing adapters, switching a selector and
/// measuring delays.
/// </summary>
[ApiController]
public sealed class ProxiesController : ControllerBase
{
    /// <summary>Clash's default delay probe URL.</summary>
    public const string DefaultTestUrl = "https://www.gstatic.com/generate_204";

    private const int DefaultTimeoutMs = 5000;

    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public ProxiesController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /proxies</c> — every adapter, keyed by name.</summary>
    [HttpGet("/proxies")]
    public IActionResult List()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        // The live registry hangs off the tunnel: a reload swaps it, while
        // ClashRuntime.Proxies keeps pointing at the retired one.
        var registry = runtime.Tunnel.Proxies;
        var proxies = new Dictionary<string, Dictionary<string, object?>>(StringComparer.Ordinal);
        foreach (var (name, proxy) in registry.Proxies)
        {
            proxies[name] = ApiProjections.BuildProxy(proxy);
        }

        return Ok(new ProxiesResponse { Proxies = proxies });
    }

    /// <summary><c>GET /proxies/:name</c> — one adapter.</summary>
    [HttpGet("/proxies/{name}")]
    public IActionResult Get(string name)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var proxy = runtime.Tunnel.Proxies.Get(name);
        if (proxy is null) return NotFound(new MessageResponse { Message = $"proxy [{name}] not found" });

        return Ok(ApiProjections.BuildProxy(proxy));
    }

    /// <summary>
    /// <c>PUT /proxies/:name</c> — selects a member of a <c>select</c> group (and
    /// of <c>GLOBAL</c>). Only selectors accept a selection.
    /// </summary>
    [HttpPut("/proxies/{name}")]
    public async Task<IActionResult> Select(string name, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var proxy = runtime.Tunnel.Proxies.Get(name);
        if (proxy is null) return NotFound(new MessageResponse { Message = $"proxy [{name}] not found" });

        if (proxy.Type != ProxyType.Selector)
        {
            return BadRequest(new MessageResponse { Message = $"proxy [{name}] is not a selector" });
        }

        YamlMap? body;
        try
        {
            body = await ApiDocuments.ReadMapAsync(Request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        var member = body?.GetNonEmptyString("name");
        if (member is null)
        {
            return BadRequest(new MessageResponse { Message = "name is required" });
        }

        if (proxy is not IProxyGroup group)
        {
            return BadRequest(new MessageResponse { Message = $"proxy [{name}] is not a group" });
        }

        if (!await group.SelectAsync(member).ConfigureAwait(false))
        {
            return BadRequest(new MessageResponse { Message = $"proxy [{member}] not found in group [{name}]" });
        }

        return NoContent();
    }

    /// <summary><c>GET /proxies/:name/delay</c> — probes one adapter.</summary>
    [HttpGet("/proxies/{name}/delay")]
    public async Task<IActionResult> Delay(
        string name,
        [FromQuery] string? url,
        [FromQuery] int timeout,
        CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var proxy = runtime.Tunnel.Proxies.Get(name);
        if (proxy is null) return NotFound(new MessageResponse { Message = $"proxy [{name}] not found" });

        var delay = await ProbeAsync(runtime, proxy, url, timeout, cancellationToken).ConfigureAwait(false);
        return Ok(new DelayResponse { Delay = delay });
    }

    /// <summary><c>GET /group/:name/delay</c> — probes every member of a group.</summary>
    [HttpGet("/group/{name}/delay")]
    public async Task<IActionResult> GroupDelay(
        string name,
        [FromQuery] string? url,
        [FromQuery] int timeout,
        CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var proxy = runtime.Tunnel.Proxies.Get(name);
        if (proxy is null) return NotFound(new MessageResponse { Message = $"proxy [{name}] not found" });
        if (proxy is not IProxyGroup group)
        {
            return BadRequest(new MessageResponse { Message = $"proxy [{name}] is not a group" });
        }

        var results = new Dictionary<string, int>(StringComparer.Ordinal);
        var effectiveUrl = string.IsNullOrWhiteSpace(url) ? group.TestUrl : url!;
        var effectiveTimeout = timeout > 0 ? timeout : DefaultTimeoutMs;

        using var gate = new SemaphoreSlim(8);
        var tasks = group.Members.Select(async member =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var delay = await ProbeAsync(runtime, member, effectiveUrl, effectiveTimeout, cancellationToken)
                    .ConfigureAwait(false);
                lock (results) results[member.Name] = delay;
            }
            finally
            {
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return Ok(results);
    }

    /// <summary><c>GET /group</c> — every group object.</summary>
    [HttpGet("/group")]
    public IActionResult Groups()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var groups = runtime.Tunnel.Proxies.Proxies.Values
            .Where(proxy => proxy.IsGroup)
            .Select(ApiProjections.BuildProxy)
            .ToList();

        return Ok(new { proxies = groups });
    }

    private static async Task<int> ProbeAsync(
        Clash.Core.Runtime.ClashRuntime runtime,
        IProxy proxy,
        string? url,
        int timeout,
        CancellationToken cancellationToken)
    {
        var target = string.IsNullOrWhiteSpace(url) ? DefaultTestUrl : url!;
        var effectiveTimeout = timeout > 0 ? timeout : DefaultTimeoutMs;

        try
        {
            var result = await runtime.Tunnel.DelayTester
                .TestAsync(proxy, target, effectiveTimeout, cancellationToken)
                .ConfigureAwait(false);

            var delay = Math.Max(0, result.DelayMs);
            if (proxy is ProxyAdapter adapter) adapter.PushHistory(delay);
            return delay;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return 0;
        }
    }

    private ObjectResult CoreUnavailable()
        => StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = _clash.UnavailableMessage });
}
