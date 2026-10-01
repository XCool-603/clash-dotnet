using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Providers;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary>
/// <c>/profiles</c>: the application level profile store backing the dashboard's
/// Profiles page, plus <c>POST /subscription/parse</c>.
/// </summary>
[ApiController]
public sealed class ProfilesController : ControllerBase
{
    private const string SubscriptionUserAgent = "clash-verge/v1.0.0";

    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public ProfilesController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /profiles</c> — every stored profile, selected first.</summary>
    [HttpGet("/profiles")]
    public IActionResult List()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        return Ok(new ProfilesResponse { Profiles = runtime.Profiles.List().Cast<object>().ToList() });
    }

    /// <summary><c>POST /profiles</c> — creates a profile from a name, type and optional body.</summary>
    [HttpPost("/profiles")]
    public async Task<IActionResult> Create(CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var body = await ReadBodyAsync(cancellationToken).ConfigureAwait(false);
        if (body is null) return BadRequest(new MessageResponse { Message = "the request body must be an object" });

        var name = body.GetNonEmptyString("name") ?? $"profile-{DateTime.Now:yyyyMMdd-HHmmss}";
        var type = (body.GetNonEmptyString("type") ?? "local").ToLowerInvariant();
        var url = body.GetNonEmptyString("url");
        var content = body.GetString("content");

        try
        {
            return Ok(runtime.Profiles.Create(name, type, url, content));
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
    }

    /// <summary><c>PUT /profiles/:id</c> — renames a profile or changes its URL/description.</summary>
    [HttpPut("/profiles/{id}")]
    public async Task<IActionResult> Update(string id, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var body = await ReadBodyAsync(cancellationToken).ConfigureAwait(false);
        if (body is null) return BadRequest(new MessageResponse { Message = "the request body must be an object" });

        var updated = runtime.Profiles.Update(
            id,
            body.GetNonEmptyString("name"),
            body.Has("url") ? body.GetString("url") : null,
            body.Has("description") ? body.GetString("description") : null);

        return updated ? NoContent() : NotFound(new MessageResponse { Message = $"profile [{id}] not found" });
    }

    /// <summary><c>DELETE /profiles/:id</c> — removes a profile.</summary>
    [HttpDelete("/profiles/{id}")]
    public IActionResult Delete(string id)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        runtime.Profiles.Delete(id);
        return NoContent();
    }

    /// <summary><c>PUT /profiles/:id/select</c> — activates a profile and reloads the core.</summary>
    [HttpPut("/profiles/{id}/select")]
    public async Task<IActionResult> Select(string id, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        if (!runtime.Profiles.Select(id)) return NotFound(new MessageResponse { Message = $"profile [{id}] not found" });

        ClashConfig config;
        try
        {
            config = runtime.Profiles.BuildActiveConfig();
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        if (!await _clash.ReloadConfigAsync(config, force: true, cancellationToken).ConfigureAwait(false))
        {
            return BadRequest(new MessageResponse { Message = _clash.LastError?.Message ?? "the reload failed" });
        }

        return NoContent();
    }

    /// <summary><c>PUT /profiles/:id/update</c> — re-downloads a remote profile and reloads it when active.</summary>
    [HttpPut("/profiles/{id}/update")]
    public async Task<IActionResult> UpdateRemote(string id, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        Profile profile;
        try
        {
            profile = await runtime.Profiles.UpdateRemoteAsync(id, cancellationToken).ConfigureAwait(false);
        }
        catch (ClashException ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
        catch (HttpRequestException ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        if (profile.Selected)
        {
            ClashConfig config;
            try
            {
                config = runtime.Profiles.BuildActiveConfig();
            }
            catch (Exception ex)
            {
                return BadRequest(new MessageResponse { Message = ex.Message });
            }

            if (!await _clash.ReloadConfigAsync(config, force: true, cancellationToken).ConfigureAwait(false))
            {
                return BadRequest(new MessageResponse { Message = _clash.LastError?.Message ?? "the reload failed" });
            }
        }

        return NoContent();
    }

    /// <summary><c>POST /profiles/import-url</c> — downloads a subscription as a new profile.</summary>
    [HttpPost("/profiles/import-url")]
    public async Task<IActionResult> ImportUrl(CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var body = await ReadBodyAsync(cancellationToken).ConfigureAwait(false);
        var url = body?.GetNonEmptyString("url");
        if (url is null) return BadRequest(new MessageResponse { Message = "url is required" });

        try
        {
            var profile = await runtime.Profiles
                .ImportUrlAsync(url, body?.GetNonEmptyString("name"), cancellationToken)
                .ConfigureAwait(false);
            return Ok(profile);
        }
        catch (ClashException ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
        catch (HttpRequestException ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
    }

    /// <summary><c>GET /profiles/:id/preview</c> — the raw YAML of a profile.</summary>
    [HttpGet("/profiles/{id}/preview")]
    public IActionResult Preview(string id)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        try
        {
            return Content(runtime.Profiles.ReadContent(id), "text/plain; charset=utf-8");
        }
        catch (ClashException ex)
        {
            return NotFound(new MessageResponse { Message = ex.Message });
        }
    }

    /// <summary><c>PUT /profiles/:id/content</c> — replaces the YAML of a profile.</summary>
    [HttpPut("/profiles/{id}/content")]
    public async Task<IActionResult> WriteContent(string id, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var body = await ReadBodyAsync(cancellationToken).ConfigureAwait(false);
        if (body is null || !body.Has("content"))
        {
            return BadRequest(new MessageResponse { Message = "content is required" });
        }

        try
        {
            runtime.Profiles.WriteContent(id, body.GetString("content") ?? string.Empty);
            return NoContent();
        }
        catch (ClashException ex)
        {
            return NotFound(new MessageResponse { Message = ex.Message });
        }
    }

    /// <summary><c>POST /subscription/parse</c> — fetches a subscription and lists its nodes.</summary>
    [HttpPost("/subscription/parse")]
    public async Task<IActionResult> ParseSubscription(CancellationToken cancellationToken)
    {
        var body = await ReadBodyAsync(cancellationToken).ConfigureAwait(false);
        var url = body?.GetNonEmptyString("url");
        if (url is null) return BadRequest(new MessageResponse { Message = "url is required" });

        if (!ShareLinks.IsAvailable)
        {
            return StatusCode(
                StatusCodes.Status501NotImplemented,
                new MessageResponse { Message = "share-link parsing is not available in this build" });
        }

        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd(SubscriptionUserAgent);

            var content = await client.GetStringAsync(url, cancellationToken).ConfigureAwait(false);
            var entries = ShareLinks.Parser.ParseSubscription(content);

            return Ok(new ParsedSubscriptionResponse
            {
                Proxies = entries
                    .Select(entry => new ParsedNode { Name = entry.Name, Type = entry.Type })
                    .ToList(),
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
    }

    private async Task<YamlMap?> ReadBodyAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await ApiDocuments.ReadMapAsync(Request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private ObjectResult CoreUnavailable()
        => StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = _clash.UnavailableMessage });
}
