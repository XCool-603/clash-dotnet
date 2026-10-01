using Clash.Core.Common;
using Clash.Core.Rules;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary><c>/rules</c>: the ordered rule list and per-rule enable/disable.</summary>
[ApiController]
public sealed class RulesController : ControllerBase
{
    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public RulesController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /rules</c> — every rule, in evaluation order.</summary>
    [HttpGet("/rules")]
    public IActionResult List()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        // The live engine lives on the tunnel; ClashRuntime.Rules is the one built
        // at startup and is replaced on every reload.
        var engine = runtime.Tunnel.Rules;
        var rules = new List<RuleObject>(engine.Rules.Count);

        foreach (var rule in engine.Rules)
        {
            var size = -1;
            if (rule.Type == RuleType.RuleSet && engine.RuleSets.TryGetValue(rule.Payload, out var set))
            {
                size = set.Count;
            }

            rules.Add(new RuleObject
            {
                Type = rule.RuleTypeName,
                Payload = rule.Payload,
                Proxy = rule.Adapter,
                Size = size,
            });
        }

        return Ok(new RulesResponse { Rules = rules });
    }

    /// <summary>
    /// <c>PATCH /rules</c> — enables or disables one rule for the lifetime of the
    /// process. The body is <c>{"type": "...", "payload": "...", "disabled": true}</c>.
    /// </summary>
    [HttpPatch("/rules")]
    public async Task<IActionResult> Patch(CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        YamlMap? body;
        try
        {
            body = await ApiDocuments.ReadMapAsync(Request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        var type = body?.GetNonEmptyString("type");
        var payload = body?.GetNonEmptyString("payload");
        if (type is null || payload is null)
        {
            return BadRequest(new MessageResponse { Message = "type and payload are required" });
        }

        var engine = runtime.Tunnel.Rules;
        if (body!.GetBool("disabled")) engine.Disable(type, payload);
        else engine.Enable(type, payload);

        return NoContent();
    }

    private ObjectResult CoreUnavailable()
        => StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = _clash.UnavailableMessage });
}
