using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary><c>/connections</c>: the live flow snapshot and flow termination.</summary>
[ApiController]
public sealed class ConnectionsController : ControllerBase
{
    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public ConnectionsController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /connections</c> — totals plus every live flow.</summary>
    [HttpGet("/connections")]
    public IActionResult List()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var connections = runtime.Tunnel.Connections;
        var traffic = runtime.Tunnel.Traffic;

        return Ok(new ConnectionsResponse
        {
            DownloadTotal = traffic.DownloadTotal,
            UploadTotal = traffic.UploadTotal,
            Memory = Environment.WorkingSet,
            Connections = connections.Snapshot().Select(ApiProjections.BuildConnection).ToList(),
        });
    }

    /// <summary><c>DELETE /connections</c> — closes every flow.</summary>
    [HttpDelete("/connections")]
    public IActionResult CloseAll()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        runtime.Tunnel.Connections.CloseAll();
        return NoContent();
    }

    /// <summary><c>DELETE /connections/:id</c> — closes one flow. Unknown ids are harmless.</summary>
    [HttpDelete("/connections/{id}")]
    public IActionResult Close(string id)
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        runtime.Tunnel.Connections.Close(id);
        return NoContent();
    }

    private ObjectResult CoreUnavailable()
        => StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = _clash.UnavailableMessage });
}
