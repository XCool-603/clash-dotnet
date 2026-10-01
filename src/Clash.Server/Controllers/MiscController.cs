using System.Globalization;
using System.Reflection;
using Clash.Core.Dns;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary>
/// The odds and ends: the greeting, the version banner, restart, the DNS and
/// fake-IP caches, and <c>GET /dns/query</c>.
/// </summary>
[ApiController]
public sealed class MiscController : ControllerBase
{
    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public MiscController(ClashService clash) => _clash = clash;

    /// <summary>
    /// <c>GET /</c> — Clash answers with the bare string <c>"clash"</c>; we return
    /// the object form <c>{"hello":"clash"}</c> so the response is always valid JSON.
    /// </summary>
    [HttpGet("/")]
    public IActionResult Hello() => Ok(new Dictionary<string, object?>(StringComparer.Ordinal) { ["hello"] = "clash" });

    /// <summary><c>GET /version</c> — the core version plus the mihomo-compatible <c>meta</c> flag.</summary>
    [HttpGet("/version")]
    public IActionResult Version()
    {
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["version"] = CoreVersion,
            ["meta"] = true,
        };

        if (_clash.StartupError is { } error) payload["error"] = error.Message;
        return Ok(payload);
    }

    /// <summary><c>GET|POST /restart</c> — tears the core down and starts it again.</summary>
    [HttpGet("/restart")]
    [HttpPost("/restart")]
    public async Task<IActionResult> Restart(CancellationToken cancellationToken)
    {
        await _clash.RestartAsync(cancellationToken).ConfigureAwait(false);
        return NoContent();
    }

    /// <summary><c>GET /cache/fakeip/flush</c> — drops the fake-IP pool.</summary>
    [HttpGet("/cache/fakeip/flush")]
    [HttpPost("/cache/fakeip/flush")]
    public IActionResult FlushFakeIp()
    {
        _clash.Runtime.Dns.FlushFakeIp();
        return NoContent();
    }

    /// <summary><c>GET /cache/dns/flush</c> — drops the DNS answer cache.</summary>
    [HttpGet("/cache/dns/flush")]
    [HttpPost("/cache/dns/flush")]
    public IActionResult FlushDns()
    {
        _clash.Runtime.Dns.FlushCache();
        return NoContent();
    }

    /// <summary><c>GET /dns/query?name=&amp;type=</c> — resolves a name through the live resolver.</summary>
    [HttpGet("/dns/query")]
    public async Task<IActionResult> Query(
        [FromQuery] string? name,
        [FromQuery] string? type,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return BadRequest(new MessageResponse { Message = "name is required" });
        }

        var queryType = ParseQueryType(type);
        var query = DnsMessage.CreateQuery(name, queryType, (ushort)Random.Shared.Next(1, ushort.MaxValue));
        var response = await _clash.Runtime.Dns.ExchangeAsync(query, cancellationToken).ConfigureAwait(false);

        var answers = response.Answers
            .Select(record => new DnsQueryAnswer
            {
                Name = record.Name,
                Type = record.Type.ToString().ToUpperInvariant(),
                TTL = record.Ttl,
                Data = RenderData(record),
            })
            .ToList();

        return Ok(new DnsQueryResponse { Status = (int)response.ResponseCode, Answer = answers });
    }

    /// <summary>The assembly version, trimmed to a semver string.</summary>
    private static string CoreVersion
    {
        get
        {
            var assembly = typeof(MiscController).Assembly;
            var informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (!string.IsNullOrWhiteSpace(informational))
            {
                var plus = informational.IndexOf('+');
                return plus > 0 ? informational[..plus] : informational;
            }

            return assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        }
    }

    private static DnsQueryType ParseQueryType(string? type)
    {
        if (string.IsNullOrWhiteSpace(type)) return DnsQueryType.A;
        if (ushort.TryParse(type, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
        {
            return (DnsQueryType)numeric;
        }

        return Enum.TryParse<DnsQueryType>(type, ignoreCase: true, out var parsed) ? parsed : DnsQueryType.A;
    }

    private static string RenderData(DnsResourceRecord record)
    {
        if (record.Address is not null) return record.Address.ToString();
        if (!string.IsNullOrEmpty(record.Target)) return record.Target!;
        return record.Data.Length == 0 ? string.Empty : Convert.ToBase64String(record.Data);
    }
}
