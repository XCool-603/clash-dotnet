using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Runtime;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary>
/// <c>/configs</c>: the general configuration object, partial updates, and
/// loading a whole document from a file or an inline payload.
/// </summary>
[ApiController]
public sealed class ConfigsController : ControllerBase
{
    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public ConfigsController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /configs</c> — the general configuration object.</summary>
    [HttpGet("/configs")]
    [HttpGet("/configs/general")]
    public IActionResult Get()
    {
        if (_clash.RuntimeOrNull is not { } runtime) return CoreUnavailable();

        var config = runtime.Config;
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["port"] = config.Port,
            ["socks-port"] = config.SocksPort,
            ["redir-port"] = config.RedirPort,
            ["tproxy-port"] = config.TProxyPort,
            ["mixed-port"] = config.MixedPort,
            ["allow-lan"] = config.AllowLan,
            ["bind-address"] = config.BindAddress,
            ["mode"] = config.Mode.ToApiString(),
            ["log-level"] = config.LogLevel,
            ["ipv6"] = config.Ipv6,
            ["interface-name"] = config.InterfaceName,
            ["routing-mark"] = config.RoutingMark,
            ["secret"] = config.Secret,
            ["external-controller"] = config.ExternalController,
            ["external-ui"] = config.ExternalUi,
            ["unified-delay"] = config.UnifiedDelay,
            ["tcp-concurrent"] = config.TcpConcurrent,
            ["find-process-mode"] = config.FindProcessMode,
            ["global-client-fingerprint"] = config.GlobalClientFingerprint,
            ["tun"] = TunObject(config.Tun),
            ["dns"] = DnsObject(config.Dns),
            ["sniffer"] = SnifferObject(config.Sniffer),
            ["profile"] = ProfileObject(config.Profile),
            ["experimental"] = ExperimentalObject(config.Experimental),
            ["hosts"] = config.Hosts,
            ["geodata"] = GeoDataObject(config.GeoData),

            // Application level additions, not part of Clash's own response.
            ["profile-path"] = runtime.ConfigPath ?? string.Empty,
            ["home-dir"] = runtime.HomeDir,
            ["inbound-ports"] = InboundPorts(runtime),
        };

        return Ok(payload);
    }

    /// <summary>
    /// <c>PATCH /configs</c> — deep-merges a partial JSON/YAML document into the
    /// live configuration and reloads. Hot reloadable keys (<c>mode</c>,
    /// <c>log-level</c>, <c>dns.*</c>, <c>sniffer</c>, <c>hosts</c>, ...) apply in
    /// place; a port change rebuilds the listeners.
    /// </summary>
    [HttpPatch("/configs")]
    public async Task<IActionResult> Patch(CancellationToken cancellationToken)
    {
        YamlMap? patch;
        try
        {
            patch = await ApiDocuments.ReadMapAsync(Request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        if (patch is null || patch.Count == 0)
        {
            return BadRequest(new MessageResponse { Message = "the request body must be a configuration object" });
        }

        try
        {
            await _clash.ApplyPatchAsync(patch, cancellationToken).ConfigureAwait(false);
            return NoContent();
        }
        catch (ClashCoreUnavailableException ex)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = ex.Message });
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
    }

    /// <summary>
    /// <c>PUT /configs?force=true</c> — loads <c>{"path": "..."}</c> or
    /// <c>{"payload": "&lt;yaml&gt;"}</c> as the new configuration.
    /// </summary>
    [HttpPut("/configs")]
    public async Task<IActionResult> Put([FromQuery] bool force, CancellationToken cancellationToken)
    {
        YamlMap? body;
        try
        {
            body = await ApiDocuments.ReadMapAsync(Request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }

        var path = body?.GetNonEmptyString("path");
        var payload = body?.GetNonEmptyString("payload");

        if (path is null && payload is null)
        {
            return BadRequest(new MessageResponse { Message = "either path or payload is required" });
        }

        try
        {
            ClashConfig config;
            if (payload is not null)
            {
                config = ConfigParser.Parse(YamlReader.Parse(payload));
            }
            else
            {
                var resolved = ResolvePath(path!);
                if (!System.IO.File.Exists(resolved))
                {
                    return BadRequest(new MessageResponse { Message = $"file not found: {resolved}" });
                }

                var text = await System.IO.File.ReadAllTextAsync(resolved, cancellationToken).ConfigureAwait(false);
                config = ConfigParser.Parse(YamlReader.Parse(text));
            }

            if (!await _clash.ReloadConfigAsync(config, force, cancellationToken).ConfigureAwait(false))
            {
                return BadRequest(new MessageResponse
                {
                    Message = _clash.LastError?.Message ?? "the configuration could not be applied",
                });
            }

            return NoContent();
        }
        catch (Exception ex)
        {
            return BadRequest(new MessageResponse { Message = ex.Message });
        }
    }

    // ── Projections ──────────────────────────────────────────────────────────

    private ObjectResult CoreUnavailable()
        => StatusCode(StatusCodes.Status503ServiceUnavailable, new MessageResponse { Message = _clash.UnavailableMessage });

    private string ResolvePath(string path)
    {
        if (System.IO.Path.IsPathRooted(path)) return path;
        var home = _clash.RuntimeOrNull?.HomeDir;
        return string.IsNullOrEmpty(home) ? path : System.IO.Path.Combine(home, path);
    }

    private static List<Dictionary<string, object?>> InboundPorts(ClashRuntime runtime)
    {
        var result = new List<Dictionary<string, object?>>();
        var config = runtime.Config;

        Add("http", string.Empty, config.Port, null);
        Add("socks", string.Empty, config.SocksPort, null);
        Add("mixed", string.Empty, config.MixedPort, null);
        Add("redir", string.Empty, config.RedirPort, null);
        Add("tproxy", string.Empty, config.TProxyPort, null);

        foreach (var listener in config.Listeners)
        {
            Add(listener.Type, listener.Name, listener.Port, listener.Listen);
        }

        foreach (var listener in runtime.ExtraListeners)
        {
            Add(listener.Type, listener.Name ?? string.Empty, listener.Port, listener.Address);
        }

        return result;

        void Add(string type, string name, int port, string? address)
        {
            if (port == 0) return;
            result.Add(new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["type"] = type,
                ["name"] = name,
                ["port"] = port,
                ["address"] = address ?? string.Empty,
            });
        }
    }

    private static Dictionary<string, object?> TunObject(TunConfig tun) => new(StringComparer.Ordinal)
    {
        ["enable"] = tun.Enable,
        ["stack"] = tun.Stack,
        ["device"] = tun.Device,
        ["auto-route"] = tun.AutoRoute,
        ["auto-detect-interface"] = tun.AutoDetectInterface,
        ["auto-redirect"] = tun.AutoRedirect,
        ["dns-hijack"] = tun.DnsHijack,
        ["mtu"] = tun.Mtu,
        ["gso"] = tun.Gso,
        ["gso-max-size"] = tun.GsoMaxSize,
        ["strict-route"] = tun.StrictRoute,
        ["endpoint-independent-nat"] = tun.EndpointIndependentNat,
        ["inet4-address"] = tun.Inet4Address,
        ["inet6-address"] = tun.Inet6Address,
        ["udp-timeout"] = tun.UdpTimeout,
        ["route-address"] = tun.RouteAddress,
        ["route-exclude-address"] = tun.RouteExcludeAddress,
        ["include-interface"] = tun.IncludeInterface,
        ["exclude-interface"] = tun.ExcludeInterface,
        ["file-descriptor"] = tun.FileDescriptor,
        ["interface-name"] = tun.InterfaceName,
        ["redirect-to-tun"] = tun.RedirectToTun,
    };

    private static Dictionary<string, object?> DnsObject(DnsConfig dns) => new(StringComparer.Ordinal)
    {
        ["enable"] = dns.Enable,
        ["listen"] = dns.Listen,
        ["ipv6"] = dns.Ipv6,
        ["enhanced-mode"] = dns.EnhancedMode,
        ["fake-ip-range"] = dns.FakeIpRange,
        ["fake-ip-range-v6"] = dns.FakeIpRangeV6,
        ["fake-ip-filter"] = dns.FakeIpFilter,
        ["default-nameserver"] = dns.DefaultNameserver,
        ["nameserver"] = dns.Nameserver,
        ["fallback"] = dns.Fallback,
        ["fallback-filter"] = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["geoip"] = dns.FallbackFilter.GeoIp,
            ["geoip-code"] = dns.FallbackFilter.GeoIpCode,
            ["ipcidr"] = dns.FallbackFilter.IpCidr,
            ["domain"] = dns.FallbackFilter.Domain,
            ["geoip-filter"] = dns.FallbackFilter.GeoIpFilter,
        },
        ["nameserver-policy"] = dns.NameserverPolicy,
        ["proxy-server-nameserver"] = dns.ProxyServerNameserver,
        ["direct-nameserver"] = dns.DirectNameserver,
        ["hosts"] = dns.Hosts,
        ["use-hosts"] = dns.UseHosts,
        ["use-system-hosts"] = dns.UseSystemHosts,
        ["respect-rules"] = dns.RespectRules,
        ["prefer-h3"] = dns.PreferH3,
        ["cache-algorithm"] = dns.CacheAlgorithm,
        ["cache-max-size"] = dns.CacheMaxSize,
    };

    private static Dictionary<string, object?> SnifferObject(SnifferConfig sniffer) => new(StringComparer.Ordinal)
    {
        ["enable"] = sniffer.Enable,
        ["override-destination"] = sniffer.OverrideDestination,
        ["force-domain"] = sniffer.ForceDomain,
        ["skip-domain"] = sniffer.SkipDomain,
        ["force-dns-mapping"] = sniffer.ForceDnsMapping,
        ["parse-pure-ip"] = sniffer.ParsePureIp,
        ["sniff"] = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["http"] = SniffProtocolObject(sniffer.Sniff.Http),
            ["tls"] = SniffProtocolObject(sniffer.Sniff.Tls),
            ["quic"] = SniffProtocolObject(sniffer.Sniff.Quic),
        },
    };

    private static Dictionary<string, object?> SniffProtocolObject(SniffProtocolConfig protocol) => new(StringComparer.Ordinal)
    {
        ["ports"] = protocol.Ports,
        ["override-destination"] = protocol.OverrideDestination,
    };

    private static Dictionary<string, object?> ProfileObject(ProfileConfig profile) => new(StringComparer.Ordinal)
    {
        ["store-selected"] = profile.StoreSelected,
        ["store-fake-ip"] = profile.StoreFakeIp,
        ["store-rtt"] = profile.StoreRtt,
    };

    private static Dictionary<string, object?> ExperimentalObject(ExperimentalConfig experimental) => new(StringComparer.Ordinal)
    {
        ["fingerprints"] = experimental.Fingerprints,
        ["quic-go"] = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["max-idle-time"] = experimental.QuicGo.MaxIdleTime,
            ["keep-alive-period"] = experimental.QuicGo.KeepAlivePeriod,
            ["disable-path-mtu-discovery"] = experimental.QuicGo.DisablePathMtuDiscovery,
            ["initial-stream-receive-window"] = experimental.QuicGo.InitialStreamReceiveWindow,
            ["max-stream-receive-window"] = experimental.QuicGo.MaxStreamReceiveWindow,
            ["initial-connection-receive-window"] = experimental.QuicGo.InitialConnectionReceiveWindow,
            ["max-connection-receive-window"] = experimental.QuicGo.MaxConnectionReceiveWindow,
        },
    };

    private static Dictionary<string, object?> GeoDataObject(GeoDataConfig geodata) => new(StringComparer.Ordinal)
    {
        ["mode"] = geodata.GeodataMode,
        ["loader"] = geodata.GeodataLoader,
        ["matcher"] = geodata.GeositeMatcher,
    };
}
