using System.Net.WebSockets;
using System.Text.Json;
using System.Threading.Channels;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server.Controllers;

/// <summary>
/// The three streaming endpoints, implemented on raw <see cref="WebSocket"/>s
/// rather than SignalR: <c>/traffic</c>, <c>/memory</c> and <c>/logs</c>.
/// <para>
/// Every subscription owns its socket and its own producer loop, so one client
/// disconnecting never affects another.
/// </para>
/// </summary>
[ApiController]
public sealed class WebSocketController : ControllerBase
{
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(1);

    private readonly ClashService _clash;

    /// <summary>Creates the controller.</summary>
    public WebSocketController(ClashService clash) => _clash = clash;

    /// <summary><c>GET /traffic</c> — one <c>{"up","down"}</c> frame per second.</summary>
    [HttpGet("/traffic")]
    public async Task Traffic(CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime)
        {
            await RejectAsync(_clash.UnavailableMessage, cancellationToken).ConfigureAwait(false);
            return;
        }

        var socket = await AcceptAsync(cancellationToken).ConfigureAwait(false);
        if (socket is null) return;

        await PumpAsync(socket, cancellationToken, async (send, token) =>
        {
            while (true)
            {
                var (up, down) = runtime.Tunnel.Traffic.TakeDelta();
                await send(new TrafficFrame { Up = up, Down = down }, token).ConfigureAwait(false);
                await Task.Delay(Tick, token).ConfigureAwait(false);
            }
        }).ConfigureAwait(false);
    }

    /// <summary><c>GET /memory</c> — one <c>{"inuse","oslimit"}</c> frame per second.</summary>
    [HttpGet("/memory")]
    public async Task Memory(CancellationToken cancellationToken)
    {
        var socket = await AcceptAsync(cancellationToken).ConfigureAwait(false);
        if (socket is null) return;

        await PumpAsync(socket, cancellationToken, async (send, token) =>
        {
            while (true)
            {
                await send(new MemoryFrame { Inuse = Environment.WorkingSet, Oslimit = 0 }, token).ConfigureAwait(false);
                await Task.Delay(Tick, token).ConfigureAwait(false);
            }
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>GET /logs?level=info</c> — every new log line at or above the requested
    /// level. Only new lines are sent; there is no backlog, matching Clash.
    /// </summary>
    [HttpGet("/logs")]
    public async Task Logs([FromQuery] string? level, CancellationToken cancellationToken)
    {
        if (_clash.RuntimeOrNull is not { } runtime)
        {
            await RejectAsync(_clash.UnavailableMessage, cancellationToken).ConfigureAwait(false);
            return;
        }

        var minimum = ParseLevel(level);
        var channel = Channel.CreateBounded<LogFrame>(new BoundedChannelOptions(1024)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false,
        });

        // Subscribe before the handshake so a line logged right after the client
        // connects is never lost.
        void Handler(string emittedLevel, string message)
        {
            if (Severity(emittedLevel) < minimum) return;
            channel.Writer.TryWrite(new LogFrame { Type = NormalizeLevel(emittedLevel), Payload = message });
        }

        runtime.Tunnel.LogEmitted += Handler;
        try
        {
            var socket = await AcceptAsync(cancellationToken).ConfigureAwait(false);
            if (socket is null) return;

            await PumpAsync(socket, cancellationToken, async (send, token) =>
            {
                await foreach (var frame in channel.Reader.ReadAllAsync(token).ConfigureAwait(false))
                {
                    await send(frame, token).ConfigureAwait(false);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            runtime.Tunnel.LogEmitted -= Handler;
            channel.Writer.TryComplete();
        }
    }

    // ── Plumbing ─────────────────────────────────────────────────────────────

    private async Task<WebSocket?> AcceptAsync(CancellationToken cancellationToken)
    {
        if (!HttpContext.WebSockets.IsWebSocketRequest)
        {
            await RejectAsync("this endpoint requires a websocket upgrade", cancellationToken).ConfigureAwait(false);
            return null;
        }

        return await HttpContext.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
    }

    private async Task RejectAsync(string message, CancellationToken cancellationToken)
    {
        HttpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
        await HttpContext.Response
            .WriteAsJsonAsync(new MessageResponse { Message = message }, ClashHost.Json, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Runs <paramref name="producer"/> until the socket closes, the client goes
    /// away or the host shuts down, then closes the socket cleanly.
    /// </summary>
    private async Task PumpAsync(
        WebSocket socket,
        CancellationToken cancellationToken,
        Func<Func<object, CancellationToken, Task>, CancellationToken, Task> producer)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, HttpContext.RequestAborted);
        var token = linked.Token;

        using (socket)
        {
            var receiver = Task.Run(
                async () =>
                {
                    var buffer = new byte[1024];
                    try
                    {
                        while (socket.State == WebSocketState.Open && !token.IsCancellationRequested)
                        {
                            var result = await socket.ReceiveAsync(buffer.AsMemory(), token).ConfigureAwait(false);
                            if (result.MessageType == WebSocketMessageType.Close) break;
                        }
                    }
                    catch (Exception)
                    {
                        // The client vanished; the cancellation below unwinds the producer.
                    }
                    finally
                    {
                        await linked.CancelAsync().ConfigureAwait(false);
                    }
                },
                CancellationToken.None);

            try
            {
                await producer(
                    async (frame, sendToken) =>
                    {
                        var payload = JsonSerializer.SerializeToUtf8Bytes(frame, ClashHost.Json);
                        await socket
                            .SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true, sendToken)
                            .ConfigureAwait(false);
                    },
                    token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or InvalidOperationException or ObjectDisposedException)
            {
                // Normal termination: the client closed, or the app is shutting down.
            }
            finally
            {
                await linked.CancelAsync().ConfigureAwait(false);
            }

            try
            {
                await receiver.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Already reported through the cancellation.
            }

            if (socket.State == WebSocketState.Open)
            {
                try
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // The peer is gone; nothing left to close.
                }
            }
        }
    }

    private static int ParseLevel(string? level) => Severity(level ?? "info");

    private static int Severity(string? level) => level?.Trim().ToLowerInvariant() switch
    {
        "debug" => 0,
        "info" or "" or null => 1,
        "warning" or "warn" => 2,
        "error" or "err" => 3,
        "silent" => 4,
        _ => 1,
    };

    private static string NormalizeLevel(string? level) => level?.Trim().ToLowerInvariant() switch
    {
        "debug" => "debug",
        "warning" or "warn" => "warning",
        "error" or "err" => "error",
        _ => "info",
    };
}
