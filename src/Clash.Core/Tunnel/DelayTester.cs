using System.Diagnostics;
using System.Net;
using System.Text;
using Clash.Core.Adapter;
using Clash.Core.Common;

namespace Clash.Core.Tunnel;

/// <summary>
/// Measures the round trip to a probe URL through an adapter, which is what
/// backs both <c>GET /proxies/:name/delay</c> and the url-test health checks.
/// </summary>
public sealed class DelayTester : IDelayTester
{
    private const string UserAgent = "clash-verge/v1.0.0";

    public async Task<DelayProbeResult> TestAsync(
        IProxy proxy,
        string url,
        int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return new DelayProbeResult(proxy.Name, 0, $"invalid probe url: {url}");
        }

        var port = uri.IsDefaultPort
            ? (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80)
            : uri.Port;

        var metadata = new Metadata
        {
            Network = Network.Tcp,
            DestinationAddress = uri.Host,
            DestinationPort = (ushort)port,
            Host = uri.Host,
            InboundType = "delay",
        };

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Math.Max(200, timeoutMs));

        var stopwatch = Stopwatch.StartNew();
        ProxyStream? stream = null;
        try
        {
            stream = await proxy.DialTcpAsync(metadata, null, timeoutCts.Token).ConfigureAwait(false);

            var path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
            var request = $"HEAD {path} HTTP/1.1\r\n" +
                          $"Host: {uri.Host}\r\n" +
                          $"User-Agent: {UserAgent}\r\n" +
                          "Accept: */*\r\n" +
                          "Accept-Encoding: identity\r\n" +
                          "Connection: close\r\n\r\n";

            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), timeoutCts.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeoutCts.Token).ConfigureAwait(false);

            var header = await ReadResponseHeadAsync(stream, timeoutCts.Token).ConfigureAwait(false);
            stopwatch.Stop();

            if (header is null)
            {
                return new DelayProbeResult(proxy.Name, 0, "no response");
            }

            // Clash reports the delay even for non-2xx responses, but a probe that
            // is clearly not speaking HTTP should count as a failure.
            var delay = (int)stopwatch.ElapsedMilliseconds;
            return delay <= 0
                ? new DelayProbeResult(proxy.Name, 1, null)
                : new DelayProbeResult(proxy.Name, delay, null);
        }
        catch (OperationCanceledException)
        {
            return new DelayProbeResult(proxy.Name, 0, "timeout");
        }
        catch (Exception ex)
        {
            return new DelayProbeResult(proxy.Name, 0, ex.Message);
        }
        finally
        {
            if (stream is not null)
            {
                try { await stream.DisposeAsync().ConfigureAwait(false); } catch { /* ignore */ }
            }
        }
    }

    /// <summary>Reads up to the end of the response header block, or the first line.</summary>
    private static async Task<string?> ReadResponseHeadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        var accumulated = new List<byte>(1024);

        while (accumulated.Count < 16 * 1024)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read <= 0) break;
            accumulated.AddRange(buffer.AsSpan(0, read).ToArray());

            // A status line is enough to consider the node responsive; waiting for
            // the full header block would penalise slow origins.
            var text = Encoding.ASCII.GetString(accumulated.ToArray());
            var lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
            if (lineEnd > 0 && text.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
            {
                return text[..lineEnd];
            }
        }

        return accumulated.Count > 0 ? Encoding.ASCII.GetString(accumulated.ToArray()) : null;
    }
}
