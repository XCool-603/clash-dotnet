using System.Net;
using System.Text;
using Clash.Core.Common;
using Clash.Core.Configuration;

namespace Clash.Tests.Providers;

/// <summary>An <see cref="HttpMessageHandler"/> that answers from memory; no test touches the network.</summary>
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public FakeHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

    /// <summary>How many requests reached the handler.</summary>
    public int Calls { get; private set; }

    /// <summary>The <c>User-Agent</c> of the last request.</summary>
    public string? LastUserAgent { get; private set; }

    /// <summary>Returns <paramref name="body"/> with 200 OK and optional extra headers.</summary>
    public static FakeHttpMessageHandler Returns(string body, params (string Name, string Value)[] headers)
        => new(_ => Response(body, headers));

    /// <summary>Fails every request with <paramref name="status"/>.</summary>
    public static FakeHttpMessageHandler Fails(HttpStatusCode status = HttpStatusCode.InternalServerError)
        => new(_ => new HttpResponseMessage(status) { Content = new StringContent("unavailable") });

    /// <summary>Throws a transport error on every request.</summary>
    public static FakeHttpMessageHandler Throws(string message = "offline")
        => new(_ => throw new HttpRequestException(message));

    /// <summary>Builds a 200 response carrying <paramref name="body"/>.</summary>
    public static HttpResponseMessage Response(string body, params (string Name, string Value)[] headers)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "text/plain"),
        };

        foreach (var (name, value) in headers) response.Headers.TryAddWithoutValidation(name, value);
        return response;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        Calls++;
        LastUserAgent = request.Headers.UserAgent.ToString();
        return Task.FromResult(_responder(request));
    }
}

/// <summary>A throw-away directory removed on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Root = Path.Combine(Path.GetTempPath(), "clash-provider-tests-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(Root);
    }

    public string Root { get; }

    public string PathOf(string relative) => Path.Combine(Root, relative.Replace('/', Path.DirectorySeparatorChar));

    public string Write(string relative, string content)
    {
        var path = PathOf(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory must never fail a test run.
        }
    }
}

/// <summary>Small helpers for building the shapes the loaders return.</summary>
internal static class TestEntries
{
    public static ProxyConfigEntry Proxy(string name, string type, params (string Key, object? Value)[] fields)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["name"] = name,
            ["type"] = type,
        };

        foreach (var (key, value) in fields) map[key] = value;
        return new ProxyConfigEntry(new YamlMap(map));
    }

    public static Metadata Flow(string host) => new() { Host = host, DestinationAddress = host, DestinationPort = 443 };
}
