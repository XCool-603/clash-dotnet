using Clash.Core.Runtime;
using Clash.Server;
using Clash.Server.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Clash.Tests.Server;

/// <summary>
/// Boots the control API in-process over a <see cref="TestServer"/> with an
/// inline configuration and the inbound listeners disabled, so every test talks
/// to the real HTTP pipeline without binding a socket.
/// </summary>
internal sealed class ServerFixture : IAsyncDisposable
{
    private readonly WebApplication _app;

    private ServerFixture(WebApplication app, TestServer server, HttpClient client, string homeDir)
    {
        _app = app;
        Server = server;
        Client = client;
        HomeDir = homeDir;
    }

    /// <summary>The in-memory server, also used to open WebSockets.</summary>
    public TestServer Server { get; }

    /// <summary>An <see cref="HttpClient"/> whose base address is the test server.</summary>
    public HttpClient Client { get; }

    /// <summary>The temporary home directory handed to the runtime.</summary>
    public string HomeDir { get; }

    /// <summary>The hosted core service.</summary>
    public ClashService Clash => _app.Services.GetRequiredService<ClashService>();

    /// <summary>The live runtime.</summary>
    public ClashRuntime Runtime => Clash.Runtime;

    /// <summary>Starts a fresh instance of the API.</summary>
    public static async Task<ServerFixture> StartAsync(string? yaml = null, string? secret = null)
    {
        var home = Path.Combine(Path.GetTempPath(), "clash-api-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(home);

        var text = yaml ?? TestConfiguration.Yaml;
        if (secret is not null)
        {
            text = text.Replace("secret: ''", $"secret: '{secret}'", StringComparison.Ordinal);
        }

        var app = ClashHost.Build([], builder =>
        {
            builder.WebHost.UseTestServer();
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            builder.Services.AddSingleton(services => new ClashRuntimeOptions
            {
                InlineYaml = text,
                HomeDir = home,
                StartListeners = false,
                CreateDefaultConfigIfMissing = false,
                LoggerFactory = services.GetRequiredService<ILoggerFactory>(),
            });
        });

        await app.StartAsync().ConfigureAwait(false);

        var server = (TestServer)app.Services.GetRequiredService<IServer>();
        return new ServerFixture(app, server, server.CreateClient(), home);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        Client.Dispose();

        try
        {
            await _app.StopAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The host is going away regardless.
        }

        await _app.DisposeAsync().ConfigureAwait(false);

        try
        {
            Directory.Delete(HomeDir, recursive: true);
        }
        catch (Exception)
        {
            // A leftover temp directory is harmless.
        }
    }
}

/// <summary>The configuration every test starts from.</summary>
internal static class TestConfiguration
{
    /// <summary>
    /// Deliberately built from the built-in adapters only, so the API tests do not
    /// depend on any outbound protocol implementation.
    /// </summary>
    public const string Yaml = """
        port: 0
        socks-port: 0
        mixed-port: 0
        redir-port: 0
        tproxy-port: 0
        allow-lan: false
        bind-address: '*'
        mode: rule
        log-level: info
        ipv6: false
        unified-delay: true
        tcp-concurrent: true
        find-process-mode: strict
        global-client-fingerprint: chrome
        external-controller: 127.0.0.1:9090
        secret: ''
        dns:
          enable: true
          enhanced-mode: normal
          nameserver:
            - 223.5.5.5
        proxy-groups:
          - name: PROXY
            type: select
            proxies:
              - DIRECT
              - REJECT
          - name: AUTO
            type: url-test
            lazy: true
            url: https://www.gstatic.com/generate_204
            interval: 300
            proxies:
              - DIRECT
        rules:
          - DOMAIN-SUFFIX,google.com,PROXY
          - DOMAIN,example.com,DIRECT
          - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
          - MATCH,PROXY
        """;
}
