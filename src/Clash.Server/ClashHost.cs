using System.Text.Json;
using System.Text.Json.Serialization;
using Clash.Server.Middleware;
using Clash.Server.Models;
using Clash.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace Clash.Server;

/// <summary>
/// Builds and runs the ASP.NET Core host that exposes the Clash-compatible
/// control API, serves the bundled Vue dashboard and owns the tunnel lifetime.
/// </summary>
public static class ClashHost
{
    /// <summary>
    /// The first path segment of every control API route. A request below one of
    /// these roots never falls back to the dashboard shell: an unknown API path
    /// answers 404 JSON.
    /// </summary>
    private static readonly string[] ApiRoots =
    [
        "version",
        "restart",
        "configs",
        "proxies",
        "group",
        "rules",
        "connections",
        "traffic",
        "memory",
        "logs",
        "providers",
        "profiles",
        "subscription",
        "cache",
        "dns",
        "openapi",
    ];

    /// <summary>JSON options shared by every controller and WebSocket payload.</summary>
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DictionaryKeyPolicy = null,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    /// <summary>Creates the application without starting it. Used by tests and the desktop shell.</summary>
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var webRoot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
            WebRootPath = Directory.Exists(webRoot) ? webRoot : null,
        });

        builder.Services.AddControllers()
            .AddJsonOptions(o =>
            {
                o.JsonSerializerOptions.DefaultIgnoreCondition = Json.DefaultIgnoreCondition;
                o.JsonSerializerOptions.PropertyNamingPolicy = Json.NamingPolicy;
                o.JsonSerializerOptions.NumberHandling = Json.NumberHandling;
            });

        // Clash's error shapes are `{"message": "..."}`; the automatic validation
        // problem details would replace them with a different document.
        builder.Services.Configure<ApiBehaviorOptions>(o => o.SuppressModelStateInvalidFilter = true);

        builder.Services.AddOpenApi();
        builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader()));

        // The core. Registered before `configure` so a test (or the desktop shell)
        // can replace the options by registering its own instance.
        builder.Services.AddSingleton(services => ClashService.CreateOptions(args, services));
        builder.Services.AddSingleton<ClashService>();
        builder.Services.AddSingleton<IHostedService>(services => services.GetRequiredService<ClashService>());

        configure?.Invoke(builder);

        var app = builder.Build();

        // Outermost: turn an escaping exception into Clash's JSON error body.
        app.Use(async (context, next) =>
        {
            try
            {
                await next().ConfigureAwait(false);
            }
            catch (Exception ex) when (!context.Response.HasStarted)
            {
                context.Response.Clear();
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await context.Response
                    .WriteAsJsonAsync(new MessageResponse { Message = ex.Message }, Json, context.RequestAborted)
                    .ConfigureAwait(false);
            }
        });

        app.UseCors();
        app.UseWebSockets();

        // The dashboard shell stays reachable without a token so it can prompt for
        // the secret; every control API route goes through the auth middleware.
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.UseRouting();

        app.UseMiddleware<AuthMiddleware>();

        app.MapControllers();
        app.MapOpenApi();

        // SPA fallback. Controllers are matched first, so only genuinely unknown
        // paths reach here; of those, only real navigations get the shell.
        app.MapFallback(async context =>
        {
            if (IsApiPath(context.Request.Path) || !AcceptsHtml(context.Request))
            {
                await WriteNotFoundAsync(context).ConfigureAwait(false);
                return;
            }

            var index = ResolveIndexHtml(app);
            if (index is null)
            {
                await WriteNotFoundAsync(context).ConfigureAwait(false);
                return;
            }

            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.SendFileAsync(index).ConfigureAwait(false);
        });

        return app;
    }

    /// <summary>Builds the application and runs it until shutdown.</summary>
    public static async Task RunAsync(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var app = Build(args, configure);
        await app.RunAsync().ConfigureAwait(false);
    }

    /// <summary>True when a path belongs to the control API surface.</summary>
    public static bool IsApiPath(PathString path)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value)) return false;

        var trimmed = value.AsSpan().Trim('/');
        if (trimmed.IsEmpty) return false;

        var slash = trimmed.IndexOf('/');
        var root = slash < 0 ? trimmed : trimmed[..slash];

        foreach (var candidate in ApiRoots)
        {
            if (root.Equals(candidate, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    private static bool AcceptsHtml(HttpRequest request)
        => request.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase);

    private static string? ResolveIndexHtml(WebApplication app)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrEmpty(app.Environment.WebRootPath))
        {
            candidates.Add(Path.Combine(app.Environment.WebRootPath, "index.html"));
        }

        candidates.Add(Path.Combine(AppContext.BaseDirectory, "wwwroot", "index.html"));

        return candidates.FirstOrDefault(File.Exists);
    }

    private static async Task WriteNotFoundAsync(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        await context.Response
            .WriteAsJsonAsync(new MessageResponse { Message = "Not Found" }, Json, context.RequestAborted)
            .ConfigureAwait(false);
    }
}
