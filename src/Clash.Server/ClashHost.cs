using System.Text.Json;
using System.Text.Json.Serialization;

namespace Clash.Server;

/// <summary>
/// Builds and runs the ASP.NET Core host that exposes the Clash-compatible
/// control API, serves the bundled Vue dashboard and owns the tunnel lifetime.
/// </summary>
public static class ClashHost
{
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
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
            WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot"),
        });

        builder.Services.AddControllers()
            .AddJsonOptions(o =>
            {
                o.JsonSerializerOptions.DefaultIgnoreCondition = Json.DefaultIgnoreCondition;
                o.JsonSerializerOptions.PropertyNamingPolicy = Json.PropertyNamingPolicy;
                o.JsonSerializerOptions.NumberHandling = Json.NumberHandling;
            });

        builder.Services.AddOpenApi();
        builder.Services.AddCors(options => options.AddDefaultPolicy(policy => policy
            .AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader()));

        configure?.Invoke(builder);

        var app = builder.Build();

        app.UseCors();
        app.UseDefaultFiles();
        app.UseStaticFiles();
        app.MapControllers();
        app.MapOpenApi();

        // SPA fallback: any non-API path serves the dashboard shell.
        app.MapFallbackToFile("index.html");

        return app;
    }

    public static async Task RunAsync(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        var app = Build(args, configure);
        await app.RunAsync().ConfigureAwait(false);
    }
}
