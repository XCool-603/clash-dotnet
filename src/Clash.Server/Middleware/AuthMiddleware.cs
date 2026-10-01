using System.Security.Cryptography;
using System.Text;
using Clash.Server.Services;

namespace Clash.Server.Middleware;

/// <summary>
/// Bearer-token authentication matching Clash's <c>secret</c> option.
/// <list type="bullet">
/// <item><description>An empty secret allows everything.</description></item>
/// <item><description>Otherwise <c>Authorization: Bearer &lt;secret&gt;</c> or <c>?token=&lt;secret&gt;</c> is required.</description></item>
/// <item><description><c>OPTIONS</c> and the static dashboard files stay open, so the UI can load and then ask for the secret.</description></item>
/// <item><description>A failure is a bare <c>401</c> with no body, exactly like Clash.</description></item>
/// </list>
/// </summary>
public sealed class AuthMiddleware
{
    private const string BearerScheme = "Bearer ";

    private static readonly HashSet<string> PublicPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/",
        "/index.html",
        "/favicon.ico",
        "/logo.png",
        "/robots.txt",
        "/manifest.json",
        "/manifest.webmanifest",
        "/assets",
    };

    private static readonly string[] PublicPrefixes = ["/assets/"];

    private readonly RequestDelegate _next;

    /// <summary>Creates the middleware.</summary>
    public AuthMiddleware(RequestDelegate next) => _next = next ?? throw new ArgumentNullException(nameof(next));

    /// <summary>True for paths that are served without authentication.</summary>
    public static bool IsPublicPath(PathString path)
    {
        var value = path.Value ?? "/";
        if (value.Length == 0) value = "/";
        if (PublicPaths.Contains(value)) return true;

        foreach (var prefix in PublicPrefixes)
        {
            if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
        }

        return false;
    }

    /// <summary>Enforces the secret.</summary>
    public async Task InvokeAsync(HttpContext context, ClashService clash)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(clash);

        if (HttpMethods.IsOptions(context.Request.Method) || IsPublicPath(context.Request.Path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // A core that never started has no secret to enforce; staying open is what
        // lets the dashboard upload a working configuration.
        var secret = clash.RuntimeOrNull?.Config.Secret;
        if (string.IsNullOrEmpty(secret) || IsAuthorized(context.Request, secret))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    private static bool IsAuthorized(HttpRequest request, string secret)
    {
        var header = request.Headers.Authorization.ToString();
        if (header.Length > BearerScheme.Length &&
            header.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase) &&
            FixedTimeEquals(header[BearerScheme.Length..].Trim(), secret))
        {
            return true;
        }

        // WebSocket clients cannot set headers, so the dashboard passes ?token=.
        var token = request.Query["token"].ToString();
        return token.Length > 0 && FixedTimeEquals(token, secret);
    }

    private static bool FixedTimeEquals(string provided, string expected)
    {
        var left = Encoding.UTF8.GetBytes(provided);
        var right = Encoding.UTF8.GetBytes(expected);
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    }
}
