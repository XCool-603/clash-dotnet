using System.Globalization;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace Clash.Core.Providers;

/// <summary>
/// Reads the subscription metadata servers advertise in response headers, most
/// importantly <c>subscription-userinfo</c>.
/// </summary>
public static partial class SubscriptionInfoParser
{
    [GeneratedRegex(@"(\w+)\s*=\s*(\d+)", RegexOptions.IgnoreCase)]
    private static partial Regex UserInfoPattern();

    [GeneratedRegex("""filename\s*=\s*"?([^";]+)"?""", RegexOptions.IgnoreCase)]
    private static partial Regex FileNamePattern();

    /// <summary>
    /// Parses <c>subscription-userinfo: upload=0; download=0; total=0; expire=0</c>
    /// plus the common alternative header names. Returns null when nothing usable
    /// is present.
    /// </summary>
    public static SubscriptionInfo? FromHeaders(HttpResponseHeaders headers)
    {
        foreach (var name in new[] { "subscription-userinfo", "Subscription-Userinfo", "userinfo" })
        {
            if (!headers.TryGetValues(name, out var values)) continue;
            var info = ParseUserInfo(string.Join(";", values));
            if (info is not null) return info;
        }

        return null;
    }

    /// <summary>Parses a <c>subscription-userinfo</c> value.</summary>
    public static SubscriptionInfo? ParseUserInfo(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;

        long upload = 0, download = 0, total = 0;
        DateTimeOffset? expire = null;
        var found = false;

        foreach (Match match in UserInfoPattern().Matches(value))
        {
            if (!long.TryParse(match.Groups[2].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
            {
                continue;
            }

            found = true;
            switch (match.Groups[1].Value.ToLowerInvariant())
            {
                case "upload": upload = number; break;
                case "download": download = number; break;
                case "total": total = number; break;
                case "expire":
                    if (number > 0)
                    {
                        try { expire = DateTimeOffset.FromUnixTimeSeconds(number); }
                        catch (ArgumentOutOfRangeException) { /* ignore a nonsense expiry */ }
                    }
                    break;
            }
        }

        return found ? new SubscriptionInfo(upload, download, total, expire) : null;
    }

    /// <summary>
    /// Derives a profile name from <c>content-disposition</c>, then
    /// <c>profile-web-page-url</c>, then <c>profile-title</c>.
    /// </summary>
    public static string? ProfileNameFromHeaders(HttpResponseHeaders headers, HttpContentHeaders contentHeaders)
    {
        if (contentHeaders.TryGetValues("content-disposition", out var dispositions))
        {
            var disposition = string.Join(";", dispositions);
            var match = FileNamePattern().Match(disposition);
            if (match.Success)
            {
                var name = match.Groups[1].Value.Trim();
                var extension = Path.GetExtension(name);
                if (extension is ".yaml" or ".yml" or ".txt" or ".conf") name = name[..^extension.Length];
                if (!string.IsNullOrWhiteSpace(name)) return name;
            }
        }

        foreach (var name in new[] { "profile-title", "profile-web-page-url" })
        {
            if (!headers.TryGetValues(name, out var values)) continue;
            var title = string.Join(" ", values).Trim();
            if (!string.IsNullOrWhiteSpace(title)) return title;
        }

        return null;
    }
}
