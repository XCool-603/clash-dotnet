using System.Text;
using System.Text.Json;
using Clash.Core.Common;
using Clash.Core.Configuration;

namespace Clash.Server.Services;

/// <summary>
/// Reads request bodies into the canonical <see cref="YamlMap"/> shape and merges
/// partial configuration documents.
/// <para>
/// The control API accepts both JSON (the dashboard) and YAML (curl users, and
/// Clash's own <c>PUT /configs</c> payload), so a body is first attempted as JSON
/// and then handed to the YAML reader.
/// </para>
/// </summary>
public static class ApiDocuments
{
    /// <summary>Reads the request body as text, or null when it is empty.</summary>
    public static async Task<string?> ReadTextAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        request.EnableBuffering();
        request.Body.Position = 0;

        using var reader = new StreamReader(
            request.Body,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096,
            leaveOpen: true);

        var text = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    /// <summary>Reads the request body as a mapping, or null when it is empty.</summary>
    public static async Task<YamlMap?> ReadMapAsync(HttpRequest request, CancellationToken cancellationToken = default)
    {
        var text = await ReadTextAsync(request, cancellationToken).ConfigureAwait(false);
        return text is null ? null : Parse(text);
    }

    /// <summary>Parses a JSON or YAML document into a mapping.</summary>
    public static YamlMap Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var trimmed = text.AsSpan().TrimStart();
        if (!trimmed.IsEmpty && (trimmed[0] == '{' || trimmed[0] == '['))
        {
            try
            {
                using var document = JsonDocument.Parse(text);
                if (document.RootElement.ValueKind == JsonValueKind.Object)
                {
                    return new YamlMap(ToDictionary(document.RootElement));
                }
            }
            catch (JsonException)
            {
                // Not valid JSON after all; the YAML reader gets the next attempt.
            }
        }

        return YamlReader.Parse(text);
    }

    private static Dictionary<string, object?> ToDictionary(JsonElement element)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in element.EnumerateObject())
        {
            map[property.Name] = ToValue(property.Value);
        }

        return map;
    }

    private static object? ToValue(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => ToDictionary(element),
        JsonValueKind.Array => element.EnumerateArray().Select(ToValue).ToList(),
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number => element.TryGetInt64(out var integer) ? integer : element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => null,
    };
}
