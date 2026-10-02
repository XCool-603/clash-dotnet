using Clash.Core.Configuration;
using Clash.Core.Providers;
using Xunit;

namespace Clash.Tests.Providers;

public sealed class SubscriptionConverterTests
{
    [Fact]
    public void TheDocumentRoundTripsThroughTheParser()
    {
        var entries = new[]
        {
            TestEntries.Proxy(
                "Tokyo: 1",
                "ss",
                ("server", "1.2.3.4"),
                ("port", 8388),
                ("cipher", "aes-128-gcm"),
                ("password", "p#w"),
                ("plugin", "obfs"),
                ("plugin-opts", new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["mode"] = "http",
                    ["host"] = "bing.com",
                }),
                ("alpn", new List<object?> { "h2", "http/1.1" })),
        };

        var yaml = SubscriptionConverter.ToYaml(entries);
        var config = ConfigParser.Parse(YamlReader.Parse(yaml));

        Assert.Single(config.Proxies);
        Assert.Equal("Tokyo: 1", config.Proxies[0].Name);
        Assert.Equal("ss", config.Proxies[0].Type);
        Assert.Equal("1.2.3.4", config.Proxies[0].Map.GetString("server"));
        Assert.Equal(8388, config.Proxies[0].Map.GetInt("port"));
        Assert.Equal("aes-128-gcm", config.Proxies[0].Map.GetString("cipher"));
        Assert.Equal("p#w", config.Proxies[0].Map.GetString("password"));
        Assert.Equal("obfs", config.Proxies[0].Map.GetString("plugin"));
        Assert.Equal("http", config.Proxies[0].Map.GetMap("plugin-opts").GetString("mode"));
        Assert.Equal("bing.com", config.Proxies[0].Map.GetMap("plugin-opts").GetString("host"));
        Assert.Equal(new[] { "h2", "http/1.1" }, config.Proxies[0].Map.GetStringList("alpn"));

        Assert.Single(config.ProxyGroups);
        Assert.Equal("PROXY", config.ProxyGroups[0].Name);
        Assert.Equal("select", config.ProxyGroups[0].Type);
        Assert.Equal(new[] { "Tokyo: 1", "DIRECT" }, config.ProxyGroups[0].Proxies);
        Assert.Equal(new[] { "MATCH,PROXY" }, config.Rules);
    }

    [Fact]
    public void NamesWithSpecialCharactersAreQuotedAndPreserved()
    {
        var entries = new[]
        {
            TestEntries.Proxy("colon: name", "ss", ("server", "a.example.com"), ("port", 1)),
            TestEntries.Proxy("hash#name", "ss", ("server", "b.example.com"), ("port", 2)),
            TestEntries.Proxy("quote\"name", "ss", ("server", "c.example.com"), ("port", 3)),
            TestEntries.Proxy("plain name", "ss", ("server", "d.example.com"), ("port", 4)),
            TestEntries.Proxy("12345", "ss", ("server", "e.example.com"), ("port", 5)),
            TestEntries.Proxy("true", "ss", ("server", "f.example.com"), ("port", 6)),
        };

        var yaml = SubscriptionConverter.ToYaml(entries);

        Assert.Contains("\"colon: name\"", yaml);
        Assert.Contains("\"hash#name\"", yaml);
        Assert.Contains("\"quote\\\"name\"", yaml);
        Assert.Contains("\"plain name\"", yaml);
        Assert.Contains("\"12345\"", yaml);
        Assert.Contains("\"true\"", yaml);

        var config = ConfigParser.Parse(YamlReader.Parse(yaml));

        Assert.Equal(
            new[] { "colon: name", "hash#name", "quote\"name", "plain name", "12345", "true" },
            config.Proxies.Select(p => p.Name));
        Assert.Equal(
            new[] { "colon: name", "hash#name", "quote\"name", "plain name", "12345", "true", "DIRECT" },
            config.ProxyGroups[0].Proxies);
    }

    [Fact]
    public void SafeScalarsStayUnquoted()
    {
        var yaml = SubscriptionConverter.ToYaml(
            [TestEntries.Proxy("node", "ss", ("server", "1.2.3.4"), ("port", 8388), ("cipher", "aes-128-gcm"))]);

        Assert.Contains("name: node", yaml);
        Assert.Contains("server: 1.2.3.4", yaml);
        Assert.Contains("port: 8388", yaml);
        Assert.Contains("cipher: aes-128-gcm", yaml);
        Assert.DoesNotContain("\"node\"", yaml);
    }

    [Fact]
    public void AnEmptyProxyListStillProducesALoadableDocument()
    {
        var yaml = SubscriptionConverter.ToYaml([]);
        var config = ConfigParser.Parse(YamlReader.Parse(yaml));

        Assert.Empty(config.Proxies);
        Assert.Single(config.ProxyGroups);
        Assert.Equal(new[] { "DIRECT" }, config.ProxyGroups[0].Proxies);
        Assert.Equal(new[] { "MATCH,PROXY" }, config.Rules);
    }

    [Fact]
    public void DuplicateNamesAreRenamedSoNoNodeIsLost()
    {
        var entries = new[]
        {
            TestEntries.Proxy("dup", "ss", ("server", "a.example.com"), ("port", 1)),
            TestEntries.Proxy("dup", "ss", ("server", "b.example.com"), ("port", 2)),
            TestEntries.Proxy("dup", "ss", ("server", "c.example.com"), ("port", 3)),
        };

        var yaml = SubscriptionConverter.ToYaml(entries);
        var config = ConfigParser.Parse(YamlReader.Parse(yaml));

        Assert.Equal(new[] { "dup", "dup 2", "dup 3" }, config.Proxies.Select(p => p.Name));
        Assert.Equal("b.example.com", config.Proxies[1].Map.GetString("server"));
        Assert.Equal(new[] { "dup", "dup 2", "dup 3", "DIRECT" }, config.ProxyGroups[0].Proxies);
    }

    [Fact]
    public void TheGroupNameCanBeChosen()
    {
        var yaml = SubscriptionConverter.ToYaml(
            [TestEntries.Proxy("node", "ss", ("server", "1.2.3.4"), ("port", 8388))],
            "AUTO");

        var config = ConfigParser.Parse(YamlReader.Parse(yaml));

        Assert.Equal("AUTO", config.ProxyGroups[0].Name);
        Assert.Equal(new[] { "MATCH,AUTO" }, config.Rules);
    }

    [Fact]
    public void DirectIsNotDuplicatedWhenANodeIsNamedDirect()
    {
        var yaml = SubscriptionConverter.ToYaml([TestEntries.Proxy("DIRECT", "ss", ("server", "1.2.3.4"), ("port", 8388))]);
        var config = ConfigParser.Parse(YamlReader.Parse(yaml));

        Assert.Equal(new[] { "DIRECT" }, config.ProxyGroups[0].Proxies);
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("aes-128-gcm", "aes-128-gcm")]
    [InlineData("has space", "\"has space\"")]
    [InlineData("colon:name", "\"colon:name\"")]
    [InlineData("hash#name", "\"hash#name\"")]
    [InlineData("", "''")]
    [InlineData("123", "\"123\"")]
    [InlineData("true", "\"true\"")]
    [InlineData("-leading", "\"-leading\"")]
    [InlineData("say \"hi\"", "\"say \\\"hi\\\"\"")]
    public void QuoteIfNeededQuotesExactlyWhatYamlWouldReinterpret(string value, string expected)
        => Assert.Equal(expected, SubscriptionConverter.QuoteIfNeeded(value));

    [Fact]
    public void QuoteEscapesBackslashesAndControlCharacters()
    {
        Assert.Equal("\"a\\\\b\"", SubscriptionConverter.Quote("a\\b"));
        Assert.Equal("\"a\\nb\"", SubscriptionConverter.Quote("a\nb"));
    }

    [Fact]
    public void FormatScalarRendersNullsAndBooleans()
    {
        Assert.Equal("''", SubscriptionConverter.FormatScalar(null));
        Assert.Equal("true", SubscriptionConverter.FormatScalar(true));
        Assert.Equal("false", SubscriptionConverter.FormatScalar(false));
        Assert.Equal("8388", SubscriptionConverter.FormatScalar(8388));
    }
}
