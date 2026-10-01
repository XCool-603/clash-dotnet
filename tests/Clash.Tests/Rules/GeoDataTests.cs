using System.Net;
using System.Text;
using Clash.Core.Configuration;
using Clash.Core.Rules;
using Xunit;

namespace Clash.Tests.Rules;

public class GeoDataTests
{
    [Fact]
    public void EmptyReturnsNothingAndNeverThrows()
    {
        var empty = GeoData.Empty;

        Assert.False(empty.TryGetCountry(IPAddress.Parse("1.1.1.1"), out var country));
        Assert.Equal(string.Empty, country);
        Assert.False(empty.TryGetAsn(IPAddress.Parse("1.1.1.1"), out var asn));
        Assert.Equal(0u, asn);
        Assert.Null(empty.GetGeoSite("cn"));
        Assert.Null(empty.GetGeoSiteCidrs("cn"));
        Assert.False(empty.HasGeoSite("cn"));
        Assert.False(empty.HasCountry("CN"));
    }

    [Fact]
    public async Task EmptyLoadIsANoOp()
    {
        await GeoData.Empty.LoadAsync();
        Assert.Null(GeoData.Empty.GetGeoSite("cn"));
    }

    [Fact]
    public async Task MissingDataDirectoryIsHarmless()
    {
        using var scope = new TempDirectory();

        using var geo = new GeoData(new ClashConfig(), Path.Combine(scope.Path, "does-not-exist"));
        await geo.LoadAsync();

        Assert.False(geo.TryGetCountry(IPAddress.Parse("1.1.1.1"), out _));
        Assert.False(geo.HasGeoSite("cn"));
    }

    [Fact]
    public async Task TextGeoSiteDirectoryIsLoaded()
    {
        using var scope = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(scope.Path, "geosite"));
        File.WriteAllText(
            Path.Combine(scope.Path, "geosite", "CN.txt"),
            "google.com\n+.gstatic.com\nfull:exact.com\nkeyword:ads\nregexp:^cdn\\.\n# comment\n");

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        Assert.True(geo.HasGeoSite("cn"));
        Assert.True(geo.HasGeoSite("CN"));

        var domains = geo.GetGeoSite("cn");
        Assert.NotNull(domains);
        Assert.Contains("google.com", domains!);
        Assert.Equal(5, domains!.Count);

        var matcher = geo.GetGeoSiteMatcher("cn");
        Assert.NotNull(matcher);
        Assert.True(matcher!.Match("www.google.com") >= 0);
        Assert.True(matcher.Match("x.gstatic.com") >= 0);
        Assert.True(matcher.Match("exact.com") >= 0);
        Assert.False(matcher.Match("www.exact.com") >= 0);
        Assert.True(matcher.Match("cdn.ads.example") >= 0);
        Assert.True(matcher.Match("cdn.example.com") >= 0);
        Assert.False(matcher.Match("example.com") >= 0);
    }

    [Fact]
    public async Task TextGeoSiteDirectoryAcceptsYaml()
    {
        using var scope = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(scope.Path, "geosite"));
        File.WriteAllText(Path.Combine(scope.Path, "geosite", "TEST.yml"), "payload:\n  - '+.example.com'\n");

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        Assert.True(geo.HasGeoSite("TEST"));
        Assert.True(geo.GetGeoSiteMatcher("TEST")!.Match("www.example.com") >= 0);
    }

    [Fact]
    public async Task TextGeoIpDirectoryIsLoaded()
    {
        using var scope = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(scope.Path, "geoip"));
        File.WriteAllText(Path.Combine(scope.Path, "geoip", "CN.txt"), "10.0.0.0/8\n192.168.0.0/16\n");

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        Assert.True(geo.TryGetCountry(IPAddress.Parse("10.1.2.3"), out var code));
        Assert.Equal("CN", code);
        Assert.True(geo.TryGetCountry(IPAddress.Parse("192.168.4.4"), out _));
        Assert.False(geo.TryGetCountry(IPAddress.Parse("8.8.8.8"), out _));
        Assert.True(geo.HasCountry("cn"));
    }

    [Fact]
    public async Task GeoSiteDatIsDecodedFromProtobuf()
    {
        using var scope = new TempDirectory();
        File.WriteAllBytes(Path.Combine(scope.Path, "geosite.dat"), BuildGeoSiteDat());

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        Assert.True(geo.HasGeoSite("CN"));

        var domains = geo.GetGeoSite("CN");
        Assert.NotNull(domains);
        Assert.Contains("google.com", domains!);
        Assert.Contains("exact.com", domains!);
        Assert.Contains("^ads\\.", domains!);

        var matcher = geo.GetGeoSiteMatcher("CN");
        Assert.NotNull(matcher);
        Assert.True(matcher!.Match("www.google.com") >= 0);
        Assert.True(matcher.Match("exact.com") >= 0);
        Assert.False(matcher.Match("www.exact.com") >= 0);
        Assert.True(matcher.Match("ads.example.com") >= 0);
        Assert.False(matcher.Match("example.com") >= 0);
    }

    [Fact]
    public async Task GeoIpDatIsDecodedFromProtobuf()
    {
        using var scope = new TempDirectory();
        File.WriteAllBytes(Path.Combine(scope.Path, "geoip.dat"), BuildGeoIpDat());

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        Assert.True(geo.HasCountry("CN"));
        Assert.True(geo.TryGetCountry(IPAddress.Parse("10.1.2.3"), out var code));
        Assert.Equal("CN", code);
        Assert.False(geo.TryGetCountry(IPAddress.Parse("8.8.8.8"), out _));
    }

    [Fact]
    public async Task GeoSiteCidrAttributeIsExposed()
    {
        using var scope = new TempDirectory();
        File.WriteAllBytes(Path.Combine(scope.Path, "geosite.dat"), BuildGeoSiteDat(withCidrs: true));

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        var cidrs = geo.GetGeoSiteCidrs("CN");
        Assert.NotNull(cidrs);
        Assert.Single(cidrs!);
        Assert.Equal("10.0.0.0", cidrs![0].Network.ToString());
        Assert.Equal(8, cidrs[0].PrefixLength);

        var matcher = geo.GetGeoSiteCidrMatcher("CN");
        Assert.NotNull(matcher);
        Assert.True(matcher!.Match(IPAddress.Parse("10.9.9.9")) >= 0);
        Assert.False(matcher.Match(IPAddress.Parse("11.9.9.9")) >= 0);
    }

    [Fact]
    public async Task GeoSiteRuleMatchesTheIpCidrAttribute()
    {
        using var scope = new TempDirectory();
        File.WriteAllBytes(Path.Combine(scope.Path, "geosite.dat"), BuildGeoSiteDat(withCidrs: true));

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        var rule = RuleParser.Parse("GEOSITE,CN@ipcidr,PROXY");
        Assert.True(rule.ShouldResolveIp);

        var engine = new RuleEngine(new FakeDnsResolver(), geo, [rule], null);
        var match = await engine.MatchAsync(TestMetadata.Flow("10.1.1.1"));

        Assert.NotNull(match);
        Assert.Equal("PROXY", match!.AdapterName);
    }

    [Fact]
    public async Task CorruptDataFilesDoNotThrow()
    {
        using var scope = new TempDirectory();
        File.WriteAllBytes(Path.Combine(scope.Path, "geosite.dat"), [0xFF, 0xFF, 0xFF, 0xFF]);
        File.WriteAllBytes(Path.Combine(scope.Path, "geoip.dat"), [0x08, 0x96, 0x01, 0xFF]);

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();

        Assert.False(geo.HasGeoSite("cn"));
        Assert.False(geo.TryGetCountry(IPAddress.Parse("1.1.1.1"), out _));
    }

    [Fact]
    public async Task DownloadsAreOptIn()
    {
        using var scope = new TempDirectory();
        var config = new ClashConfig();
        config.GeoxUrl.GeoSite = "http://127.0.0.1:1/geosite.dat";
        config.GeoxUrl.Mmdb = "http://127.0.0.1:1/Country.mmdb";

        using var geo = new GeoData(config, scope.Path, allowDownload: false);
        await geo.LoadAsync();

        Assert.False(File.Exists(Path.Combine(scope.Path, "geosite.dat")));
        Assert.False(geo.HasGeoSite("cn"));
    }

    [Fact]
    public async Task RepeatedLoadsAreIdempotent()
    {
        using var scope = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(scope.Path, "geosite"));
        File.WriteAllText(Path.Combine(scope.Path, "geosite", "CN.txt"), "google.com\n");

        using var geo = new GeoData(new ClashConfig(), scope.Path);
        await geo.LoadAsync();
        await geo.LoadAsync();

        Assert.Equal(1, geo.GetGeoSite("CN")!.Count);
    }

    [Fact]
    public void UnknownCodesNeverThrow()
    {
        using var scope = new TempDirectory();
        using var geo = new GeoData(new ClashConfig(), scope.Path);

        Assert.Null(geo.GetGeoSite("nope"));
        Assert.Null(geo.GetGeoSiteCidrs("nope"));
        Assert.Null(geo.GetGeoSiteMatcher("nope"));
        Assert.Null(geo.GetGeoSiteCidrMatcher("nope"));
        Assert.False(geo.HasGeoSite("nope"));
        Assert.False(geo.HasCountry("nope"));
        Assert.Null(geo.GetGeoSite(string.Empty));
    }

    private static byte[] BuildGeoSiteDat(bool withCidrs = false)
    {
        var entry = Concat(
            StringField(1, "CN"),
            LengthDelimited(2, Domain(2, "google.com")),
            LengthDelimited(2, Domain(3, "exact.com")),
            LengthDelimited(2, Domain(1, "^ads\\.")),
            LengthDelimited(2, Domain(0, "plain.example")));

        if (withCidrs)
        {
            var cidr = Concat(LengthDelimited(1, [10, 0, 0, 0]), VarintField(2, 8));
            entry = Concat(entry, LengthDelimited(3, cidr));
        }

        return LengthDelimited(1, entry);
    }

    private static byte[] BuildGeoIpDat()
    {
        var cidr = Concat(LengthDelimited(1, [10, 0, 0, 0]), VarintField(2, 8));
        var entry = Concat(StringField(1, "CN"), LengthDelimited(2, cidr));
        return LengthDelimited(1, entry);
    }

    private static byte[] Domain(int type, string value) => Concat(VarintField(1, (ulong)type), StringField(2, value));

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new List<byte>();
        foreach (var part in parts) result.AddRange(part);
        return [.. result];
    }

    private static byte[] Tag(int field, int wire) => Varint((ulong)((field << 3) | wire));

    private static byte[] Varint(ulong value)
    {
        var bytes = new List<byte>();
        do
        {
            var current = (byte)(value & 0x7F);
            value >>= 7;
            if (value != 0) current |= 0x80;
            bytes.Add(current);
        }
        while (value != 0);

        return [.. bytes];
    }

    private static byte[] VarintField(int field, ulong value) => Concat(Tag(field, 0), Varint(value));

    private static byte[] LengthDelimited(int field, byte[] body) => Concat(Tag(field, 2), Varint((ulong)body.Length), body);

    private static byte[] StringField(int field, string value) => LengthDelimited(field, Encoding.UTF8.GetBytes(value));

    private sealed class TempDirectory : IDisposable
    {
        public TempDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "clash-rules-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, true);
            }
            catch (IOException)
            {
                // Best effort cleanup.
            }
        }
    }
}
