using System.Buffers.Binary;
using System.Net;
using Clash.Core.Common;
using Clash.Core.Configuration;
using Clash.Core.Providers;
using Clash.Core.Rules;
using Microsoft.Extensions.Logging;
using Xunit;
using ZstdSharp;

namespace Clash.Tests.Providers;

/// <summary>
/// Covers <see cref="MrsDecoder"/>. The four fixtures are real published rule sets from
/// <see href="https://github.com/MetaCubeX/meta-rules-dat"/> (<c>meta</c> branch, under
/// <c>geo/geosite</c> and <c>geo/geoip</c>), so they are legitimate test vectors rather than
/// something written to match this decoder.
/// </summary>
public sealed class MrsDecoderTests
{
    private const string AdsFixture = "geosite-category-ads-all.mrs";
    private const string CnFixture = "geosite-cn.mrs";
    private const string GeoIpFixture = "geoip-cn.mrs";
    private const string AsnFixture = "asn-AS13335.mrs";

    private static byte[] Fixture(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Providers", "Fixtures", name);
        Assert.True(File.Exists(path), $"fixture {name} was not copied to {path}");
        return File.ReadAllBytes(path);
    }

    // ── the published fixtures ───────────────────────────────────────────────

    public static TheoryData<string> DomainFixtures => new() { AdsFixture, CnFixture };

    public static TheoryData<string> IpCidrFixtures => new() { GeoIpFixture, AsnFixture };

    public static TheoryData<string, string> AllFixtures => new()
    {
        { AdsFixture, "domain" },
        { CnFixture, "domain" },
        { GeoIpFixture, "ipcidr" },
        { AsnFixture, "ipcidr" },
    };

    [Theory]
    [MemberData(nameof(AllFixtures))]
    public void EveryFixtureDecodesToANonEmptySet(string fixture, string behavior)
    {
        var entries = MrsDecoder.Decode(Fixture(fixture), behavior);

        Assert.NotEmpty(entries);
        Assert.DoesNotContain(entries, string.IsNullOrWhiteSpace);
    }

    [Theory]
    [MemberData(nameof(AllFixtures))]
    public void DecodingTheSameFileTwiceYieldsIdenticalOutput(string fixture, string behavior)
    {
        var bytes = Fixture(fixture);

        Assert.Equal(MrsDecoder.Decode(bytes, behavior), MrsDecoder.Decode(bytes, behavior));
    }

    [Theory]
    [MemberData(nameof(DomainFixtures))]
    public void DomainFixturesUseMihomosRuleSetSyntax(string fixture)
    {
        var entries = MrsDecoder.Decode(Fixture(fixture), "domain");

        foreach (var entry in entries)
        {
            // Only the three domain forms mihomo's rule sets use: "domain", "+.domain"
            // (the domain and everything below it) and ".domain" (below it only).
            var domain = entry.StartsWith("+.", StringComparison.Ordinal) ? entry[2..]
                : entry.StartsWith('.') ? entry[1..]
                : entry;

            Assert.False(domain.Length == 0, $"entry \"{entry}\" carries no domain");
            Assert.DoesNotContain('/', domain);
            Assert.DoesNotContain(':', domain);
        }
    }

    [Fact]
    public void CategoryAdsAllContainsTheWellKnownAdDomains()
    {
        var entries = MrsDecoder.Decode(Fixture(AdsFixture), "domain");

        // Verified against the yaml twin meta-rules-dat publishes for the same list: the
        // decoded set is identical to it, entry for entry.
        Assert.Contains("+.google-analytics.com", entries);
        Assert.Contains("+.doubleclick.net", entries);
        Assert.Contains("logs.ads.vungle.com", entries);
        Assert.DoesNotContain("example.com", entries);
    }

    [Fact]
    public void CategoryAdsAllMatchesThroughTheRuleEngine()
    {
        var entries = MrsDecoder.Decode(Fixture(AdsFixture), "domain");
        var set = RuleSet.FromPayload("ads", "domain", entries);

        Assert.True(set.Match(TestEntries.Flow("google-analytics.com")));
        Assert.True(set.Match(TestEntries.Flow("www.google-analytics.com")));
        Assert.True(set.Match(TestEntries.Flow("logs.ads.vungle.com")));
        Assert.True(set.Match(TestEntries.Flow("ads.x5.ru")));
        Assert.False(set.Match(TestEntries.Flow("example.com")));
    }

    [Fact]
    public void GeositeCnContainsWellKnownChineseDomains()
    {
        var entries = MrsDecoder.Decode(Fixture(CnFixture), "domain");

        Assert.Contains("+.qq.com", entries);
        Assert.Contains("+.baidu.com", entries);
        Assert.Contains("+.bilibili.com", entries);
        Assert.Contains("+.taobao.com", entries);

        var set = RuleSet.FromPayload("cn", "domain", entries);
        Assert.True(set.Match(TestEntries.Flow("www.qq.com")));
        Assert.False(set.Match(TestEntries.Flow("www.google.com")));
    }

    [Theory]
    [MemberData(nameof(IpCidrFixtures))]
    public void IpCidrFixturesDecodeToValidPrefixes(string fixture)
    {
        var entries = MrsDecoder.Decode(Fixture(fixture), "ipcidr");

        foreach (var entry in entries)
        {
            Assert.True(IpPrefix.TryParse(entry, out var prefix), $"\"{entry}\" is not a CIDR prefix");
            Assert.Equal(entry, prefix.ToString());

            // mihomo stores IPv4 as an IPv4-mapped IPv6 address; a mapped form leaking out
            // here would never match a plain IPv4 destination.
            Assert.DoesNotContain("::ffff:", entry);
        }
    }

    [Fact]
    public void Asn13335ContainsCloudflaresWellKnownRange()
    {
        var entries = MrsDecoder.Decode(Fixture(AsnFixture), "ipcidr");

        // AS13335 is Cloudflare, and 1.1.1.0/24 is the block its public resolver lives in.
        // The set is RIR route data rather than the aggregated anycast list, so the wider
        // 104.16.0.0/13 and 172.64.0.0/13 are present only as more specific prefixes.
        Assert.Contains("1.1.1.0/24", entries);
        Assert.Contains("104.16.0.0/14", entries);

        var set = RuleSet.FromPayload("asn", "ipcidr", entries);
        Assert.True(set.Match(TestEntries.Flow("1.1.1.1")));
        Assert.True(set.Match(TestEntries.Flow("104.16.132.229")));
        Assert.False(set.Match(TestEntries.Flow("8.8.8.8")));
    }

    [Fact]
    public void GeoipCnContainsKnownChineseRangesAndCoversBothFamilies()
    {
        var entries = MrsDecoder.Decode(Fixture(GeoIpFixture), "ipcidr");

        Assert.Contains("1.0.1.0/24", entries);
        Assert.Contains(entries, entry => entry.Contains(':'));

        var set = RuleSet.FromPayload("geoip-cn", "ipcidr", entries);
        Assert.True(set.Match(TestEntries.Flow("114.114.114.114")));
        Assert.True(set.Match(TestEntries.Flow("220.181.38.148")));
        Assert.False(set.Match(TestEntries.Flow("8.8.8.8")));
        Assert.False(set.Match(TestEntries.Flow("1.1.1.1")));
    }

    // ── failures ─────────────────────────────────────────────────────────────

    [Fact]
    public void ABodyThatIsNotZstdIsRejected()
    {
        var error = Assert.Throws<ProviderException>(() => MrsDecoder.Decode("example.com\n"u8.ToArray(), "domain"));

        Assert.Contains("zstd", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ATruncatedMrsStreamIsRejected()
    {
        var bytes = Fixture(AdsFixture);
        var cut = bytes[..(bytes.Length / 2)];

        var error = Assert.Throws<ProviderException>(() => MrsDecoder.Decode(cut, "domain"));

        Assert.Contains("mrs", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ATruncatedMrsPayloadIsRejected()
    {
        var body = Decompress(Fixture(AdsFixture));

        var error = Assert.Throws<ProviderException>(
            () => MrsDecoder.Decode(MrsWriter.Compress(body[..(body.Length - 100)]), "domain"));

        Assert.Contains("truncated", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnEmptyBodyIsRejected()
    {
        Assert.Throws<ProviderException>(() => MrsDecoder.Decode([], "domain"));
    }

    [Fact]
    public void AWrongMagicIsRejected()
    {
        var bytes = MrsWriter.Container(0, 1, MrsWriter.DomainPayload(["example.com"]), magic: [(byte)'M', (byte)'R', (byte)'X', 1]);

        var error = Assert.Throws<ProviderException>(() => MrsDecoder.Decode(bytes, "domain"));

        Assert.Contains("magic", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AWrongPayloadVersionIsRejected()
    {
        var bytes = MrsWriter.Container(0, 1, MrsWriter.DomainPayload(["example.com"], version: 2));

        var error = Assert.Throws<ProviderException>(() => MrsDecoder.Decode(bytes, "domain"));

        Assert.Contains("version", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ABehaviourThatDisagreesWithTheProviderIsRejected()
    {
        var error = Assert.Throws<ProviderException>(() => MrsDecoder.Decode(Fixture(AdsFixture), "ipcidr"));

        Assert.Contains("domain", error.Message);
        Assert.Contains("ipcidr", error.Message);
    }

    [Fact]
    public void AClassicalBodyIsRejected()
    {
        var bytes = MrsWriter.Container(2, 0, [1]);

        var error = Assert.Throws<ProviderException>(() => MrsDecoder.Decode(bytes, "classical"));

        Assert.Contains("classical", error.Message);
    }

    // ── hand-built payloads ──────────────────────────────────────────────────

    [Fact]
    public void AHandBuiltDomainSetDecodesToTheExactEntries()
    {
        var bytes = MrsWriter.Domain(["example.com", "+.example.org", ".sub.example.net", "*.wild.example.io", "+.deep.a.example.org"]);

        var entries = MrsDecoder.Decode(bytes, "domain");

        Assert.Equal(
            new[] { "*.wild.example.io", "+.deep.a.example.org", "+.example.org", ".sub.example.net", "example.com" },
            entries.OrderBy(entry => entry, StringComparer.Ordinal).ToList());
    }

    [Fact]
    public void AHandBuiltDomainSetCompactsExactAndSuffixKeysIntoOneRule()
    {
        // "+." is stored as two keys; the decoder has to fold them back into one entry
        // instead of emitting both "example.com" and ".example.com".
        var bytes = MrsWriter.Domain(["+.example.com"]);

        Assert.Equal(new[] { "+.example.com" }, MrsDecoder.Decode(bytes, "domain"));
    }

    [Fact]
    public void AHandBuiltIpCidrSetDecomposesRangesIntoPrefixes()
    {
        var bytes = MrsWriter.IpCidr(
        [
            (IPAddress.Parse("1.1.1.0"), IPAddress.Parse("1.1.1.255")),
            (IPAddress.Parse("10.0.0.1"), IPAddress.Parse("10.0.0.6")),
            (IPAddress.Parse("192.168.1.1"), IPAddress.Parse("192.168.1.1")),
            (IPAddress.Parse("0.0.0.0"), IPAddress.Parse("255.255.255.255")),
            (IPAddress.Parse("2001:db8::"), IPAddress.Parse("2001:db8::ffff")),
        ]);

        Assert.Equal(
            new[]
            {
                "1.1.1.0/24",
                "10.0.0.1/32",
                "10.0.0.2/31",
                "10.0.0.4/31",
                "10.0.0.6/32",
                "192.168.1.1/32",
                "0.0.0.0/0",
                "2001:db8::/112",
            },
            MrsDecoder.Decode(bytes, "ipcidr"));
    }

    // ── loader wiring ────────────────────────────────────────────────────────

    [Fact]
    public async Task FileProviderReadsAnMrsPayload()
    {
        using var temp = new TempDirectory();
        WriteBinary(temp, "rules/ads.mrs", Fixture(AdsFixture));

        using var loader = new RuleProviderLoader(temp.Root);
        var result = await loader.LoadAsync("ads", Config("file", "mrs", "domain", path: "rules/ads.mrs"));

        Assert.Contains("+.google-analytics.com", result.Payload);

        var set = loader.ToRuleSet("ads", result);
        Assert.True(set.Match(TestEntries.Flow("www.google-analytics.com")));
        Assert.False(set.Match(TestEntries.Flow("example.com")));
    }

    [Fact]
    public async Task HttpProviderDownloadsAndCachesAnMrsBodyByteForByte()
    {
        using var temp = new TempDirectory();
        var body = Fixture(AdsFixture);
        var config = Config("http", "mrs", "domain", path: "cache/ads.mrs", url: "https://rules.example.com/ads.mrs");

        using var loader = new RuleProviderLoader(temp.Root, FakeHttpMessageHandler.Returns(body));
        var result = await loader.LoadAsync("ads", config);

        Assert.Contains("+.google-analytics.com", result.Payload);

        // The cache holds the compressed stream verbatim; decoding it as text would have
        // replaced every invalid UTF-8 sequence with U+FFFD and destroyed the file.
        Assert.Equal(body, File.ReadAllBytes(temp.PathOf("cache/ads.mrs")));

        using var offline = new RuleProviderLoader(temp.Root, FakeHttpMessageHandler.Throws());
        var cached = await offline.LoadAsync("ads", config);

        Assert.Equal(result.Payload, cached.Payload);
    }

    [Fact]
    public async Task AnUndecodableMrsProviderWarnsAndLeavesAnEmptySet()
    {
        using var temp = new TempDirectory();
        WriteBinary(temp, "rules/broken.mrs", "not an mrs body at all"u8.ToArray());

        var logger = new CapturingLogger<RuleProviderLoader>();
        using var loader = new RuleProviderLoader(temp.Root, logger);

        var result = await loader.LoadAsync("broken", Config("file", "mrs", "domain", path: "rules/broken.mrs"));

        Assert.Empty(result.Payload);
        Assert.Contains(logger.Warnings, warning => warning.Contains("broken", StringComparison.Ordinal));

        var set = loader.ToRuleSet("broken", result);
        Assert.Equal(0, set.Count);
        Assert.False(set.Match(TestEntries.Flow("example.com")));
    }

    [Fact]
    public async Task AnMrsProviderWhoseBehaviourDisagreesWithItsFileIsEmptyRatherThanWrong()
    {
        using var temp = new TempDirectory();
        WriteBinary(temp, "rules/ads.mrs", Fixture(AdsFixture));

        var logger = new CapturingLogger<RuleProviderLoader>();
        using var loader = new RuleProviderLoader(temp.Root, logger);

        // The provider claims ipcidr but the file holds domain entries; handing them to the
        // CIDR matcher would silently match nothing, so the set is left empty instead.
        var result = await loader.LoadAsync("ads", Config("file", "mrs", "ipcidr", path: "rules/ads.mrs"));

        Assert.Empty(result.Payload);
        Assert.NotEmpty(logger.Warnings);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static RuleProviderConfig Config(
        string type,
        string format,
        string behavior,
        string path = "cache/rules.mrs",
        string url = "https://rules.example.com/set.mrs")
        => new() { Type = type, Format = format, Behavior = behavior, Path = path, Url = url };

    private static void WriteBinary(TempDirectory temp, string relative, byte[] content)
    {
        var path = temp.PathOf(relative);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
    }

    private static byte[] Decompress(byte[] payload)
    {
        using var input = new MemoryStream(payload, writable: false);
        using var zstd = new DecompressionStream(input);
        using var output = new MemoryStream();
        zstd.CopyTo(output);
        return output.ToArray();
    }

    /// <summary>Captures the warnings a loader emits.</summary>
    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Warnings { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning) Warnings.Add(formatter(state, exception));
        }
    }

    /// <summary>
    /// A test-only writer mirroring mihomo's <c>WriteBin</c>/<c>buildDomainSet</c> pair. It is
    /// the only way to pin the exact text a given trie produces, because the published
    /// fixtures only say "some real rule set" and not "this input becomes that output".
    /// </summary>
    private static class MrsWriter
    {
        public static byte[] Domain(IReadOnlyList<string> patterns)
            => Container(0, patterns.Count, DomainPayload(patterns));

        public static byte[] IpCidr(IReadOnlyList<(IPAddress From, IPAddress To)> ranges)
            => Container(1, ranges.Count, IpCidrPayload(ranges));

        public static byte[] DomainPayload(IReadOnlyList<string> patterns, byte version = 1)
        {
            var (leaves, bitmap, labels) = BuildDomainSet(patterns);
            var payload = new List<byte> { version };

            WriteInt64(payload, leaves.Count);
            foreach (var word in leaves) WriteUInt64(payload, word);

            WriteInt64(payload, bitmap.Count);
            foreach (var word in bitmap) WriteUInt64(payload, word);

            WriteInt64(payload, labels.Count);
            payload.AddRange(labels);

            return [.. payload];
        }

        public static byte[] IpCidrPayload(IReadOnlyList<(IPAddress From, IPAddress To)> ranges)
        {
            var payload = new List<byte> { 1 };
            WriteInt64(payload, ranges.Count);

            foreach (var (from, to) in ranges)
            {
                payload.AddRange(As16(from));
                payload.AddRange(As16(to));
            }

            return [.. payload];
        }

        public static byte[] Container(byte behavior, long count, byte[] payload, byte[]? magic = null)
        {
            var body = new List<byte>();
            body.AddRange(magic ?? [(byte)'M', (byte)'R', (byte)'S', 1]);
            body.Add(behavior);
            WriteInt64(body, count);
            WriteInt64(body, 0); // no reserved section
            body.AddRange(payload);

            return Compress([.. body]);
        }

        public static byte[] Compress(byte[] body) => new Compressor().Wrap(body).ToArray();

        /// <summary>
        /// Mirrors <c>buildDomainSet</c>: keys are stored reversed, sorted and deduplicated,
        /// then laid out breadth first with one 0 bit per edge and one 1 bit per node.
        /// </summary>
        private static (List<ulong> Leaves, List<ulong> Bitmap, List<byte> Labels) BuildDomainSet(IReadOnlyList<string> patterns)
        {
            var keys = new List<string>();
            foreach (var pattern in patterns)
            {
                var parts = pattern.ToLowerInvariant().Split('.');
                if (parts[0] == "+")
                {
                    keys.Add(Reversed(parts[1..]));
                    keys.Add(Reversed(parts));
                }
                else
                {
                    keys.Add(Reversed(parts));
                }
            }

            keys.Sort(StringComparer.Ordinal);
            keys = [.. keys.Distinct(StringComparer.Ordinal)];

            var leaves = new List<ulong>();
            var bitmap = new List<ulong>();
            var labels = new List<byte>();

            var index = 0;
            var node = 0;
            var queue = new List<(int Start, int End)> { (0, keys.Count) };
            var next = new List<(int Start, int End)>();

            for (var column = 0; queue.Count > 0; column++)
            {
                foreach (var (first, last) in queue)
                {
                    var start = first;
                    if (column == keys[start].Length)
                    {
                        SetBit(leaves, node);
                        start++;
                    }

                    for (var j = start; j < last;)
                    {
                        var from = j;
                        while (j < last && keys[j][column] == keys[from][column]) j++;

                        next.Add((from, j));
                        labels.Add((byte)keys[from][column]);
                        index++; // the edge bit is 0 and words start zeroed
                    }

                    SetBit(bitmap, index); // the node terminator
                    index++;
                    node++;
                }

                (queue, next) = (next, []);
            }

            return (leaves, bitmap, labels);
        }

        private static string Reversed(string[] parts)
        {
            // A leading dot is the dot-wildcard; the builder spells it with a '+'.
            if (parts[0].Length == 0) parts[0] = "+";

            var characters = string.Join('.', parts).ToCharArray();
            Array.Reverse(characters);
            return new string(characters);
        }

        private static void SetBit(List<ulong> bits, int index)
        {
            while (index >> 6 >= bits.Count) bits.Add(0);
            bits[index >> 6] |= 1UL << (index & 63);
        }

        private static byte[] As16(IPAddress address)
        {
            var bytes = address.GetAddressBytes();
            if (bytes.Length == 16) return bytes;

            var mapped = new byte[16];
            mapped[10] = 0xFF;
            mapped[11] = 0xFF;
            bytes.CopyTo(mapped, 12);
            return mapped;
        }

        private static void WriteInt64(List<byte> target, long value)
        {
            Span<byte> buffer = stackalloc byte[sizeof(long)];
            BinaryPrimitives.WriteInt64BigEndian(buffer, value);
            target.AddRange(buffer);
        }

        private static void WriteUInt64(List<byte> target, ulong value)
        {
            Span<byte> buffer = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
            target.AddRange(buffer);
        }
    }
}
