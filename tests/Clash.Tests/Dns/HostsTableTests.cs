using System.Net;
using Clash.Core.Dns;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class HostsTableTests
{
    private static Dictionary<string, object?> Hosts(params (string Key, object? Value)[] entries)
    {
        var map = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in entries) map[key] = value;
        return map;
    }

    private static void AssertAddresses(IPAddress[] actual, params string[] expected)
        => Assert.Equal(expected.Select(IPAddress.Parse).ToArray(), actual);

    [Fact]
    public void ResolvesAnExactEntry()
    {
        var table = new HostsTable(Hosts(("example.com", "1.2.3.4")));

        Assert.True(table.TryResolve("example.com", out var addresses));
        AssertAddresses(addresses, "1.2.3.4");
    }

    [Fact]
    public void ResolvesAnEntryFromAListOfStrings()
    {
        var table = new HostsTable(Hosts(("example.com", new List<object?> { "1.2.3.4", "2606:4700::1" })));

        Assert.True(table.TryResolve("example.com", out var addresses));
        Assert.Equal(2, addresses.Length);
        Assert.Contains(IPAddress.Parse("1.2.3.4"), addresses);
        Assert.Contains(IPAddress.Parse("2606:4700::1"), addresses);
    }

    [Fact]
    public void ResolvesACommaSeparatedValue()
    {
        var table = new HostsTable(Hosts(("example.com", "1.2.3.4, 5.6.7.8")));

        Assert.True(table.TryResolve("example.com", out var addresses));
        Assert.Equal(2, addresses.Length);
    }

    [Fact]
    public void ExactMatchBeatsWildcard()
    {
        var table = new HostsTable(Hosts(
            ("*.example.com", "9.9.9.9"),
            ("www.example.com", "1.1.1.1")));

        Assert.True(table.TryResolve("www.example.com", out var exact));
        AssertAddresses(exact, "1.1.1.1");

        Assert.True(table.TryResolve("other.example.com", out var wildcard));
        AssertAddresses(wildcard, "9.9.9.9");
    }

    [Fact]
    public void StarWildcardDoesNotMatchTheApex()
    {
        var table = new HostsTable(Hosts(("*.example.com", "9.9.9.9")));

        Assert.False(table.TryResolve("example.com", out _));
        Assert.True(table.TryResolve("a.example.com", out var one));
        AssertAddresses(one, "9.9.9.9");
        Assert.True(table.TryResolve("a.b.example.com", out var two));
        AssertAddresses(two, "9.9.9.9");
    }

    [Fact]
    public void PlusWildcardMatchesTheApexAndSubdomains()
    {
        var table = new HostsTable(Hosts(("+.example.com", "9.9.9.9")));

        Assert.True(table.TryResolve("example.com", out var apex));
        AssertAddresses(apex, "9.9.9.9");
        Assert.True(table.TryResolve("a.b.example.com", out _));
    }

    [Fact]
    public void WildcardMatchingIsLabelBoundaryAware()
    {
        var table = new HostsTable(Hosts(("*.example.com", "9.9.9.9")));

        Assert.False(table.TryResolve("notexample.com", out _));
        Assert.False(table.TryResolve("example.com.evil.net", out _));
    }

    [Fact]
    public void LongestWildcardSuffixWins()
    {
        var table = new HostsTable(Hosts(
            ("*.example.com", "1.1.1.1"),
            ("*.deep.example.com", "2.2.2.2")));

        Assert.True(table.TryResolve("a.deep.example.com", out var deep));
        AssertAddresses(deep, "2.2.2.2");

        Assert.True(table.TryResolve("a.example.com", out var shallow));
        AssertAddresses(shallow, "1.1.1.1");
    }

    [Fact]
    public void LookupIsCaseInsensitiveAndIgnoresTrailingDots()
    {
        var table = new HostsTable(Hosts(("Example.COM", "1.2.3.4")));

        Assert.True(table.TryResolve("example.com.", out var addresses));
        AssertAddresses(addresses, "1.2.3.4");
    }

    [Fact]
    public void FollowsAliasValues()
    {
        var table = new HostsTable(Hosts(
            ("alias.example.com", "real.example.com"),
            ("real.example.com", "1.2.3.4")));

        Assert.True(table.TryResolve("alias.example.com", out var addresses));
        AssertAddresses(addresses, "1.2.3.4");
    }

    [Fact]
    public void AliasCyclesTerminate()
    {
        var table = new HostsTable(Hosts(
            ("a.example.com", "b.example.com"),
            ("b.example.com", "a.example.com")));

        Assert.False(table.TryResolve("a.example.com", out _));
    }

    [Fact]
    public void LaterSourcesOverrideEarlierOnes()
    {
        var first = Hosts(("example.com", "1.1.1.1"));
        var second = Hosts(("example.com", "2.2.2.2"));

        var table = new HostsTable([first, second], useSystemHosts: false);

        Assert.True(table.TryResolve("example.com", out var addresses));
        AssertAddresses(addresses, "2.2.2.2");
    }

    [Fact]
    public void ContainsReportsExactAndWildcardMatches()
    {
        var table = new HostsTable(Hosts(("*.example.com", "9.9.9.9")));

        Assert.True(table.Contains("a.example.com"));
        Assert.False(table.Contains("example.com"));
        Assert.False(table.Contains("example.org"));
    }

    [Fact]
    public void UnknownHostDoesNotResolve()
    {
        var table = new HostsTable(Hosts(("example.com", "1.2.3.4")));

        Assert.False(table.TryResolve("missing.example.com", out var addresses));
        Assert.Empty(addresses);
    }

    [Fact]
    public void EmptyAndMalformedEntriesAreIgnored()
    {
        var table = new HostsTable(Hosts(
            ("empty.example.com", ""),
            ("blank.example.com", new List<object?>()),
            ("good.example.com", "1.2.3.4")));

        Assert.False(table.TryResolve("empty.example.com", out _));
        Assert.False(table.TryResolve("blank.example.com", out _));
        Assert.True(table.TryResolve("good.example.com", out _));
    }

    [Fact]
    public void WildcardKeyDetectionMatchesTheDocumentedForms()
    {
        Assert.True(HostsTable.IsWildcardKey("*.example.com"));
        Assert.True(HostsTable.IsWildcardKey("+.example.com"));
        Assert.True(HostsTable.IsWildcardKey(".example.com"));
        Assert.False(HostsTable.IsWildcardKey("example.com"));
    }

    [Fact]
    public void SystemHostsPathIsPlatformAppropriate()
    {
        var path = HostsTable.SystemHostsPath;

        Assert.False(string.IsNullOrWhiteSpace(path));
        if (OperatingSystem.IsWindows())
        {
            Assert.EndsWith(Path.Combine("drivers", "etc", "hosts"), path, StringComparison.OrdinalIgnoreCase);
        }
        else
        {
            Assert.Equal("/etc/hosts", path);
        }
    }

    [Fact]
    public void MergingTheSystemHostsFileIsSafe()
    {
        // Reading the platform hosts file is not network I/O and must be safe
        // even when the file is missing.
        var table = new HostsTable(hosts: null, useSystemHosts: true);

        Assert.NotNull(table);
    }
}
