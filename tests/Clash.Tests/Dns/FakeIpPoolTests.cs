using System.Net;
using Clash.Core.Dns;
using Xunit;

namespace Clash.Tests.Dns;

public sealed class FakeIpPoolTests
{
    private static FakeIpPool Pool(int capacity = 8192)
        => new("198.18.0.1/16", "fdfe:dcba:9876::1/96", capacity);

    [Fact]
    public void AllocatesFromTheStartOfTheConfiguredRange()
    {
        var pool = Pool();

        var first = pool.Allocate("example.com");
        var second = pool.Allocate("example.org");

        Assert.Equal(IPAddress.Parse("198.18.0.1"), first);
        Assert.Equal(IPAddress.Parse("198.18.0.2"), second);
    }

    [Fact]
    public void AllocationIsStableForTheSameHost()
    {
        var pool = Pool();

        var first = pool.Allocate("example.com");
        var again = pool.Allocate("example.com");

        Assert.Equal(first, again);
        Assert.Equal(1, pool.Count);
    }

    [Fact]
    public void LookupAndLookupHostAreInverse()
    {
        var pool = Pool();
        var address = pool.Allocate("example.com");

        Assert.Equal("example.com", pool.Lookup(address));
        Assert.Equal(address, pool.LookupHost("example.com"));
        Assert.Null(pool.Lookup(IPAddress.Parse("198.18.9.9")));
        Assert.Null(pool.LookupHost("never.example"));
    }

    [Fact]
    public void LookupIsCaseAndDotInsensitive()
    {
        var pool = Pool();
        var address = pool.Allocate("Example.COM.");

        Assert.Equal(address, pool.LookupHost("example.com"));
        Assert.Equal("example.com", pool.Lookup(address));
    }

    [Fact]
    public void ContainsIsAPurePrefixCheck()
    {
        var pool = Pool();
        pool.Allocate("example.com");

        Assert.True(pool.Contains(IPAddress.Parse("198.18.0.1")));
        Assert.True(pool.Contains(IPAddress.Parse("198.18.255.254")));
        // Never allocated, but inside the range: still fake.
        Assert.True(pool.Contains(IPAddress.Parse("198.18.77.77")));
        Assert.False(pool.Contains(IPAddress.Parse("198.19.0.1")));
        Assert.False(pool.Contains(IPAddress.Parse("8.8.8.8")));
        Assert.False(pool.Contains(null));
    }

    [Fact]
    public void ContainsRecognisesIPv4MappedAddresses()
    {
        var pool = Pool();

        Assert.True(pool.Contains(IPAddress.Parse("::ffff:198.18.1.1")));
    }

    [Fact]
    public void AllocatesIpv6FromItsOwnRange()
    {
        var pool = Pool();

        var address = pool.Allocate("example.com", ipv6: true);

        Assert.NotNull(address);
        Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, address!.AddressFamily);
        Assert.True(pool.Contains(address));
        Assert.StartsWith("fdfe:dcba:9876:", address.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PreferredAddressIsHonouredWhenFree()
    {
        var pool = Pool();
        var preferred = IPAddress.Parse("198.18.5.5");

        var address = pool.Allocate("example.com", preferred: preferred);

        Assert.Equal(preferred, address);
    }

    [Fact]
    public void PreferredAddressOutsideTheRangeIsIgnored()
    {
        var pool = Pool();

        var address = pool.Allocate("example.com", preferred: IPAddress.Parse("10.0.0.1"));

        Assert.Equal(IPAddress.Parse("198.18.0.1"), address);
    }

    [Fact]
    public void EvictsTheLeastRecentlyUsedMapping()
    {
        var pool = Pool(capacity: 4);

        pool.Allocate("h1.example");
        pool.Allocate("h2.example");
        pool.Allocate("h3.example");
        pool.Allocate("h4.example");
        pool.Allocate("h5.example");

        Assert.Equal(4, pool.Count);
        Assert.Null(pool.LookupHost("h1.example"));
        Assert.NotNull(pool.LookupHost("h2.example"));
        Assert.NotNull(pool.LookupHost("h5.example"));
    }

    [Fact]
    public void TouchingAMappingKeepsItAlive()
    {
        var pool = Pool(capacity: 3);

        pool.Allocate("h1.example");
        pool.Allocate("h2.example");
        pool.Allocate("h3.example");

        // h1 becomes the most recently used, so h2 is evicted instead.
        pool.LookupHost("h1.example");
        pool.Allocate("h4.example");

        Assert.NotNull(pool.LookupHost("h1.example"));
        Assert.Null(pool.LookupHost("h2.example"));
    }

    [Fact]
    public void FlushDropsMappingsButKeepsTheRange()
    {
        var pool = Pool();
        var address = pool.Allocate("example.com");

        pool.Flush();

        Assert.Equal(0, pool.Count);
        Assert.Null(pool.Lookup(address));
        Assert.Null(pool.LookupHost("example.com"));
        Assert.True(pool.Contains(address));
        Assert.Equal(IPAddress.Parse("198.18.0.1"), pool.Allocate("example.com"));
    }

    [Fact]
    public void DisabledRangesYieldNothing()
    {
        var pool = new FakeIpPool(string.Empty, string.Empty, 16);

        Assert.False(pool.HasIPv4);
        Assert.False(pool.HasIPv6);
        Assert.Null(pool.Allocate("example.com"));
        Assert.False(pool.Contains(IPAddress.Parse("198.18.0.1")));
    }

    [Fact]
    public void ParallelAllocationProducesUniqueAddresses()
    {
        var pool = Pool();
        var hosts = Enumerable.Range(0, 128).Select(i => $"host{i}.example").ToArray();
        var addresses = new IPAddress[hosts.Length];

        Parallel.For(0, hosts.Length, i => addresses[i] = pool.Allocate(hosts[i])!);

        Assert.Equal(hosts.Length, addresses.Distinct().Count());
        Assert.Equal(hosts.Length, pool.Count);

        for (var i = 0; i < hosts.Length; i++)
        {
            Assert.Equal(hosts[i], pool.Lookup(addresses[i]));
        }
    }

    [Fact]
    public void WrapsAroundWhenTheRangeIsExhausted()
    {
        var pool = new FakeIpPool("198.18.0.0/30", string.Empty, 64);

        var first = pool.Allocate("a.example");
        var second = pool.Allocate("b.example");
        var third = pool.Allocate("c.example");

        Assert.Equal(IPAddress.Parse("198.18.0.1"), first);
        Assert.Equal(IPAddress.Parse("198.18.0.2"), second);
        Assert.Null(third);
    }
}
