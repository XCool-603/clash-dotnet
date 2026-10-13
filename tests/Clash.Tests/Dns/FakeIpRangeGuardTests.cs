using System.Net;
using Clash.Core.Dns;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Clash.Tests.Dns;

/// <summary>
/// The synthetic snapshots below reproduce the measured failure: Clash Verge's TUN
/// claims 198.18.0.0/15, the default fake-ip-range 198.18.0.1/16 sits inside it, and
/// every proxied request times out without a word in the log.
/// </summary>
public sealed class FakeIpRangeGuardTests
{
    private const string DefaultRangeV4 = "198.18.0.1/16";
    private const string DefaultRangeV6 = "fdfe:dcba:9876::1/96";

    private static IReadOnlyList<FakeIpRangeConflict> Check(
        IEnumerable<LocalRouteSnapshot>? routes,
        IEnumerable<LocalAddressSnapshot>? addresses,
        string? rangeV4 = DefaultRangeV4,
        string? rangeV6 = DefaultRangeV6)
        => FakeIpRangeGuard.Check(rangeV4, rangeV6, routes, addresses);

    [Fact]
    public void ReportsTheMeasuredClashVergeOverlapWithItsSource()
    {
        var conflicts = Check(
            [new LocalRouteSnapshot("198.18.0.0/15", "if42", "On-link", 0)],
            [new LocalAddressSnapshot("198.18.0.1", "Clash Verge", 15)]);

        Assert.Equal(2, conflicts.Count);

        var route = Assert.Single(conflicts, c => c.Source == FakeIpConflictSource.Route);
        Assert.Equal("198.18.0.0/15", route.Prefix);
        Assert.Equal(DefaultRangeV4, route.FakeIpRange);
        Assert.Equal("if42", route.InterfaceName);
        Assert.Equal("On-link", route.NextHop);

        var address = Assert.Single(conflicts, c => c.Source == FakeIpConflictSource.InterfaceAddress);
        Assert.Equal("198.18.0.1/15", address.Prefix);
        Assert.Equal("Clash Verge", address.InterfaceName);
    }

    [Fact]
    public void TheWarningTextNamesTheSourceAndTheConfiguredRange()
    {
        var conflict = Assert.Single(Check(
            [new LocalRouteSnapshot("198.18.0.0/15", "if42", "On-link", 0)],
            null));

        var text = conflict.Describe();

        Assert.Contains("198.18.0.0/15", text, StringComparison.Ordinal);
        Assert.Contains("198.18.0.1/16", text, StringComparison.Ordinal);
        Assert.Contains("routing table", text, StringComparison.Ordinal);
        Assert.Contains("if42", text, StringComparison.Ordinal);
        Assert.Contains("On-link", text, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInterfaceAddressInsideTheRangeIsAConflict()
    {
        var conflict = Assert.Single(Check(
            null,
            [new LocalAddressSnapshot("198.18.7.7", "Ethernet 2", 24)]));

        Assert.Equal(FakeIpConflictSource.InterfaceAddress, conflict.Source);
        Assert.Equal("198.18.7.7/24", conflict.Prefix);
        Assert.Contains("local interface address", conflict.Describe(), StringComparison.Ordinal);
    }

    [Fact]
    public void AnInterfaceAddressOutsideTheRangeIsSilent()
    {
        var conflicts = Check(
            null,
            [
                new LocalAddressSnapshot("192.168.1.10", "Ethernet", 24),
                // The address this core hands its own TUN adapter sits outside the pool.
                new LocalAddressSnapshot("198.19.255.1", "Clash", 32),
                new LocalAddressSnapshot("8.8.8.8", "Ethernet", 32),
            ]);

        Assert.Empty(conflicts);
    }

    [Fact]
    public void AMoreSpecificRouteInsideTheRangeIsAConflict()
    {
        var conflict = Assert.Single(Check(
            [new LocalRouteSnapshot("198.18.5.0/24", "if7", "192.168.1.1", 25)],
            null));

        Assert.Equal("198.18.5.0/24", conflict.Prefix);
        Assert.Equal(25, conflict.Metric);
        Assert.Equal("192.168.1.1", conflict.NextHop);
    }

    [Fact]
    public void ASupernetRouteSwallowingTheRangeIsAConflict()
    {
        var conflict = Assert.Single(Check(
            [new LocalRouteSnapshot("198.0.0.0/8", "if9", "On-link", 0)],
            null));

        Assert.Equal("198.0.0.0/8", conflict.Prefix);
    }

    [Fact]
    public void ARouteThatMerelyTouchesTheRangeBoundaryIsSilent()
    {
        // 198.19.0.0/16 starts exactly where 198.18.0.0/16 ends.
        Assert.Empty(Check([new LocalRouteSnapshot("198.19.0.0/16", "if1", "On-link", 0)], null));
        Assert.Empty(Check([new LocalRouteSnapshot("198.16.0.0/15", "if1", "On-link", 0)], null));
        Assert.Empty(Check([new LocalRouteSnapshot("198.17.255.0/24", "if1", "On-link", 0)], null));
    }

    [Fact]
    public void TheDefaultRouteIsNotTreatedAsAConflict()
    {
        // Every machine has a default route; flagging it would be pure noise.
        var conflicts = Check(
            [
                new LocalRouteSnapshot("0.0.0.0/0", "if4", "192.168.1.1", 25),
                new LocalRouteSnapshot("127.0.0.0/8", "if1", "On-link", 331),
                new LocalRouteSnapshot("192.168.1.0/24", "if4", "On-link", 281),
            ],
            null);

        Assert.Empty(conflicts);
    }

    [Fact]
    public void TheDefaultRouteHalvesTheTunAddsAreSilent()
    {
        // TunInterface.AddDefaultRoutes installs these two through our own adapter;
        // they must not self-report as a conflict with ourselves.
        var addresses = new[] { new LocalAddressSnapshot("198.19.255.1", "Clash", 32) };

        var conflicts = FakeIpRangeGuard.Check(
            DefaultRangeV4,
            DefaultRangeV6,
            [
                new LocalRouteSnapshot("0.0.0.0/1", "Clash", "On-link", 1),
                new LocalRouteSnapshot("128.0.0.0/1", "Clash", "On-link", 1),
            ],
            addresses);

        Assert.Empty(conflicts);
    }

    [Fact]
    public void RoutesThroughOurOwnAdapterAreNotConflicts()
    {
        var addresses = new[] { new LocalAddressSnapshot("198.19.255.1", "Clash", 32) };

        var conflicts = FakeIpRangeGuard.Check(
            DefaultRangeV4,
            DefaultRangeV6,
            [new LocalRouteSnapshot("198.18.0.0/16", "Clash", "On-link", 1)],
            addresses);

        Assert.Empty(conflicts);
    }

    [Fact]
    public void AnExplicitlyNamedOwnAdapterIsAlsoExcluded()
    {
        var conflicts = FakeIpRangeGuard.Check(
            DefaultRangeV4,
            DefaultRangeV6,
            [new LocalRouteSnapshot("198.18.0.0/15", "My Wintun", "On-link", 1)],
            null,
            ownInterfaces: ["My Wintun"]);

        Assert.Empty(conflicts);
    }

    [Fact]
    public void AnotherClientsTunOverTheSameRangeIsStillReported()
    {
        // The measured failure: Clash Verge's adapter, not ours.
        var addresses = new[]
        {
            new LocalAddressSnapshot("198.19.255.1", "Clash", 32),
            new LocalAddressSnapshot("198.18.0.1", "Clash Verge", 15),
        };

        var conflicts = FakeIpRangeGuard.Check(
            DefaultRangeV4,
            DefaultRangeV6,
            [
                new LocalRouteSnapshot("0.0.0.0/1", "Clash", "On-link", 1),
                new LocalRouteSnapshot("198.18.0.0/15", "Clash Verge", "On-link", 0),
            ],
            addresses);

        Assert.Equal(2, conflicts.Count);
        Assert.All(conflicts, c => Assert.Equal("Clash Verge", c.InterfaceName));

        var route = Assert.Single(conflicts, c => c.Source == FakeIpConflictSource.Route);
        Assert.Equal("198.18.0.0/15", route.Prefix);

        var address = Assert.Single(conflicts, c => c.Source == FakeIpConflictSource.InterfaceAddress);
        Assert.Equal("198.18.0.1/15", address.Prefix);
    }

    [Fact]
    public void TheSnapshotThisMachineActuallyHasIsReported()
    {
        // Captured from the machine this was developed on with
        // `netsh interface ipv4 show route`: another TUN client ("Meta") holds
        // 198.18.0.0/30, 198.18.0.1/32 and 198.18.0.3/32, and the default route
        // points at it. This is the real, reproduced collision.
        string[] netshOutput =
        [
            "Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name",
            "-------  --------  ---  ------------------------  ---  ------------------------",
            "No       Manual    0    0.0.0.0/0                   8  192.168.31.1",
            "No       Manual    0    0.0.0.0/0                   6  198.18.0.2",
            "No       System    256  127.0.0.0/8                 1  Loopback Pseudo-Interface 1",
            "No       System    256  192.168.31.0/24             8  以太网",
            "No       System    256  198.18.0.0/30               6  Meta",
            "No       System    256  198.18.0.1/32               6  Meta",
            "No       System    256  198.18.0.3/32               6  Meta",
        ];

        var routes = FakeIpRangeGuard.ParseRouteLines(netshOutput);
        Assert.Equal(7, routes.Count);

        var conflicts = Check(routes, null);

        Assert.Equal(3, conflicts.Count);
        Assert.All(conflicts, c => Assert.Equal("Meta", c.InterfaceName));
        Assert.Contains(conflicts, c => c.Prefix == "198.18.0.0/30");
        Assert.Contains(conflicts, c => c.Prefix == "198.18.0.1/32");
        Assert.Contains(conflicts, c => c.Prefix == "198.18.0.3/32");
    }

    [Fact]
    public void AnIpv6AddressInsideTheV6RangeIsReported()
    {
        var conflict = Assert.Single(Check(
            null,
            [new LocalAddressSnapshot("fdfe:dcba:9876::1", "Clash Verge", 96)],
            rangeV4: null,
            rangeV6: DefaultRangeV6));

        Assert.Equal(FakeIpConflictSource.InterfaceAddress, conflict.Source);
        Assert.Equal(DefaultRangeV6, conflict.FakeIpRange);
    }

    [Fact]
    public void Ipv6RoutesOverlappingTheV6RangeAreReported()
    {
        var conflict = Assert.Single(Check(
            [new LocalRouteSnapshot("fdfe:dcba:9876::/48", "if3", "On-link", 256)],
            null,
            rangeV4: null,
            rangeV6: DefaultRangeV6));

        Assert.Equal("fdfe:dcba:9876::/48", conflict.Prefix);
        Assert.Equal(DefaultRangeV6, conflict.FakeIpRange);
    }

    [Fact]
    public void FamiliesDoNotCrossContaminate()
    {
        // An IPv6 range cannot be occupied by an IPv4 route, and vice versa.
        Assert.Empty(Check(
            [new LocalRouteSnapshot("198.18.0.0/15", "if1", "On-link", 0)],
            [new LocalAddressSnapshot("198.18.0.1", "if1", 16)],
            rangeV4: null,
            rangeV6: DefaultRangeV6));
    }

    [Fact]
    public void EveryDistinctSourcePrefixIsReportedOnce()
    {
        var conflicts = Check(
            [
                new LocalRouteSnapshot("198.18.0.0/15", "if1", "On-link", 0),
                new LocalRouteSnapshot("198.18.0.0/15", "if2", "192.168.1.1", 10),
                new LocalRouteSnapshot("198.18.0.0/15", "if1", "On-link", 0),
                new LocalRouteSnapshot("198.18.5.0/24", "if1", "On-link", 0),
            ],
            null);

        Assert.Equal(3, conflicts.Count);
    }

    [Fact]
    public void DisabledRangesProduceNoConflicts()
    {
        Assert.Empty(Check(
            [new LocalRouteSnapshot("198.18.0.0/15", "if1", "On-link", 0)],
            [new LocalAddressSnapshot("198.18.0.1", "if1", 16)],
            rangeV4: string.Empty,
            rangeV6: "   "));
    }

    [Fact]
    public void AnUnparsableConfiguredRangeIsIgnoredRatherThanFatal()
    {
        var conflicts = Check(
            [new LocalRouteSnapshot("198.18.0.0/15", "if1", "On-link", 0)],
            null,
            rangeV4: "not-a-range",
            rangeV6: null);

        Assert.Empty(conflicts);
    }

    [Fact]
    public void HostileSnapshotsAreSkippedAndNothingThrows()
    {
        var conflicts = Check(
            [
                null!,
                new LocalRouteSnapshot(string.Empty),
                new LocalRouteSnapshot("   "),
                new LocalRouteSnapshot("garbage"),
                new LocalRouteSnapshot("198.18.0.0/99"),
                new LocalRouteSnapshot("198.18.0.0/-1"),
                new LocalRouteSnapshot("999.18.0.0/15"),
                new LocalRouteSnapshot("fdfe::/48"),
                new LocalRouteSnapshot("198.18.0.0/15", "if1", "On-link", 0),
            ],
            [
                null!,
                new LocalAddressSnapshot(string.Empty),
                new LocalAddressSnapshot("not-an-address"),
                new LocalAddressSnapshot("198.18.0.1", "if1", 999),
            ]);

        Assert.Equal(2, conflicts.Count);
    }

    [Fact]
    public void EmptySnapshotsAreSilent()
    {
        Assert.Empty(Check(null, null));
        Assert.Empty(Check([], []));
    }

    [Fact]
    public void Ipv4MappedInterfaceAddressesAreRecognised()
    {
        var conflict = Assert.Single(Check(
            null,
            [new LocalAddressSnapshot("::ffff:198.18.4.4", "if1", 128)]));

        Assert.Equal(FakeIpConflictSource.InterfaceAddress, conflict.Source);
        Assert.Equal("198.18.4.4/32", conflict.Prefix);
    }

    [Fact]
    public void LogConflictsWarnsOncePerConflictAndNamesTheSource()
    {
        var logger = new CapturingLogger();

        var conflicts = FakeIpRangeGuard.LogConflicts(
            DefaultRangeV4,
            DefaultRangeV6,
            [new LocalRouteSnapshot("198.18.0.0/15", "if42", "On-link", 0)],
            [new LocalAddressSnapshot("198.18.0.1", "Clash Verge", 15)],
            logger);

        Assert.Equal(2, conflicts.Count);

        // One warning per conflict plus one summary line.
        Assert.Equal(3, logger.Warnings.Count);
        Assert.Contains(logger.Warnings, w => w.Contains("198.18.0.0/15", StringComparison.Ordinal));
        Assert.Contains(logger.Warnings, w => w.Contains("Clash Verge", StringComparison.Ordinal));
        Assert.Contains(logger.Warnings, w => w.Contains("startup continues", StringComparison.Ordinal));
    }

    [Fact]
    public void LogConflictsIsSilentWhenNothingOverlaps()
    {
        var logger = new CapturingLogger();

        var conflicts = FakeIpRangeGuard.LogConflicts(
            DefaultRangeV4,
            DefaultRangeV6,
            [new LocalRouteSnapshot("0.0.0.0/0", "if14", "192.168.1.1", 25)],
            [new LocalAddressSnapshot("192.168.1.10", "Ethernet", 24)],
            logger);

        Assert.Empty(conflicts);
        Assert.Empty(logger.Warnings);
    }

    [Fact]
    public void LogConflictsAgainstTheLiveHostNeverThrowsAndNeverBlocks()
    {
        var logger = new CapturingLogger();

        // No assertion on the result: this machine may or may not have a conflict.
        // What matters for criterion 5 is that the probe is safe and advisory.
        var conflicts = FakeIpRangeGuard.LogConflicts(DefaultRangeV4, DefaultRangeV6, logger);

        Assert.NotNull(conflicts);
        // One warning per conflict, plus one summary line when there was any.
        Assert.Equal(conflicts.Count == 0 ? 0 : conflicts.Count + 1, logger.Warnings.Count);
    }

    [Fact]
    public void LogConflictsToleratesAMissingLogger()
    {
        var conflicts = FakeIpRangeGuard.LogConflicts(DefaultRangeV4, DefaultRangeV6, null);

        Assert.NotNull(conflicts);
    }

    [Fact]
    public void ProbeRoutesReadsThisMachineWithoutThrowing()
    {
        var routes = FakeIpRangeGuard.ProbeRoutes();

        Assert.NotNull(routes);
        Assert.All(routes, route => Assert.False(string.IsNullOrWhiteSpace(route.Prefix)));

        // Any machine running these tests has a loopback route, so an empty snapshot
        // would mean the netsh probe silently stopped working.
        Assert.NotEmpty(routes);
    }

    [Fact]
    public void ProbeAddressesReadsThisMachineWithoutThrowing()
    {
        var addresses = FakeIpRangeGuard.ProbeAddresses();

        Assert.NotNull(addresses);
        Assert.All(addresses, address => Assert.True(IPAddress.TryParse(address.Address, out _)));
    }

    [Fact]
    public void ParseRouteLinesAcceptsRealNetshOutput()
    {
        string[] output =
        [
            "",
            "Publish  Type      Met  Prefix                    Idx  Gateway/Interface Name",
            "-------  --------  ---  ------------------------  ---  ------------------------",
            "No        Manual    0    0.0.0.0/0                 14  192.168.1.1",
            "No        Manual    0    198.18.0.0/15             42  On-link",
            "No        System    256  192.168.1.0/24           14  Ethernet",
            "No        System    281  224.0.0.0/4              14  On-link",
            "No        Manual    0    0.0.0.0/0                 14  192.168.1.1",
            "  this line is not a route at all",
            "No        Manual    0    198.18.0.0/15             42",
        ];

        var routes = FakeIpRangeGuard.ParseRouteLines(output);

        Assert.Equal(6, routes.Count);
        Assert.Equal("0.0.0.0/0", routes[0].Prefix);
        Assert.Equal("if14", routes[0].InterfaceName);
        Assert.Equal("192.168.1.1", routes[0].NextHop);
        Assert.Equal("198.18.0.0/15", routes[1].Prefix);
        Assert.Equal("On-link", routes[1].NextHop);
        Assert.Equal(256, routes[2].Metric);
        Assert.Equal("192.168.1.0/24", routes[2].Prefix);
        // A named gateway column carries the interface name.
        Assert.Equal("Ethernet", routes[2].InterfaceName);
        // The trailing-metric-less line still parses, with metric 0.
        Assert.Equal("198.18.0.0/15", routes[5].Prefix);
        Assert.Equal(0, routes[5].Metric);
    }

    [Fact]
    public void ParseRouteLinesIgnoresEmptyAndHeaderInput()
    {
        Assert.Empty(FakeIpRangeGuard.ParseRouteLines(null));
        Assert.Empty(FakeIpRangeGuard.ParseRouteLines([]));
        Assert.Empty(FakeIpRangeGuard.ParseRouteLines(["", "   ", "---", "Publish  Type  Met  Prefix"]));
    }

    [Fact]
    public void ParsedNetshOutputFeedsStraightIntoTheDetector()
    {
        string[] output =
        [
            "No        Manual    0    0.0.0.0/0                 14  192.168.1.1",
            "No        Manual    0    198.18.0.0/15             42  On-link",
        ];

        var conflicts = Check(FakeIpRangeGuard.ParseRouteLines(output), null);

        // The default route is exempt; the /15 is not.
        var conflict = Assert.Single(conflicts);
        Assert.Equal("198.18.0.0/15", conflict.Prefix);
        Assert.Equal("On-link", conflict.InterfaceName);
        Assert.Equal("On-link", conflict.NextHop);
    }

    /// <summary>Captures the warnings the guard emits.</summary>
    private sealed class CapturingLogger : ILogger
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
}
