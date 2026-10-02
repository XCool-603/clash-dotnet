using System.Net;
using System.Net.Sockets;
using Clash.Core.Common;
using Clash.Core.Netstack;
using Clash.Core.Tun;
using Xunit;

namespace Clash.Tests.Tun;

/// <summary>
/// The Windows TUN foundation: the driver session and the interface
/// configuration around it.
/// <para>
/// Creating an adapter and touching the routing table need an administrator
/// process, so the tests that exercise the driver are skipped unless the test
/// host is elevated. That is deliberate rather than a gap: the alternative is a
/// suite that only passes on some machines, and the code path they cover is
/// verified by running <c>dotnet test</c> from an elevated prompt.
/// </para>
/// </summary>
public sealed class TunFoundationTests
{
    private const string TestAdapter = "ClashTunTest";

    /// <summary>
    /// TEST-NET-3 (RFC 5737), which exists to be routed nowhere. A /32 for it is
    /// the smallest change that can prove packets reach the adapter without
    /// disturbing the machine's real connectivity.
    /// </summary>
    private const string ProbeAddress = "203.0.113.1";

    [Theory]
    [InlineData(0u)]
    [InlineData(WintunInterop.MinRingCapacity - 1)]
    [InlineData(WintunInterop.MaxRingCapacity + 1)]
    public void ARingOutsideTheDriversBoundsIsRefused(uint capacity)
    {
        // Argument checks run before the elevation check, so this holds for any
        // process and the failure names the actual mistake.
        Assert.Throws<ArgumentOutOfRangeException>(() => TunAdapter.Open(TestAdapter, capacity));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnEmptyAdapterNameIsRefused(string name)
        => Assert.Throws<ArgumentException>(() => TunAdapter.Open(name));

    [Fact]
    public void AnOverlongAdapterNameIsRefused()
    {
        var name = new string('a', WintunInterop.MaxAdapterName);
        Assert.Throws<ArgumentException>(() => TunAdapter.Open(name));
    }

    [Fact]
    public void OpeningWithoutElevationExplainsWhy()
    {
        if (TunElevation.IsElevated) return; // covered by the driver test below

        var error = Assert.Throws<ClashException>(() => TunAdapter.Open(TestAdapter));
        Assert.Contains("administrator", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ElevationIsReportedConsistentlyWithThePlatform()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.False(TunElevation.IsElevated);
            Assert.Throws<NotSupportedException>(() => TunElevation.Require());
        }
    }

    /// <summary>
    /// The end-to-end proof that the foundation works: create the adapter, give it
    /// an address, route one destination into it, send a datagram there, and read
    /// the resulting IP packet back off the driver's ring.
    /// <para>
    /// Everything it changes is undone in the finally block, and the only route it
    /// adds is a single /32 to a reserved documentation address, so a machine
    /// running a real tunnel keeps working even if this test fails halfway.
    /// </para>
    /// </summary>
    [Fact]
    public void APacketAddressedToTheAdapterIsReadBackFromTheRing()
    {
        if (!TunElevation.IsElevated) return;

        TunAdapter? adapter = null;
        var routed = false;
        var addressed = false;

        try
        {
            adapter = TunAdapter.Open(TestAdapter);
            Assert.True(TunAdapter.DriverVersion > 0);

            TunInterface.SetAddress(TestAdapter);
            addressed = true;

            // Give the interface a moment to come up before anything is routed to it.
            Thread.Sleep(1500);

            TunInterface.AddRouteToTun(TestAdapter, ProbeAddress + "/32");
            routed = true;

            using var sender = new UdpClient(AddressFamily.InterNetwork);
            var payload = "clash-tun-probe"u8.ToArray();
            sender.Send(payload, payload.Length, new IPEndPoint(IPAddress.Parse(ProbeAddress), 9));

            var buffer = new byte[WintunInterop.MaxIpPacketSize];
            var deadline = DateTime.UtcNow.AddSeconds(10);
            Ipv4Header? observed = null;
            ushort destinationPort = 0;

            while (DateTime.UtcNow < deadline && observed is null)
            {
                var read = adapter.Read(buffer, timeoutMilliseconds: 1000);
                if (read <= 0) continue;

                if (!Ipv4Header.TryParse(buffer.AsSpan(0, read), out var header)) continue;
                if (header.Protocol != 17) continue; // UDP only; the host may emit other traffic
                if (!header.Destination.Equals(IPAddress.Parse(ProbeAddress))) continue;

                observed = header;
                destinationPort = (ushort)((buffer[header.HeaderLength + 2] << 8) | buffer[header.HeaderLength + 3]);
            }

            Assert.NotNull(observed);
            Assert.Equal(17, observed!.Value.Protocol);
            Assert.Equal(ProbeAddress, observed.Value.Destination.ToString());
            Assert.Equal(9, destinationPort);
        }
        finally
        {
            if (routed) TunInterface.RemoveRouteFromTun(TestAdapter, ProbeAddress + "/32");
            adapter?.Dispose();

            // Closing the handle removes an adapter this process created, but the
            // address assignment lives on the interface, so it is cleared here too
            // in case the adapter outlived the test.
            if (addressed) TunInterface.TryClearAddress(TestAdapter);
        }
    }
}
