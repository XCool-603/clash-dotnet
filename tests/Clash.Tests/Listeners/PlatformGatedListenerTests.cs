using Clash.Core.Configuration;
using Clash.Core.Listeners;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Clash.Tests.Listeners;

/// <summary>
/// The redir and tproxy inbounds depend on Linux/macOS kernel facilities, so on
/// Windows they must refuse to start with a clear
/// <see cref="PlatformNotSupportedException"/> instead of failing obscurely.
/// </summary>
public sealed class PlatformGatedListenerTests
{
    [Fact]
    public async Task Redir_refuses_to_start_off_linux_and_macos()
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            return;
        }

        var config = new ClashConfig { RedirPort = 0, BindAddress = "127.0.0.1" };
        var tunnel = new FakeTunnel(config);
        await using var listener = new RedirListener(config, NullLogger<RedirListener>.Instance);

        var exception = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => listener.StartAsync(tunnel));
        Assert.Contains("SO_ORIGINAL_DST", exception.Message, StringComparison.Ordinal);
        Assert.Null(listener.Address);
    }

    [Fact]
    public async Task Tproxy_refuses_to_start_off_linux()
    {
        if (OperatingSystem.IsLinux())
        {
            return;
        }

        var config = new ClashConfig { TProxyPort = 0, BindAddress = "127.0.0.1" };
        var tunnel = new FakeTunnel(config);
        await using var listener = new TProxyListener(config, NullLogger<TProxyListener>.Instance);

        var exception = await Assert.ThrowsAsync<PlatformNotSupportedException>(() => listener.StartAsync(tunnel));
        Assert.Contains("TPROXY", exception.Message, StringComparison.Ordinal);
        Assert.Null(listener.Address);
    }

    [Fact]
    public void Manager_reports_the_gated_listeners_as_unbound()
    {
        if (OperatingSystem.IsLinux())
        {
            return;
        }

        var config = new ClashConfig { RedirPort = 7893, TProxyPort = 7894, BindAddress = "127.0.0.1" };
        var manager = new ListenerManager(config, NullLogger<ListenerManager>.Instance);

        Assert.Equal(2, manager.Listeners.Count);
        Assert.Equal("redir", manager.Listeners[0].Type);
        Assert.Equal("tproxy", manager.Listeners[1].Type);
    }
}
