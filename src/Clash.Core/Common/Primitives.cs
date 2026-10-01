namespace Clash.Core.Common;

/// <summary>Transport of a proxied flow.</summary>
public enum Network
{
    Tcp = 0,
    Udp = 1,
}

/// <summary>
/// Every adapter kind Clash/mihomo understands. Group types are included so a
/// single enum can describe anything reachable from <c>/proxies</c>.
/// </summary>
public enum ProxyType
{
    Direct,
    Reject,
    Http,
    Socks5,
    Shadowsocks,
    ShadowsocksR,
    Vmess,
    Vless,
    Trojan,
    Snell,
    Wireguard,
    Hysteria,
    Hysteria2,
    Tuic,
    Ssh,
    Dns,
    AnyTls,
    Mieru,

    // Groups
    Selector,
    UrlTest,
    Fallback,
    LoadBalance,
    Relay,
    Smart,
}

/// <summary>Routing mode, mirroring the <c>mode</c> config key.</summary>
public enum Mode
{
    Rule,
    Global,
    Direct,
}

/// <summary>How a flow's destination was named.</summary>
public enum DnsMode
{
    Normal,
    FakeIp,
    Mapping,
}

/// <summary>A single delay probe result. <see cref="Delay"/> of 0 means failure.</summary>
public sealed record DelayHistory(DateTimeOffset Time, int Delay)
{
    /// <summary>Milliseconds since the probe, used for the API's relative time.</summary>
    public long AgeMs => (long)(DateTimeOffset.UtcNow - Time).TotalMilliseconds;
}

/// <summary>Base type for every error this library raises deliberately.</summary>
public class ClashException : Exception
{
    public ClashException(string message) : base(message) { }
    public ClashException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Raised when a configuration document cannot be understood.</summary>
public sealed class ClashConfigException : ClashException
{
    public ClashConfigException(string message) : base(message) { }
    public ClashConfigException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>Raised when an outbound adapter cannot be constructed.</summary>
public sealed class ProxyCreationException : ClashException
{
    public ProxyCreationException(string message) : base(message) { }
}

/// <summary>Raised by DNS resolution paths.</summary>
public sealed class DnsException : ClashException
{
    public DnsException(string message) : base(message) { }
}

/// <summary>
/// A lock-free monotonic counter used for byte accounting. Only ever added to
/// from one direction and read for reporting, so interlocked semantics suffice.
/// </summary>
public sealed class ByteCounter
{
    private long _value;

    public long Value => Interlocked.Read(ref _value);

    public void Add(long delta) => Interlocked.Add(ref _value, delta);

    public void Reset() => Interlocked.Exchange(ref _value, 0);
}

/// <summary>Well-known canonical names used by the API and rule engine.</summary>
public static class WellKnown
{
    public const string Direct = "DIRECT";
    public const string Reject = "REJECT";
    public const string RejectDrop = "REJECT-DROP";
    public const string Pass = "PASS";
    public const string Compatible = "COMPATIBLE";
    public const string Global = "GLOBAL";

    public static readonly string[] BuiltinAdapters = [Direct, Reject, RejectDrop, Pass, Compatible];
}

public static class NetworkExtensions
{
    public static string ToApiString(this Network network) => network == Network.Udp ? "udp" : "tcp";

    public static string ToApiString(this ProxyType type) => type switch
    {
        ProxyType.Direct => "Direct",
        ProxyType.Reject => "Reject",
        ProxyType.Http => "Http",
        ProxyType.Socks5 => "Socks5",
        ProxyType.Shadowsocks => "Shadowsocks",
        ProxyType.ShadowsocksR => "ShadowsocksR",
        ProxyType.Vmess => "Vmess",
        ProxyType.Vless => "Vless",
        ProxyType.Trojan => "Trojan",
        ProxyType.Snell => "Snell",
        ProxyType.Wireguard => "Wireguard",
        ProxyType.Hysteria => "Hysteria",
        ProxyType.Hysteria2 => "Hysteria2",
        ProxyType.Tuic => "Tuic",
        ProxyType.Ssh => "Ssh",
        ProxyType.Dns => "Dns",
        ProxyType.AnyTls => "AnyTLS",
        ProxyType.Mieru => "Mieru",
        ProxyType.Selector => "Selector",
        ProxyType.UrlTest => "URLTest",
        ProxyType.Fallback => "Fallback",
        ProxyType.LoadBalance => "LoadBalance",
        ProxyType.Relay => "Relay",
        ProxyType.Smart => "Smart",
        _ => type.ToString(),
    };

    public static string ToApiString(this Mode mode) => mode switch
    {
        Mode.Global => "global",
        Mode.Direct => "direct",
        _ => "rule",
    };

    public static Mode ParseMode(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "global" => Mode.Global,
        "direct" => Mode.Direct,
        _ => Mode.Rule,
    };
}
