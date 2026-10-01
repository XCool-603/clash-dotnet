using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Clash.Core.Common;

namespace Clash.Core.Transport;

/// <summary>
/// The TLS layer, wrapping the inner stream with <see cref="SslStream"/>.
/// <para>
/// <b>Honoured.</b> <c>sni</c>/<c>servername</c>, <c>skip-cert-verify</c> and
/// <c>insecure</c>, <c>alpn</c>, <c>disable-sni</c>, and
/// <c>fingerprint</c>/<c>client-fingerprint</c> to the extent the platform allows
/// it — see <see cref="BuildCipherSuitesPolicy"/>.
/// </para>
/// <para>
/// <b>Not supported.</b> <c>reality-opts</c> and the <c>shadow-tls</c> and
/// <c>restls</c> plugins. All three need a ClientHello this process authors byte
/// by byte, and <see cref="SslStream"/> deliberately exposes no such hook: it
/// owns the record layer, the key schedule and the extension set. Requesting any
/// of them raises <see cref="TransportNotSupportedException"/> naming the feature
/// rather than silently connecting with a plain TLS handshake that the server
/// would reject (REALITY) or that would be trivially fingerprinted (shadow-tls).
/// </para>
/// </summary>
public sealed class TlsTransport : ITransportLayer
{
    /// <summary>ALPN protocols used when the configuration does not name any.</summary>
    public static readonly string[] DefaultAlpn = ["h2", "http/1.1"];

    public string Name => "tls";

    public async Task<ProxyStream> WrapAsync(
        ProxyStream? inner,
        DialContext context,
        YamlMap options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (inner is null) throw new ClashException("tls: the layer needs an inner stream");

        ThrowIfUnsupportedPlugin(options);

        var tls = TransportOptions.ReadTlsOptions(options);
        if (!string.IsNullOrEmpty(tls.RealityPublicKey) || !string.IsNullOrEmpty(tls.RealityShortId))
        {
            throw new TransportNotSupportedException(
                "reality-opts (REALITY requires the client to author the ClientHello itself: a forged session id, a "
                + "purpose-built key_share and an HMAC over the ClientHello signed with the server's X25519 public key. "
                + "System.Net.Security.SslStream owns the record layer and exposes no hook for any of that, so REALITY "
                + "cannot be driven from SslStream. Use a plain 'tls: true' outbound, or terminate REALITY outside .NET.)");
        }

        return await AuthenticateAsync(inner, context, tls, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Raises for the plugin names this layer cannot reproduce.</summary>
    public static void ThrowIfUnsupportedPlugin(YamlMap options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var plugin = TransportOptions.UnsupportedPlugin(TransportOptions.ReadPlugin(options));
        if (plugin is null) return;

        throw new TransportNotSupportedException(plugin switch
        {
            "shadow-tls" => "shadow-tls (the plugin wraps the stream in its own TLS-in-TLS record layer with a "
                + "password-derived handshake that SslStream cannot express; it needs a bespoke record codec)",
            _ => "restls (restls forges TLS records around a real TLS session and verifies the server's record pattern, "
                + "which needs full control of the record layer that SslStream does not grant)",
        });
    }

    /// <summary>Performs the handshake and returns the wrapped stream.</summary>
    public static async Task<ProxyStream> AuthenticateAsync(
        ProxyStream inner,
        DialContext context,
        TlsOptions tls,
        CancellationToken cancellationToken)
    {
        var targetHost = ResolveTargetHost(inner, context, tls);
        var protocols = tls.Alpn.Count > 0 ? tls.Alpn : [.. DefaultAlpn];

        var ssl = new SslStream(
            inner.Inner,
            leaveInnerStreamOpen: true,
            userCertificateValidationCallback: tls.SkipCertVerify || tls.Insecure ? static (_, _, _, _) => true : null);

        var authOptions = new SslClientAuthenticationOptions
        {
            TargetHost = targetHost,
            ApplicationProtocols = [.. protocols.Select(static p => new SslApplicationProtocol(p))],
            EnabledSslProtocols = SslProtocols.None,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            AllowRenegotiation = false,
            CipherSuitesPolicy = BuildCipherSuitesPolicy(tls.ClientFingerprint ?? tls.Fingerprint),
        };

        try
        {
            await ssl.AuthenticateAsClientAsync(authOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException)
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw new ClashException($"tls: handshake with {targetHost} failed: {ex.Message}", ex);
        }

        return TransportStream.Wrap(ssl, inner);
    }

    /// <summary>
    /// Chooses the SNI name. <c>disable-sni</c> substitutes the peer's IP literal,
    /// because .NET omits the <c>server_name</c> extension when <c>TargetHost</c>
    /// is an address rather than a name.
    /// </summary>
    public static string ResolveTargetHost(ProxyStream inner, DialContext context, TlsOptions tls)
    {
        if (!string.IsNullOrEmpty(tls.ServerName)) return tls.ServerName;

        if (tls.DisableSni)
        {
            return inner.RemoteEndPoint is IPEndPoint endpoint ? endpoint.Address.ToString() : "localhost";
        }

        return string.IsNullOrEmpty(context.Host) ? "localhost" : context.Host;
    }

    /// <summary>
    /// Approximates a browser's cipher-suite ordering with
    /// <see cref="CipherSuitesPolicy"/>.
    /// <para>
    /// This is the most a managed TLS stack can do towards fingerprinting. It
    /// cannot reorder extensions, cannot insert GREASE values, cannot change the
    /// <c>supported_versions</c> layout, and on platforms without
    /// <see cref="CipherSuitesPolicy"/> (Windows raises
    /// <see cref="PlatformNotSupportedException"/>) it degrades to the OS default
    /// order. The result is therefore closer to the named browser than the OS
    /// default, but it is not a byte-identical ClientHello.
    /// </para>
    /// </summary>
    public static CipherSuitesPolicy? BuildCipherSuitesPolicy(string? fingerprint)
    {
        if (string.IsNullOrEmpty(fingerprint)) return null;

        var suites = fingerprint.Trim().ToLowerInvariant() switch
        {
            "chrome" or "chromium" or "edge" or "android" or "360" or "qq" => ChromeSuites,
            "firefox" => FirefoxSuites,
            "safari" or "ios" or "macos" or "ipad" or "iphone" => SafariSuites,
            "random" or "randomized" => Shuffle(ChromeSuites),
            _ => null,
        };

        if (suites is null) return null;

        try
        {
            return new CipherSuitesPolicy(suites);
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Fingerprint names this layer recognises.</summary>
    public static IReadOnlyList<string> KnownFingerprints { get; } =
        ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];

    private static readonly TlsCipherSuite[] ChromeSuites =
    [
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
    ];

    private static readonly TlsCipherSuite[] FirefoxSuites =
    [
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    ];

    private static readonly TlsCipherSuite[] SafariSuites =
    [
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    ];

    private static TlsCipherSuite[] Shuffle(TlsCipherSuite[] source)
    {
        var copy = source.ToArray();
        Random.Shared.Shuffle(copy);
        return copy;
    }
}
