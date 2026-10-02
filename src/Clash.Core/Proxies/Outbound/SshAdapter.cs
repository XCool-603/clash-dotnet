using Clash.Core.Adapter;
using Clash.Core.Common;
using Clash.Core.Configuration;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The <c>ssh</c> factory.
/// <para>
/// <b>SSH is not supported by this build.</b> A usable SSH client needs the whole
/// of RFC 4253/4252/4254 implemented and, critically, verified against a real
/// server: the binary packet codec with its per-direction cipher/MAC state, the
/// KEX exchange hash (whose byte order is unforgiving), host key verification,
/// public-key authentication over the exact signature blob the server expects, and
/// the channel window/flow-control state machine. None of that can be exercised in
/// this offline environment — there is no SSH server to test against — and a
/// client that is merely *plausible* fails in ways that look like a network
/// problem, which is exactly the failure mode this project must avoid.
/// </para>
/// <para>
/// The entry is therefore validated and then refused with the list of what a
/// complete implementation still needs, instead of shipping a handshake that
/// cannot be trusted.
/// </para>
/// </summary>
internal sealed class SshAdapterFactory : IAdapterFactory
{
    /// <inheritdoc />
    public string Type => "ssh";

    /// <inheritdoc />
    public IReadOnlyList<string> Aliases => [];

    /// <inheritdoc />
    public IProxy Create(ProxyConfigEntry entry, AdapterBuildContext context)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        // Validate the configuration first, so a typo is reported as a typo.
        _ = OutboundOptions.RequireEndpoint(entry);

        var user = entry.Map.GetNonEmptyString("user");
        if (user is null)
        {
            throw new ProxyCreationException($"proxy [{entry.Name}] (ssh) requires a non-empty 'user'");
        }

        var password = entry.Map.GetNonEmptyString("password");
        var privateKey = entry.Map.GetNonEmptyString("private-key") ?? entry.Map.GetNonEmptyString("private_key");
        if (password is null && privateKey is null)
        {
            throw new ProxyCreationException(
                $"proxy [{entry.Name}] (ssh) needs either 'password' or 'private-key' to authenticate as '{user}'");
        }

        throw new ProxyCreationException(
            $"proxy [{entry.Name}] (ssh): SSH is not supported by this build. A correct client needs the binary packet "
            + "codec with per-direction cipher/MAC state, the curve25519-sha256 and diffie-hellman-group14-sha256 key "
            + "exchanges with their exchange-hash computation, ssh-ed25519/rsa-sha2 host key verification, password and "
            + "publickey authentication (including OpenSSH and PEM private key parsing), and the direct-tcpip channel "
            + "state machine with window management. None of that can be verified in this environment because no SSH "
            + "server is reachable, and an unverified handshake would fail as an opaque timeout. Remove the node, or "
            + "reach the host through a protocol that is supported.");
    }
}
