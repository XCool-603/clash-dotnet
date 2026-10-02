using System.Security.Principal;
using Clash.Core.Common;

namespace Clash.Core.Tun;

/// <summary>
/// Whether this process may create a TUN adapter.
/// <para>
/// Creating the adapter and changing the routing table are machine-wide
/// operations, so TUN mode needs an elevated process. This type exists to answer
/// that question <b>before</b> anything is attempted, so the user gets one clear
/// sentence instead of a driver error code.
/// </para>
/// </summary>
internal static class TunElevation
{
    /// <summary>True when the current process holds the administrator role.</summary>
    public static bool IsElevated
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;

            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception)
            {
                // A token that cannot be inspected is not one to assume is privileged.
                return false;
            }
        }
    }

    /// <summary>The message shown when TUN mode is requested without elevation.</summary>
    public const string NotElevatedMessage =
        "tun mode needs an administrator process: creating the adapter and changing the routing "
        + "table are machine-wide operations. Restart Clash as administrator, then enable tun mode again.";

    /// <summary>Throws when this process cannot create an adapter.</summary>
    public static void Require()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new NotSupportedException("tun mode is implemented for Windows only in this build");
        }

        if (!IsElevated) throw new ClashException(NotElevatedMessage);
    }
}
