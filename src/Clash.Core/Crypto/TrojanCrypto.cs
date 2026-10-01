using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Clash.Core.Crypto;

/// <summary>
/// Trojan's password hash, request header and UDP framing.
/// <para>
/// <b>Wire layout implemented here.</b>
/// </para>
/// <code>
/// Request: hex(SHA-224(password)) (56) | CRLF | cmd(1) | atyp(1) | addr | port(2, BE) | CRLF | payload
/// UDP    : atyp(1) | addr | port(2, BE) | length(2, BE) | CRLF | payload
/// </code>
/// <para>
/// The password hash is lower-case hex of the raw SHA-224 digest, which is why
/// it is always 56 characters. Trojan has no encryption of its own — the request
/// rides inside the TLS session the transport layer established.
/// </para>
/// </summary>
public static class TrojanCrypto
{
    /// <summary>Length of the hex-encoded SHA-224 password hash.</summary>
    public const int PasswordHashLength = 56;

    /// <summary>Command byte for a proxied TCP connection.</summary>
    public const byte CommandConnect = 0x01;

    /// <summary>Command byte for a UDP association.</summary>
    public const byte CommandUdpAssociate = 0x03;

    /// <summary>The CRLF that delimits the request header and the UDP length field.</summary>
    public static ReadOnlySpan<byte> Crlf => "\r\n"u8;

    /// <summary>Computes the raw 28-byte SHA-224 digest of the password.</summary>
    public static byte[] ComputePasswordHash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        var bytes = Encoding.UTF8.GetBytes(password);
        var digest = new Sha224Digest();
        digest.BlockUpdate(bytes, 0, bytes.Length);
        var result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        CryptographicOperations.ZeroMemory(bytes);
        return result;
    }

    /// <summary>Computes the 56-character lower-case hex password hash Trojan puts on the wire.</summary>
    public static string ComputePasswordHashHex(string password) => ClashHex.Encode(ComputePasswordHash(password));

    /// <summary>
    /// Writes the request header. Returns the number of bytes written, which the
    /// caller follows with the first payload bytes.
    /// </summary>
    public static int WriteRequestHeader(Span<byte> destination, string passwordHashHex, byte command, string host, int port)
    {
        ArgumentNullException.ThrowIfNull(passwordHashHex);
        if (passwordHashHex.Length != PasswordHashLength)
        {
            throw new ArgumentException($"password hash must be {PasswordHashLength} hex characters", nameof(passwordHashHex));
        }

        var addressSize = Socks5Address.Size(host);
        var required = PasswordHashLength + 2 + 1 + addressSize + 2;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        var offset = 0;
        Encoding.ASCII.GetBytes(passwordHashHex, destination);
        offset += PasswordHashLength;
        Crlf.CopyTo(destination[offset..]);
        offset += 2;
        destination[offset++] = command;
        offset += Socks5Address.Write(destination[offset..], host, port);
        Crlf.CopyTo(destination[offset..]);
        offset += 2;

        return offset;
    }

    /// <summary>
    /// Measures and decodes a request header. <paramref name="consumed"/> is the
    /// offset at which the payload begins.
    /// </summary>
    public static bool TryReadRequestHeader(
        ReadOnlySpan<byte> source,
        out int consumed,
        out string passwordHashHex,
        out byte command,
        out string host,
        out int port)
    {
        consumed = 0;
        passwordHashHex = string.Empty;
        command = 0;
        host = string.Empty;
        port = 0;

        if (source.Length < PasswordHashLength + 4) return false;
        if (source[PasswordHashLength] != (byte)'\r' || source[PasswordHashLength + 1] != (byte)'\n') return false;

        passwordHashHex = Encoding.ASCII.GetString(source[..PasswordHashLength]);
        command = source[PasswordHashLength + 2];

        var addressOffset = PasswordHashLength + 3;
        if (!Socks5Address.TryParse(source[addressOffset..], out var addressLength, out host, out port)) return false;

        var afterAddress = addressOffset + addressLength;
        if (source.Length < afterAddress + 2) return false;
        if (source[afterAddress] != (byte)'\r' || source[afterAddress + 1] != (byte)'\n') return false;

        consumed = afterAddress + 2;
        return true;
    }

    /// <summary>
    /// Writes one Trojan UDP packet: address, big-endian length, CRLF, payload.
    /// Returns the bytes written.
    /// </summary>
    public static int WriteUdpPacket(Span<byte> destination, string host, int port, ReadOnlySpan<byte> payload)
    {
        if (payload.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(payload), payload.Length, "UDP payload too long");

        var addressSize = Socks5Address.Size(host);
        var required = addressSize + 2 + 2 + payload.Length;
        if (destination.Length < required) throw new ArgumentException($"destination must be at least {required} bytes", nameof(destination));

        var offset = Socks5Address.Write(destination, host, port);
        BinaryPrimitives.WriteUInt16BigEndian(destination[offset..], (ushort)payload.Length);
        offset += 2;
        Crlf.CopyTo(destination[offset..]);
        offset += 2;
        payload.CopyTo(destination[offset..]);
        offset += payload.Length;

        return offset;
    }

    /// <summary>Measures the length of a Trojan UDP packet at the head of <paramref name="source"/>.</summary>
    public static bool TryMeasureUdpPacket(ReadOnlySpan<byte> source, out int packetLength, out int payloadOffset)
    {
        packetLength = 0;
        payloadOffset = 0;

        if (!Socks5Address.TryMeasure(source, out var addressLength)) return false;
        if (source.Length < addressLength + 4) return false;

        var length = BinaryPrimitives.ReadUInt16BigEndian(source[addressLength..]);
        var offset = addressLength + 2;
        if (source[offset] != (byte)'\r' || source[offset + 1] != (byte)'\n') return false;

        payloadOffset = offset + 2;
        packetLength = payloadOffset + length;
        return source.Length >= packetLength;
    }

    /// <summary>Decodes one Trojan UDP packet.</summary>
    public static bool TryReadUdpPacket(ReadOnlySpan<byte> source, out int consumed, out string host, out int port, out byte[] payload)
    {
        consumed = 0;
        host = string.Empty;
        port = 0;
        payload = [];

        if (!Socks5Address.TryParse(source, out var addressLength, out host, out port)) return false;
        if (!TryMeasureUdpPacket(source, out consumed, out var payloadOffset)) return false;

        payload = source[payloadOffset..consumed].ToArray();
        return true;
    }
}
