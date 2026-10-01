using System.Buffers.Binary;
using System.Text;

namespace Clash.Core.Tunnel;

/// <summary>
/// Protocol sniffers that recover the requested hostname from the first bytes of
/// a client flow. This is what lets a domain rule match a flow whose destination
/// arrived as a bare IP address.
/// </summary>
public static class Sniffer
{
    private const int TlsRecordHandshake = 0x16;
    private const int TlsHandshakeClientHello = 0x01;
    private const int ExtensionServerName = 0x0000;

    /// <summary>
    /// Extracts the SNI from a TLS ClientHello. Returns null when the buffer does
    /// not contain a complete, parseable ClientHello with a server_name extension.
    /// </summary>
    public static string? SniffTlsServerName(ReadOnlySpan<byte> data)
    {
        try
        {
            if (data.Length < 6) return null;
            if (data[0] != TlsRecordHandshake) return null;

            // TLS record: type(1) version(2) length(2) then the handshake body.
            var recordLength = BinaryPrimitives.ReadUInt16BigEndian(data[3..5]);
            var body = data[5..];
            if (body.Length < 4) return null;
            if (recordLength < body.Length) body = body[..recordLength];
            if (body.Length < 4) return null;

            if (body[0] != TlsHandshakeClientHello) return null;

            var handshakeLength = (body[1] << 16) | (body[2] << 8) | body[3];
            var hello = body[4..];
            if (hello.Length < 34) return null;
            if (handshakeLength < hello.Length) hello = hello[..handshakeLength];

            var offset = 0;

            // legacy_version(2) + random(32)
            offset += 2 + 32;
            if (offset >= hello.Length) return null;

            // legacy_session_id
            var sessionIdLength = hello[offset];
            offset += 1 + sessionIdLength;
            if (offset + 2 > hello.Length) return null;

            // cipher_suites
            var cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
            offset += 2 + cipherSuitesLength;
            if (offset >= hello.Length) return null;

            // legacy_compression_methods
            var compressionLength = hello[offset];
            offset += 1 + compressionLength;
            if (offset + 2 > hello.Length) return null;

            // extensions
            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(hello[offset..]);
            offset += 2;
            var extensions = hello[offset..];
            if (extensionsLength < extensions.Length) extensions = extensions[..extensionsLength];

            var position = 0;
            while (position + 4 <= extensions.Length)
            {
                var extensionType = BinaryPrimitives.ReadUInt16BigEndian(extensions[position..]);
                var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(extensions[(position + 2)..]);
                position += 4;
                if (position + extensionLength > extensions.Length) break;

                if (extensionType == ExtensionServerName)
                {
                    var extension = extensions.Slice(position, extensionLength);
                    var name = ParseServerNameExtension(extension);
                    if (!string.IsNullOrEmpty(name)) return name;
                }

                position += extensionLength;
            }

            return null;
        }
        catch (Exception)
        {
            // Sniffing is opportunistic: a malformed packet simply yields no host.
            return null;
        }
    }

    private static string? ParseServerNameExtension(ReadOnlySpan<byte> extension)
    {
        if (extension.Length < 5) return null;

        // server_name_list length(2), then entries of type(1) length(2) name.
        var listLength = BinaryPrimitives.ReadUInt16BigEndian(extension);
        var list = extension[2..];
        if (listLength < list.Length) list = list[..listLength];

        var position = 0;
        while (position + 3 <= list.Length)
        {
            var nameType = list[position];
            var nameLength = BinaryPrimitives.ReadUInt16BigEndian(list[(position + 1)..]);
            position += 3;
            if (position + nameLength > list.Length) break;

            if (nameType == 0)
            {
                var name = Encoding.ASCII.GetString(list.Slice(position, nameLength));
                return string.IsNullOrWhiteSpace(name) ? null : name;
            }

            position += nameLength;
        }

        return null;
    }

    /// <summary>
    /// Extracts the <c>Host</c> header from a plain HTTP request. Returns null when
    /// the buffer does not start with a request line or has no Host header.
    /// </summary>
    public static string? SniffHttpHost(ReadOnlySpan<byte> data)
    {
        try
        {
            if (data.Length < 16) return null;

            // A request line must start with a known method token.
            if (!StartsWithMethod(data)) return null;

            var text = Encoding.ASCII.GetString(data);
            var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            var headerBlock = headerEnd >= 0 ? text[..headerEnd] : text;

            foreach (var line in headerBlock.Split("\r\n"))
            {
                var colon = line.IndexOf(':');
                if (colon <= 0) continue;
                var name = line[..colon].Trim();
                if (!name.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;

                var value = line[(colon + 1)..].Trim();
                return string.IsNullOrWhiteSpace(value) ? null : StripPort(value);
            }

            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort QUIC Initial SNI extraction. QUIC payloads are encrypted, so
    /// this only succeeds when the client sent a cleartext ClientHello; returns
    /// null otherwise.
    /// </summary>
    public static string? SniffQuicServerName(ReadOnlySpan<byte> data)
    {
        // A long-header QUIC Initial carries the ClientHello in the clear only
        // before keys are derived; scanning for the server_name extension marker
        // is the pragmatic approach and is deliberately conservative.
        for (var i = 0; i + 4 < data.Length; i++)
        {
            if (data[i] != 0x00 || data[i + 1] != 0x00) continue;

            var candidate = SniffTlsServerName(data[(i + 4)..]);
            if (!string.IsNullOrEmpty(candidate)) return candidate;
        }
        return null;
    }

    private static bool StartsWithMethod(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<string> methods = ["GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "CONN", "TRAC"];
        foreach (var method in methods)
        {
            if (data.Length >= method.Length && Encoding.ASCII.GetString(data[..method.Length]) == method) return true;
        }
        return false;
    }

    private static string StripPort(string host)
    {
        if (host.StartsWith('['))
        {
            var close = host.IndexOf(']');
            return close > 0 ? host[1..close] : host;
        }

        var colon = host.IndexOf(':');
        return colon > 0 ? host[..colon] : host;
    }
}
