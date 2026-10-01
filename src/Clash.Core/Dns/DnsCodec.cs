using System.Buffers.Binary;
using System.Net;
using System.Text;
using Clash.Core.Common;

namespace Clash.Core.Dns;

/// <summary>
/// RFC 1035 wire-format codec for DNS messages, with the record types a proxy
/// actually needs (<c>A</c>, <c>AAAA</c>, <c>CNAME</c>, <c>NS</c>, <c>PTR</c>,
/// <c>MX</c>, <c>TXT</c>, <c>SOA</c>, <c>SRV</c> and <c>HTTPS</c>/SVCB).
/// </summary>
/// <remarks>
/// <para>
/// Decoding follows compression pointers, refuses pointers that do not point
/// strictly backwards (which is what makes pointer loops impossible), caps the
/// number of jumps and the total name length, and bounds-checks every read, so a
/// hostile or truncated packet raises <see cref="DnsException"/> instead of
/// reading out of bounds or hanging.
/// </para>
/// <para>
/// Encoding never compresses except for one optional optimisation: the owner
/// name of an answer/authority/additional record that is identical to the first
/// question name is written as a pointer back to offset 12. RDATA is always
/// emitted uncompressed, which keeps re-encoding a decoded message lossless even
/// when the original used pointers.
/// </para>
/// <para>
/// The frozen <see cref="DnsMessage"/> shape has no <c>CD</c> (checking disabled)
/// bit, so <see cref="Encode(DnsMessage)"/> always emits <c>CD=0</c> and
/// <see cref="Decode"/> ignores it. Callers that care can use
/// <see cref="Encode(DnsMessage, bool)"/> and <see cref="IsCheckingDisabled"/>.
/// </para>
/// </remarks>
public sealed class DnsCodec : IDnsCodec
{
    /// <summary>Length of the fixed DNS header, in bytes.</summary>
    public const int HeaderLength = 12;

    /// <summary>Maximum length of a domain name on the wire, in bytes (RFC 1035 §3.1).</summary>
    public const int MaxNameLength = 255;

    /// <summary>Maximum length of a single label, in bytes.</summary>
    public const int MaxLabelLength = 63;

    /// <summary>Upper bound on compression-pointer hops, as a belt-and-braces loop guard.</summary>
    public const int MaxPointerJumps = 128;

    private const ushort FlagResponse = 0x8000;
    private const ushort FlagAuthoritative = 0x0400;
    private const ushort FlagTruncated = 0x0200;
    private const ushort FlagRecursionDesired = 0x0100;
    private const ushort FlagRecursionAvailable = 0x0080;
    private const ushort FlagAuthenticatedData = 0x0020;
    private const ushort FlagCheckingDisabled = 0x0010;
    private const ushort CompressionMask = 0xC000;
    private const ushort CompressionPointer = 0xC000;
    private const int CompressionOffsetMask = 0x3FFF;

    /// <inheritdoc />
    public byte[] Encode(DnsMessage message) => Encode(message, checkingDisabled: false);

    /// <summary>
    /// Encodes <paramref name="message"/>, optionally setting the <c>CD</c>
    /// (checking disabled) header bit that <see cref="DnsMessage"/> cannot carry.
    /// </summary>
    public byte[] Encode(DnsMessage message, bool checkingDisabled)
    {
        ArgumentNullException.ThrowIfNull(message);

        var questions = message.Questions ?? [];
        var answers = message.Answers ?? [];
        var authorities = message.Authorities ?? [];
        var additionals = message.Additionals ?? [];

        using var stream = new MemoryStream(512);

        WriteUInt16(stream, message.Id);

        var flags = (ushort)0;
        if (message.IsResponse) flags |= FlagResponse;
        flags |= (ushort)((message.OpCode & 0x0F) << 11);
        if (message.AuthoritativeAnswer) flags |= FlagAuthoritative;
        if (message.Truncated) flags |= FlagTruncated;
        if (message.RecursionDesired) flags |= FlagRecursionDesired;
        if (message.RecursionAvailable) flags |= FlagRecursionAvailable;
        if (message.AuthenticatedData) flags |= FlagAuthenticatedData;
        if (checkingDisabled) flags |= FlagCheckingDisabled;
        flags |= (ushort)((byte)message.ResponseCode & 0x0F);
        WriteUInt16(stream, flags);

        WriteCount(stream, questions.Count, "question");
        WriteCount(stream, answers.Count, "answer");
        WriteCount(stream, authorities.Count, "authority");
        WriteCount(stream, additionals.Count, "additional");

        var questionName = questions.Count > 0 ? questions[0].Name : null;
        // The first question name always starts right after the header, so its
        // offset is a constant we can point answers at.
        var questionNameOffset = HeaderLength;

        foreach (var question in questions)
        {
            WriteName(stream, question.Name);
            WriteUInt16(stream, (ushort)question.Type);
            WriteUInt16(stream, question.Class == 0 ? (ushort)1 : question.Class);
        }

        WriteRecords(stream, answers, questionName, questionNameOffset);
        WriteRecords(stream, authorities, questionName, questionNameOffset);
        WriteRecords(stream, additionals, questionName, questionNameOffset);

        return stream.ToArray();
    }

    /// <inheritdoc />
    public DnsMessage Decode(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < HeaderLength)
        {
            throw new DnsException(
                $"DNS message is truncated: {buffer.Length} byte(s) is shorter than the {HeaderLength}-byte header");
        }

        var position = 0;
        var id = ReadUInt16(buffer, ref position);
        var flags = ReadUInt16(buffer, ref position);
        var questionCount = ReadUInt16(buffer, ref position);
        var answerCount = ReadUInt16(buffer, ref position);
        var authorityCount = ReadUInt16(buffer, ref position);
        var additionalCount = ReadUInt16(buffer, ref position);

        var message = new DnsMessage
        {
            Id = id,
            IsResponse = (flags & FlagResponse) != 0,
            OpCode = (flags >> 11) & 0x0F,
            AuthoritativeAnswer = (flags & FlagAuthoritative) != 0,
            Truncated = (flags & FlagTruncated) != 0,
            RecursionDesired = (flags & FlagRecursionDesired) != 0,
            RecursionAvailable = (flags & FlagRecursionAvailable) != 0,
            AuthenticatedData = (flags & FlagAuthenticatedData) != 0,
            ResponseCode = (DnsResponseCode)(flags & 0x0F),
        };

        message.Questions = new List<DnsQuestion>(Math.Min((int)questionCount, 16));
        message.Answers = new List<DnsResourceRecord>(Math.Min((int)answerCount, 16));
        message.Authorities = new List<DnsResourceRecord>(Math.Min((int)authorityCount, 16));
        message.Additionals = new List<DnsResourceRecord>(Math.Min((int)additionalCount, 16));

        for (var i = 0; i < questionCount; i++)
        {
            var name = ReadName(buffer, ref position);
            var type = (DnsQueryType)ReadUInt16(buffer, ref position);
            var klass = ReadUInt16(buffer, ref position);
            message.Questions.Add(new DnsQuestion { Name = name, Type = type, Class = klass });
        }

        ReadRecords(buffer, ref position, answerCount, message.Answers, "answer");
        ReadRecords(buffer, ref position, authorityCount, message.Authorities, "authority");
        ReadRecords(buffer, ref position, additionalCount, message.Additionals, "additional");

        return message;
    }

    /// <summary>True when the wire form carries the <c>CD</c> (checking disabled) bit.</summary>
    /// <exception cref="DnsException">The buffer is too short to hold a header.</exception>
    public static bool IsCheckingDisabled(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < HeaderLength)
        {
            throw new DnsException(
                $"DNS message is truncated: {buffer.Length} byte(s) is shorter than the {HeaderLength}-byte header");
        }

        var flags = BinaryPrimitives.ReadUInt16BigEndian(buffer[2..]);
        return (flags & FlagCheckingDisabled) != 0;
    }

    /// <summary>
    /// Builds an empty response that mirrors <paramref name="query"/>'s id,
    /// opcode, question and RD bit, with RA set.
    /// </summary>
    public static DnsMessage CreateResponse(DnsMessage query, DnsResponseCode code)
    {
        ArgumentNullException.ThrowIfNull(query);
        return new DnsMessage
        {
            Id = query.Id,
            IsResponse = true,
            OpCode = query.OpCode,
            RecursionDesired = query.RecursionDesired,
            RecursionAvailable = true,
            ResponseCode = code,
            Questions = new List<DnsQuestion>(query.Questions ?? []),
        };
    }

    /// <summary>
    /// Builds a NOERROR response carrying <paramref name="answers"/>, forcing
    /// every record's TTL to <paramref name="ttl"/>.
    /// </summary>
    public static DnsMessage WithAnswers(DnsMessage query, IEnumerable<DnsResourceRecord> answers, uint ttl)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(answers);

        var response = CreateResponse(query, DnsResponseCode.NoError);
        foreach (var answer in answers)
        {
            if (answer is null) continue;
            answer.Ttl = ttl;
            response.Answers.Add(answer);
        }

        return response;
    }

    /// <summary>Convenience factory for a single-address answer record.</summary>
    public static DnsResourceRecord CreateAddressRecord(string name, IPAddress address, uint ttl = 1) => new()
    {
        Name = name,
        Type = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? DnsQueryType.Aaaa
            : DnsQueryType.A,
        Class = 1,
        Ttl = ttl,
        Data = address.GetAddressBytes(),
        Address = address,
    };

    /// <summary>Splits a presentation-format domain name into unescaped labels.</summary>
    /// <exception cref="DnsException">The name is malformed or too long.</exception>
    public static IReadOnlyList<string> SplitLabels(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var trimmed = name.Trim();
        if (trimmed.Length == 0 || trimmed == ".") return [];

        var labels = new List<string>();
        var current = new StringBuilder();

        for (var i = 0; i < trimmed.Length; i++)
        {
            var c = trimmed[i];
            if (c == '\\')
            {
                if (i + 1 >= trimmed.Length)
                {
                    throw new DnsException($"DNS name '{name}' ends with a dangling escape character");
                }

                // \DDD decimal escape, otherwise the next character is literal.
                if (i + 3 < trimmed.Length
                    && char.IsAsciiDigit(trimmed[i + 1])
                    && char.IsAsciiDigit(trimmed[i + 2])
                    && char.IsAsciiDigit(trimmed[i + 3]))
                {
                    var value = ((trimmed[i + 1] - '0') * 100) + ((trimmed[i + 2] - '0') * 10) + (trimmed[i + 3] - '0');
                    if (value > 255) throw new DnsException($"DNS name '{name}' contains an out-of-range escape \\{value:D3}");
                    current.Append((char)value);
                    i += 3;
                }
                else
                {
                    current.Append(trimmed[i + 1]);
                    i++;
                }

                continue;
            }

            if (c == '.')
            {
                labels.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(c);
        }

        // A trailing dot only marks the name as absolute; it adds no label.
        if (current.Length > 0) labels.Add(current.ToString());

        foreach (var label in labels)
        {
            if (label.Length == 0) throw new DnsException($"DNS name '{name}' contains an empty label");
            if (Encoding.Latin1.GetByteCount(label) > MaxLabelLength)
            {
                throw new DnsException($"DNS label '{label}' in '{name}' exceeds the {MaxLabelLength}-octet limit");
            }
        }

        return labels;
    }

    // ── Encoding ────────────────────────────────────────────────────────────

    private static void WriteRecords(Stream stream, List<DnsResourceRecord> records, string? questionName, int questionNameOffset)
    {
        foreach (var record in records)
        {
            if (record is null) continue;

            var canPoint = questionName is { Length: > 0 }
                && questionNameOffset >= 0
                && questionNameOffset <= CompressionOffsetMask
                && record.Name.Length > 0
                && string.Equals(record.Name, questionName, StringComparison.OrdinalIgnoreCase);

            if (canPoint)
            {
                WriteUInt16(stream, (ushort)(CompressionPointer | questionNameOffset));
            }
            else
            {
                WriteName(stream, record.Name);
            }

            WriteUInt16(stream, (ushort)record.Type);
            WriteUInt16(stream, record.Class == 0 ? (ushort)1 : record.Class);
            WriteUInt32(stream, record.Ttl);

            var rdata = BuildRData(record);
            if (rdata.Length > ushort.MaxValue)
            {
                throw new DnsException($"RDATA for '{record.Name}' is {rdata.Length} bytes, above the 65535-byte limit");
            }

            WriteUInt16(stream, (ushort)rdata.Length);
            stream.Write(rdata, 0, rdata.Length);
        }
    }

    private static byte[] BuildRData(DnsResourceRecord record)
    {
        switch (record.Type)
        {
            case DnsQueryType.A when record.Address is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork }:
                return record.Address.GetAddressBytes();

            case DnsQueryType.Aaaa when record.Address is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetworkV6 }:
                return record.Address.GetAddressBytes();

            case DnsQueryType.Cname or DnsQueryType.Ns or DnsQueryType.Ptr
                when !string.IsNullOrEmpty(record.Target) && (record.Data is null || record.Data.Length == 0):
            {
                using var buffer = new MemoryStream(64);
                WriteName(buffer, record.Target);
                return buffer.ToArray();
            }

            default:
                return record.Data ?? [];
        }
    }

    private static void WriteName(Stream stream, string name)
    {
        var labels = SplitLabels(name);
        var wireLength = 1;
        foreach (var label in labels) wireLength += 1 + Encoding.Latin1.GetByteCount(label);

        if (wireLength > MaxNameLength)
        {
            throw new DnsException($"DNS name '{name}' encodes to {wireLength} bytes, above the {MaxNameLength}-byte limit");
        }

        foreach (var label in labels)
        {
            var bytes = Encoding.Latin1.GetBytes(label);
            stream.WriteByte((byte)bytes.Length);
            stream.Write(bytes, 0, bytes.Length);
        }

        stream.WriteByte(0);
    }

    private static void WriteCount(Stream stream, int count, string section)
    {
        if (count is < 0 or > ushort.MaxValue)
        {
            throw new DnsException($"DNS {section} count {count} does not fit in 16 bits");
        }

        WriteUInt16(stream, (ushort)count);
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)(value & 0xFF));
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        stream.WriteByte((byte)(value >> 24));
        stream.WriteByte((byte)((value >> 16) & 0xFF));
        stream.WriteByte((byte)((value >> 8) & 0xFF));
        stream.WriteByte((byte)(value & 0xFF));
    }

    // ── Decoding ────────────────────────────────────────────────────────────

    private static void ReadRecords(
        ReadOnlySpan<byte> buffer,
        ref int position,
        int count,
        List<DnsResourceRecord> into,
        string section)
    {
        for (var i = 0; i < count; i++)
        {
            var name = ReadName(buffer, ref position);
            var type = (DnsQueryType)ReadUInt16(buffer, ref position);
            var klass = ReadUInt16(buffer, ref position);
            var ttl = ReadUInt32(buffer, ref position);
            var length = ReadUInt16(buffer, ref position);

            if (position + length > buffer.Length)
            {
                throw new DnsException(
                    $"DNS {section} record '{name}' declares {length} RDATA byte(s) but only {buffer.Length - position} remain");
            }

            var rdataStart = position;
            var record = new DnsResourceRecord
            {
                Name = name,
                Type = type,
                Class = klass,
                Ttl = ttl,
            };

            switch (type)
            {
                case DnsQueryType.A:
                    if (length != 4)
                    {
                        throw new DnsException($"DNS A record '{name}' has RDLENGTH {length}, expected 4");
                    }

                    record.Address = new IPAddress(buffer.Slice(position, 4));
                    record.Data = buffer.Slice(position, 4).ToArray();
                    position += 4;
                    break;

                case DnsQueryType.Aaaa:
                    if (length != 16)
                    {
                        throw new DnsException($"DNS AAAA record '{name}' has RDLENGTH {length}, expected 16");
                    }

                    record.Address = new IPAddress(buffer.Slice(position, 16));
                    record.Data = buffer.Slice(position, 16).ToArray();
                    position += 16;
                    break;

                case DnsQueryType.Cname:
                case DnsQueryType.Ns:
                case DnsQueryType.Ptr:
                {
                    var target = ReadName(buffer, ref position);
                    if (position - rdataStart > length)
                    {
                        throw new DnsException($"DNS record '{name}' name field overruns its {length}-byte RDATA");
                    }

                    // Store the decompressed form so re-encoding stays lossless.
                    record.Target = target;
                    record.Data = EncodeNameOnly(target);
                    position = rdataStart + length;
                    break;
                }

                case DnsQueryType.Mx:
                {
                    if (length < 3)
                    {
                        throw new DnsException($"DNS MX record '{name}' has RDLENGTH {length}, expected at least 3");
                    }

                    var preference = ReadUInt16(buffer, ref position);
                    var exchange = ReadName(buffer, ref position);
                    if (position - rdataStart > length)
                    {
                        throw new DnsException($"DNS MX record '{name}' name field overruns its {length}-byte RDATA");
                    }

                    using var rdata = new MemoryStream(length);
                    WriteUInt16(rdata, preference);
                    WriteName(rdata, exchange);
                    record.Data = rdata.ToArray();
                    record.Target = exchange;
                    position = rdataStart + length;
                    break;
                }

                case DnsQueryType.Soa:
                {
                    var primary = ReadName(buffer, ref position);
                    var responsible = ReadName(buffer, ref position);
                    if (position - rdataStart > length)
                    {
                        throw new DnsException($"DNS SOA record '{name}' name fields overrun their {length}-byte RDATA");
                    }

                    var remainder = length - (position - rdataStart);
                    if (remainder != 20)
                    {
                        throw new DnsException($"DNS SOA record '{name}' has {remainder} trailing byte(s), expected 20");
                    }

                    using var rdata = new MemoryStream(length);
                    WriteName(rdata, primary);
                    WriteName(rdata, responsible);
                    rdata.Write(buffer.Slice(position, 20));
                    record.Data = rdata.ToArray();
                    record.Target = primary;
                    position = rdataStart + length;
                    break;
                }

                case DnsQueryType.Srv:
                {
                    if (length < 7)
                    {
                        throw new DnsException($"DNS SRV record '{name}' has RDLENGTH {length}, expected at least 7");
                    }

                    var prefix = buffer.Slice(position, 6).ToArray();
                    position += 6;
                    var target = ReadName(buffer, ref position);
                    if (position - rdataStart > length)
                    {
                        throw new DnsException($"DNS SRV record '{name}' target overruns its {length}-byte RDATA");
                    }

                    using var rdata = new MemoryStream(length);
                    rdata.Write(prefix, 0, prefix.Length);
                    WriteName(rdata, target);
                    record.Data = rdata.ToArray();
                    record.Target = target;
                    position = rdataStart + length;
                    break;
                }

                case DnsQueryType.Https:
                {
                    if (length < 3)
                    {
                        throw new DnsException($"DNS HTTPS record '{name}' has RDLENGTH {length}, expected at least 3");
                    }

                    var priority = ReadUInt16(buffer, ref position);
                    var target = ReadName(buffer, ref position);
                    if (position - rdataStart > length)
                    {
                        throw new DnsException($"DNS HTTPS record '{name}' target overruns its {length}-byte RDATA");
                    }

                    using var rdata = new MemoryStream(length);
                    WriteUInt16(rdata, priority);
                    WriteName(rdata, target);
                    rdata.Write(buffer.Slice(position, length - (position - rdataStart)));
                    record.Data = rdata.ToArray();
                    record.Target = target;
                    position = rdataStart + length;
                    break;
                }

                default:
                    record.Data = buffer.Slice(position, length).ToArray();
                    position += length;
                    break;
            }

            into.Add(record);
        }
    }

    private static byte[] EncodeNameOnly(string name)
    {
        using var buffer = new MemoryStream(64);
        WriteName(buffer, name);
        return buffer.ToArray();
    }

    private static string ReadName(ReadOnlySpan<byte> buffer, ref int position)
    {
        if (position >= buffer.Length)
        {
            throw new DnsException($"DNS name starts past the end of the message (offset {position}, length {buffer.Length})");
        }

        var labels = new List<string>();
        var cursor = position;
        var end = -1;
        var jumps = 0;
        var wireLength = 1;

        while (true)
        {
            if (cursor >= buffer.Length)
            {
                throw new DnsException($"DNS name at offset {position} runs past the end of the message");
            }

            var length = buffer[cursor];

            if ((length & CompressionMask) == CompressionPointer)
            {
                if (cursor + 1 >= buffer.Length)
                {
                    throw new DnsException($"DNS compression pointer at offset {cursor} is cut short");
                }

                var target = ((length & 0x3F) << 8) | buffer[cursor + 1];
                if (target >= buffer.Length)
                {
                    throw new DnsException($"DNS compression pointer at offset {cursor} points past the end of the message ({target})");
                }

                // RFC 1035 §4.1.4: a pointer must reference a prior occurrence.
                // Enforcing "strictly backwards" is what makes pointer loops
                // structurally impossible.
                if (target >= cursor)
                {
                    throw new DnsException(
                        $"DNS compression pointer at offset {cursor} does not point backwards (target {target}); refusing to follow it");
                }

                if (++jumps > MaxPointerJumps)
                {
                    throw new DnsException($"DNS name at offset {position} exceeds {MaxPointerJumps} compression pointer jumps");
                }

                if (end < 0) end = cursor + 2;
                cursor = target;
                continue;
            }

            if ((length & CompressionMask) != 0)
            {
                throw new DnsException($"DNS name at offset {cursor} uses reserved label type 0x{length:X2}");
            }

            cursor++;

            if (length == 0)
            {
                if (end < 0) end = cursor;
                break;
            }

            if (length > MaxLabelLength)
            {
                throw new DnsException($"DNS label at offset {cursor - 1} claims {length} octets, above the {MaxLabelLength}-octet limit");
            }

            if (cursor + length > buffer.Length)
            {
                throw new DnsException($"DNS label at offset {cursor - 1} claims {length} octets but only {buffer.Length - cursor} remain");
            }

            wireLength += 1 + length;
            if (wireLength > MaxNameLength)
            {
                throw new DnsException($"DNS name at offset {position} exceeds the {MaxNameLength}-byte limit");
            }

            labels.Add(EscapeLabel(buffer.Slice(cursor, length)));
            cursor += length;
        }

        position = end;
        return string.Join('.', labels);
    }

    private static string EscapeLabel(ReadOnlySpan<byte> label)
    {
        var builder = new StringBuilder(label.Length);
        foreach (var b in label)
        {
            switch (b)
            {
                case (byte)'.':
                case (byte)'\\':
                    builder.Append('\\').Append((char)b);
                    break;
                default:
                    builder.Append((char)b);
                    break;
            }
        }

        return builder.ToString();
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> buffer, ref int position)
    {
        if (position + 2 > buffer.Length)
        {
            throw new DnsException($"DNS message truncated: need 2 byte(s) at offset {position}, message is {buffer.Length} byte(s)");
        }

        var value = BinaryPrimitives.ReadUInt16BigEndian(buffer[position..]);
        position += 2;
        return value;
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> buffer, ref int position)
    {
        if (position + 4 > buffer.Length)
        {
            throw new DnsException($"DNS message truncated: need 4 byte(s) at offset {position}, message is {buffer.Length} byte(s)");
        }

        var value = BinaryPrimitives.ReadUInt32BigEndian(buffer[position..]);
        position += 4;
        return value;
    }
}
