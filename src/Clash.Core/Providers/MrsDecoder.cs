using System.Buffers.Binary;
using System.Net;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using ZstdSharp;

namespace Clash.Core.Providers;

/// <summary>
/// Decodes mihomo's <c>mrs</c> rule-set container into the same textual entries the
/// <c>yaml</c> and <c>text</c> formats produce, so <see cref="Rules.RuleSet"/> consumes
/// every provider format through one path.
/// </summary>
/// <remarks>
/// <para>
/// The whole body is one zstd stream. Inside it sit the four magic bytes
/// <c>"MRS" 0x01</c>, one behaviour byte (<c>0</c> domain, <c>1</c> ipcidr, <c>2</c>
/// classical), a big-endian <c>int64</c> entry count and a big-endian <c>int64</c> length
/// of reserved bytes to skip. The versioned payload that follows depends on the behaviour.
/// </para>
/// <para>
/// <c>classical</c> has no mrs representation at all — mihomo's own reader has no
/// <c>FromMrs</c> for it and rejects the file — so it is refused here instead of guessed at.
/// </para>
/// <para>
/// Every failure leaves as a <see cref="ProviderException"/>: the loader turns that into a
/// warning plus an empty rule set, because a corrupt provider file must never take a reload
/// down. The decoder is deliberately defensive about lengths — it validates every count
/// against the bytes actually left before it allocates — so a hostile or truncated body
/// cannot make it allocate wildly or read past its buffer.
/// </para>
/// </remarks>
public static class MrsDecoder
{
    // mihomo's provider.RuleBehavior byte values.
    private const byte BehaviorDomain = 0;
    private const byte BehaviorIpCidr = 1;
    private const byte BehaviorClassical = 2;

    // Both payloads carry their own version byte, and only version 1 exists.
    private const byte PayloadVersion = 1;

    private const int AddressSize = 16;
    private const int RangeSize = AddressSize * 2;

    /// <summary>The container magic: <c>"MRS"</c> followed by format version 1.</summary>
    private static readonly byte[] Magic = [(byte)'M', (byte)'R', (byte)'S', 1];

    /// <summary>
    /// Decodes an mrs body into rule-set entries: mihomo's domain syntax
    /// (<c>domain</c>, <c>+.domain</c>, <c>.domain</c>) for the <c>domain</c> behaviour and
    /// <c>a.b.c.d/len</c> prefixes for the <c>ipcidr</c> behaviour.
    /// </summary>
    /// <param name="payload">The raw provider body, i.e. the zstd stream.</param>
    /// <param name="behavior">
    /// The behaviour the provider declares. It has to agree with the byte inside the file,
    /// otherwise the entries would be handed to the wrong matcher.
    /// </param>
    /// <returns>The decoded entries, in the order the payload stores them.</returns>
    /// <exception cref="ProviderException">The body is not a well-formed mrs payload.</exception>
    public static List<string> Decode(byte[] payload, string? behavior)
    {
        ArgumentNullException.ThrowIfNull(payload);

        try
        {
            var expected = ParseBehavior(behavior);
            var body = Decompress(payload);
            var reader = new Reader(body);

            var magic = reader.ReadBytes(Magic.Length);
            if (!magic.SequenceEqual(Magic)) throw Invalid("the body does not start with the MRS v1 magic");

            var actual = reader.ReadByte();
            if (actual == BehaviorClassical)
            {
                throw Invalid("behaviour \"classical\" has no mrs representation");
            }

            if (actual != expected)
            {
                throw Invalid($"the payload holds \"{Name(actual)}\" entries but the provider declares \"{Name(expected)}\"");
            }

            // The count is how many entries mihomo inserted; the payloads below are
            // self-describing (and the domain payload deduplicates), so it is not needed here.
            _ = reader.ReadInt64();

            var reserved = reader.ReadInt64();
            if (reserved < 0) throw Invalid("the reserved-section length is negative");
            if (reserved > reader.Remaining) throw Invalid("the reserved section runs past the end of the payload");
            reader.Skip((int)reserved);

            // Behaviour 2 was refused above, so the only two left are domain and ipcidr.
            return actual == BehaviorDomain ? DecodeDomain(ref reader) : DecodeIpCidr(ref reader);
        }
        catch (ProviderException)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The contract with the loader is "ProviderException or nothing": an unexpected
            // shape in a provider file is a decode failure, not a core failure.
            throw new ProviderException($"mrs payload could not be decoded: {ex.Message}", ex);
        }
    }

    private static byte ParseBehavior(string? behavior) => (behavior ?? "domain").Trim().ToLowerInvariant() switch
    {
        "domain" or "" => BehaviorDomain,
        "ipcidr" or "ip-cidr" => BehaviorIpCidr,
        "classical" => BehaviorClassical,
        _ => throw Invalid($"the provider declares unknown behaviour \"{behavior}\""),
    };

    private static string Name(byte behavior) => behavior switch
    {
        BehaviorDomain => "domain",
        BehaviorIpCidr => "ipcidr",
        BehaviorClassical => "classical",
        _ => $"unknown ({behavior})",
    };

    private static byte[] Decompress(byte[] payload)
    {
        if (payload.Length == 0) throw Invalid("the body is empty");

        try
        {
            using var input = new MemoryStream(payload, writable: false);
            using var zstd = new DecompressionStream(input);
            using var output = new MemoryStream(payload.Length);
            zstd.CopyTo(output);
            return output.ToArray();
        }
        catch (EndOfStreamException ex)
        {
            // DecompressionStream raises this when the frame ends mid-way.
            throw new ProviderException("mrs zstd stream is truncated", ex);
        }
        catch (ZstdException ex)
        {
            throw new ProviderException($"mrs body is not a valid zstd stream: {ex.Message}", ex);
        }
        catch (IOException ex)
        {
            throw new ProviderException($"mrs body could not be decompressed: {ex.Message}", ex);
        }
    }

    // ── domain ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Rebuilds mihomo's succinct domain trie. The three arrays are a breadth-first node
    /// layout: node <c>n</c> owns the bitmap bits from its start index up to its terminator
    /// bit, its <c>j</c>-th edge is labelled <c>labels[start + j - n]</c> and leads to node
    /// <c>start + j - n + 1</c>. A node whose own bit is set in <c>leaves</c> is a stored key.
    /// </summary>
    private static List<string> DecodeDomain(ref Reader reader)
    {
        if (reader.ReadByte() != PayloadVersion) throw Invalid("the domain payload has an unsupported version");

        var leaves = ReadBitmap(ref reader, "leaves");
        var labelBitmap = ReadBitmap(ref reader, "labelBitmap");
        var labels = ReadLabels(ref reader);

        return EnumerateDomains(leaves, labelBitmap, labels);
    }

    /// <summary>
    /// Walks the node layout once to record where every node's edge list starts. Every edge
    /// creates one node and every node contributes one terminator bit, so the label count
    /// fixes the node count and the trailing bits of the last word have to be padding.
    /// </summary>
    private static int[] BuildStarts(ulong[] labelBitmap, int nodeCount)
    {
        var starts = new int[nodeCount];
        var bit = 0;

        for (var node = 0; node < nodeCount; node++)
        {
            starts[node] = bit;
            while (!GetBit(labelBitmap, bit)) bit++;
            bit++;
        }

        var padding = ((long)labelBitmap.Length * 64) - bit;
        if (padding >= 64) throw Invalid("the label bitmap has more words than the trie uses");

        for (var i = 0; i < padding; i++)
        {
            if (GetBit(labelBitmap, bit + i)) throw Invalid("the label bitmap does not describe a well-formed trie");
        }

        return starts;
    }

    private static List<string> EnumerateDomains(ulong[] leaves, ulong[] labelBitmap, ReadOnlySpan<byte> labels)
    {
        var nodeCount = labels.Length + 1;
        var starts = BuildStarts(labelBitmap, nodeCount);
        var end = (2 * labels.Length) + 1;

        var result = new List<string>();
        var path = new List<byte>(32);
        var frames = new List<Frame>();

        frames.Add(new Frame { Node = 0, PairChild = -1 });

        while (frames.Count > 0)
        {
            var index = frames.Count - 1;
            var frame = frames[index];

            if (!frame.Entered)
            {
                frame.Start = starts[frame.Node];
                frame.Edges = Terminator(starts, nodeCount, end, frame.Node) - frame.Start;
                frame.Wildcard = FindEdge(labels, frame.Node, frame.Start, frame.Edges, (byte)'+');
                frame.Entered = true;

                var exact = GetBit(leaves, frame.Node);
                var marker = frame.Wildcard >= 0
                    && GetBit(leaves, frame.Start + frame.Wildcard - frame.Node + 1);

                // A domain that carries both halves is stored as two keys, "domain" and
                // ".domain"; they sit at neighbouring nodes and compact back into the single
                // "+.domain" rule the yaml and text providers spell out.
                var dot = FindEdge(labels, frame.Node, frame.Start, frame.Edges, (byte)'.');
                var pairChild = dot >= 0 ? frame.Start + dot - frame.Node + 1 : -1;
                if (exact && pairChild >= 0 && HasSuffixMarker(leaves, labels, starts, nodeCount, end, pairChild))
                {
                    frame.PairChild = pairChild;
                }

                frames[index] = frame;

                if (exact || (marker && !frame.SkipSuffix))
                {
                    var domain = Render(path);
                    if (domain.Length > 0)
                    {
                        // A marker node's path ends in the '.' that separates the wildcard from
                        // the domain, so its rendering already carries the leading dot.
                        result.Add(frame.PairChild >= 0 ? "+." + domain : domain);
                    }
                }
            }

            var edge = frame.Next;
            while (edge < frame.Edges && edge == frame.Wildcard) edge++;

            if (edge < frame.Edges)
            {
                var child = frame.Start + edge - frame.Node + 1;
                if ((uint)child >= (uint)nodeCount) throw Invalid("the domain trie points at a node that does not exist");

                frame.Next = edge + 1;
                frames[index] = frame;

                path.Add(labels[frame.Start + edge - frame.Node]);

                // The '.' child of a compacted pair only repeats what its parent just wrote.
                frames.Add(new Frame { Node = child, PairChild = -1, SkipSuffix = child == frame.PairChild });
            }
            else
            {
                frames.RemoveAt(index);
                if (path.Count > 0) path.RemoveAt(path.Count - 1);
            }
        }

        return result;
    }

    /// <summary>The bitmap index of a node's terminator, i.e. one past its last edge.</summary>
    private static int Terminator(int[] starts, int nodeCount, int end, int node)
        => node + 1 < nodeCount ? starts[node + 1] - 1 : end - 1;

    /// <summary>True when a node has a '+' edge to a leaf, i.e. it is a dot-wildcard key.</summary>
    private static bool HasSuffixMarker(ulong[] leaves, ReadOnlySpan<byte> labels, int[] starts, int nodeCount, int end, int node)
    {
        if ((uint)node >= (uint)nodeCount) return false;

        var start = starts[node];
        var edge = FindEdge(labels, node, start, Terminator(starts, nodeCount, end, node) - start, (byte)'+');
        return edge >= 0 && GetBit(leaves, start + edge - node + 1);
    }

    /// <summary>Reverses the stored key, which is the domain written back to front.</summary>
    private static string Render(List<byte> path)
    {
        var bytes = CollectionsMarshal.AsSpan(path);
        bytes.Reverse();
        var domain = Encoding.UTF8.GetString(bytes);
        bytes.Reverse();
        return domain;
    }

    private static ulong[] ReadBitmap(ref Reader reader, string name)
    {
        var count = reader.ReadInt64();
        if (count < 1) throw Invalid($"the {name} bitmap declares {count} words");
        if (count > reader.Remaining / sizeof(ulong)) throw Invalid($"the {name} bitmap is truncated");

        var bitmap = new ulong[count];
        for (var i = 0; i < count; i++) bitmap[i] = (ulong)reader.ReadInt64();
        return bitmap;
    }

    private static ReadOnlySpan<byte> ReadLabels(ref Reader reader)
    {
        var count = reader.ReadInt64();
        if (count < 1) throw Invalid($"the label list declares {count} bytes");
        if (count > reader.Remaining) throw Invalid("the label list is truncated");
        return reader.ReadBytes((int)count);
    }

    private static int FindEdge(ReadOnlySpan<byte> labels, int node, int start, int edges, byte label)
    {
        for (var edge = 0; edge < edges; edge++)
        {
            if (labels[start + edge - node] == label) return edge;
        }

        return -1;
    }

    private static bool GetBit(ulong[] bitmap, int index)
    {
        var word = index >> 6;
        if ((uint)word >= (uint)bitmap.Length) throw Invalid("the domain payload is truncated");
        return (bitmap[word] & (1UL << (index & 63))) != 0;
    }

    // ── ipcidr ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Turns the stored IP ranges back into CIDR entries. mihomo writes a merged range set,
    /// not a prefix list, so a range that is not itself a power-of-two aligned block becomes
    /// several entries.
    /// </summary>
    private static List<string> DecodeIpCidr(ref Reader reader)
    {
        if (reader.ReadByte() != PayloadVersion) throw Invalid("the ipcidr payload has an unsupported version");

        var count = reader.ReadInt64();
        if (count < 1) throw Invalid($"the ipcidr payload declares {count} ranges");
        if (count > reader.Remaining / RangeSize) throw Invalid("the ipcidr range list is truncated");

        var result = new List<string>();
        for (var i = 0; i < count; i++)
        {
            var (from, fromBits) = ReadAddress(ref reader);
            var (to, toBits) = ReadAddress(ref reader);
            if (fromBits != toBits) throw Invalid("an ipcidr range mixes address families");
            if (from > to) throw Invalid("an ipcidr range ends before it starts");

            AppendPrefixes(result, from, to, fromBits);
        }

        return result;
    }

    /// <summary>
    /// Reads one big-endian 16-byte address. mihomo writes <c>netip.Addr.As16()</c>, so an
    /// IPv4 address arrives as <c>::ffff:a.b.c.d</c> and has to be unmapped back.
    /// </summary>
    private static (UInt128 Value, int Bits) ReadAddress(ref Reader reader)
    {
        var bytes = reader.ReadBytes(AddressSize);

        var mapped = true;
        for (var i = 0; i < 10; i++)
        {
            if (bytes[i] == 0) continue;
            mapped = false;
            break;
        }

        if (mapped && bytes[10] == 0xFF && bytes[11] == 0xFF)
        {
            return (BinaryPrimitives.ReadUInt32BigEndian(bytes[12..]), 32);
        }

        return (BinaryPrimitives.ReadUInt128BigEndian(bytes), 128);
    }

    /// <summary>
    /// Decomposes an inclusive range into the smallest set of CIDR blocks covering it: at each
    /// step take the largest block that both starts on its own alignment and still fits.
    /// </summary>
    private static void AppendPrefixes(List<string> result, UInt128 from, UInt128 to, int bits)
    {
        while (from <= to)
        {
            var alignment = from == 0 ? bits : Math.Min(bits, TrailingZeroCount(from));

            var span = to - from;
            var fits = span == UInt128.MaxValue ? 128 : 127 - LeadingZeroCount(span + 1);

            var size = Math.Min(alignment, fits);
            result.Add(RenderPrefix(from, bits, bits - size));

            if (size >= 128) return;
            from += UInt128.One << size;
        }
    }

    private static string RenderPrefix(UInt128 value, int bits, int prefix)
    {
        Span<byte> bytes = stackalloc byte[AddressSize];

        if (bits == 32)
        {
            BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)value);
            return $"{new IPAddress(bytes[..4])}/{prefix}";
        }

        BinaryPrimitives.WriteUInt128BigEndian(bytes, value);
        return $"{new IPAddress(bytes)}/{prefix}";
    }

    private static int TrailingZeroCount(UInt128 value)
    {
        var low = (ulong)value;
        if (low != 0) return BitOperations.TrailingZeroCount(low);

        var high = (ulong)(value >> 64);
        return high == 0 ? 128 : 64 + BitOperations.TrailingZeroCount(high);
    }

    private static int LeadingZeroCount(UInt128 value)
    {
        var high = (ulong)(value >> 64);
        if (high != 0) return BitOperations.LeadingZeroCount(high);

        var low = (ulong)value;
        return low == 0 ? 128 : 64 + BitOperations.LeadingZeroCount(low);
    }

    // ── plumbing ─────────────────────────────────────────────────────────────

    private static ProviderException Invalid(string message) => new($"mrs: {message}");

    /// <summary>One node of the rebuilt domain trie, walked iteratively so a deep or cyclic
    /// (corrupt) payload cannot overflow the stack.</summary>
    private struct Frame
    {
        public int Node;
        public int Start;
        public int Edges;
        public int Next;
        public int Wildcard;
        public int PairChild;
        public bool Entered;
        public bool SkipSuffix;
    }

    /// <summary>A bounds-checked big-endian cursor over the decompressed body.</summary>
    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _buffer;
        private int _offset;

        public Reader(ReadOnlySpan<byte> buffer)
        {
            _buffer = buffer;
            _offset = 0;
        }

        public int Remaining => _buffer.Length - _offset;

        public byte ReadByte()
        {
            if (_offset >= _buffer.Length) throw Invalid("the payload is truncated");
            return _buffer[_offset++];
        }

        public long ReadInt64()
        {
            if (Remaining < sizeof(long)) throw Invalid("the payload is truncated");
            var value = BinaryPrimitives.ReadInt64BigEndian(_buffer[_offset..]);
            _offset += sizeof(long);
            return value;
        }

        public ReadOnlySpan<byte> ReadBytes(int count)
        {
            if (count < 0 || Remaining < count) throw Invalid("the payload is truncated");
            var slice = _buffer.Slice(_offset, count);
            _offset += count;
            return slice;
        }

        public void Skip(int count)
        {
            if (count < 0 || Remaining < count) throw Invalid("the payload is truncated");
            _offset += count;
        }
    }
}
