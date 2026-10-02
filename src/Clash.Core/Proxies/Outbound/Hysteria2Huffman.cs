using Clash.Core.Common;

namespace Clash.Core.Proxies.Outbound;

/// <summary>
/// The HPACK/QPACK Huffman code of RFC 7541 Appendix B, decode-only.
/// <para>
/// <b>Why this is needed at all.</b> A QPACK encoder may Huffman-encode any name or
/// value string and signals the choice with the <c>H</c> bit of the length prefix.
/// The reference server is quic-go, whose QPACK encoder takes the shorter of the raw
/// and Huffman forms, so the names it invents (<c>hysteria-udp</c>,
/// <c>hysteria-cc-rx</c>) arrive Huffman-encoded and a decoder without this table
/// would fail the auth handshake on the very first response. There is no setting that
/// turns the peer's Huffman off, so the table has to be here.
/// </para>
/// <para>
/// <b>Decode only.</b> This client never Huffman-encodes: the raw form is always a
/// legal encoding, so the encoder side of the codec is deliberately absent. The
/// codes below are right-aligned with the widths in <see cref="Lengths"/>; entry 256
/// is the EOS symbol, which is legal in the table but must never appear in a decoded
/// string (RFC 7541 §5.2).
/// </para>
/// </summary>
internal static class Hysteria2Huffman
{
    /// <summary>Index of the EOS symbol in the code tables.</summary>
    internal const int EosSymbol = 256;

    private static readonly Node Root = BuildTree();

    /// <summary>
    /// Decodes one Huffman string. Throws <see cref="ClashException"/> for an invalid
    /// code, for EOS, and for padding that is not a prefix of EOS shorter than eight
    /// bits — the three ways RFC 7541 §5.2 says a Huffman string can be malformed.
    /// </summary>
    internal static byte[] Decode(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty) return [];

        var output = new List<byte>(source.Length);
        var node = Root;
        var bitsSinceSymbol = 0;
        var allOnes = true;

        foreach (var b in source)
        {
            for (var i = 7; i >= 0; i--)
            {
                var bit = (b >> i) & 1;
                var next = bit == 0 ? node.Zero : node.One;
                if (next is null)
                {
                    throw new ClashException("hysteria2: the QPACK Huffman string is not a valid code");
                }

                node = next;
                bitsSinceSymbol++;
                allOnes &= bit == 1;

                if (node.Symbol < 0) continue;

                if (node.Symbol == EosSymbol)
                {
                    throw new ClashException("hysteria2: the QPACK Huffman string contains the EOS symbol");
                }

                output.Add((byte)node.Symbol);
                node = Root;
                bitsSinceSymbol = 0;
                allOnes = true;
            }
        }

        if (node != Root && (bitsSinceSymbol > 7 || !allOnes))
        {
            throw new ClashException("hysteria2: the QPACK Huffman string ends with invalid padding");
        }

        return [.. output];
    }

    /// <summary>Builds the decoding trie once, from the two flat tables below.</summary>
    private static Node BuildTree()
    {
        var root = new Node();
        for (var symbol = 0; symbol < Codes.Length; symbol++)
        {
            var node = root;
            for (var bit = Lengths[symbol] - 1; bit >= 0; bit--)
            {
                var zero = ((Codes[symbol] >> bit) & 1U) == 0;
                var next = zero ? node.Zero : node.One;
                if (next is null)
                {
                    next = new Node();
                    if (zero) node.Zero = next;
                    else node.One = next;
                }

                node = next;
            }

            node.Symbol = symbol;
        }

        return root;
    }

    /// <summary>One node of the decoding trie: two children and, for a leaf, the symbol.</summary>
    private sealed class Node
    {
        internal Node? Zero;
        internal Node? One;
        internal int Symbol = -1;
    }

    /// <summary>HPACK Huffman codes, right-aligned; <c>Codes[i]</c> is <c>Lengths[i]</c> bits wide.</summary>
    private static readonly uint[] Codes =
    [
        0x1FF8U, 0x7FFFD8U, 0xFFFFFE2U, 0xFFFFFE3U, 0xFFFFFE4U, 0xFFFFFE5U, 0xFFFFFE6U, 0xFFFFFE7U,
        0xFFFFFE8U, 0xFFFFEAU, 0x3FFFFFFCU, 0xFFFFFE9U, 0xFFFFFEAU, 0x3FFFFFFDU, 0xFFFFFEBU, 0xFFFFFECU,
        0xFFFFFEDU, 0xFFFFFEEU, 0xFFFFFEFU, 0xFFFFFF0U, 0xFFFFFF1U, 0xFFFFFF2U, 0x3FFFFFFEU, 0xFFFFFF3U,
        0xFFFFFF4U, 0xFFFFFF5U, 0xFFFFFF6U, 0xFFFFFF7U, 0xFFFFFF8U, 0xFFFFFF9U, 0xFFFFFFAU, 0xFFFFFFBU,
        0x14U, 0x3F8U, 0x3F9U, 0xFFAU, 0x1FF9U, 0x15U, 0xF8U, 0x7FAU,
        0x3FAU, 0x3FBU, 0xF9U, 0x7FBU, 0xFAU, 0x16U, 0x17U, 0x18U,
        0x0U, 0x1U, 0x2U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU,
        0x1EU, 0x1FU, 0x5CU, 0xFBU, 0x7FFCU, 0x20U, 0xFFBU, 0x3FCU,
        0x1FFAU, 0x21U, 0x5DU, 0x5EU, 0x5FU, 0x60U, 0x61U, 0x62U,
        0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU,
        0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U, 0x71U, 0x72U,
        0xFCU, 0x73U, 0xFDU, 0x1FFBU, 0x7FFF0U, 0x1FFCU, 0x3FFCU, 0x22U,
        0x7FFDU, 0x3U, 0x23U, 0x4U, 0x24U, 0x5U, 0x25U, 0x26U,
        0x27U, 0x6U, 0x74U, 0x75U, 0x28U, 0x29U, 0x2AU, 0x7U,
        0x2BU, 0x76U, 0x2CU, 0x8U, 0x9U, 0x2DU, 0x77U, 0x78U,
        0x79U, 0x7AU, 0x7BU, 0x7FFEU, 0x7FCU, 0x3FFDU, 0x1FFDU, 0xFFFFFFCU,
        0xFFFE6U, 0x3FFFD2U, 0xFFFE7U, 0xFFFE8U, 0x3FFFD3U, 0x3FFFD4U, 0x3FFFD5U, 0x7FFFD9U,
        0x3FFFD6U, 0x7FFFDAU, 0x7FFFDBU, 0x7FFFDCU, 0x7FFFDDU, 0x7FFFDEU, 0xFFFFEBU, 0x7FFFDFU,
        0xFFFFECU, 0xFFFFEDU, 0x3FFFD7U, 0x7FFFE0U, 0xFFFFEEU, 0x7FFFE1U, 0x7FFFE2U, 0x7FFFE3U,
        0x7FFFE4U, 0x1FFFDCU, 0x3FFFD8U, 0x7FFFE5U, 0x3FFFD9U, 0x7FFFE6U, 0x7FFFE7U, 0xFFFFEFU,
        0x3FFFDAU, 0x1FFFDDU, 0xFFFE9U, 0x3FFFDBU, 0x3FFFDCU, 0x7FFFE8U, 0x7FFFE9U, 0x1FFFDEU,
        0x7FFFEAU, 0x3FFFDDU, 0x3FFFDEU, 0xFFFFF0U, 0x1FFFDFU, 0x3FFFDFU, 0x7FFFEBU, 0x7FFFECU,
        0x1FFFE0U, 0x1FFFE1U, 0x3FFFE0U, 0x1FFFE2U, 0x7FFFEDU, 0x3FFFE1U, 0x7FFFEEU, 0x7FFFEFU,
        0xFFFEAU, 0x3FFFE2U, 0x3FFFE3U, 0x3FFFE4U, 0x7FFFF0U, 0x3FFFE5U, 0x3FFFE6U, 0x7FFFF1U,
        0x3FFFFE0U, 0x3FFFFE1U, 0xFFFEBU, 0x7FFF1U, 0x3FFFE7U, 0x7FFFF2U, 0x3FFFE8U, 0x1FFFFECU,
        0x3FFFFE2U, 0x3FFFFE3U, 0x3FFFFE4U, 0x7FFFFDEU, 0x7FFFFDFU, 0x3FFFFE5U, 0xFFFFF1U, 0x1FFFFEDU,
        0x7FFF2U, 0x1FFFE3U, 0x3FFFFE6U, 0x7FFFFE0U, 0x7FFFFE1U, 0x3FFFFE7U, 0x7FFFFE2U, 0xFFFFF2U,
        0x1FFFE4U, 0x1FFFE5U, 0x3FFFFE8U, 0x3FFFFE9U, 0xFFFFFFDU, 0x7FFFFE3U, 0x7FFFFE4U, 0x7FFFFE5U,
        0xFFFECU, 0xFFFFF3U, 0xFFFEDU, 0x1FFFE6U, 0x3FFFE9U, 0x1FFFE7U, 0x1FFFE8U, 0x7FFFF3U,
        0x3FFFEAU, 0x3FFFEBU, 0x1FFFFEEU, 0x1FFFFEFU, 0xFFFFF4U, 0xFFFFF5U, 0x3FFFFEAU, 0x7FFFF4U,
        0x3FFFFEBU, 0x7FFFFE6U, 0x3FFFFECU, 0x3FFFFEDU, 0x7FFFFE7U, 0x7FFFFE8U, 0x7FFFFE9U, 0x7FFFFEAU,
        0x7FFFFEBU, 0xFFFFFFEU, 0x7FFFFECU, 0x7FFFFEDU, 0x7FFFFEEU, 0x7FFFFEFU, 0x7FFFFF0U, 0x3FFFFEEU,
        0x3FFFFFFFU,
    ];

    /// <summary>Bit width of each entry in <see cref="Codes"/>, EOS included.</summary>
    private static readonly byte[] Lengths =
    [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
        30,
    ];
}
