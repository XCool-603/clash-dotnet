using System.Text;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Crypto;

/// <summary>The shared encoding helpers the protocol adapters rely on.</summary>
public class HelperTests
{
    // ---- ClashBase64 ------------------------------------------------------------

    [Theory]
    [InlineData("aGVsbG8=", "hello")]      // standard, padded
    [InlineData("aGVsbG8", "hello")]       // standard, unpadded
    [InlineData("aGVsbG8h", "hello!")]     // different payload, padded
    [InlineData("-_8=", "\u00fb\u00ff")]   // url-safe, padded
    [InlineData("-_8", "\u00fb\u00ff")]    // url-safe, unpadded
    [InlineData("+/8=", "\u00fb\u00ff")]   // standard alphabet for the same bytes
    public void DecodeAcceptsEveryAlphabetAndPadding(string encoded, string expectedLatin1)
    {
        var bytes = ClashBase64.Decode(encoded);
        Assert.Equal(Encoding.Latin1.GetBytes(expectedLatin1), bytes);
    }

    [Fact]
    public void DecodeIgnoresSurroundingWhitespace()
    {
        Assert.Equal(Encoding.ASCII.GetBytes("hello"), ClashBase64.Decode("  aGVsbG8= \r\n"));
    }

    [Fact]
    public void TryDecodeReportsInvalidInput()
    {
        Assert.False(ClashBase64.TryDecode("not base64!", out var bytes));
        Assert.Empty(bytes);
        Assert.False(ClashBase64.TryDecode("a", out _));
        Assert.True(ClashBase64.TryDecode("aGVsbG8", out var ok));
        Assert.Equal(Encoding.ASCII.GetBytes("hello"), ok);
    }

    [Fact]
    public void EncodeUrlSafeIsUnpaddedAndUrlSafe()
    {
        var bytes = new byte[] { 0xFB, 0xFF, 0x00 };
        Assert.Equal("-_8A", ClashBase64.EncodeUrlSafe(bytes));
        Assert.DoesNotContain('=', ClashBase64.EncodeUrlSafe(bytes));
        Assert.DoesNotContain('+', ClashBase64.EncodeUrlSafe(bytes));
        Assert.DoesNotContain('/', ClashBase64.EncodeUrlSafe(bytes));

        // Round-trips back through the tolerant decoder.
        Assert.Equal(bytes, ClashBase64.Decode(ClashBase64.EncodeUrlSafe(bytes)));
    }

    [Fact]
    public void EncodeUsesTheStandardAlphabet()
    {
        Assert.Equal("+/8=", ClashBase64.Encode(new byte[] { 0xFB, 0xFF }));
        Assert.Equal("aGVsbG8=", ClashBase64.Encode(Encoding.ASCII.GetBytes("hello")));
    }

    // ---- ClashHex ---------------------------------------------------------------

    [Fact]
    public void HexEncodeIsLowercase()
    {
        Assert.Equal("00ff10", ClashHex.Encode(new byte[] { 0x00, 0xFF, 0x10 }));
    }

    [Fact]
    public void HexDecodeToleratesWhitespaceAndCase()
    {
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, ClashHex.Decode(" DEADBEEF "));
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, ClashHex.Decode("deadbeef"));
        Assert.False(ClashHex.TryDecode("zz", out var bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void UuidRoundTripsThroughBothForms()
    {
        const string canonical = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        const string stripped = "6ba7b8109dad11d180b400c04fd430c8";

        var bytes = ClashHex.ParseUuid(canonical);
        Assert.Equal(16, bytes.Length);
        Assert.Equal(bytes, ClashHex.ParseUuid(stripped));
        Assert.Equal(canonical, ClashHex.FormatUuid(bytes));

        Assert.True(ClashHex.IsUuid(canonical));
        Assert.True(ClashHex.IsUuid(stripped));
        Assert.False(ClashHex.IsUuid("not-a-uuid"));
        Assert.False(ClashHex.IsUuid("6ba7b810-9dad-11d1-80b4-00c04fd430c"));
    }

    [Fact]
    public void UuidParsingRejectsMalformedInput()
    {
        Assert.Throws<FormatException>(() => ClashHex.ParseUuid("6ba7b810-9dad-11d1-80b4-00c04fd430c"));
        Assert.Throws<FormatException>(() => ClashHex.ParseUuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    }

    [Fact]
    public void UuidFormattingRoundTripsForArbitraryBytes()
    {
        for (var seed = 0; seed < 32; seed++)
        {
            var bytes = new byte[16];
            for (var i = 0; i < bytes.Length; i++) bytes[i] = (byte)(seed * 7 + i * 13);
            var formatted = ClashHex.FormatUuid(bytes);
            Assert.Equal(bytes, ClashHex.ParseUuid(formatted));
            Assert.True(ClashHex.IsUuid(formatted));
        }
    }
}
