using System.Text;
using Clash.Core.Crypto;
using Xunit;

namespace Clash.Tests.Crypto;

/// <summary>
/// Known-answer tests and streaming-equivalence tests for every registered
/// <see cref="IStreamCipher"/>.
/// </summary>
public class StreamCipherTests
{
    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    private static byte[] Sequence(int length, byte start = 1)
    {
        var result = new byte[length];
        for (var i = 0; i < length; i++) result[i] = (byte)(start + i);
        return result;
    }

    public static TheoryData<string> AllStreamCiphers()
    {
        var data = new TheoryData<string>();
        foreach (var name in StreamCiphers.Names.Order(StringComparer.Ordinal)) data.Add(name);
        return data;
    }

    [Fact]
    public void RegistryKnowsEveryDocumentedName()
    {
        string[] expected =
        [
            "none", "rc4-md5",
            "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
            "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
            "chacha20-ietf", "salsa20",
            "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
        ];

        foreach (var name in expected)
        {
            Assert.True(StreamCiphers.TryGet(name, out var cipher), $"missing stream cipher: {name}");
            Assert.NotNull(cipher);
        }

        Assert.True(StreamCiphers.TryGet("AES-256-CFB", out _), "lookup must be case-insensitive");
        Assert.False(StreamCiphers.TryGet("aes-512-cfb", out _));
        Assert.Throws<NotSupportedException>(() => StreamCiphers.Get("nope"));
    }

    [Fact]
    public void KeyAndIvSizesMatchTheSpecification()
    {
        Assert.Equal((0, 0), Sizes("none"));
        Assert.Equal((16, 16), Sizes("rc4-md5"));
        Assert.Equal((16, 16), Sizes("aes-128-cfb"));
        Assert.Equal((24, 16), Sizes("aes-192-cfb"));
        Assert.Equal((32, 16), Sizes("aes-256-cfb"));
        Assert.Equal((16, 16), Sizes("aes-128-ctr"));
        Assert.Equal((24, 16), Sizes("aes-192-ctr"));
        Assert.Equal((32, 16), Sizes("aes-256-ctr"));
        Assert.Equal((32, 12), Sizes("chacha20-ietf"));
        Assert.Equal((32, 8), Sizes("salsa20"));
        Assert.Equal((16, 16), Sizes("camellia-128-cfb"));
        Assert.Equal((24, 16), Sizes("camellia-192-cfb"));
        Assert.Equal((32, 16), Sizes("camellia-256-cfb"));

        static (int Key, int Iv) Sizes(string name)
        {
            var cipher = StreamCiphers.Get(name);
            return (cipher.KeySize, cipher.IvSize);
        }
    }

    [Fact]
    public void NoneIsAPassThrough()
    {
        var cipher = StreamCiphers.Get("none");
        cipher.Init([], []);
        var buffer = Encoding.ASCII.GetBytes("unchanged");
        var expected = buffer.ToArray();
        cipher.Process(buffer);
        Assert.Equal(expected, buffer);
    }

    // ---- NIST SP 800-38A known answers ------------------------------------------

    [Fact]
    public void Aes128Cfb128MatchesNistF3_13()
    {
        var cipher = StreamCipherFactory.CreateEncryptor(
            "aes-128-cfb",
            FromHex("2b7e151628aed2a6abf7158809cf4f3c"),
            FromHex("000102030405060708090a0b0c0d0e0f"));

        var plaintext = FromHex("6bc1bee22e409f96e93d7e117393172a");
        cipher.Process(plaintext);
        Assert.Equal("3b3fd92eb72dad20333449f8e83cfb4a", Hex(plaintext));
    }

    [Fact]
    public void Aes256Cfb128MatchesNistF3_17()
    {
        var cipher = StreamCipherFactory.CreateEncryptor(
            "aes-256-cfb",
            FromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            FromHex("000102030405060708090a0b0c0d0e0f"));

        var plaintext = FromHex("6bc1bee22e409f96e93d7e117393172a");
        cipher.Process(plaintext);
        Assert.Equal("dc7e84bfda79164b7ecd8486985d3860", Hex(plaintext));
    }

    [Fact]
    public void Aes256CtrMatchesNistF5_5()
    {
        var cipher = StreamCiphers.Get("aes-256-ctr");
        cipher.Init(
            FromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            FromHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));

        var plaintext = FromHex("6bc1bee22e409f96e93d7e117393172a");
        cipher.Process(plaintext);
        Assert.Equal("601ec313775789a5b7a7f504bbf3d228", Hex(plaintext));
    }

    [Fact]
    public void ChaCha20IetfMatchesAnIndependentKeystream()
    {
        var cipher = StreamCiphers.Get("chacha20-ietf");
        cipher.Init(Sequence(32, 0), FromHex("000000090000004a00000000"));

        var buffer = new byte[64];
        cipher.Process(buffer);
        Assert.Equal(
            "8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582"
            + "cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d690a35d4",
            Hex(buffer));
    }

    [Fact]
    public void ChaCha20WithTheOriginalNonceMatchesAnIndependentKeystream()
    {
        var cipher = StreamCiphers.Get("chacha20");
        cipher.Init(Sequence(32, 0), FromHex("000000000000004a"));

        var buffer = new byte[32];
        cipher.Process(buffer);
        Assert.Equal("6051353e00dccf5111147ff097739acda8035d23f02a3d80b650c835691790eb", Hex(buffer));
    }

    // ---- streaming behaviour ----------------------------------------------------

    [Theory]
    [MemberData(nameof(AllStreamCiphers))]
    public void EveryCipherRoundTripsThroughEncryptorAndDecryptor(string name)
    {
        var spec = StreamCiphers.Get(name);
        var key = Sequence(spec.KeySize, 1);
        var iv = Sequence(spec.IvSize, 50);
        var plaintext = Sequence(1000, 7);

        var encryptor = StreamCipherFactory.CreateEncryptor(name, key, iv);
        var ciphertext = new byte[plaintext.Length];
        encryptor.Process(plaintext, ciphertext);

        var decryptor = StreamCipherFactory.CreateDecryptor(name, key, iv);
        var recovered = new byte[ciphertext.Length];
        decryptor.Process(ciphertext, recovered);

        Assert.Equal(plaintext, recovered);

        if (name is not "none")
        {
            Assert.NotEqual(plaintext, ciphertext);
        }
    }

    [Theory]
    [MemberData(nameof(AllStreamCiphers))]
    public void ChunkedProcessingMatchesWholeBufferProcessing(string name)
    {
        var spec = StreamCiphers.Get(name);
        var key = Sequence(spec.KeySize, 1);
        var iv = Sequence(spec.IvSize, 50);
        var plaintext = Sequence(4096, 3);

        var whole = new byte[plaintext.Length];
        StreamCipherFactory.CreateEncryptor(name, key, iv).Process(plaintext, whole);

        var chunked = new byte[plaintext.Length];
        var chunkedCipher = StreamCipherFactory.CreateEncryptor(name, key, iv);
        int[] sizes = [1, 2, 3, 7, 15, 16, 17, 31, 64, 100, 255, 1024];
        var offset = 0;
        var index = 0;
        while (offset < plaintext.Length)
        {
            var size = Math.Min(sizes[index++ % sizes.Length], plaintext.Length - offset);
            chunkedCipher.Process(plaintext.AsSpan(offset, size), chunked.AsSpan(offset, size));
            offset += size;
        }

        Assert.Equal(whole, chunked);
    }

    [Theory]
    [MemberData(nameof(AllStreamCiphers))]
    public void InPlaceAndOutOfPlaceProcessingAgree(string name)
    {
        var spec = StreamCiphers.Get(name);
        var key = Sequence(spec.KeySize, 1);
        var iv = Sequence(spec.IvSize, 50);
        var plaintext = Sequence(512, 11);

        var inPlace = plaintext.ToArray();
        StreamCipherFactory.CreateEncryptor(name, key, iv).Process(inPlace);

        var outOfPlace = new byte[plaintext.Length];
        StreamCipherFactory.CreateEncryptor(name, key, iv).Process(plaintext, outOfPlace);

        Assert.Equal(outOfPlace, inPlace);
    }

    [Fact]
    public void CfbIsDirectionalAndCtrIsNot()
    {
        var cfb = StreamCiphers.Get("aes-256-cfb");
        Assert.IsAssignableFrom<IDirectionalStreamCipher>(cfb);

        var ctr = StreamCiphers.Get("aes-256-ctr");
        Assert.False(ctr is IDirectionalStreamCipher);
    }

    [Fact]
    public void CfbEncryptorAndDecryptorDiffer()
    {
        // The encryptor feeds the byte it produced back into the shift register,
        // the decryptor feeds the byte it consumed, so the two are not the same
        // transform once more than one byte has been processed.
        var key = Sequence(16, 1);
        var iv = Sequence(16, 50);
        var data = Sequence(64, 9);

        var encryptor = StreamCipherFactory.CreateEncryptor("aes-128-cfb", key, iv);
        var decryptor = StreamCipherFactory.CreateDecryptor("aes-128-cfb", key, iv);

        var a = data.ToArray();
        encryptor.Process(a);
        var b = data.ToArray();
        decryptor.Process(b);

        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ProcessRejectsAnUndersizedDestination()
    {
        var cipher = StreamCiphers.Get("aes-256-ctr");
        cipher.Init(Sequence(32, 1), Sequence(16, 2));
        Assert.Throws<ArgumentException>(() => cipher.Process(new byte[8], new byte[4]));
    }

    [Fact]
    public void InitRejectsWrongSizedInputs()
    {
        var cipher = StreamCiphers.Get("aes-256-cfb");
        Assert.Throws<ArgumentException>(() => cipher.Init(new byte[16], new byte[16]));
        Assert.Throws<ArgumentException>(() => cipher.Init(new byte[32], new byte[8]));
    }

    [Fact]
    public void Rc4Md5UsesMd5OfKeyConcatenatedWithIv()
    {
        // RC4-MD5 is RC4 keyed with MD5(key || iv), so an independent RC4 over the
        // same derived key must produce the same stream.
        var key = Sequence(16, 1);
        var iv = Sequence(16, 50);
        var expected = StreamCiphers.Get("rc4-md5");
        expected.Init(key, iv);

        var material = new byte[32];
        key.CopyTo(material, 0);
        iv.CopyTo(material, 16);
        var sessionKey = System.Security.Cryptography.MD5.HashData(material);

        var reference = new Org.BouncyCastle.Crypto.Engines.RC4Engine();
        reference.Init(true, new Org.BouncyCastle.Crypto.Parameters.KeyParameter(sessionKey));

        var actual = new byte[256];
        expected.Process(actual);
        var expectedBytes = new byte[256];
        reference.ProcessBytes(new byte[256], 0, 256, expectedBytes, 0);

        Assert.Equal(expectedBytes, actual);
    }
}
