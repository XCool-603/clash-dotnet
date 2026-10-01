namespace Clash.Core.Crypto;

/// <summary>
/// Registers the built-in AEAD ciphers. Filled in by the cipher implementation
/// file; kept separate so <see cref="AeadCiphers"/> stays a pure registry.
/// </summary>
internal static class AeadCipherRegistry
{
    internal static void Register()
    {
        // ---- SIP004 (original) AEAD ciphers -------------------------------------
        // Subkey = HKDF-SHA1(ikm = masterKey, salt = salt, info = "ss-subkey").
        AeadCiphers.Register("aes-128-gcm", () => new HkdfAeadCipher("aes-128-gcm", HkdfAeadCipher.Primitive.Aes128Gcm));
        AeadCiphers.Register("aes-192-gcm", () => new HkdfAeadCipher("aes-192-gcm", HkdfAeadCipher.Primitive.Aes192Gcm));
        AeadCiphers.Register("aes-256-gcm", () => new HkdfAeadCipher("aes-256-gcm", HkdfAeadCipher.Primitive.Aes256Gcm));
        AeadCiphers.Register("chacha20-ietf-poly1305", () => new HkdfAeadCipher("chacha20-ietf-poly1305", HkdfAeadCipher.Primitive.ChaCha20Poly1305));
        AeadCiphers.Register("xchacha20-ietf-poly1305", () => new HkdfAeadCipher("xchacha20-ietf-poly1305", HkdfAeadCipher.Primitive.XChaCha20Poly1305));

        // Aliases Clash/mihomo accept in configuration files.
        AeadCiphers.Register("chacha20-poly1305", () => new HkdfAeadCipher("chacha20-ietf-poly1305", HkdfAeadCipher.Primitive.ChaCha20Poly1305));
        AeadCiphers.Register("xchacha20-poly1305", () => new HkdfAeadCipher("xchacha20-ietf-poly1305", HkdfAeadCipher.Primitive.XChaCha20Poly1305));
        AeadCiphers.Register("aead-chacha20-ietf-poly1305", () => new HkdfAeadCipher("chacha20-ietf-poly1305", HkdfAeadCipher.Primitive.ChaCha20Poly1305));

        // ---- Shadowsocks 2022 (SIP022) ciphers ----------------------------------
        // Subkey = BLAKE3-DERIVE-KEY("shadowsocks 2022 session subkey", masterKey || salt).
        AeadCiphers.Register(
            "2022-blake3-aes-128-gcm",
            () => new Blake3AeadCipher("2022-blake3-aes-128-gcm", HkdfAeadCipher.Primitive.Aes128Gcm, keySize: 16, saltSize: 16));
        AeadCiphers.Register(
            "2022-blake3-aes-256-gcm",
            () => new Blake3AeadCipher("2022-blake3-aes-256-gcm", HkdfAeadCipher.Primitive.Aes256Gcm, keySize: 32, saltSize: 32));
        AeadCiphers.Register(
            "2022-blake3-chacha20-poly1305",
            () => new Blake3AeadCipher("2022-blake3-chacha20-poly1305", HkdfAeadCipher.Primitive.ChaCha20Poly1305, keySize: 32, saltSize: 32));

        // mihomo also answers to the "-ietf-" spelling for the 2022 ChaCha cipher.
        AeadCiphers.Register(
            "2022-blake3-chacha20-ietf-poly1305",
            () => new Blake3AeadCipher("2022-blake3-chacha20-poly1305", HkdfAeadCipher.Primitive.ChaCha20Poly1305, keySize: 32, saltSize: 32));
    }
}

/// <summary>Registers the built-in stream ciphers.</summary>
internal static class StreamCipherRegistry
{
    internal static void Register()
    {
        StreamCiphers.Register("none", () => new NoneStreamCipher());

        // RC4 keyed with MD5(key || iv).
        StreamCiphers.Register("rc4-md5", () => new Rc4Md5StreamCipher());

        // AES in CFB-128 and CTR-128.
        StreamCiphers.Register("aes-128-cfb", () => new CfbStreamCipher("aes-128-cfb", 16, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-192-cfb", () => new CfbStreamCipher("aes-192-cfb", 24, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-256-cfb", () => new CfbStreamCipher("aes-256-cfb", 32, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-128-ctr", () => new CtrStreamCipher("aes-128-ctr", 16, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-192-ctr", () => new CtrStreamCipher("aes-192-ctr", 24, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-256-ctr", () => new CtrStreamCipher("aes-256-ctr", 32, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));

        // Camellia in CFB-128.
        StreamCiphers.Register("camellia-128-cfb", () => new CfbStreamCipher("camellia-128-cfb", 16, static () => new Org.BouncyCastle.Crypto.Engines.CamelliaEngine()));
        StreamCiphers.Register("camellia-192-cfb", () => new CfbStreamCipher("camellia-192-cfb", 24, static () => new Org.BouncyCastle.Crypto.Engines.CamelliaEngine()));
        StreamCiphers.Register("camellia-256-cfb", () => new CfbStreamCipher("camellia-256-cfb", 32, static () => new Org.BouncyCastle.Crypto.Engines.CamelliaEngine()));

        // ChaCha20 with the IETF 12-byte nonce (RFC 7539) and the original 8-byte nonce.
        StreamCiphers.Register(
            "chacha20-ietf",
            () => new BouncyCastleStreamCipher("chacha20-ietf", 32, 12, static () => new Org.BouncyCastle.Crypto.Engines.ChaCha7539Engine()));
        StreamCiphers.Register(
            "chacha20",
            () => new BouncyCastleStreamCipher("chacha20", 32, 8, static () => new Org.BouncyCastle.Crypto.Engines.ChaChaEngine()));

        // Salsa20 with the original 8-byte nonce.
        StreamCiphers.Register(
            "salsa20",
            () => new BouncyCastleStreamCipher("salsa20", 32, 8, static () => new Org.BouncyCastle.Crypto.Engines.Salsa20Engine()));

        // Legacy aliases seen in the wild.
        StreamCiphers.Register("aes-128-cfb128", () => new CfbStreamCipher("aes-128-cfb", 16, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-192-cfb128", () => new CfbStreamCipher("aes-192-cfb", 24, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
        StreamCiphers.Register("aes-256-cfb128", () => new CfbStreamCipher("aes-256-cfb", 32, static () => new Org.BouncyCastle.Crypto.Engines.AesEngine()));
    }
}
