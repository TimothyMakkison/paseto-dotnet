using System;
using System.Security.Cryptography;
using NaCl.Core;
using NaCl.Core.Internal;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Paseto.Cryptography;
using static Paseto.Utils.EncodingHelper;

namespace Paseto.PaserkOperations.Wrap;

internal static class Pie
{
    // Versions 1 and 3
    public static byte[] AesDecrypt(byte[] header, byte[] data, byte[] wrappingKey)
    {
        // The first 48 bytes of the decoded bytes will be the authentication tag t. The next 32 bytes will be the nonce n. The remaining bytes will be the wrapped key, c.
        var t = data[..48];
        var n = data[48..80];
        var c = data[80..];

        // Derive the authentication key Ak as:
        // Ak = HMAC-SHA384(msg = 0x81 || n, key = wk)
        using var hmac1 = new HMACSHA384(wrappingKey);
        var msg = CryptoBytes.Combine(new byte[] { 129 }, n);
        var ak = hmac1.ComputeHash(msg)[..32];

        // Recalculate the authentication tag t2 as: t2 = HMAC-SHA384(msg = h || n || c, key = Ak)
        using var hmac2 = new HMACSHA384(ak);
        var t2Msg = CryptoBytes.Combine(header, n, c);
        var t2 = hmac2.ComputeHash(t2Msg);

        // Compare t with t2 in constant-time.If it doesn't match, abort.
        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new Exception("Paserk has invalid authentication tag.");

        // Derive the encryption key Ek and CTR nonce n2 as:
        // x = HMAC-SHA384(msg = 0x80 || n, key = wk)
        // Ek = x[0:32]
        // n2 = x[32:]
        using var hmacWk = new HMACSHA384(wrappingKey);
        var msg2 = CryptoBytes.Combine(new byte[] { 128 }, n);
        var x = hmacWk.ComputeHash(msg2);

        var ek = x[0..32];
        var n2 = x[32..];

        // Decrypt the wrapped key c with Ek and n2 to obtain the plaintext key ptk:
        //         ptk = AES-256-CTR(msg = c, key = Ek, nonce = n2)
        // Return ptk.
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), n2));

        return cipher.DoFinal(c);
    }

    // Versions 1 and 3
    public static string AesEncrypt(byte[] header, byte[] ptk, byte[] wrappingKey)
    {
        // Generate a 256 bit(32 bytes) random nonce, n.
        var n = new byte[32];
        RandomNumberGenerator.Fill(n);

        // Derive the encryption key Ek and CTR nonce n2 as:
        // x = HMAC-SHA384(msg = 0x80 || n, key = wk)
        // Ek = x[0:32]
        // n2 = x[32:]
        using var hmacWk = new HMACSHA384(wrappingKey);
        var msg1 = CryptoBytes.Combine(new byte[] { 128 }, n);
        var x = hmacWk.ComputeHash(msg1);
        var (ek, n2) = (x[..32], x[32..]);

        // Derive the authentication key Ak as:
        // Ak = HMAC-SHA384(msg = 0x81 || n, key = wk)
        var msg2 = CryptoBytes.Combine(new byte[] { 129 }, n);
        var ak = hmacWk.ComputeHash(msg2)[..32];

        // Encrypt the plaintext key ptk with Ek and n2 to obtain the wrapped key c:
        //         c = AES-256-CTR(msg = ptk, key = Ek, nonce = n2)
        var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
        cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", ek), n2));
        var c = cipher.DoFinal(ptk);

        // Calculate the authentication tag t as: t = HMAC-SHA384(msg = h || n || c, key = Ak)
        var hmacAk = new HMACSHA384(ak);
        var msg3 = CryptoBytes.Combine(header, n, c);
        var t = hmacAk.ComputeHash(msg3);

        // Return base64url(t || n || c).
        return ToBase64Url(CryptoBytes.Combine(t, n, c));
    }

    // Versions 2 and 4
    public static byte[] ChaChaDecrypt(byte[] header, byte[] data, byte[] wrappingKey)
    {
        // Decode b from Base64url.The first 32 bytes of the decoded bytes will be the authentication tag t.The next 32 bytes will be the nonce n. The remaining bytes will be the wrapped key, c.

        var t = data[..32];
        var n = data[32..64];
        var c = data[64..];

        // Derive the authentication key Ak as: Ak = crypto_generichash(msg = 0x81 || n, key = wk, length = 32)(This will return a 256-bit(32-byte) output.)
        var blakeWk = new Blake2bMac(32*8) { Key = wrappingKey };
        var msg1 = CryptoBytes.Combine(new byte[] { 129 }, n);
        var ak = blakeWk.ComputeHash(msg1);

        // Recalculate the authentication tag t2 as: t2 = crypto_generichash(msg = h || n || c, key = Ak, length = 32)(This will return a 256-bit(32-byte) output.)
        var blakeAk = new Blake2bMac(32*8) { Key = ak };
        var msg2 = CryptoBytes.Combine(header, n, c);
        var t2 = blakeAk.ComputeHash(msg2);

        // Compare t with t2 in constant-time.If it doesn't match, abort.
        if (!CryptoBytes.ConstantTimeEquals(t, t2))
            throw new Exception("Paserk has invalid authentication tag.");

        // Derive the encryption key Ek and XChaCha nonce n2 as:
        // x = crypto_generichash(msg = 0x80 || n, key = wk, length = 56)
        // Ek = x[0:32]
        // n2 = x[32:]
        var blake448 = new Blake2bMac(56*8) { Key = wrappingKey };
        var msg3 = CryptoBytes.Combine(new byte[] { 128 }, n);
        var x = blake448.ComputeHash(msg3);
        var (ek, n2) = (x[..32], x[32..]);

        // Decrypt the wrapped key c with Ek and n2 to obtain the plaintext key ptk:
        // ptk = XChaCha20(msg = c, key = Ek, nonce = n2)
        var ptk = new byte[c.Length];
        var algo = new XChaCha20(ek, 0);
        algo.Encrypt(c, n2, ptk);

        // Return ptk.
        return ptk;
    }

    public static string ChaChaEncrypt(byte[] header, byte[] ptk, byte[] wrappingKey)
    {
        // Generate a 256 bit(32 bytes) random nonce, n.
        var n = new byte[32];
        RandomNumberGenerator.Fill(n);

        // Derive the encryption key Ek and XChaCha nonce n2 as:
        // x = crypto_generichash(msg = 0x80 || n, key = wk, length = 56)
        // Ek = x[0:32]
        // n2 = x[32:]
        var blakeWk1 = new Blake2bMac(56 * 8) { Key = wrappingKey };
        var msg1 = CryptoBytes.Combine(new byte[] { 128 }, n);
        var x = blakeWk1.ComputeHash(msg1);
        var (ek, n2) = (x[..32], x[32..]);

        // Derive the authentication key Ak as: Ak = crypto_generichash(msg = 0x81 || n, key = wk, length = 32)(This will return a 256-bit(32-byte) output.)
        var blakeWk2 = new Blake2bMac(32 * 8) { Key = wrappingKey };
        var msg2 = CryptoBytes.Combine(new byte[] { 129 }, n);
        var ak = blakeWk2.ComputeHash(msg2);

        // Encrypt the plaintext key ptk with Ek and n2 to obtain the wrapped key c:
        // c = XChaCha20(msg = ptk, key = Ek, nonce = n2)
        var c = new byte[ptk.Length];
        var algo = new XChaCha20(ek, 0);
        algo.Encrypt(ptk, n2, c);

        // Calculate the authentication tag t as: t = crypto_generichash(msg = h || n || c, key = Ak, length = 32)(This will return a 256-bit(32-byte) output.)
        var blakeAk = new Blake2bMac(32 * 8) { Key = ak };
        var msg3 = CryptoBytes.Combine(header, n, c);
        var t = blakeAk.ComputeHash(msg3);

        // Return base64url(t || n || c).
        return ToBase64Url(CryptoBytes.Combine(t, n, c));
    }
}