using System.Security.Cryptography;

namespace EncryptionApps;

public class KeyGenerator
{
    public static void GenerateAESKey(out byte[] secretKey, out byte[] secretVI)
    {
        using Aes aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();
        secretKey = aes.Key;
        secretVI = aes.IV;
    }

    public static void GenerateAESGMKey(out byte[] secretKey)
    { 
        // Generate random key (256-bit)
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        secretKey = key;
    }
}
