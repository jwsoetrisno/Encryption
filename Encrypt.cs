using System.Security.Cryptography;
using System.Text;

namespace EncryptionApps;

public class Encrypt
{
    public static byte[] EncryptAES(string plainText, byte[] Key, byte[] IV)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException(nameof(plainText));

        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (StreamWriter sw = new StreamWriter(cs))
            {
                sw.Write(plainText);
                sw.Close();
                return ms.ToArray();
            }
        }
    }

    public static (byte[] CipherText, byte[] Nonce, byte[] Tag) EncryptAesGM(string plainText, byte[] key)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);

        byte[] nonce = new byte[12]; // recommended size for GCM
        RandomNumberGenerator.Fill(nonce);

        byte[] cipherText = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16]; // authentication tag

        using (var aes = new AesGcm(key))
        {
            aes.Encrypt(nonce, plaintextBytes, cipherText, tag);
        }

        return (cipherText, nonce, tag);
    }

    public static void EncryptFile(string inputFile, string outputFile, out byte[] key)
    {
        byte[] fileBytes = File.ReadAllBytes(inputFile);

        // Generate key
        key = new byte[32]; // 256-bit
        RandomNumberGenerator.Fill(key);

        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        byte[] cipherText = new byte[fileBytes.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(key))
        {
            aes.Encrypt(nonce, fileBytes, cipherText, tag);
        }

        using (var fs = new FileStream(outputFile, FileMode.Create))
        {
            fs.Write(nonce, 0, nonce.Length);
            fs.Write(tag, 0, tag.Length);
            fs.Write(cipherText, 0, cipherText.Length);
        }
    }
}
