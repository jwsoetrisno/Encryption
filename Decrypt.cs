using System.Security.Cryptography;
using System.Text;

namespace EncryptionApps;


public class Decrypt
{
    public static string DecryptAES(byte[] cipherText, byte[] Key, byte[] IV)
    {
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException(nameof(cipherText));

        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherText))
            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
            {
                return sr.ReadToEnd();
            }
        }
    }

    public static string DecryptAesGM(byte[] cipherText, byte[] tag, byte[] nonce, byte[] key)
    {
        byte[] plaintextBytes = new byte[cipherText.Length];

        using (var aes = new AesGcm(key))
        {
            aes.Decrypt(nonce, cipherText, tag, plaintextBytes);
        }

        return Encoding.UTF8.GetString(plaintextBytes);
    }

    public static void DecryptFile(string inputFile, string outputFile, byte[] key)
    {
        byte[] fileBytes = File.ReadAllBytes(inputFile);

        byte[] nonce = new byte[12];
        byte[] tag = new byte[16];
        byte[] cipherText = new byte[fileBytes.Length - 28];

        Array.Copy(fileBytes, 0, nonce, 0, 12);
        Array.Copy(fileBytes, 12, tag, 0, 16);
        Array.Copy(fileBytes, 28, cipherText, 0, cipherText.Length);

        byte[] plainText = new byte[cipherText.Length];

        using (var aes = new AesGcm(key))
        {
            aes.Decrypt(nonce, cipherText, tag, plainText);
        }

        File.WriteAllBytes(outputFile, plainText);
    }
}
