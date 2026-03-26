// See https://aka.ms/new-console-template for more information
using EncryptionApps;



Console.Write("Enter text to encrypt: ");
string plainText = Console.ReadLine();

byte[] secretKey;
byte[] secretIV;
KeyGenerator.GenerateAESKey(out secretKey,out secretIV);
byte[] encrypted = Encrypt.EncryptAES(plainText, secretKey, secretIV);

Console.WriteLine("\n--- Encryption Result ---");
Console.WriteLine($"Encrypted Text (Base64): {Convert.ToBase64String(encrypted)}");
Console.WriteLine($"AES Key (Base64): {Convert.ToBase64String(secretKey)}");
Console.WriteLine($"AES IV  (Base64): {Convert.ToBase64String(secretIV)}");


string decrypted = Decrypt.DecryptAES(encrypted, secretKey, secretIV);
Console.WriteLine($"Decrypt {decrypted}");
Console.WriteLine($"AES Key (Base64): {Convert.ToBase64String(secretKey)}");
Console.WriteLine($"AES IV  (Base64): {Convert.ToBase64String(secretIV)}");


byte[] key;
KeyGenerator.GenerateAESGMKey(out key);
var result = Encrypt.EncryptAesGM(plainText, key);
Console.WriteLine("\n--- Encryption AES GCM ---");
Console.WriteLine("Cipher (Base64): " + Convert.ToBase64String(result.CipherText));
Console.WriteLine("Key    (Base64): " + Convert.ToBase64String(key));
Console.WriteLine("Nonce  (Base64): " + Convert.ToBase64String(result.Nonce));
Console.WriteLine("Tag    (Base64): " + Convert.ToBase64String(result.Tag));
string gcmDecrypted = Decrypt.DecryptAesGM(result.CipherText, result.Tag, result.Nonce, key);
Console.WriteLine("\n--- Decryption AES GCM Result ---");
Console.WriteLine("Decrypted Text: " + gcmDecrypted);


Console.WriteLine("\n--- Encryption & Decrypt File ---");
Console.WriteLine("1 = Encrypt File");
Console.WriteLine("2 = Decrypt File");
Console.Write("Choose: ");
string choice = Console.ReadLine();

if (choice == "1")
{
    Console.Write("Input file path: ");
    string input = Console.ReadLine();

    Console.Write("Output encrypted file: ");
    string output = Console.ReadLine();

    Encrypt.EncryptFile(input, output, out byte[] fileKey);

    Console.WriteLine("\n--- SAVE THIS KEY ---");
    Console.WriteLine(Convert.ToBase64String(fileKey));
}
else if (choice == "2")
{
    Console.Write("Encrypted file path: ");
    string input = Console.ReadLine();

    Console.Write("Output decrypted file: ");
    string output = Console.ReadLine();

    Console.Write("Enter key (Base64): ");
    byte[] fileKey = Convert.FromBase64String(Console.ReadLine());

    Decrypt.DecryptFile(input, output, fileKey);

    Console.WriteLine("File decrypted successfully!");
}