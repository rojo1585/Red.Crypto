using System.Security.Cryptography;
using System.Text;

namespace Red.Crypto;

public static class SymmetricEncryption
{
    /// <summary>
    /// Encrypts with symmetric algorithms such as aes or TripleDES
    /// </summary>
    public static (byte[] encryptedData, byte[] key, byte[] iv) Encrypt<TCrypto>(string str) where TCrypto : SymmetricAlgorithm, new()
    {
        if (string.IsNullOrEmpty(str))
            throw new ArgumentException("The string to encrypt cannot be null or empty.");

        using var algorithm = new TCrypto();
        algorithm.Padding = PaddingMode.PKCS7;
        algorithm.GenerateKey();
        algorithm.GenerateIV();

        using var encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV);
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(str);
        byte[] encryptedBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);
        return (encryptedBytes, algorithm.Key, algorithm.IV);
    }
    /// <summary>
    /// Decrypts with symmetric algorithms such as aes or TripleDES
    /// </summary>
    public static string Decrypt<TCrypto>(byte[] encryptedBytes, byte[] key, byte[] iv) where TCrypto : SymmetricAlgorithm, new()
    {
        if (encryptedBytes is null or { Length: 0 })
            throw new ArgumentException("Encrypted bytes cannot be null or empty.");
        if (key is null or { Length: 0 })
            throw new ArgumentException("Key cannot be null or empty.");
        if (iv is null or { Length: 0 })
            throw new ArgumentException("IV cannot be null or empty.");

        using var algorithm = new TCrypto();
        algorithm.Padding = PaddingMode.PKCS7;

        using var decrypted = algorithm.CreateDecryptor(key, iv);
        byte[] decryptedBytes = decrypted.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}
