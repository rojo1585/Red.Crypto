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

}
