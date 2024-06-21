using System.Security.Cryptography;
using System.Text;

namespace Red.Crypto.Extensions.Byte;

public static class ByteExtensions
{
    public static string DecryptAES(this byte[] encryptedBytes, byte[] key, byte[] iv)
    {
        if (encryptedBytes == null || encryptedBytes.Length == 0)
            throw new ArgumentException("Encrypted bytes cannot be null or empty.");
        if (key == null || key.Length == 0)
            throw new ArgumentException("Key cannot be null or empty.");
        if (iv == null || iv.Length == 0)
            throw new ArgumentException("IV cannot be null or empty.");

        using var aes = Aes.Create();
        aes.KeySize = key.Length * 8;
        aes.Padding = PaddingMode.PKCS7;

        using var descriptor = aes.CreateDecryptor(key, iv);
        byte[] decryptedBytes = descriptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}
