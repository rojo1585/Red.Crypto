using System.Security.Cryptography;
using System.Text;

namespace Red.Crypto.Extensions.String
{
    public static class StringExtensions
    {
        public static string ToSHA256(this string str)
        {
            byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(str));
            return Convert.ToHexString(hashBytes);
        }
        public static (byte[] encryptedData, byte[] key, byte[] iv) EncryptAES(this string str, int keySize = 256) =>
            AES.EncryptAES(str, keySize);

    }
}
