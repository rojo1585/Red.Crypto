namespace Red.Crypto.Extensions.Byte;

public static class ByteExtensions
{
    public static string DecryptAES(this byte[] encryptedBytes, byte[] key, byte[] iv) =>
        AES.DecryptAES(encryptedBytes, key, iv);
}
