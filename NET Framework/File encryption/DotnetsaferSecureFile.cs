using System;
using System.IO;
using System.Security.Cryptography;

namespace SecureApplication
{
    internal static class DotnetsaferSecureFile
    {
        public static void WriteAllText(string path, string contents, string password) {
            var (key, iV) = FromPassword(password);
            var encryptedText = EncryptStringToBytes(contents, key, iV);
            File.WriteAllBytes(path,encryptedText);
        }
        public static string ReadAllText(string path, string password) {
            var encryptedText = File.ReadAllBytes(path);
            var (key, iV) = FromPassword(password);
            return DecryptStringFromBytes(encryptedText, key, iV);
        }
        public static void WriteAllBytes(string path, byte[] contents, string password) => WriteAllText(path, contents.ConvertToString(), password);
        public static byte[] ReadAllBytes(string path, string password) => ReadAllText(path, password).ToArray();

        private static readonly byte[] Salt = { 0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c };
        private static (byte[] key, byte[] iV) FromPassword(string password)
        {
            var rijndael = Rijndael.Create();
            var pdb = new Rfc2898DeriveBytes(password, Salt);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            return (rijndael.Key, rijndael.IV);
        }
        private static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException(nameof(plainText));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));
            byte[] encrypted;

            using (var rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                var encryption = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using var msEncrypt = new MemoryStream();
                using var csEncrypt = new CryptoStream(msEncrypt, encryption, CryptoStreamMode.Write);
                using (var swEncrypt = new StreamWriter(csEncrypt)) {
                    swEncrypt.Write(plainText);
                }
                encrypted = msEncrypt.ToArray();
            }
            return encrypted;
        }
        private static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));
            string plaintext;
            using (var rijAlg = new RijndaelManaged()) {
                rijAlg.Key = key;
                rijAlg.IV = iv;

                var decryption = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using var msDecrypt = new MemoryStream(cipherText);
                using var csDecrypt = new CryptoStream(msDecrypt, decryption, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                plaintext = srDecrypt.ReadToEnd();
            }
            return plaintext;
        }

        private static string ConvertToString(this byte[] array)
        {
            var chars = new char[array.Length / sizeof(char)];
            System.Buffer.BlockCopy(array, 0, chars, 0, array.Length);
            return new string(chars);
        }

        private static byte[] ToArray(this string str)
        {
            var bytes = new byte[str.Length * sizeof(char)];
            Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }
    }
}
