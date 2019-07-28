using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace AngryWasp.Cryptography
{
    public static class Aes
    {
        private const int keySize = 128;
        private const int derivationIterations = 1000;

        public static byte[] Encrypt(byte[] input, byte[] key)
        {
            var saltStringBytes = Helper.GenerateSecureBytes(16);
            var ivStringBytes = Helper.GenerateSecureBytes(16);

            using (var password = new Rfc2898DeriveBytes(key, saltStringBytes, derivationIterations))
            {
                var keyBytes = password.GetBytes(keySize / 8);
                using (var symmetricKey = new AesManaged())
                {
                    symmetricKey.BlockSize = 128;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;

                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(input, 0, input.Length);
                                cryptoStream.FlushFinalBlock();
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return cipherTextBytes;
                            }
                        }
                    }
                }
            }
        }

        public static byte[] Decrypt(byte[] input, byte[] key)
        {
            var saltStringBytes = input.Take(keySize / 8).ToArray();
            var ivStringBytes = input.Skip(keySize / 8).Take(keySize / 8).ToArray();
            var cipherTextBytes = input.Skip((keySize / 8) * 2).Take(input.Length - ((keySize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(key, saltStringBytes, derivationIterations))
            {
                var keyBytes = password.GetBytes(keySize / 8);
                using (var symmetricKey = new AesManaged())
                {
                    symmetricKey.BlockSize = 128;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;

                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return plainTextBytes.Take(decryptedByteCount).ToArray();
                            }
                        }
                    }
                }
            }
        }
    }
}