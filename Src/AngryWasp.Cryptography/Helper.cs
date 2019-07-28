using System.Security.Cryptography;

namespace AngryWasp.Cryptography
{
    public static class Helper
    {
        public static byte[] GenerateSecureBytes(int count)
        {
            var randomBytes = new byte[count];
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}