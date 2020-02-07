using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace AngryWasp.Cryptography
{
    public static class Kdf
    {
        public static byte[] Hash(byte[] message, byte[] salt, int iterations)
        {
            Pkcs5S2ParametersGenerator kdf = new Pkcs5S2ParametersGenerator();
            kdf.Init(message, salt, iterations);
            return ((KeyParameter)kdf.GenerateDerivedMacParameters(256)).GetKey();
        }
    }
}