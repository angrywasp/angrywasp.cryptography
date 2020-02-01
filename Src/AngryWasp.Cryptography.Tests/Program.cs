using System;

namespace AngryWasp.Cryptography.Tests
{
    public static class MainClass
    {
        [STAThread]
        public static void Main(string[] args)
        {
            PgpVerifier.AddPublicKey("angrywasp", "./VerifyTestData/pk.asc");

            string keyringTag, keyId;
            if (PgpVerifier.Verify("./VerifyTestData/rand.bin.sig","./VerifyTestData/rand.bin", out keyringTag, out keyId))
                Console.WriteLine(keyId);
            else
                Console.Write("File signature failed verification");
        }
    }
}
