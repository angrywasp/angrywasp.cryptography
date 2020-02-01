using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace AngryWasp.Cryptography
{
    public static class SignatureVerification
    {
        private static Dictionary<string, PgpPublicKey> keyring = new Dictionary<string, PgpPublicKey>();

        public static void AddPublicKey(string name, string publicKeyFile)
        {
            var stream = PgpUtilities.GetDecoderStream(File.OpenRead(publicKeyFile));

            PgpObjectFactory pgpFact = new PgpObjectFactory(stream);
            var keyRing = (PgpPublicKeyRing)pgpFact.NextPgpObject();
            PgpPublicKey publicKey = keyRing.GetPublicKey();

            if (keyring.ContainsKey(name))
                keyring[name] =  publicKey;
            else
                keyring.Add(name, publicKey);
        }

        public static bool Verify(string signatureFilePath, string verifyFilePath, out string keyringTag, out string keyId)
        {
            keyringTag = keyId = null;

            foreach (var k in keyring)
            {
                var stream = PgpUtilities.GetDecoderStream(File.OpenRead(signatureFilePath));
                PgpObjectFactory pgpFact = new PgpObjectFactory(stream);
                PgpSignatureList sList = pgpFact.NextPgpObject() as PgpSignatureList;

                if (sList == null)
                    continue;

                PgpSignature firstSig = sList[0];

                firstSig.InitVerify(k.Value);
                firstSig.Update(File.ReadAllBytes(verifyFilePath));

                bool isValid = firstSig.Verify();

                if (isValid)
                {
                    var u = k.Value.GetUserIds().GetEnumerator();
                    if (u.MoveNext())
                    {
                        keyringTag = k.Key;
                        keyId = u.Current.ToString();
                        return true;
                    }
                }
            }

            return false;
        }
    }
}