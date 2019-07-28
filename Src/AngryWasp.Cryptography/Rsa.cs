using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace AngryWasp.Cryptography
{
    public static class Rsa
	{
		public static void GenerateKeyPair(int keySize, out byte[] publicKey, out byte[] privateKey)
		{
			RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();  
			rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));  
			var keyPair = rsaGenerator.GenerateKeyPair(); 

			{ //Public Key
				RsaKeyParameters p = (RsaKeyParameters)keyPair.Public;
				var m = p.Modulus.ToByteArray();
				var e = p.Exponent.ToByteArray();

				List<byte> pk = new List<byte>();
				pk.Add((byte)m.Length);
				pk.Add((byte)e.Length);
				pk.AddRange(m);
				pk.AddRange(e);

				publicKey = pk.ToArray();
			}	

			{ //Private Key
				RsaKeyParameters p = (RsaKeyParameters)keyPair.Private;
				var m = p.Modulus.ToByteArray();
				var e = p.Exponent.ToByteArray();

				List<byte> pk = new List<byte>();
				pk.Add((byte)m.Length);
				pk.Add((byte)e.Length);
				pk.AddRange(m);
				pk.AddRange(e);

				privateKey = pk.ToArray();
			}
		}

		public static byte[] Sign(byte[] input, byte[] privateKey)
        {
            var keyParameters = GetPrivateKeyParams(privateKey);

            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, keyParameters);
            signer.BlockUpdate(input, 0, input.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(byte[] input, byte[] publicKey, byte[] signature)
        {
            var keyParameters = GetPublicKeyParams(publicKey);

            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(false, keyParameters);
            signer.BlockUpdate(input, 0, input.Length);
            return signer.VerifySignature(signature);
        }

		public static byte[] Encrypt(byte[] input, byte[] publicKey)
		{
			RsaKeyParameters p = GetPublicKeyParams(publicKey);

			var encryptEngine = new Pkcs1Encoding(new RsaEngine());
			encryptEngine.Init(true, p);
			return encryptEngine.ProcessBlock(input, 0, input.Length);
		}

		public static byte[] Decrypt(byte[] input, byte[] privateKey)
		{
			RsaKeyParameters p = GetPrivateKeyParams(privateKey);

			var encryptEngine = new Pkcs1Encoding(new RsaEngine());
			encryptEngine.Init(false, p);
			return encryptEngine.ProcessBlock(input, 0, input.Length);
		}

		private static RsaKeyParameters GetPublicKeyParams(byte[] publicKey)
		{
			BinaryReader br = new BinaryReader(new MemoryStream(publicKey));
			byte ml = br.ReadByte();
			byte el = br.ReadByte();
			byte[] mb = br.ReadBytes(ml);
			byte[] eb = br.ReadBytes(el);

			return new RsaKeyParameters(false, 
				new BigInteger(mb),
				new BigInteger(eb));
		}
		
		private static RsaKeyParameters GetPrivateKeyParams(byte[] privateKey)
		{
			BinaryReader br = new BinaryReader(new MemoryStream(privateKey));
			byte ml = br.ReadByte();
			byte el = br.ReadByte();
			byte[] mb = br.ReadBytes(ml);
			byte[] eb = br.ReadBytes(el);

			return new RsaKeyParameters(false, 
				new BigInteger(mb),
				new BigInteger(eb));
		}
	}
}