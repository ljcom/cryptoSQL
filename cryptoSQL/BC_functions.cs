using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Modes;
using System.Text;

namespace cryptoSQL
{
    static class BCFunctions
    {
        public static AsymmetricCipherKeyPair GenerateKeys(int keySize)
        {
            var gen = new ECKeyPairGenerator();
            var secureRandom = new SecureRandom();
            var keyGenParam = new KeyGenerationParameters(secureRandom, keySize);
            gen.Init(keyGenParam);
            return gen.GenerateKeyPair();

        }
        public static string RetrievePublicKey(string keySize, BigInteger d)
        {
            X9ECParameters ecParams = NistNamedCurves.GetByName("P-" + keySize);
            ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());

            //public key
            ECPoint q = domainParameters.G.Multiply(d);
            ECPublicKeyParameters pubkeyParam = new ECPublicKeyParameters(q, domainParameters);

            return Convert.ToBase64String(pubkeyParam.Q.GetEncoded());

        }

        public static bool VerifySignature(AsymmetricCipherKeyPair key, string plainText, byte[] signature)
        {
            var encoder = new ASCIIEncoding();
            var inputData = encoder.GetBytes(plainText);
            var signer = SignerUtilities.GetSigner("ECDSA");
            signer.Init(false, key.Public);
            signer.BlockUpdate(inputData, 0, inputData.Length);
            return signer.VerifySignature(signature);
        }


        public static byte[] GetSignature(string plainText, ICipherParameters privateKey)
        //private static byte[] GetSignature(string plainText, AsymmetricCipherKeyPair key)
        {
            /* Init alg */
            var signer = SignerUtilities.GetSigner("ECDSA");

            /* Populate key */
            //signer.Init(true, key.Private);
            signer.Init(true, privateKey);

            /* Get the bytes to be signed from the string */
            var bytes = Encoding.UTF8.GetBytes(plainText);

            /* Calc the signature */
            signer.BlockUpdate(bytes, 0, bytes.Length);
            byte[] signature = signer.GenerateSignature();

            /* Base 64 encode the sig so its 8-bit clean */
            //var signedString = Convert.ToBase64String(signature);
            //return signedString;
            return signature;
        }

        public static byte[] Hash(string text, string key)
        {
            var hmac = new HMac(new Sha256Digest());
            hmac.Init(new KeyParameter(Encoding.UTF8.GetBytes(key)));
            byte[] result = new byte[hmac.GetMacSize()];
            byte[] bytes = Encoding.UTF8.GetBytes(text);

            hmac.BlockUpdate(bytes, 0, bytes.Length);
            hmac.DoFinal(result, 0);

            return result;
        }

        public static Byte[] getSharedSecret(Byte[] PrivateKeyIn, Byte[] PublicKeyIn)
        {
            ECDHCBasicAgreement agreement = new ECDHCBasicAgreement();
            X9ECParameters curve = null;
            ECDomainParameters ecParam = null;
            ECPrivateKeyParameters privKey = null;
            ECPublicKeyParameters pubKey = null;
            ECPoint point = null;

            curve = NistNamedCurves.GetByName("P-256");
            ecParam = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            privKey = new ECPrivateKeyParameters(new BigInteger(PrivateKeyIn), ecParam);
            point = ecParam.Curve.DecodePoint(PublicKeyIn);
            pubKey = new ECPublicKeyParameters(point, ecParam);

            agreement.Init(privKey);

            BigInteger secret = agreement.CalculateAgreement(pubKey);

            return secret.ToByteArrayUnsigned();
        }

        public static byte[] DeriveSymmetricKeyFromSharedSecret(byte[] sharedSecret)
        {
            ECDHKekGenerator egH = new ECDHKekGenerator(DigestUtilities.GetDigest("SHA256"));

            egH.Init(new DHKdfParameters(NistObjectIdentifiers.Aes, sharedSecret.Length, sharedSecret));
            byte[] symmetricKey = new byte[DigestUtilities.GetDigest("SHA256").GetDigestSize()];
            egH.GenerateBytes(symmetricKey, 0, symmetricKey.Length);

            return symmetricKey;
        }

    }
    static class BCDES
    {
        public static byte[] EncryptDES(byte[] data, byte[] derivedKey)
        {
            byte[] output = null;
            try
            {
                KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DES", derivedKey);
                IBufferedCipher cipher = CipherUtilities.GetCipher("DES/ECB/ISO7816_4PADDING");
                cipher.Init(true, keyparam);
                try
                {
                    output = cipher.DoFinal(data);
                    return output;
                }
                catch (System.Exception ex)
                {
                    throw new CryptoException(ex.Message);
                }
            }
            catch
            {

            }

            return output;
        }
        public static byte[] DecryptDES(byte[] cipherData, byte[] derivedKey)
        {
            byte[] output = null;
            try
            {
                KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("DES", derivedKey);
                IBufferedCipher cipher = CipherUtilities.GetCipher("DES/ECB/ISO7816_4PADDING");
                cipher.Init(false, keyparam);
                try
                {
                    output = cipher.DoFinal(cipherData);

                }
                catch (System.Exception ex)
                {
                    throw new CryptoException(ex.Message);
                }
            }
            catch 
            {
            }

            return output;
        }
    }
    static class BCAES
    {
        public static byte[] EncryptAES(byte[] inputBytes, byte[] key, byte[] iVector)
        {
            //Convert.FromBase64String(keyString);
            //Set up
            byte[] iv = iVector; //new byte[16];

            AesEngine engine = new AesEngine();
            CbcBlockCipher blockCipher = new CbcBlockCipher(engine); //CBC
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7
            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);

            // Encrypt
            cipher.Init(true, keyParamWithIV);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, outputBytes, 0);
            cipher.DoFinal(outputBytes, length); //Do the final block
                                                 //string encryptedInput = Convert.ToBase64String(outputBytes);

            //cipher.Init(false, keyParamWithIV);
            //byte[] comparisonBytes = new byte[cipher.GetOutputSize(outputBytes.Length)];
            //length = cipher.ProcessBytes(outputBytes, comparisonBytes, 0);
            //cipher.DoFinal(comparisonBytes, length); //Do the final block

            return outputBytes;
        }
        public static byte[] DecryptAES(byte[] outputBytes, byte[] key, byte[] iVector)
        {
            byte[] iv = iVector; //new byte[16]; 

            AesEngine engine = new AesEngine();
            CbcBlockCipher blockCipher = new CbcBlockCipher(engine); //CBC
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); //Default scheme is PKCS5/PKCS7
            KeyParameter keyParam = new KeyParameter(key);
            ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);

            //Decrypt            
            cipher.Init(false, keyParamWithIV);
            byte[] comparisonBytes = new byte[cipher.GetOutputSize(outputBytes.Length)];
            int length = cipher.ProcessBytes(outputBytes, comparisonBytes, 0);
            cipher.DoFinal(comparisonBytes, length); //Do the final block

            return comparisonBytes;
        }
    }
    public class BC2F
    {
        private readonly Encoding _encoding;
        private readonly IBlockCipher _blockCipher;
        private PaddedBufferedBlockCipher _cipher;
        private IBlockCipherPadding _padding;

        public BC2F()
        {

        }

        BC2F(IBlockCipher blockCipher, Encoding encoding)
        {
            _blockCipher = blockCipher;
            _encoding = encoding;
        }

        #region Public Methods


        public static string Encrypt2F(string TextPlain, string Password, byte[] Salt)
        {
            Sha3Digest Sha3Digest = new Sha3Digest();
            Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator(Sha3Digest);
            gen.Init(Encoding.UTF8.GetBytes(Password), Salt, 1000);
            KeyParameter param = (KeyParameter)gen.GenerateDerivedParameters(new TwofishEngine().AlgorithmName, 256);

            BC2F bcEngine = new BC2F(new TwofishEngine(), Encoding.UTF8);
            bcEngine.SetPadding(new Pkcs7Padding());
            return bcEngine.Encrypt(TextPlain, param);
        }

        public static string Decrypt2F(string TextEncripted, string Password, byte[] Salt)
        {
            Sha3Digest Sha3Digest = new Sha3Digest();
            Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator(Sha3Digest);
            gen.Init(Encoding.UTF8.GetBytes(Password), Salt, 1000);
            KeyParameter param = (KeyParameter)gen.GenerateDerivedParameters(new TwofishEngine().AlgorithmName, 256);

            BC2F bcEngine = new BC2F(new TwofishEngine(), Encoding.UTF8);
            bcEngine.SetPadding(new Pkcs7Padding());
            return bcEngine.Decrypt(TextEncripted, param);
        }

        #endregion

        #region Private Methods

        void SetPadding(IBlockCipherPadding padding)
        {
            if (padding != null)
                _padding = padding;
        }

        string Encrypt(string plain, ICipherParameters SetKeyParameter)
        {
            byte[] result = BouncyCastleCrypto(true, _encoding.GetBytes(plain), SetKeyParameter);
            return Convert.ToBase64String(result);
        }

        string Decrypt(string cipher, ICipherParameters SetKeyParameter)
        {
            byte[] result = BouncyCastleCrypto(false, Convert.FromBase64String(cipher), SetKeyParameter);
            return _encoding.GetString(result, 0, result.Length);
        }

        byte[] BouncyCastleCrypto(bool forEncrypt, byte[] input, ICipherParameters SetKeyParameter)
        {
            try
            {
                _cipher = _padding == null ?
                new PaddedBufferedBlockCipher(_blockCipher) : new PaddedBufferedBlockCipher(_blockCipher, _padding);

                _cipher.Init(forEncrypt, SetKeyParameter);

                byte[] ret = _cipher.DoFinal(input);
                return ret;

            }
            catch (CryptoException ex)
            {
                Console.Write(ex.Message);
                //MessageBox(ex.Message);
            }
            return null;
        }

        #endregion

    }

}


