using System;
using System.Text;
using System.Linq;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System.Xml;

namespace cryptoSQL
{
    public static class functions
    {
        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlXml generateKeys(SqlString keySize, SqlString network)
        {
            AsymmetricCipherKeyPair key = BCFunctions.GenerateKeys(Convert.ToInt16(keySize.ToString()));

            ECPublicKeyParameters publicKeyParam = (ECPublicKeyParameters)key.Public;
            ECPrivateKeyParameters privateKeyParam = (ECPrivateKeyParameters)key.Private;

            var privateKey = privateKeyParam.D.ToString();
            BigInteger d = new BigInteger(privateKey, 10);

            var publicKey = BCFunctions.RetrievePublicKey(keySize.ToString(), d);

            var addressText = "0x" + BitConverter.ToString(BCFunctions.Hash(publicKey, network.ToString())).Replace("-", "");

            var r = "<sqroot><D>" + privateKey + "</D><Q>" + publicKey + "</Q><A>" + addressText + "</A></sqroot>";
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(r);
            XmlNodeReader xnr = new XmlNodeReader(xmlDoc);
            SqlXml rx = new SqlXml(xnr);
            return (rx);
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString retrievePublicKey(SqlString keySize, SqlString privateKey)
        {
            BigInteger DString = new BigInteger(privateKey.ToString(), 10);
            return BCFunctions.RetrievePublicKey(keySize.ToString(), DString);
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString getSignature(SqlString keySize, SqlString PrivateKey, SqlString Message)
        {
            X9ECParameters ecParams = NistNamedCurves.GetByName("P-" + keySize.ToString());
            ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
            var G = ecParams.G;
            ECCurve curve = ecParams.Curve;

            //private Key
            BigInteger d = new BigInteger(PrivateKey.ToString(), 10);
            ECPrivateKeyParameters keyParameters = new ECPrivateKeyParameters(d, domainParameters);

            //public key
            ECPoint q = domainParameters.G.Multiply(d);
            ECPublicKeyParameters pubkeyParam = new ECPublicKeyParameters(q, domainParameters);

            string s = Message.ToString();
            var signature = BCFunctions.GetSignature(s, keyParameters);
            var signedString = Convert.ToBase64String(signature);
            var txtSignature = signedString;
            return txtSignature;
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlBoolean verifySignature(SqlString keySize, SqlString PublicKey, SqlString message, SqlString signature)
        {

            byte[] messageBytes = Encoding.ASCII.GetBytes(message.ToString());
            byte[] signatureBytes = Convert.FromBase64String(signature.ToString());

            X9ECParameters ecParams = NistNamedCurves.GetByName("P-" + keySize.ToString());
            ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
            var G = ecParams.G;
            Org.BouncyCastle.Math.EC.ECCurve curve = ecParams.Curve;

            byte[] encoded = Convert.FromBase64String(PublicKey.ToString());
            ECPoint q = curve.DecodePoint(encoded);

            try
            {
                ECPublicKeyParameters pubkeyParam = new ECPublicKeyParameters(q, domainParameters);
                var verifier = SignerUtilities.GetSigner("ECDSA");
                verifier.Init(false, pubkeyParam);
                verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);
                bool signatureOK = verifier.VerifySignature(signatureBytes);

                return signatureOK;

            }
            catch
            {
                return (false);
            }
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString getSharedSecret(SqlString keySize, SqlString PrivateKey, SqlString PublicKey)
        {
            //X9ECParameters ecP = NistNamedCurves.GetByName("P-" + keySize.ToString());
            //var c = (FpCurve)ecP.Curve;
            //var eCDomainParameters = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());

            BigInteger dA = new BigInteger(PrivateKey.ToString(), 10);
            //ECPrivateKeyParameters keyParametersA = new ECPrivateKeyParameters(dA, eCDomainParameters);
            byte[] pkBytes = dA.ToByteArray();

            byte[] pbBytes = Convert.FromBase64String(PublicKey.ToString());

            byte[] ss = BCFunctions.getSharedSecret(pkBytes, pbBytes);
            return Convert.ToBase64String(ss);

        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString getDerivedKey(SqlString sharedSecret)
        {
            byte[] ssBytes = Encoding.ASCII.GetBytes(sharedSecret.ToString());
            try
            {
                byte[] dk = BCFunctions.DeriveSymmetricKeyFromSharedSecret(ssBytes);
                return Convert.ToBase64String(dk);
            }
            catch { return ""; }
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString encrypt2F(SqlString message, SqlString pwd, SqlString salt)
        {
            try
            {
                byte[] saltBytes = Encoding.ASCII.GetBytes(salt.ToString());
                return BC2F.Encrypt2F(message.ToString(), pwd.ToString(), saltBytes);
            }
            catch (Exception ex) { return ex.Message; }

        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString decrypt2F(SqlString message, SqlString pwd, SqlString salt)
        {
            byte[] saltBytes = Encoding.ASCII.GetBytes(salt.ToString());
            try
            {
                return BC2F.Decrypt2F(message.ToString(), pwd.ToString(), saltBytes);
            }
            catch (Exception ex) { return ex.Message; }
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString encryptAES(SqlString message, SqlString key, SqlString iv)
        {

            //byte[] key = Convert.FromBase64String(txtDKA.Text);

            //byte[] iv = new byte[16]; //derivedKeyA.Take(16).ToArray();

            byte[] mBytes = Encoding.UTF8.GetBytes(message.ToString());
            byte[] keyBytes = Convert.FromBase64String(key.ToString());
            byte[] ivBytes = Convert.FromBase64String(iv.ToString());
            try
            {
                return Convert.ToBase64String(BCAES.EncryptAES(mBytes, keyBytes, ivBytes));
            }
            catch (Exception ex) { return ex.Message; }
        }

        [Microsoft.SqlServer.Server.SqlFunction(DataAccess = DataAccessKind.Read)]
        public static SqlString decryptAES(SqlString message, SqlString key, SqlString iv)
        {
            byte[] mBytes = Convert.FromBase64String(message.ToString());
            byte[] keyBytes = Convert.FromBase64String(key.ToString());
            byte[] ivBytes = Convert.FromBase64String(iv.ToString());
            try
            {
                byte[] dText = BCAES.DecryptAES(mBytes, keyBytes, ivBytes);
                return Encoding.UTF8.GetString(dText);
            }
            catch (Exception ex) { return ex.Message; }   
        }
    }

}
