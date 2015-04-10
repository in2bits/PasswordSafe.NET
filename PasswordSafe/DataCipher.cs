using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace PasswordSafe
{
    public class DataCipher : CbcBlockCipher
    {
        public DataCipher(bool forEncryption, byte[] key, byte[] iv)
            : base(new TwofishEngine())
        {
            Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        }
    }
}