using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using PasswordSafe.Crypto;

namespace PasswordSafe
{
    public class KeyCipher : BufferedBlockCipher
    {
        private readonly IPasswordSafeCrypto _crypto;
        private readonly byte[] _key;

        public KeyCipher(IPasswordSafeCrypto crypto, bool forEncryption, string passkey, byte[] salt, uint N)
            : base(new TwofishEngine())
        {
            _crypto = crypto;

            _key = _crypto.StretchKey(passkey, salt, N);

            var param = new KeyParameter(_key);
            Init(forEncryption, param);
        }

        public bool ValidateHashedKey(byte[] expectedKeyHash)
        {
            var keyHash = GetHashedKey();
            return ByteUtil.AreBytesEqual(keyHash, expectedKeyHash);
        }

        public byte[] GetHashedKey()
        {
            return _crypto.SHA256ManagedFactory.New().ComputeHash(_key);
        }
    }
}