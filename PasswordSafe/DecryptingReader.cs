using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using PasswordSafe.Crypto;

namespace PasswordSafe
{
    internal class DecryptingReader : Reader
    {
        private readonly IPasswordSafeCrypto _crypto;

        public DecryptingReader(Stream stream, IPasswordSafeCrypto crypto)
            : base(stream)
        {
            _crypto = crypto;
        }

        private CbcBlockCipher _dataCipher;
        private IKeyedHashAlgorithm _hmac;

        public void Init(string passkey)
        {
            //0-4
            AssertNextBytesEqual(Safe.Tag);
                
            //5-36
            var salt = ReadBytes(Safe.SaltLengthV3);

            //37-40
            var iterations = ReadUInt32();

            var keyCipher = new KeyCipher(_crypto, false, passkey, salt, iterations);

            //41-72 
            var expectedKeyHash = ReadBytes(Safe.StretchedPasskeyHashLength);
            if (!keyCipher.ValidateHashedKey(expectedKeyHash))
                throw new InvalidPasskeyException();

            //73-104
            var dataKey = Decrypt(keyCipher, Safe.DataKeyLength);

            //105-136
            var hmacKey = Decrypt(keyCipher, Safe.HmacKeyLength);

            //137-152
            var dataInitializationVector = ReadBytes(Safe.DataInitializationVectorLength);

            _dataCipher = new DataCipher(false, dataKey, dataInitializationVector);

            _hmac = _crypto.HMACSHA256Factory.From(hmacKey);
        }

        private byte[] Decrypt(BufferedBlockCipher cipher, int byteCount)
        {
            var encrypted = ReadBytes(byteCount);
            var clear = new byte[byteCount];
            var l1 = cipher.ProcessBytes(encrypted, 0, encrypted.Length, clear, 0);
            cipher.DoFinal(clear, l1);
            return clear;
        }

        protected override int GetFieldDataBlockSize()
        {
            return _dataCipher.GetBlockSize();
        }

        protected override void ProcessFieldDataBlock(byte[] block)
        {
            _dataCipher.ProcessBlock(block, 0, block, 0);
        }
    }
}