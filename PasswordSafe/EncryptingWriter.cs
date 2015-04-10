using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.IO;
using Org.BouncyCastle.Crypto.Prng;
using PasswordSafe.Crypto;

namespace PasswordSafe
{
    internal class EncryptingWriter : Writer
    {
        private readonly IPasswordSafeCrypto _crypto;
        private DataCipher _dataCipher;
        private IKeyedHashAlgorithm _hmac;

        public EncryptingWriter(Stream stream, IPasswordSafeCrypto crypto) 
            : base(stream)
        {
            _crypto = crypto;
            _prng = crypto.RandomGeneratorFactory.Create();
        }

        public void Init(string passkey, UInt32 iterations)
        {
            WriteBytes(Safe.Tag);

            var salt = GetRandomData(Safe.SaltLengthV3);
            var sha256 = _crypto.SHA256ManagedFactory.New();
            if (salt.Length != Safe.SaltLengthV3)
                throw new Exception("Invalid salt length");
            salt = sha256.ComputeHash(salt);
            WriteBytes(salt);
            WriteBytes(BitConverter.GetBytes(iterations));
            var keyCipher = new KeyCipher(_crypto, true, passkey, salt, iterations);

            var keyHash = keyCipher.GetHashedKey();
            if (keyHash.Length != Safe.StretchedPasskeyHashLength)
                throw new Exception("Invalid hashed key length");
            WriteBytes(keyHash);

            var dataKey = GetRandomData(Safe.DataKeyLength);
            var encryptedDataKey = new byte[dataKey.Length];
            var l1 = keyCipher.ProcessBytes(dataKey, 0, dataKey.Length, encryptedDataKey, 0);
            keyCipher.DoFinal(encryptedDataKey, l1);
            WriteBytes(encryptedDataKey);

            var hmacKey = GetRandomData(Safe.HmacKeyLength);
            var encryptedHmacKey = new byte[hmacKey.Length];
            l1 = keyCipher.ProcessBytes(hmacKey, 0, encryptedHmacKey.Length, encryptedHmacKey, 0);
            keyCipher.DoFinal(encryptedHmacKey, l1);
            WriteBytes(encryptedHmacKey);

            var dataInitializationVector = GetRandomData(Safe.DataInitializationVectorLength);
            var hasher = _crypto.SHA256ManagedFactory.New();
            var hashedDataInitializationVector = hasher.ComputeHash(dataInitializationVector);
            Buffer.BlockCopy(hashedDataInitializationVector, 0, dataInitializationVector, 0, Safe.DataInitializationVectorLength);
            WriteBytes(dataInitializationVector);

            _dataCipher = new DataCipher(true, dataKey, dataInitializationVector);

            _hmac = _crypto.HMACSHA256Factory.From(hmacKey);
        }

        private IRandomGenerator _prng;// = _crypto.RandomGeneratorFactory.Create();// CryptoApiRandomGenerator();
        /// <summary>
        /// TODO: Implement Random Generator per PWS code
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        private byte[] GetRandomData(int length)
        {
            var data = new byte[length];
            _prng.NextBytes(data);
            return data;
        }

        protected override void ProcessFieldDataBlock(byte[] block, int dataOffset, int dataLength)
        {
            var data = new byte[dataLength];
            Buffer.BlockCopy(block, dataOffset, data, 0, dataLength);
            _hmac.TransformBlock(data, 0, data.Length, data, 0);
            _dataCipher.ProcessBlock(block, 0, block, 0);
        }

        public override void WriteEof()
        {
            base.WriteEof();
            WriteHmac();
        }

        private void WriteHmac()
        {
            var buffer = new byte[0];
            _hmac.TransformFinalBlock(buffer, 0, 0);
            var hash = _hmac.Hash;
            WriteBytes(hash);
        }
    }
}