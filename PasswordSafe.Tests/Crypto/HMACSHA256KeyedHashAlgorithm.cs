using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PasswordSafe.Crypto;

namespace PasswordSafe.Net.Crypto
{
    public class HMACSHA256KeyedHashAlgorithm : IKeyedHashAlgorithm
    {
        private readonly HMACSHA256 _algo;

        public HMACSHA256KeyedHashAlgorithm(byte[] key)
        {
            _algo = new HMACSHA256(key);
        }

        public void TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            _algo.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        public byte[] ComputeHash(byte[] buffer)
        {
            return _algo.ComputeHash(buffer);
        }

        public byte[] Hash { get { return _algo.Hash; } }

        public void TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            _algo.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public void Clear()
        {
            _algo.Clear();
        }
    }
}
