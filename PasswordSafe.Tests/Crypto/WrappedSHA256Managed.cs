using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PasswordSafe.Crypto;

namespace PasswordSafe.Net.Crypto
{
    public class WrappedSHA256Managed : ISHA256
    {
        private SHA256Managed _sha256;

        public WrappedSHA256Managed()
        {
            _sha256 = new SHA256Managed();
        }

        public void Dispose()
        {
            Hash = null;
            _sha256 = null;
        }

        public byte[] ComputeHash(byte[] buffer)
        {
            Hash = _sha256.ComputeHash(buffer);
            return Hash;
        }

        public void TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            _sha256.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public void TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            _sha256.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            Hash = _sha256.Hash;
        }

        public byte[] Hash { get; private set; }
    }
}
