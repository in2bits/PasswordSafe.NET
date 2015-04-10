using System;

namespace PasswordSafe.Crypto
{
    public interface ISHA256 : IDisposable
    {
        byte[] ComputeHash(byte[] buffer);
        void TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);
        void TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
        byte[] Hash { get; }
    }
}