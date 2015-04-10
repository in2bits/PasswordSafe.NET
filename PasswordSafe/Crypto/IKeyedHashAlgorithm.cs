namespace PasswordSafe.Crypto
{
    public interface IKeyedHashAlgorithm
    {
        byte[] ComputeHash(byte[] buffer);
        void TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
        byte[] Hash { get; }
        void TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);
        void Clear();
    }
}
