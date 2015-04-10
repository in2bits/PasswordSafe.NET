using System;

namespace PasswordSafe
{
    public static class ByteUtil
    {
        public static void AssertBytesEqual(byte[] left, byte[] right)
        {
            if (!AreBytesEqual(left, right))
                throw new Exception("Bytes mismatch");
        }

        public static bool AreBytesEqual(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
                return false;
            for (var i = 0; i < left.Length; i++)
                if (left[i] != right[i])
                    return false;
            return true;
        }
    }
}