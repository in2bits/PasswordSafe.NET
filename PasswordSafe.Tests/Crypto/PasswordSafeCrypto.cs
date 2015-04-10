using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PasswordSafe.Crypto;
using PasswordSafe.Tests.Crypto;

namespace PasswordSafe.Net.Crypto
{
    public class PasswordSafeCrypto : IPasswordSafeCrypto
    {
        public IRandomGeneratorFactory RandomGeneratorFactory { get; private set; }
        public IHMACSHA256Factory HMACSHA256Factory { get; private set; }
        public ISHA256ManagedFactory SHA256ManagedFactory { get; private set; }

        public PasswordSafeCrypto()
        {
            RandomGeneratorFactory = new RandomGeneratorFactory();
            HMACSHA256Factory = new HMACSHA256Factory();
            SHA256ManagedFactory = new SHA256ManagedFactory();
        }

        public byte[] StretchKey(string passKey, byte[] salt, uint N)
        {
            var pstr = ConvertString(passKey);

            byte[] X;

            using (var H0 = SHA256ManagedFactory.New())
            {
                H0.TransformBlock(pstr, 0, pstr.Length, null, 0);
                H0.TransformFinalBlock(salt, 0, salt.Length);

                X = H0.Hash;
            }

            for (int i = 0; i < N; ++i)
            {
                using (var H = SHA256ManagedFactory.New())
                    X = H.ComputeHash(X);
            }

            return X;
        }

        private static byte[] ConvertString(string raw)
        {
            //http://stackoverflow.com/a/14110903/8787
            var encoding = Encoding.GetEncoding("ISO-8859-1"); //we'll just see if this works
            byte[] ansiEncodedValue = encoding.GetBytes(raw);
            return ansiEncodedValue;
        }
    }
}
