using Org.BouncyCastle.Crypto.Prng;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PasswordSafe.Tests.Crypto
{
    public class RandomGenerator : IRandomGenerator
    {
        private readonly RNGCryptoServiceProvider _rng;

        public RandomGenerator()
        {
            _rng = new RNGCryptoServiceProvider();
        }

        public void AddSeedMaterial(long seed)
        {
            throw new NotSupportedException("AddSeedMaterial(long seed) not supported by RandomGenerator (RNGCryptoServiceProvider)");
        }

        public void AddSeedMaterial(byte[] seed)
        {
            throw new NotSupportedException("AddSeedMaterial(byte[] seed) not supported by RandomGenerator (RNGCryptoServiceProvider)");
        }

        public void NextBytes(byte[] bytes, int start, int len)
        {
            throw new NotSupportedException("NextBytes(byte[] bytes, int start, int len) not supported by RandomGenerator (RNGCryptoServiceProvider)");
        }

        public void NextBytes(byte[] bytes)
        {
            _rng.GetBytes(bytes);
        }
    }
}
