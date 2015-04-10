using PasswordSafe.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordSafe.Tests.Crypto
{
    public class RandomGeneratorFactory : IRandomGeneratorFactory
    {
        public Org.BouncyCastle.Crypto.Prng.IRandomGenerator Create()
        {
            return new RandomGenerator();
        }
    }
}
