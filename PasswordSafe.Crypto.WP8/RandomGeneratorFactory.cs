using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PasswordSafe.Crypto.WP8
{
    public class RandomGeneratorFactory : IRandomGeneratorFactory
    {
        public Org.BouncyCastle.Crypto.Prng.IRandomGenerator Create()
        {
            return new RandomGenerator();
        }
    }
}
