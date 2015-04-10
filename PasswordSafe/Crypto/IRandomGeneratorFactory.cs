using Org.BouncyCastle.Crypto.Prng;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PasswordSafe.Crypto
{
    public interface IRandomGeneratorFactory
    {
        IRandomGenerator Create();  
    }
}
