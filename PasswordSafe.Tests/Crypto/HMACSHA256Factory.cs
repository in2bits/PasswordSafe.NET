using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PasswordSafe.Crypto;

namespace PasswordSafe.Net.Crypto
{
    public class HMACSHA256Factory : IHMACSHA256Factory
    {
        public IKeyedHashAlgorithm From(byte[] key)
        {
            return new HMACSHA256KeyedHashAlgorithm(key);
        }
    }
}
