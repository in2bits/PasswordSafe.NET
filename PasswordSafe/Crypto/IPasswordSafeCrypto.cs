using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PasswordSafe.Crypto
{
    public interface IPasswordSafeCrypto
    {
        IRandomGeneratorFactory RandomGeneratorFactory { get; }
        IHMACSHA256Factory HMACSHA256Factory { get; }
        ISHA256ManagedFactory SHA256ManagedFactory { get; }
        byte[] StretchKey(string passKey, byte[] salt, uint N);
    }
}
