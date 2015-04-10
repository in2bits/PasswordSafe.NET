using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PasswordSafe.Crypto;

namespace PasswordSafe.Net.Crypto
{
    public class SHA256ManagedFactory : ISHA256ManagedFactory
    {
        public ISHA256 New()
        {
            return new WrappedSHA256Managed();
        }
    }
}
