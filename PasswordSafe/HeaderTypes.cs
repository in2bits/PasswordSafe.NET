using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PasswordSafe
{
    internal enum HeaderTypes
    {
        Version = 0x00,
        Uuid = 0x01,
        NonDefaultUserPrefs = 0x02,
        DisplayStatus = 0x03,
        LastUpdateTime = 0x04,
        LastUpdateUserhost = 0x05,
        LastUpdateApplication = 0x06,
        LastUpdateUser = 0x07,
        LastUpdateHost = 0x08,
        DbName = 0x09,
        DbDescription = 0x0a,
        Filters = 0x0b,
        Reserved1 = 0x0c,
        Reserved2 = 0x0d,
        Reserved3 = 0x0e,
        Rue = 0x0f,
        PasswordPolicies = 0x10,
        EmptyGroup = 0x11,
        Reserved4 = 0x12,
        //Last,
        End = 0xff
    }
}
