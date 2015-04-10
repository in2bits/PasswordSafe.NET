using System;
using Org.BouncyCastle.Crypto;

namespace PasswordSafe.Properties
{
    public class VersionProperty : Property<Version>
    {
        public VersionProperty(byte fieldType, string name) : base(fieldType, name)
        {
        }

        protected override byte[] GetBytes(Version value)
        {
            var bytes = new byte[2];
            bytes[1] = (byte)value.Major;
            bytes[0] = (byte) value.Minor;
            return bytes;
        }

        protected override Version GetValue()
        {
            var data = _field.Data;
            if (data.Length != 2)
                throw new DataLengthException();
            var major = data[1];
            var minor = data[0];
            return new Version(major, minor);
        }
    }
}