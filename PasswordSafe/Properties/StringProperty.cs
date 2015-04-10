using System;
using System.Text;

namespace PasswordSafe.Properties
{
    public class StringProperty : Property<string>
    {
        private readonly Encoding _encoding;

        public StringProperty(byte fieldType, string name, Encoding encoding = null) : base(fieldType, name)
        {
            if (encoding == null)
                _encoding = Encoding.UTF8;
        }

        protected override byte[] GetBytes(string value)
        {
            return _encoding.GetBytes(value);
        }

        protected override string GetValue()
        {
            var data = _field.Data;
            return _encoding.GetString(data, 0, data.Length);
        }
    }
}