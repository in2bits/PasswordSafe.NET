using System;

namespace PasswordSafe.Properties
{
    public class GuidProperty : Property<Guid>
    {
        public GuidProperty( byte fieldType, string name) : base(fieldType, name)
        {
        }

        protected override byte[] GetBytes(Guid value)
        {
            return value.ToByteArray();
        }

        protected override Guid GetValue()
        {
            return new Guid(_field.Data);
        }
    }
}