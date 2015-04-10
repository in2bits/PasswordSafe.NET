using System;

namespace PasswordSafe.Properties
{
    public class DateTimeProperty : Property<DateTime>
    {
        public DateTimeProperty(byte fieldType, string name) : base(fieldType, name)
        {
        }

        protected override byte[] GetBytes(DateTime value)
        {
            var unixTimeDecimal = value.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            var unixTime = (UInt32) unixTimeDecimal;
            return BitConverter.GetBytes(unixTime);
        }

        protected override DateTime GetValue()
        {
            var unixTime = BitConverter.ToInt32(_field.Data, 0);
            DateTime netTime = DateTime.MinValue;
            if (unixTime != 0)
                netTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(unixTime);
            return netTime;
        }
    }
}