using System;
using System.IO;

namespace PasswordSafe.Properties
{
    public class Property
    {
        protected readonly byte _fieldType;
        protected readonly string _name;

        protected Field _field;

        internal Property(byte fieldType, string name)
        {
            if (string.IsNullOrEmpty(name))
                throw new ArgumentNullException("name");
            _fieldType = fieldType;
            _name = name;
        }

        internal void SetValue(Field field)
        {
            if (field.Type != _fieldType)
                throw new Exception("type does not match expected type");
            _field = field;
        }

        public bool HasValue { get { return _field != null; } }

        internal Field Field
        {
            get { return _field; }
        }
    }

    public abstract class Property<T> : Property
    {
        internal Property(byte fieldType, string name)
            : base(fieldType, name)
        {

        }

        protected abstract byte[] GetBytes(T value);
        protected abstract T GetValue();

        public void SetValue(T value)
        {
            var bytes = GetBytes(value);
            if (_field == null)
                _field = new Field(_fieldType);
            _field.Data = bytes;
        }

        public T Value
        {
            get
            {
                if (!HasValue)
                    throw new NullReferenceException("No value!");
                return GetValue();
            }
        }

        public T SafeValue
        {
            get
            {
                if (!HasValue)
                    return default(T);
                return Value;
            }
        }
    }
}