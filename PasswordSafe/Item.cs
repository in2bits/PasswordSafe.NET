using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using PasswordSafe.Properties;

namespace PasswordSafe
{
    public class Item
    {
        private readonly StringProperty _group;
        public String Group
        {
            get { return _group.SafeValue; } 
            set { _group.SetValue(value);}
        }

        private readonly StringProperty _title;
        public String Title
        {
            get { return _title.SafeValue; } 
            set { _title.SetValue(value); }
        }

        private readonly StringProperty _url;
        public String Url
        {
            get { return _url.SafeValue; } 
            set { _url.SetValue(value); }
        }

        private readonly StringProperty _user;
        public String User
        {
            get { return _user.SafeValue; }
            set { _user.SetValue(value); }
        }

        private readonly StringProperty _password;
        public String Password
        {
            get { return _password.SafeValue; }
            set { _password.SetValue(value); }
        }

        private readonly StringProperty _notes;
        public String Notes
        {
            get { return _notes.SafeValue; }
            set { _notes.SetValue(value); }
        }

        private readonly StringProperty _autoType;
        public String AutoType
        {
            get { return _autoType.SafeValue; }
            set { _autoType.SetValue(value); }
        }

        private readonly DateTimeProperty _passwordModified;
        public DateTime PasswordModified
        {
            get { return _passwordModified.SafeValue; }
            set { _passwordModified.SetValue(value); }
        }

        private readonly DateTimeProperty _passwordExpires;
        public DateTime PasswordExpires
        {
            get { return _passwordExpires.SafeValue; }
            set { _passwordExpires.SetValue(value); }
        }

        private readonly DateTimeProperty _modifiedTime;
        public DateTime ModifiedTime
        {
            get { return _modifiedTime.SafeValue; }
            set { _modifiedTime.SetValue(value); }
        }

        private readonly DateTimeProperty _createdTime;
        public DateTime CreatedTime
        {
            get { return _createdTime.SafeValue; }
            set { _createdTime.SetValue(value); }
        }

        private readonly DateTimeProperty _accessedTime;
        public DateTime AccessedTime
        {
            get { return _accessedTime.SafeValue; }
            set { _accessedTime.SetValue(value); }
        }

        private readonly GuidProperty _uuid;
        public Guid Uuid
        {
            get { return _uuid.SafeValue; }
            set { _uuid.SetValue(value); }
        }

        internal ICollection<Field> Fields
        {
            get 
            {
                var fields = new Collection<Field>();
                foreach (var property in Properties)
                {
                    if (property.HasValue)
                        fields.Add(property.Field);
                }
                return fields;
            }
        }

        internal ICollection<Property> Properties { get; private set; } 

        internal ICollection<Property> NotImplementedProperties { get; private set; } 

        public static readonly Item Eof = new Item();

        public Item()
        {
            _group = new StringProperty((byte)FieldTypes.Group, "Group");
            _title = new StringProperty((byte) FieldTypes.Title, "Title");
            _url = new StringProperty((byte) FieldTypes.Url, "Url");
            _user = new StringProperty((byte) FieldTypes.User, "User");
            _password = new StringProperty((byte) FieldTypes.Password, "Password");
            _notes = new StringProperty((byte) FieldTypes.Notes, "Notes");
            _autoType = new StringProperty((byte) FieldTypes.Autotype, "AutoType");
            _passwordModified = new DateTimeProperty((byte) FieldTypes.PasswordModified, "PasswordModified");
            _passwordExpires = new DateTimeProperty((byte) FieldTypes.PasswordExpires, "PasswordExpires");
            _modifiedTime = new DateTimeProperty((byte) FieldTypes.RecordModifiedTime, "ModifiedTime");
            _createdTime = new DateTimeProperty((byte) FieldTypes.CreatedTime, "CreatedTime");
            _accessedTime = new DateTimeProperty((byte) FieldTypes.AccessTime, "AccessedTime");
            _uuid = new GuidProperty((byte) FieldTypes.Uuid, "Uuid");

            Properties = new Collection<Property>()
            {
                _uuid,
                _group,
                _title,
                _user,
                _password,
                _notes,
                _url,
                _autoType,
                _accessedTime,
                _createdTime,
                _passwordExpires,
                _passwordModified,
                _modifiedTime
            };
            NotImplementedProperties = new Collection<Property>();
        }

        public static Item From(IEnumerable<Field> itemFields)
        {
            var item = new Item();
            foreach (var field in itemFields)
            {
                item.InitItem(field);
            }
            return item;
        }

        private void InitItem(Field field)
        {
            var type = (FieldTypes) field.Type;
            switch (type)
            {
                case FieldTypes.Start:
                    break;
                case FieldTypes.Uuid:
                    _uuid.SetValue(field);
                    break;
                case FieldTypes.Group:
                    _group.SetValue(field);
                    break;
                case FieldTypes.Title:
                    _title.SetValue(field);
                    break;
                case FieldTypes.User:
                    _user.SetValue(field);
                    break;
                case FieldTypes.Notes:
                    _notes.SetValue(field);
                    break;
                case FieldTypes.Password:
                    _password.SetValue(field);
                    break;
                case FieldTypes.CreatedTime:
                    _createdTime.SetValue(field);
                    break;
                case FieldTypes.PasswordModified:
                    _passwordModified.SetValue(field);
                    break;
                case FieldTypes.AccessTime:
                    _accessedTime.SetValue(field);
                    break;
                case FieldTypes.PasswordExpires:
                    _passwordExpires.SetValue(field);
                    break;
                case FieldTypes.RecordModifiedTime:
                    _modifiedTime.SetValue(field);
                    break;
                case FieldTypes.Url:
                    _url.SetValue(field);
                    break;
                case FieldTypes.Autotype:
                    _autoType.SetValue(field);
                    break;
                case FieldTypes.Reserved:
                case FieldTypes.PasswordHistory:
                case FieldTypes.Policy:
                case FieldTypes.XtimeInt:
                case FieldTypes.RunCommand:
                case FieldTypes.DoubleClickAction:
                case FieldTypes.Email:
                case FieldTypes.Protected:
                case FieldTypes.Symbols:
                case FieldTypes.ShiftDoubleClickAction:
                case FieldTypes.PolicyName:
                case FieldTypes.KeyboardShortcuts:
                    var property = new Property(field.Type, "Not Implemented: " + field.Type);
                    NotImplementedProperties.Add(property);
                    break;
                case FieldTypes.End:
                    break;
                case FieldTypes.EntrySize:
                case FieldTypes.EntryType:
                case FieldTypes.EntryStatus:
                case FieldTypes.PasswordLength:
                case FieldTypes.UnknownFields:
                default:
                    throw new ArgumentOutOfRangeException();
            }
            Fields.Add(field);
        }
    }
}