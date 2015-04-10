using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using PasswordSafe.Crypto;
using PasswordSafe.Properties;

namespace PasswordSafe
{
    public class Safe
    {
        private readonly StringProperty _name;
        public String Name
        {
            get { return _name.SafeValue; }
            set { _name.SetValue(value); }
        }

        private readonly StringProperty _description;
        public String Description
        {
            get { return _description.SafeValue; }
            set { _description.SetValue(value); }
        }

        private readonly StringProperty _nonDefaultUserPrefs;
        public String NonDefaultUserPrefs
        {
            get { return _nonDefaultUserPrefs.SafeValue; }
            set { _nonDefaultUserPrefs.SetValue(value); }
        }

        private readonly StringProperty _lastUpdateUser;
        public String LastUpdateUser
        {
            get { return _lastUpdateUser.SafeValue; }
            set { _lastUpdateUser.SetValue(value); }
        }

        private readonly StringProperty _lastUpdateHost;
        public String LastUpdateHost
        {
            get { return _lastUpdateHost.SafeValue; }
            set { _lastUpdateHost.SetValue(value); }
        }

        private readonly StringProperty _lastUpdateApplication;
        public String LastUpdateApplication
        {
            get { return _lastUpdateApplication.SafeValue; }
            set { _lastUpdateApplication.SetValue(value); }
        }

        private readonly VersionProperty _version;
        public Version Version
        {
            get { return _version.SafeValue; }
            set { _version.SetValue(value); }
        }

        private readonly DateTimeProperty _lastUpdateTime;
        public DateTime LastUpdateTime
        {
            get { return _lastUpdateTime.SafeValue; }
            set { _lastUpdateTime.SetValue(value); }
        }

        private GuidProperty _uuid;
        public Guid Uuid
        {
            get { return _uuid.SafeValue; }
            set { _uuid.SetValue(value); }
        }

        private ICollection<Field> Fields
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

        public IList<Item> Items { get; private set; }

        internal static readonly byte[] EofBytes =
        {
            (byte)'P', (byte)'W', (byte)'S', (byte)'3', (byte)'-', (byte)'E', (byte)'O', (byte)'F',
            (byte)'P', (byte)'W', (byte)'S', (byte)'3', (byte)'-', (byte)'E', (byte)'O', (byte)'F'
        };

        internal static readonly byte[] Tag = { (byte)'P', (byte)'W', (byte)'S', (byte)'3' };
        private readonly IPasswordSafeCrypto _crypto;

        private const int MinHashIterations = 2048;
        internal const int SaltLengthV3 = 32;
        internal const int StretchedPasskeyHashLength = 32;
        internal const int DataKeyLength = 32;
        internal const int HmacKeyLength = 32;
        internal const int DataInitializationVectorLength = 16;

        public Safe()
        {
            _name = new StringProperty((byte)HeaderTypes.DbName, "Name");
            _description = new StringProperty((byte)HeaderTypes.DbDescription, "Description");
            _nonDefaultUserPrefs = new StringProperty((byte)HeaderTypes.NonDefaultUserPrefs, "NonDefaultUserPrefs");
            _lastUpdateUser = new StringProperty((byte)HeaderTypes.LastUpdateUser, "LastUpdateUser");
            _lastUpdateHost = new StringProperty((byte)HeaderTypes.LastUpdateHost, "LastUpdateHost");
            _lastUpdateApplication = new StringProperty((byte)HeaderTypes.LastUpdateApplication, "LastUpdateApplication");
            _version = new VersionProperty((byte)HeaderTypes.Version, "Version");
            _lastUpdateTime = new DateTimeProperty((byte)HeaderTypes.LastUpdateTime, "LastUpdateTime");
            _uuid = new GuidProperty((byte)HeaderTypes.Uuid, "Uuid");

            Items = new List<Item>();
            Properties = new Collection<Property>
                {
                    _name,
                    _description,
                    _nonDefaultUserPrefs,
                    _lastUpdateUser,
                    _lastUpdateHost,
                    _lastUpdateApplication,
                    _version,
                    _lastUpdateTime,
                    _uuid
                };
            NotImplementedProperties = new Collection<Property>();
        }

        public Safe(IPasswordSafeCrypto cryto) : this()
        {
            _crypto = cryto;
        }

        public static Safe Load(IPasswordSafeCrypto crypto, Stream stream, string passphrase)
        {
            var safe = new Safe(crypto);
            var reader = new DecryptingReader(stream, safe._crypto);
            reader.Init(passphrase);
            safe.LoadCore(reader);
            return safe;
        }

        public static Safe LoadUnencrypted(Stream stream)
        {
            var safe = new Safe();
            var reader = new Reader(stream);
            safe.LoadCore(reader);
            return safe;
        }

        private void LoadCore(Reader reader)
        {
            var headerFields = reader.ReadFieldsToEnd();
            InitFrom(headerFields);
            var item = reader.ReadItem();
            while (item != Item.Eof)
            {
                Items.Add(item);
                item = reader.ReadItem();
            }
            reader.ReadHmac();
        }

        public void Save(Stream stream, string passphrase)
        {
            var writer = new EncryptingWriter(stream, _crypto);
            writer.Init(passphrase, MinHashIterations);
            SaveCore(writer);
        }

        public void SaveUnencrypted(Stream stream)
        {
            var writer = new Writer(stream);
                SaveCore(writer);
        }

        private void SaveCore(Writer writer)
        {
            var headerFields = Fields;
            foreach (var field in headerFields)
                writer.WriteField(field);
            writer.WriteField(Field.Eof);
            for (int i = 0; i < Items.Count; i++)
            {
                writer.WriteItem(Items[i]);
                if (i < Items.Count)
                    writer.WriteField(Field.Eof);
            }
            writer.WriteEof();
        }

        private void InitFrom(IEnumerable<Field> fields)
        {
            foreach (var field in fields)
                InitFrom(field);
        }

        private void InitFrom(Field field)
        {
            var type = (HeaderTypes)field.Type;
            switch (type)
            {
                case HeaderTypes.Version:
                    _version.SetValue(field);
                    break;
                case HeaderTypes.Uuid:
                    _uuid.SetValue(field);
                    break;
                case HeaderTypes.NonDefaultUserPrefs:
                    _nonDefaultUserPrefs.SetValue(field);
                    break;
                case HeaderTypes.LastUpdateTime:
                    _lastUpdateTime.SetValue(field);
                    break;
                case HeaderTypes.LastUpdateApplication:
                    _lastUpdateApplication.SetValue(field);
                    break;
                case HeaderTypes.LastUpdateUser:
                    _lastUpdateUser.SetValue(field);
                    break;
                case HeaderTypes.LastUpdateHost:
                    _lastUpdateHost.SetValue(field);
                    break;
                case HeaderTypes.DbName:
                    _name.SetValue(field);
                    break;
                case HeaderTypes.DbDescription:
                    _description.SetValue(field);
                    break;
                case HeaderTypes.DisplayStatus:
                case HeaderTypes.Filters:
                case HeaderTypes.LastUpdateUserhost:
                case HeaderTypes.Reserved1:
                case HeaderTypes.Reserved2:
                case HeaderTypes.Reserved3:
                case HeaderTypes.Rue:
                case HeaderTypes.PasswordPolicies:
                case HeaderTypes.EmptyGroup:
                case HeaderTypes.Reserved4:
                    var property = new Property(field.Type, "Not Implemented: " + field.Type);
                    NotImplementedProperties.Add(property);
                    break;
                case HeaderTypes.End:
                    return;
                default:
                    throw new ArgumentOutOfRangeException("type");
            }
            Fields.Add(field);
        }
    }
}